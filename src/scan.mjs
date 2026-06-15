// Vulnerability Scan orchestrator — the pure spine that wires the module seams:
//
//   enumerate (pure) -> fetch feed (impure, injected) -> normalize (pure)
//     -> match (pure) -> abandoned lookup (impure, injected) -> render + upsert
//     issue (impure, injected) -> diff vs. prior persisted Findings (pure) -> exit gate
//
// The impure edges (feed fetch, per-slug wordpress.org lookup, issue upsert) are
// injected so this orchestrator is testable end-to-end against a fixture tree without
// a live network or runner. The thin entrypoint (index.mjs) supplies the real
// implementations.
//
// Alert-only-on-new: the deduped issue is the persistence layer. The upsert returns
// the *prior* issue body (the thin impure read); the pure differ recovers the prior
// Findings from it and keeps only the new/worsened subset, which alone gates the
// failing workflow status. The issue itself is always updated in place with the
// current Findings, so an unchanged site renders the same Findings yet runs GREEN.

import { enumerateInventory } from './inventory.mjs';
import { normalizeWordfenceFeed } from './wordfence.mjs';
import { matchVulnerabilities, isAlertWorthy } from './matcher.mjs';
import { abandonedFinding } from './abandoned.mjs';
import { mergeDatasets } from './wpscan.mjs';
import { renderIssueTitle, renderIssueBody, parsePersistedFindings } from './report.mjs';
import { diffFindings } from './differ.mjs';

// Bound the per-slug wordpress.org fan-out: a full-inventory site can carry 30+
// plugins, and we will not query them all at once (socket/rate pressure on wp.org).
const WPORG_CONCURRENCY = 5;

// Bound the per-slug WPScan fan-out hard. The WPScan free tier is a LOW daily call
// budget (one call per plugin; ADR-0003), which is the whole reason WPScan is a
// cross-reference and not the primary — so keep the concurrency conservative.
const WPSCAN_CONCURRENCY = 2;

// Cross-reference WPScan per top-level plugin slug, returning a merged WPScan dataset in
// the SAME shape the Wordfence normalizer produces. OPTIONAL and fail-safe: when no
// `fetchWpscanData` edge is injected (the zero-secret default — no token) this is a
// no-op and the scan behaves exactly as before. Each per-slug lookup that rejects is
// swallowed so a flaky or budget-exhausted cross-reference never aborts the run;
// Wordfence stays authoritative. The returned dataset is folded into the primary
// Wordfence dataset by mergeDatasets and matched through the one shared matcher — there
// is no parallel matching path.
async function crossReferenceWpscan(inventory, fetchWpscanData) {
  if (typeof fetchWpscanData !== 'function') return {};

  // Unique top-level plugin slugs only (mirrors the wp.org fan-out). Embedded plugins
  // have no update channel and themes/core are not WPScan plugin records.
  const seen = new Set();
  const targets = [];
  for (const item of inventory) {
    if (!item || item.kind !== 'plugin' || item.embedded === true) continue;
    if (seen.has(item.slug)) continue;
    seen.add(item.slug);
    targets.push(item.slug);
  }

  const datasets = [];
  let cursor = 0;
  async function worker() {
    while (cursor < targets.length) {
      const slug = targets[cursor];
      cursor += 1;
      try {
        const ds = await fetchWpscanData(slug);
        if (ds && typeof ds === 'object') datasets.push(ds);
      } catch {
        // A transport failure / rate limit is not evidence of anything — fail safe.
      }
    }
  }

  const workers = Array.from(
    { length: Math.min(WPSCAN_CONCURRENCY, targets.length) },
    () => worker(),
  );
  await Promise.all(workers);

  // Fold the per-slug datasets together (WPScan-vs-WPScan dedup handled by mergeDatasets).
  return datasets.reduce((acc, ds) => mergeDatasets(acc, ds), {});
}

// Detect Abandoned (closed/removed) plugins. For each *top-level* plugin slug (an
// embedded plugin is handled by the matcher's embedded detector; core/themes/drop-ins
// are not wordpress.org plugins), query the injected impure edge and let the pure
// decision (abandonedFinding) shape the verdict. The lookup is fail-safe: a rejected
// or garbage response yields no Finding, so a flaky lookup never fires a false alert.
async function detectAbandoned(inventory, fetchPluginInfo) {
  if (typeof fetchPluginInfo !== 'function') return [];

  // Unique top-level plugin slugs only — never query the same slug twice.
  const seen = new Set();
  const targets = [];
  for (const item of inventory) {
    if (!item || item.kind !== 'plugin' || item.embedded === true) continue;
    if (seen.has(item.slug)) continue;
    seen.add(item.slug);
    targets.push(item);
  }

  const findings = [];
  // Simple bounded worker pool over a shared cursor — concurrent but capped.
  let cursor = 0;
  async function worker() {
    while (cursor < targets.length) {
      const item = targets[cursor];
      cursor += 1;
      let response = null;
      try {
        response = await fetchPluginInfo(item.slug);
      } catch {
        // A transport failure is not evidence of abandonment — fail safe.
        response = null;
      }
      const finding = abandonedFinding(item, response);
      if (finding) findings.push(finding);
    }
  }

  const workers = Array.from(
    { length: Math.min(WPORG_CONCURRENCY, targets.length) },
    () => worker(),
  );
  await Promise.all(workers);

  return findings;
}

export async function runVulnScan({
  siteRoot,
  repoSlug,
  fetchFeed,
  fetchPluginInfo,
  fetchWpscanData,
  upsertIssue,
} = {}) {
  const inventory = enumerateInventory(siteRoot);

  const rawFeed = await fetchFeed();
  const wordfence = normalizeWordfenceFeed(rawFeed);

  // OPTIONAL WPScan cross-reference. Absent (no token) => {} => the dataset is exactly
  // the Wordfence one and behavior is unchanged. Present => folded in (Wordfence wins on
  // shared CVEs; WPScan-only entries added) and matched through the same matcher.
  const wpscan = await crossReferenceWpscan(inventory, fetchWpscanData);
  const dataset = mergeDatasets(wordfence, wpscan);

  const findings = matchVulnerabilities(inventory, dataset);

  // Fold in Abandoned (closed/removed) Findings from the wordpress.org lookup.
  const abandoned = await detectAbandoned(inventory, fetchPluginInfo);
  for (const f of abandoned) findings.push(f);

  const alertWorthy = findings.filter(isAlertWorthy);

  const title = renderIssueTitle(alertWorthy);
  const body = renderIssueBody(repoSlug, alertWorthy);

  // Upsert in place. The returned `priorBody` is the existing issue's body from before
  // this run (null on the first run, when no issue exists yet) — the thin impure read
  // that feeds the pure diff.
  const upsert = (await upsertIssue({ repoSlug, title, body })) || {};

  // Alert only on the new/worsened subset: recover the prior persisted Findings and
  // diff. The failing-status gate fires on this subset alone, so an unchanged site
  // (same Findings, none new or worsened) runs GREEN.
  const prior = parsePersistedFindings(upsert.priorBody);
  const newOrWorsened = diffFindings(prior, alertWorthy);

  return {
    inventory,
    findings,
    alertWorthy: alertWorthy.length,
    newOrWorsened: newOrWorsened.length,
    exitCode: newOrWorsened.length > 0 ? 1 : 0,
  };
}
