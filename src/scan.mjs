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
import { matchVulnerabilities, isAlertWorthy, severityRank } from './matcher.mjs';
import { abandonedFinding } from './abandoned.mjs';
import { outdatedFinding } from './outdated.mjs';
import { mergeDatasets } from './wpscan.mjs';
import { renderIssueTitle, renderIssueBody, parsePersistedFindings } from './report.mjs';
import { diffFindings } from './differ.mjs';

// The `fail-on` severity threshold (issue #9). It governs ONLY the failing workflow
// status: the deduped issue is always upserted with every current Finding regardless,
// but the run fails iff at least one NEW or WORSENED alert-worthy Finding meets-or-
// exceeds this severity. The per-site workflow sets it to ratchet the noise of the
// failing status down for a fleet without ever changing what is reported.
//
// `low` is the default — it gates on every scored band low..critical, preserving the
// pre-#9 contract (every new/worsened alert-worthy Finding failed the run). An
// unrecognized / empty value falls back to `low` rather than disabling the gate: a
// security gate must never be silently disarmed by a typo. There is deliberately no
// "off"/"none" sentinel that disables failure — a site that wants the issue-only
// behavior raises the threshold above its Findings explicitly.
const DEFAULT_FAIL_ON = 'low';

// Resolve a `fail-on` input string to a numeric rank using the matcher's existing
// severity scale. An unknown token resolves to the low rank (fail-safe default).
function failOnRank(failOn) {
  const token = String(failOn ?? '').trim().toLowerCase() || DEFAULT_FAIL_ON;
  const rank = severityRank(token);
  // severityRank returns 0 for an unrecognized token (it shares `unknown`'s rank).
  // Only `unknown` itself legitimately ranks 0; any *other* unrecognized token must
  // fall back to the low default so a typo never disables the gate.
  if (rank === 0 && token !== 'unknown') return severityRank(DEFAULT_FAIL_ON);
  return rank;
}

// Does a Finding's severity meet-or-exceed the threshold? An UNSCORED CVE (severity
// 'unknown', rank 0 — a CVE the feed carries with no CVSS) is treated as always
// meeting any threshold: a security tool must not silently swallow a vuln it cannot
// rank. Every other band is a straight rank comparison.
function meetsThreshold(finding, thresholdRank) {
  if (!finding) return false;
  if (finding.severity === 'unknown') return true;
  return severityRank(finding.severity) >= thresholdRank;
}

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

// Query wordpress.org per *top-level* plugin slug (an embedded plugin is handled by the
// matcher's embedded detector; core/themes/drop-ins are not wordpress.org plugins) and
// derive BOTH wp.org-sourced verdicts from the single recorded response, reusing it:
//   - Abandoned (closed/removed): the plugin has no update channel  — ALERT-worthy.
//   - Outdated (installed < the wp.org latest, no CVE, not abandoned): merely behind —
//     REPORT-ONLY (never trips the gate; the scanner must not cry wolf).
// `cveSlugs` is the set of slugs already carrying a Known CVE Finding, so an outdated
// verdict is suppressed for them — the PRD's notion is "outdated-but-no-CVE" and a CVE
// alert already owns that slug. The lookup is fail-safe: a rejected or garbage response
// yields no Finding, so a flaky lookup never fires a false alert.
async function detectWporgFindings(inventory, fetchPluginInfo, cveSlugs) {
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

      const abandoned = abandonedFinding(item, response);
      if (abandoned) {
        findings.push(abandoned);
        continue; // abandoned owns the slug; never also report it as merely outdated.
      }

      // Report-only outdated-but-no-CVE: skip slugs that already carry a CVE alert.
      if (cveSlugs.has(item.slug)) continue;
      const outdated = outdatedFinding(item, response);
      if (outdated) findings.push(outdated);
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
  failOn,
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

  // Fold in the wordpress.org-sourced Findings from one per-slug lookup: Abandoned
  // (closed/removed; alert-worthy) and report-only Outdated (installed < latest, no
  // CVE; never trips the gate). Outdated is suppressed for any slug already carrying a
  // Known CVE Finding — the PRD's notion is "outdated-but-no-CVE."
  const cveSlugs = new Set(
    findings.filter((f) => f.type === 'cve').map((f) => f.slug),
  );
  const wporgFindings = await detectWporgFindings(inventory, fetchPluginInfo, cveSlugs);
  for (const f of wporgFindings) findings.push(f);

  const alertWorthy = findings.filter(isAlertWorthy);

  // The rendered report shows EVERY detected Finding (including report-only outdated) so
  // a maintainer has the complete picture; the reporter persists + counts only the
  // alert-worthy subset, so report-only items never trip the gate. The differ below
  // still runs over `alertWorthy` alone.
  const title = renderIssueTitle(findings);
  const body = renderIssueBody(repoSlug, findings);

  // Upsert in place. The returned `priorBody` is the existing issue's body from before
  // this run (null on the first run, when no issue exists yet) — the thin impure read
  // that feeds the pure diff.
  const upsert = (await upsertIssue({ repoSlug, title, body })) || {};

  // Alert only on the new/worsened subset: recover the prior persisted Findings and
  // diff. The failing-status gate fires on this subset alone, so an unchanged site
  // (same Findings, none new or worsened) runs GREEN.
  const prior = parsePersistedFindings(upsert.priorBody);
  const newOrWorsened = diffFindings(prior, alertWorthy);

  // The `fail-on` threshold further narrows the gate to the new/worsened Findings whose
  // severity meets-or-exceeds it. The deduped issue above already carries EVERY current
  // Finding (the report is complete regardless of fail-on); this only governs whether
  // the workflow *status* fails. An unscored CVE always counts (fail-loud).
  const threshold = failOnRank(failOn);
  const gating = newOrWorsened.filter((f) => meetsThreshold(f, threshold));

  return {
    inventory,
    findings,
    alertWorthy: alertWorthy.length,
    newOrWorsened: newOrWorsened.length,
    exitCode: gating.length > 0 ? 1 : 0,
  };
}
