// `mode: both` — run the Vulnerability Scan and Drift Detection together and report
// their Findings in ONE deduped per-site issue (CONTEXT.md "one per site"). Combining
// is just concatenating the two Finding lists and finalizing once through the shared
// report+gate tail, so there is no second upsert and no clobbered state block.
//
// Order matters for failure semantics: the drift collector (the impure live read) runs
// FIRST so a collector error fails the run loudly BEFORE any issue is upserted —
// `both` must never file a half-done issue (vuln Findings only) when it could not read
// live state. The pure differ still never fabricates drift from a bad read (ADR-0010).

import { produceVulnFindings } from './scan.mjs';
import { produceDriftFindings } from './drift-scan.mjs';
import { finalizeFindings } from './report-gate.mjs';

export async function runCombinedScan({
  siteRoot,
  repoSlug,
  baseline,
  failOn,
  fetchFeed,
  fetchPluginInfo,
  fetchWpscanData,
  collectSnapshot,
  upsertIssue,
} = {}) {
  // Drift first: a collector failure must abort before any upsert (fail loud).
  const driftFindings = await produceDriftFindings({ baseline, collectSnapshot });

  const { inventory, findings: vulnFindings } = await produceVulnFindings({
    siteRoot, fetchFeed, fetchPluginInfo, fetchWpscanData,
  });

  // Merge both lists; vuln and drift Finding identities never collide (distinct
  // `type`s), so the differ dedups each independently across runs.
  const findings = [...vulnFindings, ...driftFindings];

  const finalized = await finalizeFindings({ repoSlug, findings, failOn, upsertIssue });

  return { mode: 'both', inventory, ...finalized };
}
