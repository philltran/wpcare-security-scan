// Finding differ / dedup — PURE, deep module. Drives "alert only on new/worsened."
//
//   diffFindings(priorFindings, currentFindings) -> [ Finding ]
//
// Given the prior persisted Findings (read from the existing deduped issue) and the
// current scan's Findings, return only the subset that should fire an alert: the
// *new* Findings (no prior Finding shares their identity) and the *worsened* ones (a
// prior Finding shares their identity but the current severity outranks it). When the
// current Findings match the prior set exactly, the subset is empty — repeated runs
// are idempotent and the failing-status gate stays green. A severity *increase* on an
// existing Finding re-alerts; an equal or lower severity does not.
//
// Pure and fixture-tested: no network, no persistence. The thin impure read of the
// prior Findings out of the deduped issue body lives at the reporter edge, not here.

import { severityRank } from './matcher.mjs';

// Finding identity — what makes two Findings "the same" across runs, so a severity
// bump is a *worsening* of one Finding rather than a brand-new one. Keyed on the
// stable facets only: the Finding `type`, the `slug`, the on-disk `location`, and —
// for a CVE — the `cve` id (so two distinct CVEs against one plugin are two distinct
// Findings). Deliberately NOT keyed on `version`: a partial update that leaves the
// item still vulnerable is the same unresolved Finding, not a new one, so it must not
// spuriously re-alert. `severity` is excluded too — it is the thing we compare to
// decide "worsened," not part of identity.
export function findingIdentity(finding) {
  if (!finding || typeof finding !== 'object') return '';
  return [finding.type, finding.slug, finding.location, finding.cve ?? '']
    .map((p) => String(p ?? ''))
    .join('|');
}

export function diffFindings(priorFindings, currentFindings) {
  const prior = Array.isArray(priorFindings) ? priorFindings : [];
  const current = Array.isArray(currentFindings) ? currentFindings : [];

  // Index the prior set by identity, keeping the strongest prior severity seen for
  // each identity so a worsening is measured against the worst we last reported.
  const priorRankByIdentity = new Map();
  for (const f of prior) {
    const id = findingIdentity(f);
    const rank = severityRank(f.severity);
    const seen = priorRankByIdentity.get(id);
    if (seen === undefined || rank > seen) priorRankByIdentity.set(id, rank);
  }

  const subset = [];
  for (const f of current) {
    const id = findingIdentity(f);
    if (!priorRankByIdentity.has(id)) {
      subset.push(f); // new: no prior Finding shares this identity
      continue;
    }
    if (severityRank(f.severity) > priorRankByIdentity.get(id)) {
      subset.push(f); // worsened: same identity, strictly higher severity
    }
  }

  return subset;
}
