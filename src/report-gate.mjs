// Shared report + gate tail — PURE spine shared by every scan mode.
//
//   finalizeFindings({ repoSlug, findings, failOn, upsertIssue }) -> { ...counts, exitCode }
//
// Given the complete current Finding list (from the Vulnerability Scan, Drift
// Detection, or BOTH combined), this renders the deduped per-site issue, upserts it in
// place, recovers the prior persisted Findings, diffs to the new/worsened subset, and
// applies the fail-on gate. It is the single place the "alert only on new/worsened"
// contract (ADR-0005) and the fail-on gate (ADR-0008) are applied, so combining vuln +
// drift Findings into one issue is just concatenating the lists and finalizing once —
// no second upsert, no clobbered state block.
//
// The deduped issue ALWAYS carries every current Finding (the report is complete); the
// gate governs only the failing workflow status, and only on the new/worsened subset.

import { isAlertWorthyFinding } from './finding.mjs';
import { renderIssueTitle, renderIssueBody, parsePersistedFindings } from './report.mjs';
import { diffFindings } from './differ.mjs';
import { failOnRank, meetsThreshold } from './gate.mjs';

export async function finalizeFindings({ repoSlug, findings, failOn, upsertIssue }) {
  const list = Array.isArray(findings) ? findings : [];
  const alertWorthy = list.filter(isAlertWorthyFinding);

  const title = renderIssueTitle(list);
  const body = renderIssueBody(repoSlug, list);
  const upsert = (await upsertIssue({ repoSlug, title, body })) || {};

  const prior = parsePersistedFindings(upsert.priorBody);
  const newOrWorsened = diffFindings(prior, alertWorthy);

  const threshold = failOnRank(failOn);
  const gating = newOrWorsened.filter((f) => meetsThreshold(f, threshold));

  return {
    findings: list,
    alertWorthy: alertWorthy.length,
    newOrWorsened: newOrWorsened.length,
    exitCode: gating.length > 0 ? 1 : 0,
  };
}
