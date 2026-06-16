// The `fail-on` severity gate — PURE, shared. Resolves a `fail-on` input to a numeric
// threshold and decides whether a Finding meets it. Mirrors the contract scan.mjs
// established for the Vulnerability Scan (ADR-0008) so the Drift Detection path gates
// identically: the gate governs ONLY the failing workflow status, never the report;
// `low` is the fail-safe default; an unscored/`unknown`-severity Finding always meets
// any threshold (fail loud, never swallow); and an unrecognized token falls back to
// `low` so a typo never silently disarms the gate.

import { severityRank } from './matcher.mjs';

const DEFAULT_FAIL_ON = 'low';

export function failOnRank(failOn) {
  const token = String(failOn ?? '').trim().toLowerCase() || DEFAULT_FAIL_ON;
  const rank = severityRank(token);
  // severityRank returns 0 for `unknown` AND for any unrecognized token. Only the
  // literal `unknown` legitimately ranks 0; any other unrecognized token falls back to
  // the low default so a typo never disables the gate.
  if (rank === 0 && token !== 'unknown') return severityRank(DEFAULT_FAIL_ON);
  return rank;
}

export function meetsThreshold(finding, thresholdRank) {
  if (!finding) return false;
  // An unscored Finding (severity 'unknown', rank 0) always trips any gate.
  if (finding.severity === 'unknown') return true;
  return severityRank(finding.severity) >= thresholdRank;
}
