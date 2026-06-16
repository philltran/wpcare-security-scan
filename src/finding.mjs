// Shared Finding predicate — the union of the two mode-specific alert-worthy sets.
//
// Mode 1 (Vulnerability Scan) alert-worthy types live in src/matcher.mjs (cve /
// abandoned / embedded); mode 2 (Drift Detection) alert-worthy types live in
// src/drift.mjs (security-control-disabled / unexpected-admin / changed-option). The
// reporter renders, persists, and counts Findings from EITHER mode, so it needs one
// predicate covering both — without widening the vuln matcher's own ALERT_WORTHY set
// (that stays the vuln-mode contract) or the drift differ's isDriftFinding.

import { isAlertWorthy as isVulnAlertWorthy } from './matcher.mjs';
import { isDriftFinding } from './drift.mjs';

// A Finding fires an alert if it is a vuln alert-worthy type OR a drift type. Used by
// the reporter (title count, the persisted state block) so a drift Finding dedups
// across runs exactly like a vuln Finding — alert only on new/worsened.
export function isAlertWorthyFinding(finding) {
  return isVulnAlertWorthy(finding) || isDriftFinding(finding);
}
