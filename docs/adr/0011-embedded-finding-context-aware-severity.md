# 11. The Embedded-plugin Finding's severity is context-aware, escalate-only

Date: 2026-06-16

Status: Accepted

## Context

The Vuln matcher emits an `embedded` Finding for every bundled, no-update-channel copy
it detects (ADR-0004), originally at a flat `severity: 'medium'`. But a bundled copy
that *also* satisfies a known CVE in the normalized dataset is materially worse than a
bundled-but-clean copy — it carries a real, exploitable vulnerability the site owner
cannot patch in place — yet it ranked identically. The most-severe-first ordering
(issue #4) buried these behind unrelated `high`/`critical` CVE Findings.

## Decision

The `embedded` Finding's severity is computed from the worst CVE the same slug+version
also satisfies, reusing the existing CVSS→severity mapping (`severityFromCvss`), the
`fixed_in` boundary logic (`isAffected`), and the severity ranking (`severityRank`) —
no parallel scheme. It is **escalate-only**: `medium` is a floor. A bundled copy with
no matching CVE, or one matching only a `low`/`unknown`-severity CVE, keeps `medium`,
because a vulnerable bundled copy is never *less* urgent than a clean one.

The separate `cve` Finding (carrying `fixed_in`/`cve`/`url`) is still emitted alongside
the escalated `embedded` Finding when a CVE matches — the two describe different facts
(this code is unpatchable bundled code; this code matches CVE-X). The matcher remains a
pure function of `(inventory, normalizedDataset)`.

## Consequences

- A bundled, CVE-bearing copy (the exact incident shape from ADR-0004) now surfaces at
  its true severity and sorts among the worst Findings, not pinned at `medium`.
- A clean bundled copy is unchanged; the `low`/`unknown` floor avoids the perverse
  result of a low-CVSS CVE *lowering* an embedded copy's urgency.
- The escalated `embedded` Finding and its sibling `cve` Finding co-exist; consumers
  that want to dedupe by `slug + location` can, but the matcher does not.
