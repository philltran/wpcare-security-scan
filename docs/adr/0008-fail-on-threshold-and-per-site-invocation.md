# 8. The `fail-on` severity gate, `@v0` pinning, and the per-site invocation contract

Date: 2026-06-15

Status: Accepted

## Context

The Action exists (ADR-0002) and a WordPress site opts in through a thin per-site
workflow. PRD #1 / issue #9 ask for the **invocation and distribution surface**: the
inputs a site sets, the triggers, the version a site pins, and the boundary the scan
runs inside. Three decisions had to be settled.

1. **`fail-on` was a declared-but-inert input.** `action.yml` exposed `fail-on` with a
   `low` default, but it was never read — the failing-status gate fired on *every*
   new/worsened alert-worthy Finding. A fleet needs to ratchet the noise of the failing
   *status* down (e.g. file a new medium CVE in the issue but only fail the run on
   high+), without ever changing what is reported. The open questions were the exact
   gating semantics and how an **unscored CVE** (a feed CVE with no CVSS — severity
   `unknown`) interacts with the threshold.
2. **Which moving major tag a site pins.** The PRD's language is `@v1`; this repo is
   pre-1.0 and has no `v1`.
3. **The secret boundary** for the per-site workflow.

## Decision

- **`fail-on` gates the failing status only; it never narrows the report.** The deduped
  issue is always upserted with every current Finding (the report stays complete —
  ADR-0007). The orchestrator additionally filters the new/worsened subset (ADR-0005)
  to Findings whose severity **meets-or-exceeds** the threshold, and fails the run iff
  that filtered subset is non-empty. The threshold reuses the matcher's existing
  `severityRank` scale (`critical > high > medium > low > none > unknown`) — no new
  scale. Valid inputs: `low | medium | high | critical`.
- **`low` is the default and preserves the pre-#9 contract.** At `low`, every
  new/worsened alert-worthy Finding of a scored band trips the gate, exactly as before.
- **An unscored CVE (`severity: unknown`) always meets any threshold — fail loud.** A
  security tool must not silently swallow a vuln it cannot rank: an unscored CVE that
  is genuinely critical must still fail a `high` gate. So `unknown` is special-cased to
  always count, rather than ranking it below `low` (where it would be silently dropped
  at the default). A CVE explicitly scored `0.0` → `none` is a different thing (the feed
  *did* rank it) and ranks normally, below `low`.
- **An unrecognized / empty `fail-on` falls back to `low`, never "off."** A typo must
  not disarm the gate, and there is deliberately **no** sentinel that disables failing.
  A site that wants issue-only behavior raises the threshold above its Findings
  explicitly (a visible, auditable choice), it does not turn the gate off.
- **Sites pin the moving major tag, `@v0` while pre-1.0.** Consumers pin
  `philltran/wpcare-security-scan@v0` (a moving tag the repo advances to the latest
  compatible release) so a fix propagates fleet-wide without editing every site repo.
  Pre-1.0 the input/output contract in `action.yml` may still shift; the example
  workflow and README document `@v0` and the deliberate upgrade to `@v1` when 1.0 ships.
  The PRD's `@v1` is the post-1.0 steady state, reconciled here to today's `@v0`.
- **The scan runs entirely inside the calling repo's secret boundary.** Vuln mode needs
  **zero secrets** — only the repo's own `GITHUB_TOKEN` (for the issue upsert) and the
  optional `wpscan-token`, which is the *calling* repo's secret. No cross-repo
  credentials. The per-site workflow triggers on `pull_request` (shift-left), **never**
  `pull_request_target` (issue #14): a fork PR's head is attacker-controlled and must
  not run with write scope + secrets in scope. `permissions:` is least-privilege
  (`contents: read`, `issues: write`).

## Consequences

- `fail-on` is now load-bearing and covered through the public `runVulnScan` seam
  (`test/scan-fail-on.test.mjs`): default-low, raised thresholds filing-without-failing,
  the unscored-CVE fail-loud rule, and the typo-defaults-to-low guard.
- The pipeline label is already settled: the reporter sets `ISSUE_LABEL =
  'security-scan'` (report.mjs), which is the canonical `triage`/`ship-issues`-ready
  label — no new decision was needed for issue #9's "canonical pipeline label."
- The default (`low`) means existing adopters see no behavior change; raising `fail-on`
  is an opt-in, deliberate quieting of the *status* only, never the issue.
