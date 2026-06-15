# 9. The Drift Baseline contract, the live-state snapshot shape, and the drift differ

Date: 2026-06-15

Status: Accepted

## Context

PRD #1 / issue #10 introduce **Drift Detection (mode 2)**: a diff of *live
security-critical state* read off the running site against a committed,
deliberately-blessed **Baseline** (`.security/baseline.json`), raising Findings for
unexpected changes — the motivating incident being an attacker disabling the site's
SSO plugin (CONTEXT.md "Drift Detection" / "Baseline"; user stories 25–29).

This slice ships the **pure, testable half**: the Baseline file shape, the live-state
snapshot shape, and a pure differ over them. The **impure half** — the Terminus/WP-CLI
reads that produce the snapshot, plus credential and allow-list scoping — is the
follow-up slice (#11), which is `blockedBy` this one. So this slice must leave a clean,
documented snapshot/Baseline contract for #11's collector to fill.

Three decisions had to be settled:

- **What does the Baseline capture, and what is the live-state snapshot it diffs?**
- **What does drift watch for** — so it catches a control going away or an option
  changing, without crying wolf over routine maintenance (user story 27)?
- **How does a drift Finding express itself** without reshaping the shared v1 Finding
  contract that the vuln-mode matcher / differ / reporter depend on?

## Decision

- **The Baseline lists EXPECTED state, not exhaustive state** (committed
  `.security/baseline.json`):

  ```json
  {
    "version": 1,
    "blessedAt": "<ISO-8601>",
    "activePlugins":  ["<slug>", "..."],
    "activeThemes":   ["<slug>", "..."],
    "administrators": ["<login>", "..."],
    "criticalOptions": { "<name>": "<expected value>" }
  }
  ```

  `activePlugins`/`activeThemes` are slugs expected to stay **active**;
  `administrators` is the **full** expected admin-account set; `criticalOptions` is a
  **curated allow-list** mapping each watched option name to its blessed value. It is
  re-blessed deliberately via the workflow's `update-baseline` dispatch when a change
  is intentional (the re-bless mechanism is later; the "freshly-blessed Baseline → no
  drift" property is pinned here).

- **The live-state snapshot is the SHAPE #11's collector produces**, modeled on the
  `wp` commands it will run — `wp plugin list --status=active` (`activePlugins`), the
  active theme(s) (`activeThemes`), `wp user list --role=administrator`
  (`administrators`), and `wp option get <name>` per allow-list entry
  (`criticalOptions`). Lists are diffed as **sets** (order-insensitive — a live read
  won't preserve Baseline ordering) and option values are compared as **strings**
  (WP-CLI emits option values as text).

- **Drift watches for "expected control gone" and "watched option changed," never for
  additions.** An expected active plugin/theme that is no longer active is a
  *disabled security control*; a live administrator absent from the expected set is an
  *unexpected admin*; an allow-listed option whose live value differs from the blessed
  value is a *changed option*. An **extra** active plugin or a change to an
  **unwatched** option is deliberately **not** drift — that is the curation (user
  story 27) that keeps routine maintenance from firing false alerts.

- **Drift reuses the shared v1 Finding shape ADDITIVELY — no contract change.**
  Mirroring how `outdated` added an optional `latest` field (ADR-0007, "additive and
  report-only; alert-worthy consumers never read it"), drift adds three new `type`
  values — `security-control-disabled`, `unexpected-admin`, `changed-option` — and two
  optional fields, `expected` / `actual`, carrying the before/after for a changed
  option and the active/inactive verdict for a disabled control. No existing field
  changes meaning; the same `report.mjs` renderer renders these (it already tolerates a
  missing `version`/`cve`/`url`). For an account or an option there is no plugin slug,
  so the account login / option name rides the `slug` slot and `location` records the
  live source. This was the *smallest* change that satisfies the acceptance criteria
  and keeps vuln-mode green — a genuine reshape of the shared contract would have been a
  separate decision, but an additive-optional-field extension is not.

- **Drift alert-worthiness lives in the drift module, not the vuln matcher.** Drift
  Findings are alert-worthy in *drift mode* via `isDriftFinding` in `src/drift.mjs`;
  they are deliberately **not** added to the vuln matcher's `ALERT_WORTHY` set, which
  is the *vuln-mode* contract. So the two modes keep separate alert-worthiness rules
  without one bleeding into the other.

- **Severity ordering: a rogue admin outranks a disabled control outranks a changed
  option.** `unexpected-admin` is `critical` (post-compromise persistence), a disabled
  control is `high`, a changed option is `medium`. The differ returns Findings
  most-severe-first via a stable sort, matching the vuln matcher's idiom.

## Consequences

- `src/drift.mjs` is a pure deep module — `detectDrift(snapshot, baseline) → [Finding]`
  plus `isDriftFinding(finding)` — fixture-tested through its public interface with no
  network, mirroring `matcher.mjs` / `differ.mjs` / `abandoned.mjs`. It is **not yet
  wired into `src/index.mjs`**, which still ships `mode=vuln` only, so the committed
  `dist/` bundle is unchanged and `check-dist` passes untouched. Wiring it behind a
  Terminus collector and `mode=drift` is #11.
- The Finding shape stays a stable cross-module contract: vuln-mode consumers (the
  matcher, the new/worsened differ, the reporter, the persistence state block) read
  none of the new fields and keep working. The reporter renders drift Findings as-is.
- The snapshot shape is a published contract #11's collector fills; if a `wp` read
  produces a missing/garbage snapshot the differ fails safe (no Findings, no throw), so
  a flaky live read never fabricates a false alert.
- Fail-safe everywhere: a missing/garbage snapshot OR Baseline yields no drift; a
  watched option deleted live reads as an empty value and still drifts from its blessed
  value; only the allow-list keys are diffed.
