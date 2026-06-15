# wpcare-security-scan

An **off-platform, scheduled scanner** for WordPress sites — distributed as a **reusable
GitHub Action** that each site repo calls from a thin ~15-line workflow. It surfaces the
latent security holes the normal update cycle misses, without running anything on the site
(Pantheon-friendly, no paid plugin).

> **Status (2026-06-15): Drift Baseline contract + drift differ — the pure half of mode 2 (issue #10, v0.9.0).**
> Drift Detection's testable half lands: the committed **Baseline** shape
> (`.security/baseline.json` — expected active plugins/themes, the full admin-account
> set, and a curated **critical-options allow-list** with blessed values), the live-state
> **snapshot** shape the upcoming Terminus collector (#11) will produce, and a **pure**
> differ (`src/drift.mjs`, `detectDrift(snapshot, baseline) → Findings`). It raises drift
> for an expected **security control turned off** (e.g. the SSO plugin deactivated), a
> **new/unexpected administrator account** (post-compromise persistence), and a **changed
> critical option** — and stays **silent when the snapshot matches a freshly-blessed
> Baseline**. The Baseline lists *expected* state, not exhaustive state, so an extra active
> plugin or an unwatched option never cries wolf. Drift Findings reuse the shared Finding
> shape **additively** (new `type`s + optional `expected`/`actual`), so the same reporter
> renders them and vuln mode is untouched — `mode=vuln` still ships, the **Terminus
> collector + credential/allow-list scoping is the follow-up slice (#11)**. See
> [ADR-0009](docs/adr/0009-drift-baseline-contract-and-differ.md). Earlier slice:
> per-site invocation surface + `fail-on` gate (issue #9, v0.8.0).
>
> **Status (2026-06-15): per-site invocation surface + working `fail-on` gate (issue #9, v0.8.0).**
> The per-site workflow template, the Action's input contract, and version pinning are now
> documented as the adoption surface (a WordPress site opts in with the ~15-line workflow
> below). The previously-inert **`fail-on`** input is now load-bearing: it sets the **minimum
> severity that fails the workflow status** (`low | medium | high | critical`) while the
> deduped issue still files **every** Finding — so a fleet can ratchet the failing *status*
> down (e.g. file a new medium CVE but only fail on high+) without ever changing what is
> reported. An **unscored CVE always fails** (fail-loud; a security tool must not swallow a
> vuln it cannot rank) and a typo'd threshold falls back to `low` (the gate is never silently
> disarmed). The scan runs entirely inside the **calling repo's own secret boundary** — vuln
> mode needs only `GITHUB_TOKEN`, no cross-repo credentials — and the per-site workflow uses
> `pull_request` (shift-left), **never** `pull_request_target`. See
> [ADR-0008](docs/adr/0008-fail-on-threshold-and-per-site-invocation.md). Earlier slice:
> full report + report-only outdated (issue #8, v0.7.0).
>
> **Status (2026-06-15): full report + report-only outdated (issue #8, v0.7.0).**
> The scanner now renders the **full report of everything detected**, not just the
> alert-worthy subset: the deduped issue carries an **Alert-worthy Findings** section and
> a clearly-labeled **Report-only (not alerting)** section. New **outdated-but-no-CVE**
> detection (`src/outdated.mjs`, pure) compares each top-level plugin's installed version
> against the **latest published on wordpress.org** — reusing the *same* wp.org response
> the Abandoned detector already fetches (no new data source) — and raises a **report-only
> `outdated` Finding** whose remediation points at **update** (the
> `wordpress-maintenance-updates` / `wordpress-update-flow` domain). Report-only by
> construction: `outdated` is excluded from the alert-worthy set, is suppressed for any
> slug already abandoned or carrying a CVE, and is **never persisted in the differ's state
> block nor counted in the title**, so it can never trip the failing workflow status — the
> scanner does not cry wolf over a plugin that is merely behind. Every Finding carries
> slug, version, location, and a type-appropriate remediation (CVE → update;
> abandoned/embedded → remove; outdated → update, report-only). See
> [ADR-0007](docs/adr/0007-report-only-outdated-and-full-report.md). Earlier slice:
> optional WPScan cross-reference (issue #7, v0.6.0).
> The Vulnerability Scan also takes an **optional WPScan cross-reference** that deepens
> coverage when a `WPSCAN_API_TOKEN` is supplied — and stays a **zero-secret default** when
> it is not. With no token, behavior is unchanged and the scan needs no credentials; with a
> token, per-plugin WPScan data is folded into the Wordfence dataset and matched through the
> **same** version-range / severity matcher (no parallel path), adding Findings the free feed
> missed. The fetch is a thin impure edge (`src/wpscan.mjs`, token-gated, fail-safe, like the
> Wordfence loader) verified by recorded fixtures; normalization + the cross-source merge are
> pure. The merge **dedups by CVE with Wordfence winning** (authoritative metadata), and
> **still emits no-CVE WPScan vulns** — giving them a stable identity by carrying the WPScan
> vuln id in the `cve` slot as `WPSCAN-<id>` (no schema change, so persistence + the differ
> are untouched; rendered as a WPScan reference, not a CVE). See
> [ADR-0006](docs/adr/0006-wpscan-cross-reference-merge.md). Earlier slice:
> alert only on new/worsened — the Finding differ (issue #6, v0.5.0):
> Alerts now fire **only on new or newly-worsened Findings**. A pure differ
> (`src/differ.mjs`) takes the prior persisted Findings + the current scan and returns just
> the new/worsened subset; the **failing workflow status gates on that subset alone**, so a
> repeated run over an unchanged site is **GREEN** even though its Findings are still filed,
> while a **severity increase** on an existing Finding re-alerts. The prior state is persisted
> in the deduped issue body as a hidden JSON block and read back on the next run (the thin
> impure edge in `src/issue.mjs`); Finding identity is `type|slug|location|cve`, and "worsened"
> reuses the matcher's existing severity rank (see [ADR-0005](docs/adr/0005-persist-prior-findings-in-issue-body.md)).
> Earlier slices: abandoned/closed plugin detection (issue #5, v0.4.0) — each
> top-level plugin slug is checked against the free, no-auth wordpress.org
> plugin_information endpoint; a plugin that has been **closed or removed** (hence has no
> update channel) raises an **Abandoned-plugin Finding** whose remediation is **remove**,
> never update. The wordpress.org query is a thin impure edge (`src/wporg.mjs`, like the
> Wordfence feed loader) verified by recorded transcript, while the closed/removed → Finding
> decision (`src/abandoned.mjs`) is pure and pinned by fixtures offline; the per-slug
> lookup fans out with bounded concurrency and fail-safes a flaky lookup to no alert.
> vuln matcher hardened (#4, v0.3.0) decides
> CVE membership at the `fixed_in` boundary with a WordPress-tolerant version comparison —
> a version below `fixed_in` is a Finding; at or above is patched and yields none — maps the
> CVE's CVSS score onto the Finding severity (critical/high/medium/low/none, plus `unknown`
> for a missing score), and returns all Findings (CVE + embedded together) most-severe-first
> so the worst surface first. deep + embedded enumeration (#3, v0.2.0) walks
> `wp-content` deeply — top-level plugins, mu-plugins, drop-ins, all themes (active or not),
> and core — and recursively sniffs headers nested inside other plugins/themes, so a plugin
> **bundled inside a theme** (the Slider Revolution blind spot) is caught and flagged
> `embedded: true`; the walking skeleton (#2, v0.1.0) wired the end-to-end path — enumerate →
> match the Wordfence feed → Findings → deduped per-site GitHub issue + failing gate. A later
> phase adds Drift Detection.

## What it does

Two modes, shipped in phases:

- **Vulnerability Scan (mode 1, v1 core)** — reads the site's **git repo** (the canonical
  code inventory on Pantheon), deeply enumerates every code surface on disk (plugins,
  mu-plugins, all themes incl. inactive, drop-ins, core) **and recursively detects plugins
  bundled inside themes/other plugins**, then matches each against the **free Wordfence
  Intelligence vulnerability feed** (optional WPScan cross-reference). Raises Findings for
  known CVEs, abandoned/closed plugins, and embedded plugins. Activation status is ignored —
  it reads files, not WordPress's active-plugin list. Zero secrets.
- **Drift Detection (mode 2)** — reads live security-critical state via **Terminus** and
  diffs it against a committed, deliberately-blessed **Baseline** (`.security/baseline.json`):
  active plugins/themes, administrator accounts, a critical-options allow-list. Catches
  tampering like a security control (SSO) being switched off.

Alerts fire **only on new/worsened Findings**, delivered as a **deduped GitHub issue** (one
per site, pipeline-ready) + a **failing workflow status** (the email ping, free via GitHub
watch notifications). Triggers: **weekly** schedule + `pull_request` + `workflow_dispatch`.

## Why it exists

A vulnerable Slider Revolution was **bundled inside a theme** on a site — deactivated, never
"installed," and with no update channel, so the WordPress update screen never flagged it.
Regular updates gave false assurance; an attacker exploited the hole and disabled the SSO
plugin. This scanner reads files (not the active-plugin list), looks *inside* themes, and
runs off-platform so a site compromise can't disable it.

## Using The Action (per-site adoption)

A WordPress site opts in by dropping one ~15-line workflow into its repo at
`.github/workflows/security-scan.yml` — the **only** per-site footprint. All scan logic
lives in this versioned Action, so a fix ships fleet-wide without editing every site.
Copy [`examples/per-site-workflow.yml`](./examples/per-site-workflow.yml):

```yaml
name: Security Scan
on:
  schedule:
    - cron: '17 6 * * 1'   # weekly, Monday 06:17 UTC
  pull_request:            # shift-left: catch vulnerable/bundled code before it merges
  workflow_dispatch:       # on-demand
permissions:
  contents: read           # read the checked-out code on disk
  issues: write            # upsert the deduped per-site security issue
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: philltran/wpcare-security-scan@v0
        with:
          mode: vuln
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: low     # low | medium | high | critical
```

### Inputs

| Input | Required | Default | Purpose |
|-------|----------|---------|---------|
| `mode` | no | `vuln` | Scan mode. Only `vuln` (Vulnerability Scan) ships today; `drift` / `both` are later phases. |
| `github-token` | yes | — | Token to upsert the deduped per-site issue (needs `issues: write`). Pass `${{ secrets.GITHUB_TOKEN }}`. |
| `fail-on` | no | `low` | Minimum severity that **fails the workflow status** (`low \| medium \| high \| critical`). The issue always files *every* Finding; this only gates the failing status. An unscored CVE always fails; an unknown value falls back to `low`. |
| `site-path` | no | `$GITHUB_WORKSPACE` | Path override for a non-standard docroot (e.g. a johnpbloch `wp/` layout). Defaults to the checked-out repo root. |
| `wpscan-token` | no | — | Optional WPScan API token (the calling repo's own secret) to cross-reference per-plugin WPScan data. Omit for the zero-secret default. Pass `${{ secrets.WPSCAN_API_TOKEN }}`. |

Outputs: `finding-count`, `alert-count`, `new-count` (see [`action.yml`](./action.yml)).

### Versioning & pinning

Pin the **moving major tag** so a fix propagates fleet-wide without touching every site
repo:

- **Pre-1.0 (today): `@v0`.** This repo is pre-1.0; sites pin `…@v0`, which the
  maintainer advances to the latest compatible release. The input/output contract in
  `action.yml` may still shift before 1.0 — upgrades within `@v0` can change behavior, so
  read the release notes.
- **`@v1` (the PRD's steady state):** when 1.0 ships, sites move to `@v1` deliberately and
  the contract is then stable within the major. The PRD's `@v1` language describes that
  post-1.0 state; today the live tag is `@v0`.
- A site that wants byte-for-byte reproducibility pins a **full release SHA** instead of a
  moving tag, trading automatic fix-propagation for pinning.

### Secret boundary

The scan runs **entirely inside the calling repo's own secret boundary** — there are no
cross-repo credentials. Vuln mode is **zero-secret**: it needs only the repo's own
`GITHUB_TOKEN` (to upsert the issue). The optional `wpscan-token` is the *calling* repo's
secret, masked in logs. The per-site workflow triggers on **`pull_request`** (so a vulnerable
or bundled-plugin change is caught *before* it merges — shift-left) and deliberately **never**
on `pull_request_target`: a fork PR's head is attacker-controlled and must not run with write
scope and secrets in scope.

## Design docs (source of truth)

- [`CONTEXT.md`](./CONTEXT.md) — domain language (Vulnerability Scan, Drift Detection,
  Finding, Embedded plugin, Abandoned plugin, Baseline, The Action, Per-site workflow).
- [`docs/adr/`](./docs/adr/README.md) — the architectural decisions:
  - 0001 — scan off-platform from a GitHub Action, not an on-site plugin
  - 0002 — ship as a reusable Action in its own repo
  - 0003 — use the free Wordfence Intelligence feed as the primary source
  - 0004 — enumerate the filesystem deeply, not WordPress's plugin list
  - 0005 — persist prior Findings in the deduped issue body (alert only on new/worsened)
  - 0006 — merge the optional WPScan cross-reference into the Wordfence dataset
  - 0007 — render the full report and detect outdated-but-no-CVE as report-only
  - 0008 — the `fail-on` severity gate, `@v0` pinning, and the per-site invocation contract
  - 0009 — the Drift Baseline contract, the live-state snapshot shape, and the drift differ
- **PRD:** [philltran/wpcare-security-scan#1](https://github.com/philltran/wpcare-security-scan/issues/1)
  — the parent document the build is sliced from.

## Build pipeline

This repo's work flows through the agent-aware issue pipeline:

```
grill (done) → make-prd (done: #1) → make-issues (NEXT) → triage → ship-issues
```

**Next step:** run `/make-issues` *from this repo* to slice PRD #1 into tracer-bullet
vertical issues that cite `#1` as `## Parent`. Natural first slice: the Vulnerability Scan
walking skeleton (inventory enumerator → Wordfence match → one Finding → deduped issue);
Drift Detection is a later phase.

## Building The Action

This is a **JavaScript GitHub Action** (`runs.using: node24`). It runs the **committed
bundle**, not `node_modules` — the runner does not `npm install`. After any change under
`src/`, rebuild and commit the bundle:

```
npm install          # toolkit deps + bundler (one-time / on dep change)
npm test             # node:test suite over the pure spine + fixtures
npm run build        # @vercel/ncc -> committed dist/index.mjs (action.yml's main)
npm run check-dist   # rebuild + git diff --exit-code dist (guards bundle drift)
```

- Toolkit: `@actions/core`, `@actions/github` (Octokit), `@actions/http-client` (feed).
  Bundler: `@vercel/ncc`. Runtime: Node 24 on the runner.
- `dist/` is committed and must stay in sync with `src/`; `check-dist` catches a stale
  bundle. Source is ESM (`.mjs`), so the bundle is `dist/index.mjs`.
- **Versioning:** semver. Consumers pin the moving major tag (`@v0` pre-1.0 in the
  example workflow). Pre-1.0, the input/output contract in `action.yml` may still shift.

## Prior art to port (not import)

The grill originated in the `pt-claude-skills` repo, which has patterns to **re-implement
here with tests** (this is a standalone repo — don't take a code dependency):

- Filesystem/header walk — `plugins/wordpress/maintenance-updates/scripts/premium.mjs`
  (reads plugin headers, `Plugin URI:`, detects nested `.git`).
- WPScan version-range CVE matching — `plugins/wordpress/updates-report` (the
  `old < fixed_in <= new` logic and per-slug API call shape).
