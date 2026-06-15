# wpcare-security-scan

An **off-platform, scheduled scanner** for WordPress sites — distributed as a **reusable
GitHub Action** that each site repo calls from a thin ~15-line workflow. It surfaces the
latent security holes the normal update cycle misses, without running anything on the site
(Pantheon-friendly, no paid plugin).

> **Status (2026-06-15): alert only on new/worsened — the Finding differ (issue #6, v0.5.0).**
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

## Design docs (source of truth)

- [`CONTEXT.md`](./CONTEXT.md) — domain language (Vulnerability Scan, Drift Detection,
  Finding, Embedded plugin, Abandoned plugin, Baseline, The Action, Per-site workflow).
- [`docs/adr/`](./docs/adr/README.md) — the architectural decisions:
  - 0001 — scan off-platform from a GitHub Action, not an on-site plugin
  - 0002 — ship as a reusable Action in its own repo
  - 0003 — use the free Wordfence Intelligence feed as the primary source
  - 0004 — enumerate the filesystem deeply, not WordPress's plugin list
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
