# wpcare-security-scan

An **off-platform, scheduled scanner** for WordPress sites — distributed as a **reusable
GitHub Action** that each site repo calls from a thin ~15-line workflow. It surfaces the
latent security holes the normal update cycle misses, without running anything on the site
(Pantheon-friendly, no paid plugin).

> **Status (2026-06-15): deep + embedded enumeration shipped (issue #3, v0.2.0).** The
> Vulnerability Scan now walks `wp-content` deeply — top-level plugins, mu-plugins, drop-ins,
> all themes (active or not), and core — and recursively sniffs headers nested inside other
> plugins/themes, so a plugin **bundled inside a theme** (the Slider Revolution blind spot) is
> caught and flagged `embedded: true`. An Embedded plugin raises an alert-worthy Finding even
> with no CVE; a false "embedded copy" is a triageable Finding, never a fatal error. The
> earlier walking skeleton (issue #2) wired the end-to-end path — enumerate → match the
> Wordfence feed → Findings → deduped per-site GitHub issue + failing gate. Later slices
> thicken matching (range satisfaction, Abandoned plugins) and add Drift Detection.

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
- [`docs/adr/`](./docs/adr/) — the architectural decisions:
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

This is a **JavaScript GitHub Action** (`runs.using: node20`). It runs the **committed
bundle**, not `node_modules` — the runner does not `npm install`. After any change under
`src/`, rebuild and commit the bundle:

```
npm install          # toolkit deps + bundler (one-time / on dep change)
npm test             # node:test suite over the pure spine + fixtures
npm run build        # @vercel/ncc -> committed dist/index.mjs (action.yml's main)
npm run check-dist   # rebuild + git diff --exit-code dist (guards bundle drift)
```

- Toolkit: `@actions/core`, `@actions/github` (Octokit), `@actions/http-client` (feed).
  Bundler: `@vercel/ncc`. Runtime: Node 20 on the runner.
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
