# WordPress Security Scan

A scheduled, **off-platform** scanner that surveils a WordPress codebase for the
latent security holes the normal update cycle misses — known-vulnerable code
present on disk regardless of activation, plugins with no update channel, and
(phase 2) unexpected drift in live security-critical state. Concepts are written
CMS-neutrally so a Drupal sibling can reuse the design; the v1 implementation is
WordPress-only.

> Origin: a grill-with-docs session in `pt-claude-skills` on 2026-06-14.
> This repo is `philltran/wpcare-security-scan`.

## Language

**Vulnerability Scan** (mode 1):
A full-inventory check of the *code present in the repo* against a vulnerability
database. Static; runs with zero site credentials. Distinct from an update report,
which only inspects packages that *change*.
_Avoid_: "update check" (that's the update-flow), "audit" (overloaded).

**Drift Detection** (mode 2):
A diff of *live security-critical state* (read off the running site) against a
committed, deliberately-blessed **Baseline**. Dynamic; needs site credentials.
_Avoid_: "monitoring", "IDS".

**Finding**:
One detected issue carrying a type, severity, the affected slug+version, and a
remediation. Three alert-worthy types — **Known CVE**, **Abandoned plugin**,
**Embedded plugin** — plus report-only types (e.g. outdated-no-CVE).
_Avoid_: "alert" (an alert is the *delivery* of new findings), "vulnerability"
(a finding may be non-CVE, e.g. an embedded plugin with no current CVE).

**Embedded plugin**:
A plugin (or theme) detected by its header *nested inside another plugin or theme*
rather than at its registered top-level path — e.g. a Slider Revolution bundled in
a premium theme. Unflagged by WordPress's update screen, un-updatable by the site
owner. The blind spot this tool exists to close.
_Avoid_: "bundled dependency", "vendored plugin".

**Abandoned plugin**:
A plugin removed or closed on wordpress.org, hence with no update channel. Its
remediation is *removal*, never *update*.
_Avoid_: "outdated" (an outdated plugin can still be updated).

**Baseline**:
The committed `.security/baseline.json` snapshot of expected live state that Drift
Detection diffs against. Its `criticalOptions` is a curated allow-list; the seeded
default watches five privilege-escalation / hijack vectors — `default_role`,
`users_can_register`, `siteurl`, `home`, `admin_email` (ADR-0010). Re-blessing is a
deliberate, occasional human act, **not** a per-deploy or per-run step: when an
*intentional* change would otherwise keep firing drift, the `update-baseline` dispatch
opens a **PR** carrying the regenerated Baseline (diff in the body), and merging it is
the re-bless.
_Avoid_: "snapshot" (ambiguous), "config".

**The Action**:
The versioned, reusable GitHub Action — in its own repo — that contains all scan
logic. Site repos never copy the logic; they reference it. Explicitly **not** a
WordPress plugin and nothing runs on the site. Implemented as a **JavaScript action**
(`runs.using: node24`) that ships a committed `dist/index.mjs` bundle (built from
`src/` with `@vercel/ncc` via `npm run build`); the runner executes the bundle, not
`node_modules`. See the README "Building The Action".
_Avoid_: "the script", "the plugin".

**Per-site workflow**:
The ~15-line `.github/workflows/*.yml` in each WordPress site repo that calls The
Action on a schedule / PR / dispatch. The only per-site footprint.

## Relationships

- A **Vulnerability Scan** reads the **git repo** (the canonical code inventory on
  Pantheon) → emits **Findings** → new/worsened Findings become an **alert**.
- **Drift Detection** reads **live state via Terminus** → diffs the **Baseline** →
  unexpected changes become **Findings**.
- An alert is delivered as a deduped **GitHub issue** (one per site, updated in
  place) plus a **failing workflow status** (which emails repo watchers — the
  zero-secrets "email ping").
- A security **GitHub issue** is pipeline-ready: it can flow into the repo's
  `triage → ship-issues` pipeline as work.
- Remediation hands off by Finding type: a **Known CVE** → "update" (the
  `wordpress-maintenance-updates` / `wordpress-update-flow` domain); an
  **Abandoned** or **Embedded plugin** → "remove" (no update can fix it).

## Triggers

- **Weekly** scheduled run (catches a fresh CVE against frozen code within 7 days).
- **pull_request** (catches vulnerable/bundled code *entering* the repo — shift-left).
- **workflow_dispatch** (on-demand runs; also blesses the Drift **Baseline** via an
  `update-baseline` input).

## Flagged ambiguities

- **"No Wordfence."** The constraint was *no Wordfence plugin* (paid, poor on
  Pantheon). The scanner uses the *Wordfence Intelligence vulnerability data feed*
  — a free JSON download consumed off-platform (the v3 feed needs a free registered
  token; the old no-auth feed was removed — ADR-0003 as amended by ADR-0013). Different
  thing; see ADR-0003.
- **"Ping us via email."** v1 delivers the email ping via GitHub's watch
  notification on a *failing workflow run*, not a dedicated SMTP mailer (deferred).
  The requirement is met without managing mail credentials.
- **"It wasn't installed / not active."** Activation status is irrelevant to the
  Vulnerability Scan — it scans files on disk, not WordPress's active-plugin list;
  see ADR-0004.

## Example dialogue

> **Dev:** "Slider Revolution wasn't even active — why would a scanner care?"
> **Maintainer:** "The **Vulnerability Scan** reads files, not the active-plugin
> list. The vulnerable PHP was on disk inside a theme — an **Embedded plugin** — so
> it's a **Finding** regardless of activation."
> **Dev:** "And if we just deactivate it?"
> **Maintainer:** "Still a Finding. The code's still reachable. Remediation for an
> **Embedded** or **Abandoned plugin** is *remove*, not *update*."

## Deferred to the PRD / implementation

- GitHub issue label name that feeds `triage`/`ship-issues`.
- Optional later layers: SMTP/Slack delivery, a cross-site fleet roll-up dashboard.
- Platform-enforced read-only collector via a site-side signed REST endpoint
  (mu-plugin) — shelved; breaks "nothing runs on the site" (ADR-0010).

_Resolved (ADR-0010):_ the critical-options allow-list now has a seeded default, and
Pantheon machine-token least privilege is achieved by scoping the **user** (a dedicated
shared Team-Member service account in an org of only in-scope sites) since the token
itself cannot be scoped.
