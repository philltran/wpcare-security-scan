# CMS-neutral concepts

This document describes the scanner's concepts and deep-module contracts in
**CMS-neutral** terms, so a future sibling for another CMS (a Drupal scanner, say)
can reuse the *design* without reverse-engineering the WordPress implementation.

The v1 implementation in this repo is WordPress-only. Everything below is written so
that "plugin/theme" reads as "**package/extension**", "Wordfence feed" reads as "**the
platform's advisory feed**", and "Terminus / WP-CLI" reads as "**the platform's
live-state read tool**". A Drupal sibling swaps the *backends* (drupal.org security
advisories + `composer audit` for the feed, `composer.lock` + the module tree for the
inventory, Drush for the drift collector) while keeping the *shapes* — the matcher,
the differ, the baseline differ, the reporter, and the fail-on gate stay identical.

The domain vocabulary itself is defined in [`../CONTEXT.md`](../CONTEXT.md); the
architectural decisions are in [`adr/`](adr/README.md). This doc is the bridge between
them and a second CMS.

## How to read this with the code

Each module contract below is grounded in a real `src/*.mjs` module. The shapes are
the actual ones the code passes between seams — read this alongside the source. The
guiding architecture (which every contract obeys) is **a pure spine with the impure
IO injected at the edges**: enumeration, normalization, matching, differing, gating,
and rendering are pure and fixture-tested offline; the network/filesystem/process
reads (advisory feed fetch, per-package registry lookup, live-state collection, issue
upsert, re-bless PR) are thin injected closures. A CMS sibling re-implements only the
edges.

---

## The concepts

### Vulnerability Scan (mode 1)

A full-inventory check of **the code present in the repo** against a vulnerability
database. Static; runs with **zero site credentials**. It enumerates every code
surface on disk — regardless of whether the CMS considers it active — matches each
against the platform's advisory feed, and raises Findings for known CVEs, packages
with no update channel, and packages embedded inside other packages.

This is distinct from an *update report* (which inspects only packages that change).
CMS-neutrally: it reads **the version-controlled package tree**, not the CMS's runtime
"enabled extensions" list.

- **WordPress backend:** walks `wp-content` (plugins, mu-plugins, themes, drop-ins) +
  core; matches the free Wordfence Intelligence feed (optional WPScan cross-reference).
- **Drupal sibling backend:** would read `composer.lock` and the module/theme tree;
  match drupal.org security advisories and/or `composer audit` output. The
  *normalized dataset shape* it feeds the matcher is identical (see below), so only
  the loader and inventory enumerator change.

### Drift Detection (mode 2)

A diff of **live security-critical state** read off the running site against a
committed, deliberately-blessed **Baseline**. Dynamic; **needs site credentials**. It
catches tampering the update cycle never sees — an expected security control switched
off, a rogue administrator account, a hijack-vector option changed.

CMS-neutrally: it reads the live runtime state of a small set of security-critical
facets, compares them to a curated expected set, and raises a Finding for each
**unexpected disappearance or change** (never for additions — that is the curation
that keeps routine maintenance quiet).

- **WordPress backend:** reads live state over **Terminus / WP-CLI** (`plugin list`,
  `theme list`, `user list`, `option get`).
- **Drupal sibling backend:** would read the same facets over **Drush** (e.g.
  `drush pml`, the active theme, the user/role list, `drush config:get` or
  `drush state:get` for the watched settings). The snapshot/Baseline *shape* and the
  pure differ are unchanged.

### Finding

One detected issue, carrying a `type`, a `severity`, the affected slug + version, a
`location`, and a `remediation`. The **Finding shape is the central cross-module
contract** — every detector emits it and every consumer (differ, reporter, gate)
reads it, so it is CMS-neutral by construction.

```
{
  type,                 // see the type vocabulary below
  severity,             // critical | high | medium | low | none | unknown
  slug,                 // the package slug — OR an account login / option name (drift)
  version?,             // the installed version (absent for account/option Findings)
  kind,                 // package | theme | core | account | option | ... (CMS-specific labels)
  location,             // where it was found: on-disk path, or a live-state source
  fixed_in?,            // the version the fix landed in (cve type)
  cve?,                 // the advisory id, or a synthetic stable id (e.g. WPSCAN-<id>)
  url?,                 // a reference link
  latest?,              // the latest available version (report-only outdated)
  expected?, actual?,   // before/after for a drift Finding
  remediation           // the human action to take
}
```

**Finding types** fall into two alert-worthiness buckets, kept as two mode-specific
sets that the reporter unions (`src/finding.mjs`):

| Bucket | Mode | Types | Meaning |
|--------|------|-------|---------|
| **Alert-worthy** | Vuln | `cve` | installed version below the advisory's `fixed_in` |
| | Vuln | `abandoned` | package has no update channel (removed/closed upstream) |
| | Vuln | `embedded` | package detected nested inside another package |
| | Drift | `security-control-disabled` | an expected-active package/theme is no longer active |
| | Drift | `unexpected-admin` | a live administrator absent from the expected set |
| | Drift | `changed-option` | a watched critical option whose live value drifted |
| **Report-only** | Vuln | `outdated` | merely behind the latest version, no known CVE |

Alert-worthy types gate the failing status (on the new/worsened subset only).
Report-only types appear in the report for completeness but never fail the run and are
never persisted into the dedup state — the scanner does not cry wolf over a package
that is merely behind. The two type vocabularies are CMS-neutral; a Drupal sibling
reuses them verbatim (`cve` covers a drupal.org SA, `abandoned` covers an unsupported
module, etc.).

### The Action

The versioned, reusable thing that contains **all** scan logic, referenced (never
copied) by each site repo. In this repo it is a JavaScript GitHub Action
(`runs.using: node24`) shipping a committed bundle. CMS-neutrally: it is the **single
shared distribution of the scan logic** — a CMS sibling would be its own Action in its
own repo, sharing the design but not a code dependency.

### Per-site workflow

The thin (~15-line) caller in each site repo that invokes The Action on a schedule /
PR / dispatch. The only per-site footprint. CMS-neutral: the adoption surface stays a
thin per-site caller whatever the CMS.

### Baseline

The committed `.security/baseline.json` snapshot of **expected** live state that Drift
Detection diffs against. It lists expected state, **not exhaustive state**, so it
watches for an expected control going *away* and a watched option *changing* — not for
additions. Re-blessing (regenerating it from current live state) is a deliberate,
occasional human act done **via a PR**, never a per-run write. See the Baseline /
drift-collector contracts below for the shape.

---

## The deep-module contracts

Described in CMS-neutral input/output terms. Each names the real module and notes
where a CMS sibling swaps the backend. Purity is marked because it is the whole point:
the **pure** modules are reusable across CMSes unchanged; only the **impure** edges
are re-implemented.

### 1. Inventory enumerator — pure (`src/inventory.mjs`)

> **input:** a code tree root (a filesystem path)
> **output:** `[ { slug, kind, version, path, embedded } ]`

Walks the version-controlled code tree and returns one **inventory item** per code
surface found, reading the declared version out of each package's metadata. Crucially
it walks **deeply and recursively**, sniffing for package/theme metadata **nested
inside another package or theme**, marking those `embedded: true` — the bundled-
dependency blind spot the tool exists to close. Activation status is ignored entirely:
it reads files, not the CMS's enabled-extensions list.

- **WordPress backend:** reads `Plugin Name:` / `Version:` headers from PHP files and
  theme `style.css`; surfaces `wp-content/{plugins,mu-plugins,themes}`, drop-ins, and
  core's `version.php`.
- **Drupal sibling backend:** would derive items from `composer.lock` and the
  `modules/`/`themes/` tree, reading `*.info.yml` (`version`) and Composer package
  versions; core is the `drupal/core` package. The **output item shape is identical**
  (`{ slug, kind, version, path, embedded }`), so everything downstream is unchanged.
  The deep "embedded" sniff is just as relevant (a library vendored inside a module).

### 2. Advisory feed loader — impure (`src/feed.mjs`)

> **input:** a feed URL
> **output:** the raw feed object (handed straight to the normalizer)

A deliberately thin impure edge: fetch the platform's advisory data and return the raw
object. **No matching logic lives here.** A CMS sibling replaces this with its own
fetch (drupal.org advisories endpoint, or shelling `composer audit --format=json`) and
nothing else changes — the normalizer absorbs the format difference.

### 3. Advisory feed normalizer — pure (`src/wordfence.mjs`)

> **input:** the raw feed object
> **output:** `{ slug -> [ { affected_range, fixed_in, cvss, cve, title, url } ] }`

Flattens the platform-specific raw feed into a per-slug list of advisory records in a
**normalized, CMS-neutral shape**. This shape is the contract the matcher consumes —
it is the seam where a CMS sibling plugs in.

- **WordPress backend:** keys the Wordfence feed by CVE, flattens each record's
  affected `software[]` by slug, deriving `fixed_in` from the range's exclusive upper
  bound.
- **Drupal sibling backend:** would normalize drupal.org SAs / `composer audit` into
  this **exact** `{ slug -> [ranges] }` shape — `fixed_in` from the SA's "fixed in"
  release, `cvss`/`cve` from the advisory. **This is the single most important
  swap point:** produce this shape and the matcher, differ, gate, and reporter all
  work with no change.

### 4. Optional cross-reference normalizer + merge — pure (`src/wpscan.mjs`)

> **fetch:** impure, token-gated edge `(slug, token) -> raw response | null`
> **normalize:** `raw -> { slug -> [records] }` (the same shape as #3)
> **merge:** `(primary, secondary) -> merged dataset` (dedup by advisory id, primary wins)

An optional deepening: a second advisory source folded into the primary dataset and
matched through the **one** shared matcher (no parallel matching path). Fail-safe and
zero-secret by default. CMS-neutral: any CMS can add a secondary advisory source by
emitting the same normalized shape and reusing `mergeDatasets`. No-id records are kept
under a synthetic stable id so they still dedup across runs.

### 5. Vuln matcher — pure (`src/matcher.mjs`)

> **input:** inventory `[items]` + the normalized advisory dataset `{ slug -> [records] }`
> **output:** `[ Finding ]` (most-severe-first)

Decides version-range satisfaction and severity, emitting a Finding per matched item.
A package is affected when its installed version is **strictly below** the advisory's
`fixed_in`; at or above is patched. Version comparison is segment-by-segment and
tolerant of loose, non-strict-semver version strings. Severity maps from the advisory
CVSS onto the Finding severity vocabulary (a missing score is `unknown`, not `none`).
Also emits an `embedded` Finding for every `embedded: true` inventory item independent
of any CVE (no update channel → remediation is *removal*).

**Fully CMS-neutral** — it operates only on the two normalized shapes above and the
severity vocabulary. A Drupal sibling reuses it **unchanged**. (It also exports the
shared `severityRank` / `compareVersions` helpers the differ and gate depend on.)

### 6. Abandoned / no-update-channel detector — pure decision (`src/abandoned.mjs`)

> **input:** an inventory item + a recorded registry response `{ statusCode, body }`
> **output:** a `Finding` (type `abandoned`) or `null`

Decides whether a package has been removed/closed upstream (hence has no update
channel and cannot be patched in place — remediation is *removal*, never *update*).
The live registry query itself is a thin impure edge (`src/wporg.mjs`); this pure half
decides the closed/removed signal from the *recorded* response and is fixture-pinned.
Anything ambiguous (a transport error) is deliberately **not** treated as abandoned —
a flaky lookup never fires a false alert.

- **WordPress backend:** the wordpress.org `plugin_information` endpoint per slug;
  closed/removed = non-2xx or a body carrying `error`/`closed`.
- **Drupal sibling backend:** would consult drupal.org's project status (an
  unsupported/obsolete project) over the same `{ statusCode, body }`-shaped recorded
  response. The decision logic and Finding shape are unchanged.

### 7. Report-only outdated detector — pure decision (`src/outdated.mjs`)

> **input:** an inventory item + the same recorded registry response
> **output:** a `Finding` (type `outdated`, report-only) or `null`

Reuses the *same* registry response the abandoned detector fetched (no new data
source): if the installed version trails the latest published version but carries no
CVE and is not abandoned, it is a **report-only** `outdated` Finding (remediation:
*update*; never gates the status). CMS-neutral: "latest published version" comes from
whatever registry the CMS uses; the comparison and report-only semantics are identical.

### 8. Finding differ / dedup — pure (`src/differ.mjs`)

> **input:** prior persisted Findings + current Findings
> **output:** the **new + worsened** subset only

Drives "alert only on new/worsened." Finding **identity** is the stable tuple
`type | slug | location | cve` (deliberately *not* version or severity, so a partial
update that leaves an item vulnerable is the same unresolved Finding, not a new one). A
Finding is new if no prior Finding shares its identity, or worsened if one does but the
current severity strictly outranks the prior. Idempotent: an unchanged site yields an
empty subset (green run). **Fully CMS-neutral** — it operates only on the Finding shape
and `severityRank`. Reused unchanged.

### 9. Fail-on severity gate — pure (`src/gate.mjs`)

> **input:** a Finding + a resolved threshold rank (from a `fail-on` token)
> **output:** boolean "meets-or-exceeds the threshold"

Governs **only** the failing workflow status, never the report. `low` is the fail-safe
default; an unrecognized token falls back to `low` (a typo never disarms the gate); an
unscored (`unknown`) Finding always trips any gate (fail loud). **Fully CMS-neutral** —
reused unchanged.

### 10. Reporter / issue rendering + persistence — pure (`src/report.mjs`)

> **render title:** `[Findings] -> string` (alert-worthy count only)
> **render body:** `(repoSlug, [Findings]) -> string` (full report + hidden state block)
> **find existing:** `(issues, marker) -> issue | null`
> **parse prior:** `body -> [prior Findings]`

The deduped issue is the scanner's **persistence layer**: each run embeds the current
alert-worthy Findings in the body as a hidden, machine-readable state block, so the
*next* run reads them back as the prior state and diffs (alert only on the
new/worsened subset). Dedup is by a stable per-site hidden marker (one issue per site).
The body shows **every** Finding (alert-worthy first, then a clearly-labeled
report-only section); only alert-worthy Findings are persisted/counted. **Fully
CMS-neutral** — it renders the Finding shape; the only assumption is "an issue tracker
with a body to persist into," which any CMS sibling shares.

The **impure** issue upsert (the Octokit list/create/update calls) lives in
`src/issue.mjs` and returns the prior body for the differ — the thin edge a sibling
re-implements against its own tracker.

### 11. Drift collector — impure edge (`src/collector.mjs`)

> **input:** site/env identifiers + a credential + the watched option names
> **output:** a live-state **snapshot**:
> `{ activePlugins[], activeThemes[], administrators[], criticalOptions{} }`

Authenticates with a machine credential (held as a secret, never logged) and reads
security-critical live state into the snapshot shape the pure differ consumes. Kept
deliberately thin and **read-only** — it issues only read verbs. Untrusted identifiers
from the per-site workflow are validated against a conservative allow-list and passed
as an argv array (never shell-interpolated). It reads only the option names the
Baseline's allow-list names, so it collects only what the differ will compare.

- **WordPress backend:** Terminus + WP-CLI over SSH (`plugin list --status=active`,
  `theme list --status=active`, `user list --role=administrator`, `option get <name>`).
- **Drupal sibling backend:** would read the same facets over **Drush** — enabled
  modules, the active/admin theme, the user list for the administrator role, and the
  watched config/state values. The **snapshot shape is unchanged**, so the pure differ
  is reused verbatim. This is the credential-touching edge a sibling re-implements.

### 12. Baseline differ — pure (`src/drift.mjs`)

> **input:** a live-state snapshot + the committed Baseline
> **output:** `[ Finding ]` (drift types, most-severe-first)

The pure decision of Drift Detection. Emits a Finding for: an expected-active
package/theme no longer active (`security-control-disabled`, `high`); a live
administrator absent from the expected set (`unexpected-admin`, `critical`); a watched
critical option whose live value differs from the blessed value (`changed-option`,
`medium`). Lists are diffed as **sets** (order-insensitive); option values compared as
**strings**; **only** the allow-listed option keys are diffed (so an unwatched edit is
never drift). Fail-safe: a missing/garbage snapshot or Baseline yields no Findings and
never throws. Emits **nothing** against a freshly-blessed Baseline. **Fully
CMS-neutral** — it operates only on the snapshot/Baseline shapes. Reused unchanged.

The **Baseline shape** (committed `.security/baseline.json`):

```
{
  version,              // contract version, for future migration
  blessedAt,            // ISO-8601: when last re-blessed
  activePlugins[],      // package slugs expected to stay active
  activeThemes[],       // theme slugs expected to stay active
  administrators[],     // the full expected administrator-account set
  criticalOptions{}     // a curated allow-list: watched name -> blessed value
}
```

The snapshot mirrors the first four facets with live values. A Drupal sibling fills the
same facets from Drush; only the *labels* are CMS-flavoured (a "plugin slug" becomes a
"module machine name"), not the structure.

### 13. Baseline helpers + re-bless — pure decisions (`src/baseline.mjs`) + impure PR opener (`src/rebless.mjs`)

> **load:** `path -> Baseline | null` (absent = bootstrap; malformed = throw, fail loud)
> **seed / rebuild:** `(snapshot, prior?) -> a fresh Baseline` (preserves the curated allow-list)
> **render diff:** `(old, new) -> human-readable PR-body diff`

Re-blessing is the deliberate, human act of regenerating the Baseline from current live
state. It is done **via a PR** (the pure half renders the file + a "here is the drift
you are about to bless away" diff; the impure half opens the PR) — never a blind direct
write, because re-blessing a compromised live state would silently bless the compromise
in. Merging the PR is the re-bless. **CMS-neutral:** the load/seed/rebuild/diff logic is
pure and reusable; only the PR-opener edge (`src/rebless.mjs`) and the live-state read
(#11) are CMS/host-specific.

### 14. Orchestrators + shared finalize tail — pure spines (`src/scan.mjs`, `src/drift-scan.mjs`, `src/combined.mjs`, `src/report-gate.mjs`)

The mode orchestrators wire the seams above with the impure edges **injected**, so each
runs end-to-end offline against fixtures. All three modes funnel through one shared
**finalize tail** (`finalizeFindings` in `src/report-gate.mjs`): render the deduped
issue, upsert it, recover the prior Findings, diff to the new/worsened subset, apply the
fail-on gate. `mode: both` is just concatenating the vuln + drift Finding lists and
finalizing **once** — one issue, one state block, no second upsert. **Fully
CMS-neutral** — the spine names the seams by their contracts, not their backends; a CMS
sibling injects its own edges and reuses the orchestration shape.

### 15. The Action shell — thin glue (`src/index.mjs`, `action.yml`)

Reads inputs, masks secrets, builds the **real** impure edges, wires them into the pure
orchestrators, and sets the failing status. Deliberately boring — all logic lives in
the testable modules above. CMS-neutral: a sibling re-implements this shell for its host
(its own `action.yml` inputs and real-edge constructors) and reuses everything else.

---

## Summary: the swap points for a CMS sibling

A second CMS reuses the **pure core unchanged** and re-implements only the **edges**:

| Layer | Reuse / swap |
|-------|--------------|
| Inventory enumerator (#1) | **Swap** the backend (read `composer.lock` + module/theme tree); keep the `{ slug, kind, version, path, embedded }` output shape. |
| Advisory feed loader (#2) | **Swap** the fetch (drupal.org SAs / `composer audit`). |
| Advisory feed normalizer (#3) | **Swap** the format parsing; emit the **same** `{ slug -> [ranges] }` shape — the key swap point. |
| Abandoned detector backend (#6) | **Swap** the registry source (drupal.org project status); keep the recorded-response decision shape. |
| Drift collector (#11) | **Swap** the read tool (Drush); keep the snapshot shape. |
| Re-bless PR opener (#13) / issue upserter (#10 edge) | **Swap** for the sibling's tracker/host. |
| Action shell (#15) | **Re-implement** for the host. |
| Matcher (#5), differ (#8), gate (#9), reporter rendering (#10), baseline differ (#12), baseline helpers + re-bless logic (#13), orchestrators + finalize tail (#14) | **Reuse unchanged** — they operate only on the CMS-neutral Finding / dataset / snapshot / Baseline shapes. |

In short: the Finding shape, the normalized `{ slug -> [ranges] }` dataset, and the
snapshot/Baseline shapes are the three CMS-neutral contracts. Hit those and a Drupal
sibling inherits the matcher, differ, gate, reporter, baseline differ, and
orchestration for free.

## Canonical references

- Domain vocabulary: [`../CONTEXT.md`](../CONTEXT.md)
- Architectural decisions: [`adr/README.md`](adr/README.md) — especially
  [ADR-0003](adr/0003-wordfence-feed-primary.md) (advisory feed as primary source),
  [ADR-0004](adr/0004-deep-embedded-enumeration.md) (deep + embedded enumeration),
  [ADR-0005](adr/0005-persist-prior-findings-in-issue-body.md) (alert only on
  new/worsened), [ADR-0007](adr/0007-report-only-outdated-and-full-report.md)
  (report-only outdated), [ADR-0008](adr/0008-fail-on-threshold-and-per-site-invocation.md)
  (the fail-on gate), [ADR-0009](adr/0009-drift-baseline-contract-and-differ.md) (the
  Baseline + snapshot + drift differ contracts), and
  [ADR-0010](adr/0010-drift-collector-terminus-least-privilege-and-rebless.md) (the
  drift collector edge + PR-based re-bless).
- The implementation it mirrors: `src/*.mjs` (read alongside this doc).
