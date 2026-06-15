# 5. Persist prior Findings in the deduped issue body to alert only on new/worsened

Date: 2026-06-15

Status: Accepted

## Context

Alerts must fire **only on new or newly-worsened Findings**: a repeated run over an
unchanged site must be GREEN, while a severity increase on an existing Finding must
re-alert (PRD #1, issue #6). That requires comparing this run's Findings against the
*prior* run's. The scanner is stateless and credential-light by design — it runs
off-platform with no database — so it needs a persistence layer that already exists
and costs nothing.

The deduped per-site GitHub issue (ADR-0002, one per site, updated in place, found by
a hidden marker) is exactly that store. The open question was the **identity** of a
Finding across runs (so a severity bump is a *worsening* of one Finding, not a brand
new one) and the **format** in which prior Findings are persisted.

## Decision

- **Finding identity** is `type | slug | location | cve` — the stable facets only.
  `version` is deliberately excluded: a partial update that leaves an item still
  vulnerable is the same unresolved Finding and must not spuriously re-alert. `cve` is
  included so two distinct CVEs against one plugin are two Findings. `severity` is
  excluded from identity — it is the value compared (via the matcher's existing
  `severityRank`, not a new scale) to decide "worsened."
- **The differ is a pure function** (`src/differ.mjs`): `diffFindings(prior, current)`
  returns only the new (no prior identity match) or worsened (same identity, strictly
  higher severity) subset. Fixture-tested, no network.
- **Persistence rides in the issue body** as a single hidden HTML comment carrying a
  JSON array of the current Findings (the identity facets + severity + version), beside
  the existing dedup marker. Each run reads the prior body (the thin impure edge in the
  issue upserter), parses it, diffs, and rewrites it. Parsing is fail-safe: a missing,
  markerless, or malformed body yields an empty prior set, so the run treats every
  current Finding as new rather than crashing on a hand-edited issue.
- **The failing workflow status gates on the new/worsened subset only.** The issue is
  still updated in place with the full current Finding set every run, so an unchanged
  site renders the same Findings yet runs GREEN.

## Consequences

- No external state store, no extra secrets: the issue *is* the database.
- The issue body now carries a machine-readable block; a human who hand-edits the body
  must leave the `<!-- wpcare-security-scan:state ... -->` comment intact or the next
  run will re-alert (fail-safe, never a crash). Documented here so the format is not a
  surprise.
- A site whose only "change" is a still-vulnerable partial update will not re-alert —
  intended, since nothing was resolved and the Finding is already filed.
