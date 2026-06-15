# 6. Merge the optional WPScan cross-reference into the Wordfence dataset

Date: 2026-06-15

Status: Accepted

## Context

ADR-0003 made the free Wordfence Intelligence feed the primary vuln source and named
an optional `WPSCAN_API_TOKEN` cross-reference. Issue #7 implements that cross-reference
to deepen coverage — adding Findings the Wordfence feed missed — while keeping the
Vulnerability Scan a **zero-secret default**.

Two questions had to be settled to do this without a parallel matching path:

1. **How do the two sources combine?** Both must end up in the one normalized dataset
   shape `{ slug -> [ { affected_range, fixed_in, cvss, cve, title, url } ] }` so the
   single pure matcher (`src/matcher.mjs`) decides version-range membership and severity
   for both — no second code path.
2. **What happens when both sources describe the same CVE for a slug, and what about
   WPScan vulns that carry no CVE at all** (common — WPScan often lists only a `vuln.id`)?

## Decision

- **Zero-secret default.** With no token the WPScan edge is never injected; the scan
  runs exactly as before and needs no credentials. The token is read from the Action
  input only, `core.setSecret`-masked, and never logged.
- **A thin impure edge + pure normalization**, mirroring the Wordfence and wordpress.org
  paths. `src/wpscan.mjs` holds the token-gated per-slug fetch (`fetchWpscanPlugin`,
  `Authorization: Token token=<TOKEN>`, fail-safe to `null` on any non-2xx) and the pure
  `normalizeWpscanResponse` that maps a WPScan plugin response into the shared dataset
  shape. WPScan exposes no lower bound, so `affected_range` is `null` and "below
  `fixed_in`" is affected — exactly how the matcher already treats a `fixed_in`-only
  record. A missing `cvss` stays `null`, which the matcher maps to severity `unknown`.
- **Cross-source merge: dedup by CVE, Wordfence wins.** A pure `mergeDatasets(wordfence,
  wpscan)` folds WPScan into the primary dataset per slug. If a Wordfence record already
  covers a CVE for that slug, the WPScan duplicate is **dropped** — Wordfence metadata is
  authoritative (ADR-0003).
- **No-CVE WPScan vulns are still emitted.** They are real "Findings Wordfence missed."
  They are given a stable, non-CVE identity by carrying the WPScan `vuln.id` in the
  Finding's `cve` slot as **`WPSCAN-<id>`**. This is deliberately the existing `cve`
  field (no schema change), so `report.mjs` persistence and `differ.findingIdentity`
  (`type|slug|location|cve`, ADR-0005) keep working unchanged. Such entries are a WPScan
  **reference**, not a CVE — and should be labeled that way wherever the `cve` slot is
  rendered to a human.
- **The merged dataset feeds the existing matcher.** There is no parallel matching path;
  WPScan data goes through the same version-range / CVSS→severity logic as Wordfence data.

## Consequences

- WPScan only ever *adds* coverage; it can never override Wordfence on a shared CVE.
- The `cve` slot is now overloaded: it holds a real `CVE-…` id OR a `WPSCAN-<id>`
  reference. This is the price of zero schema churn through persistence and the differ;
  renderers must treat a `WPSCAN-` value as a reference, not a CVE number.
- The per-slug WPScan fan-out is bounded to a low concurrency because the free tier has a
  small daily call budget (the reason WPScan is a cross-reference, not the primary). A
  rejected or budget-exhausted lookup is swallowed; the cross-reference fails safe and
  never aborts a run, so Wordfence Findings always stand.
