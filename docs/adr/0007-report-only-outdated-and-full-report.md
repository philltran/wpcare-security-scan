# 7. Render the full report and detect outdated-but-no-CVE as report-only

Date: 2026-06-15

Status: Accepted

## Context

The scanner so far rendered only **alert-worthy** Findings (cve / abandoned / embedded)
into the deduped issue. PRD #1 (user stories 23/24, issue #8) asks for two more things:

1. A **full report of everything detected** on demand, so a maintainer has the complete
   picture — not just the alert-worthy subset.
2. **Outdated-but-no-CVE detection**: a plugin whose installed version trails the latest
   published version but which carries no known CVE. These must be **report-only** — they
   appear in the report but **never** trip the failing workflow status, so the scanner
   does not cry wolf over a plugin that is merely behind.

Two questions had to be settled:

- **Where does "latest available version" come from** — a new data source, or an
  existing one?
- **How is the report-only nature enforced** so an outdated item can never leak into an
  alert, given the differ persists Findings in the issue body and re-alerts on the
  new/worsened subset (ADR-0005)?

## Decision

- **Reuse the wordpress.org plugin_information response — no new data source.** The
  Abandoned detector (ADR-0003, issue #5) already fetches that response per top-level
  plugin slug, and a live plugin object carries a top-level `version` field: the latest
  on wp.org. A new pure module `src/outdated.mjs` (`outdatedFinding(item, response)`,
  mirroring `src/abandoned.mjs`) compares the installed version against it using the
  matcher's existing WordPress-tolerant `compareVersions` (now exported). Installed
  strictly below the latest, with a known latest and a known installed version, is an
  `outdated` Finding; at or above is current. The orchestrator folds this verdict into
  the **same** per-slug wp.org loop as Abandoned — one fetch, both verdicts.
- **`outdated` is report-only by construction.** It was already one of the PRD's
  report-only types and is excluded from the matcher's `ALERT_WORTHY` set, so
  `isAlertWorthy` returns false and the exit-code/failing-status gate in `scan.mjs`
  (which filters to alert-worthy before the differ) never sees it. Its severity is
  `none` and its remediation points at **update** — routing into the
  `wordpress-maintenance-updates` / `wordpress-update-flow` domain — never removal.
- **Suppression rules so it never double-reports or cries wolf.** An outdated verdict is
  skipped for a slug that is **abandoned** (closed/removed plugins have no update channel
  — telling a maintainer to "update" one is wrong) and for a slug that already carries a
  **Known CVE** Finding (the PRD's notion is *outdated-but-no-CVE*; the CVE alert already
  owns that slug). A missing/garbage response, a missing latest, or a missing installed
  version yields no Finding — fail-safe, like the Abandoned path.
- **The report renders everything; persistence + the title stay alert-worthy only.**
  `renderIssueBody` now splits the Finding list into an **Alert-worthy Findings** section
  and a clearly-labeled **Report-only (not alerting)** section, rendering both. But the
  hidden state block the differ reads back (ADR-0005) and the issue title count are
  derived from the **alert-worthy subset alone**, so a report-only Finding can never be
  diffed into an alert or inflate the headline. The orchestrator passes the full Finding
  list to the reporter; the reporter does the splitting.

## Consequences

- The "latest version" signal costs nothing extra: it rides the wp.org lookup the
  Abandoned detector already performs. With no `fetchPluginInfo` injected, outdated
  detection is simply skipped, exactly like Abandoned.
- The issue body is longer (a second section), but the machine-readable state block stays
  small and alert-worthy-only, so the differ contract (ADR-0005) is unchanged — a
  report-only item is invisible to it.
- `outdated` carries an extra `latest` field (the update target) on top of the v1 Finding
  shape. This is additive and report-only; alert-worthy consumers (the differ's identity,
  persistence) never read it.
- A plugin that is both behind *and* has a CVE surfaces once, as the (alert-worthy) CVE
  Finding — never twice. A behind-but-clean plugin surfaces once, as a report-only item.
