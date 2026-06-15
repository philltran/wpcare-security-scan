# Architecture Decision Records

- [0001 — Scan off-platform from a GitHub Action, not an on-site WordPress plugin](0001-off-platform-action-not-onsite-plugin.md)
- [0002 — Ship the scanner as a reusable Action in its own repo](0002-reusable-action-own-repo.md)
- [0003 — Use the free Wordfence Intelligence feed as the primary vuln source](0003-wordfence-feed-primary.md)
- [0004 — Enumerate the filesystem deeply, not WordPress's plugin list](0004-deep-embedded-enumeration.md)
- [0005 — Persist prior Findings in the deduped issue body to alert only on new/worsened](0005-persist-prior-findings-in-issue-body.md)
- [0006 — Merge the optional WPScan cross-reference into the Wordfence dataset](0006-wpscan-cross-reference-merge.md)
- [0007 — Render the full report and detect outdated-but-no-CVE as report-only](0007-report-only-outdated-and-full-report.md)
