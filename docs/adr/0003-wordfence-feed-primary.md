# 3. Use the free Wordfence Intelligence feed as the primary vuln source

Date: 2026-06-14

Status: Accepted — **amended by [ADR-0013](0013-wordfence-v3-feed-requires-free-token.md)**
(2026-06-16): the v1/v2 no-auth feeds were removed; the v3 feed is still free but now
requires a free registered API token. Wordfence remains the primary source; the "zero
secrets / no-auth" property below no longer holds for vuln mode.

## Context

A future reader will note the maintainer said "no Wordfence." That objection was
to the Wordfence **plugin** (paid, poor on Pantheon) — not its data. Sources
considered:

- **WPScan API** — free tier is 25 calls/day, one call per plugin; a single
  full-inventory scan of a ~30-plugin site exhausts it. Cannot be primary under a
  no-pay constraint.
- **GitHub Dependabot** — only sees Composer-managed plugins (many Pantheon WP
  sites commit plugin files directly); the GitHub Advisory DB has weak WP-plugin
  CVE coverage; it cannot see raw committed plugin files or embedded plugins.
- **Patchstack** — free tier is browse-oriented; API is more commercial/limited.

## Decision

Primary source is the **Wordfence Intelligence vulnerability data feed** — a free,
no-auth, commercial-OK bulk JSON download — matched locally by slug + version. An
optional `WPSCAN_API_TOKEN` cross-references when present.

## Consequences

- Zero secrets by default, no per-request rate limit, scales to the whole fleet.
- The naming is a trap to document: "we use Wordfence" means the free data feed,
  not the plugin the constraint rejected.
