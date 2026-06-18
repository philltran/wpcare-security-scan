# 14. A feed-source override (`feed-path`) enables caching and mirroring

Date: 2026-06-17

Status: Accepted

## Context

ADR-0013 moved the Vulnerability Scan onto the Wordfence v3 feed: a ~123 MB JSON download
behind a free token, rate-limited to **1 request per 30 minutes per token**. Fetching it
directly on every run is doubly painful:

- The free-tier limit is hit immediately by normal usage — a `pull_request` push plus a
  re-run, or a fleet of sites on one shared token, collide inside the 30-minute window and
  the run fails `HTTP 429: API key limit exceeded` (observed on the first live pilot run).
- Re-downloading 123 MB per run is wasteful when the feed changes only periodically.

The Action originally always called Wordfence itself, so there was no way to interpose a
cache or a mirror.

## Decision

Add one input, **`feed-path`** — a path to a pre-fetched feed JSON file on disk. When set,
the Action reads the feed from that file (`loadFeedFromFile`) instead of calling Wordfence,
and `wordfence-token` is no longer required (the credential, if any, lived in the workflow
step that produced the file). This single primitive enables both strategies as *workflow*
compositions, with no further Action surface:

- **Cache (per-repo):** an `actions/cache` step keyed by the UTC day, plus a conditional
  `curl` that fetches the feed only on a cache miss. PR pushes, re-runs, and the weekly scan
  reuse the cached file — at most one Wordfence call per repo per day. This is the shipped
  example workflow.
- **Mirror (fleet):** a workflow step (or a separate publish job — see the central-mirror
  issue) writes a mirrored copy to the path; sites consume the mirror with no Wordfence
  token at all.

Direct fetch via `fetchWordfenceFeed(token)` remains the default when `feed-path` is unset,
so trying the scanner needs no extra steps.

Both the direct fetch and the file read **fail loud**, never silent-green: a missing,
unreadable, truncated, or non-JSON file throws, and (correcting an ADR-0013 oversight) an
`HTTP 429` is detected from the error `@actions/http-client` *throws* on a non-2xx — the
earlier code checked a returned status code that `getJson` never returns on failure, so the
friendly message was dead code and the raw error body leaked instead.

## Consequences

- The recommended production wiring is feed-path + a day-keyed cache; the example workflow
  ships it. The token is used at most once per repo per day.
- The central, fleet-wide mirror (one scheduled download republished for all sites, removing
  the per-repo token entirely) is the natural next step and is tracked separately. It shares
  read-only **data**, not credentials or repo access, so it does not reopen the blast-radius
  concern that rejected a central *scanner* (ADR-0002).
- Licensing: the feed is free for personal and commercial use, but a republished mirror
  should be **private** to the fleet, not a public redistribution — to be confirmed against
  Wordfence's terms before standing one up.
- The implausible-feed plausibility floor (an empty/truncated *2xx* body or a tiny cached
  file) remains the open guard tracked in issue #15.
