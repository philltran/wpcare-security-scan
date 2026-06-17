# 13. The Wordfence feed is v3 and requires a free API token (amends ADR-0003)

Date: 2026-06-16

Status: Accepted (amends ADR-0003)

## Context

ADR-0003 chose the **free, no-auth** Wordfence Intelligence vulnerability feed as the
primary data source, matched locally by slug + version. A core property was that the
**Vulnerability Scan needed zero secrets** (PRD user story 31) — adopt the scanner on a
repo before wiring any credentials.

In 2026 Wordfence changed the API. The v1 and v2 feed endpoints were **removed** (they now
return HTTP 410), and the surviving **v3 production feed requires a registered API token**
sent as a `Bearer` token. The feed is still **free for personal and commercial use** with
the same data — the token is free, generated in a Wordfence account under *Integrations* —
but it is no longer anonymous. Wordfence made the change to manage a feed that has grown to
~123 MB and to apply rate limits; the free tier allows **1 request per 30 minutes per
token**. (Higher limits are an enterprise arrangement.)

This is an upstream breaking change outside our control. The "free" premise of ADR-0003
survives; the "no-auth / zero-secret" premise does not.

## Decision

- Fetch the **v3** production feed and authenticate with a **free Wordfence Intelligence
  API token**, sent as `Authorization: Bearer <token>`. The token is a new Action input,
  `wordfence-token`, masked as a secret.
- The token is **required for any mode that runs the Vulnerability Scan** (`vuln` | `both`)
  and validated at runtime with a clear error; **drift-only mode does not need it**
  (mirroring how the Pantheon inputs are required only for drift). PRD user story 31
  ("zero secrets") is **revised**: vuln mode now requires this one free token. The Action's
  own `GITHUB_TOKEN` remains automatic; only the Wordfence token must be provisioned.
- Failures are surfaced **loud and distinctly**, never as a clean/empty scan: a missing
  token is a configuration error before any request; an HTTP 429 is a named rate-limit
  error; any other non-2xx is a status error. (The plausibility floor on an empty/truncated
  2xx body — newly relevant at 123 MB — is the orchestrator guard tracked in issue #15.)
- **Token provisioning is a workflow concern, not the Action's** — the Action only reads the
  `wordfence-token` input. Because the free tier is 1 request / 30 minutes per token, a
  single shared org token will collide across a busy fleet (simultaneous weekly crons and
  bursty `pull_request` runs). The recommended fleet model is a **per-repo token** (each
  repo gets its own 48/day budget); a shared org token is viable only with staggered
  schedules and an acceptance of occasional `429`s on PR runs.

## Consequences

- Onboarding a repo to vuln mode now requires one free secret. The README, the per-site
  example workflows, and `action.yml` document `wordfence-token` and name the
  `WORDFENCE_INTELLIGENCE_TOKEN` secret.
- The normalizer (`src/wordfence.mjs`) consumes whatever shape the v3 feed returns; the v3
  record shape must be validated against a real payload (the docs are token-gated). If v3
  diverges from the v2 record shape the normalizer assumes, it is adjusted there — the
  matcher and the rest of the pipeline are unaffected because they consume the normalized
  `{ slug -> [records] }` shape, not the raw feed.
- The 123 MB feed makes the issue-#15 hardening (request timeout, memory-aware handling,
  and the implausible-feed guard that must distinguish 429 / empty / truncated from a
  genuine clean result) materially more important than when first filed.
- A future fleet-scale option (out of scope here) is a single scheduled job that downloads
  the feed once and republishes it for sites to consume, trading one shared rate-limit
  budget for a small shared-data component — distinct from the rejected central *scanner*
  of ADR-0002 because it shares data, not credentials or repo access.
