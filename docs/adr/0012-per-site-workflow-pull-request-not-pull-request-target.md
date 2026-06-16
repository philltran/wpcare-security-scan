# 12. The per-site workflow uses `pull_request`, never `pull_request_target`

Date: 2026-06-16

Status: Accepted

## Context

The per-site workflow triggers the scan on a weekly schedule, on `pull_request`
(shift-left — catch a vulnerable or bundled-plugin change *before* it merges), and on
`workflow_dispatch` (PRD #1, ADR-0008). Today the Action only reads files on disk and
upserts one deduped GitHub issue, so `pull_request` is safe: it runs in the PR's own
context with a **read-only, secret-less** `GITHUB_TOKEN`.

`pull_request_target` is the superficially-tempting alternative — it would give the
scan a read/write token and the repo's secrets even on a fork PR. But it runs in the
**base** repo's context against a **fork-supplied head that is attacker-controlled** —
the classic GitHub Actions privilege-escalation foot-gun. As later slices add behavior
that checks out, reads, or executes PR-supplied content (build scripts, dependency
install lifecycle, the PR's own bundled code), running that under `pull_request_target`
with secrets in scope would be remote code execution against the fleet's credentials.

## Decision

The per-site workflow stays on **`pull_request`** and **never** uses
`pull_request_target`. The same prohibition holds for the drift workflow and any future
example. The rule is twofold: (1) do not trigger the scan with `pull_request_target`,
and (2) never execute PR-supplied code with an elevated/base-repo token. The shipped
examples and the README state this with an explicit comment explaining *why*.

The convention is **enforced**, not just documented. The repo tests itself with
`node --test` over pure `src/*.mjs` modules and ships no YAML parser, so the guard is a
pure, zero-dependency text scan (`src/workflow-safety.mjs`,
`findPullRequestTargetTrigger`) that flags any `pull_request_target` trigger while
ignoring `#`-comment mentions (the docs deliberately name the forbidden trigger to
explain it). A test (`test/workflow-safety.test.mjs`) asserts every shipped
`examples/*.yml` stays clean. Because CI already runs `npm test`, any PR that
introduces `pull_request_target` into a shipped example fails CI. The guard is a
build-/test-time module — it is *not* imported by `src/index.mjs`, so `dist/` is
unchanged.

## Consequences

- The `pull_request_target` prohibition cannot silently drift: a future slice that adds
  it to an example workflow turns CI red with a message naming the file and this issue.
- The guard is intentionally a simple text scan, not a full YAML parse, to avoid adding
  a dependency the repo deliberately avoids; it ignores commented mentions but does not
  attempt to validate arbitrary YAML. It guards the shipped examples — it does not (and
  cannot) police the workflows consumers write in their own repos.
- The scan stays entirely inside the calling repo's own secret boundary: vuln mode is
  zero-secret beyond `GITHUB_TOKEN`, and no cross-repo credentials are ever in scope on
  a fork PR.
