# 2. Ship the scanner as a reusable Action in its own repo

Date: 2026-06-14

Status: Accepted

## Context

The scan logic must run across a fleet of WordPress site repos. Three shapes were
considered: copy the script into every repo (drifts out of sync — the problem
we're trying to escape), a central scanner repo holding read access to every site
repo (one fat blast radius — a single compromise exposes all code), or a reusable
Action referenced by each site.

## Decision

The scanner is a versioned, reusable GitHub Action in its own repo. Each site repo
carries only a ~15-line **per-site workflow** that does
`uses: philltran/wpcare-security-scan@vN`.

## Consequences

- Fix-once / propagate: bump the Action, every site picks it up on its next run.
- Each scan runs inside its own site repo's trust boundary (only that repo's
  secrets) — no single repo holds credentials to all code, which matters for a
  security tool.
- Cost: no built-in single-pane fleet dashboard (a cross-site roll-up would be a
  later, separate addition); each site must adopt the workflow + its own secrets.
