// Issue #14 — workflow-safety guard. PURE, zero-dependency.
//
// Flags any workflow that triggers on `pull_request_target`. That trigger runs in the
// BASE repo's context with its read/write GITHUB_TOKEN and secrets in scope, but a fork
// PR's head is attacker-controlled — the classic Actions privilege-escalation foot-gun.
// The per-site workflow uses `pull_request` (shift-left, runs in the PR's own read-only,
// secret-less context) and must never drift to `pull_request_target` as later slices add
// behavior that checks out, reads, or executes PR-supplied content.
//
// The repo tests itself with `node --test` over pure `src/*.mjs` modules and ships no
// YAML parser, so this guard is a pure text scan (no new dependency): it strips `#`
// comments line-by-line — the README/examples deliberately NAME the forbidden trigger in
// comments to explain WHY, which must not be a false positive — then looks for the token
// as an actual trigger. The accompanying test asserts every shipped example stays clean.

// Remove the `#`-comment tail from a single YAML line. Good enough for the trigger
// scan: the guard only needs to ignore commented-out mentions, and example workflows
// don't put `#` inside quoted scalars on trigger lines. (A full YAML parse would be
// heavier and pull in a dependency the repo deliberately avoids.)
function stripComment(line) {
  const hash = line.indexOf('#');
  return hash === -1 ? line : line.slice(0, hash);
}

// True if the workflow YAML uses `pull_request_target` as a trigger (mapping key
// `pull_request_target:` or a flow-sequence entry like `on: [push, pull_request_target]`),
// ignoring any mention inside a `#` comment.
export function findPullRequestTargetTrigger(yamlText) {
  const lines = String(yamlText ?? '').split(/\r?\n/);
  for (const raw of lines) {
    const line = stripComment(raw);
    if (/(^|[\s[,])pull_request_target(\s*[:,\]]|\s*$)/.test(line)) {
      return true;
    }
  }
  return false;
}
