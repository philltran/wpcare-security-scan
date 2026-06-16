// action-metadata-safety guard. PURE, zero-dependency.
//
// A `${{ ... }}` template expression in this action's metadata (action.yml) breaks the
// Action at LOAD time: GitHub evaluates `${{ }}` anywhere in a metadata file against the
// contexts available there, and the `secrets` context is workflow-only — so a literal
// `${{ secrets.* }}` example in an input description fails with "Unrecognized named-value:
// secrets" and the whole Action fails to load (regression: a real first-run failure that
// no test caught because action.yml was never exercised by the suite).
//
// This is a JavaScript action (`runs.using: node24`) with NO composite `runs.steps`, so
// its metadata needs NO template expressions at all — any `${{ }}` is a bug. (A composite
// action WOULD legitimately use `${{ inputs.* }}` in its steps; this guard is scoped to
// this node-action and would need loosening before reuse on a composite one.)
//
// The repo ships no YAML parser and tests itself with `node --test` over pure `src/*.mjs`,
// so this is a pure text scan (mirrors src/workflow-safety.mjs). The accompanying test
// asserts the shipped action.yml stays clean.

// Return every `${{ ... }}` template expression found in the metadata text (the snippets,
// so a failing assertion can name what leaked). Non-greedy and multi-line aware: a folded
// YAML scalar can wrap an expression across lines.
export function findTemplateExpressions(text) {
  const matches = String(text ?? '').match(/\$\{\{[\s\S]*?\}\}/g);
  return matches ? [...matches] : [];
}
