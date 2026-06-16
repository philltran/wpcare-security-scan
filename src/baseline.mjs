// Baseline helpers — PURE module for the live Drift Detection edge (mode 2, #11).
//
// The committed .security/baseline.json captures the deliberately-blessed expected
// live state the pure differ (src/drift.mjs) diffs against. This module owns the pure
// decisions around that file:
//
//   loadBaseline(path)                          -> the parsed Baseline, or null (bootstrap)
//   seedBaseline(snapshot, { blessedAt })       -> a fresh Baseline with the seeded allow-list
//   buildBaselineFromSnapshot(snapshot, prior, opts) -> a re-blessed Baseline
//   renderBaselineDiff(oldBaseline, newBaseline)-> the human-readable PR-body diff
//
// The IMPURE halves — reading live state (src/collector.mjs) and opening the re-bless
// PR (src/rebless.mjs) — are kept thin and are NOT unit-tested. This module is where
// the seeded allow-list (ADR-0010) and the "here is the drift you are about to bless
// away" diff are pinned by tests.

import { readFileSync } from 'node:fs';

// The contract version of the committed Baseline shape (matches src/drift.mjs).
export const BASELINE_VERSION = 1;

// The seeded critical-options allow-list (ADR-0010): the five genuine privilege-
// escalation / hijack vectors, not config noise. wp_user_roles is OPT-IN (a noisy
// serialized blob) and is therefore NOT seeded — an operator adds it to a Baseline's
// criticalOptions by hand, and a re-bless then carries it over (see
// buildBaselineFromSnapshot).
export const SEEDED_CRITICAL_OPTIONS = new Set([
  'default_role',
  'users_can_register',
  'siteurl',
  'home',
  'admin_email',
]);

// Read and parse the committed Baseline. Three outcomes, deliberately distinct:
//   - present + valid JSON object -> the Baseline,
//   - absent (ENOENT)             -> null (bootstrap: no Baseline blessed yet),
//   - present + unparseable       -> THROW (an operator error; never silently treat a
//     corrupt Baseline as "no Baseline" and bless live state over it).
export function loadBaseline(path) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Malformed Baseline at ${path}: ${err.message}`, { cause: err });
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Malformed Baseline at ${path}: expected a JSON object.`);
  }
  return parsed;
}

function asSlugArray(list) {
  return Array.isArray(list) ? list.map((s) => String(s)) : [];
}

// Pick only the allow-listed option keys out of a live snapshot's options, in the
// order the allow-list iterates, coercing every value to a string (WP-CLI emits
// option values as text and the differ compares as strings).
function pickOptions(liveOptions, allowKeys) {
  const live = liveOptions && typeof liveOptions === 'object' ? liveOptions : {};
  const out = {};
  for (const key of allowKeys) {
    if (key in live) out[key] = String(live[key]);
  }
  return out;
}

// Build a Baseline from a live snapshot, blessing the options named by `allowKeys`.
function baselineFrom(snapshot, allowKeys, blessedAt) {
  const snap = snapshot && typeof snapshot === 'object' ? snapshot : {};
  return {
    version: BASELINE_VERSION,
    blessedAt: blessedAt || new Date().toISOString(),
    activePlugins: asSlugArray(snap.activePlugins),
    activeThemes: asSlugArray(snap.activeThemes),
    administrators: asSlugArray(snap.administrators),
    criticalOptions: pickOptions(snap.criticalOptions, allowKeys),
  };
}

// Seed a brand-new Baseline (bootstrap) from live state: blesses exactly the five
// seeded allow-list options (ADR-0010), never every option the live site carries.
export function seedBaseline(snapshot, { blessedAt } = {}) {
  return baselineFrom(snapshot, [...SEEDED_CRITICAL_OPTIONS], blessedAt);
}

// Re-bless: regenerate a Baseline from current live state. When a prior Baseline
// exists, its CURATED allow-list keys are preserved (so an operator's opt-in — e.g.
// wp_user_roles — survives re-bless and an unwatched live option never sneaks in);
// with no prior Baseline this is a bootstrap and falls back to the seeded allow-list.
export function buildBaselineFromSnapshot(snapshot, priorBaseline, { blessedAt } = {}) {
  const priorOptions =
    priorBaseline
    && typeof priorBaseline.criticalOptions === 'object'
    && priorBaseline.criticalOptions
      ? Object.keys(priorBaseline.criticalOptions)
      : null;
  const allowKeys = priorOptions && priorOptions.length
    ? priorOptions
    : [...SEEDED_CRITICAL_OPTIONS];
  return baselineFrom(snapshot, allowKeys, blessedAt);
}

function setDiff(before, after) {
  const beforeSet = new Set(asSlugArray(before));
  const afterSet = new Set(asSlugArray(after));
  const removed = [...beforeSet].filter((x) => !afterSet.has(x));
  const added = [...afterSet].filter((x) => !beforeSet.has(x));
  return { removed, added };
}

function optionDiffLines(before, after) {
  const b = before && typeof before === 'object' ? before : {};
  const a = after && typeof after === 'object' ? after : {};
  const keys = new Set([...Object.keys(b), ...Object.keys(a)]);
  const lines = [];
  for (const key of keys) {
    const bv = key in b ? String(b[key]) : '(absent)';
    const av = key in a ? String(a[key]) : '(absent)';
    if (bv !== av) lines.push(`- option \`${key}\`: \`${bv}\` -> \`${av}\``);
  }
  return lines;
}

// Render the "here is the drift you are about to bless away" diff for the re-bless PR
// body (ADR-0010). A bootstrap (no prior Baseline) renders an explicit note rather than
// a diff. The diff is descriptive prose, not a machine format — a human reads it before
// merging the PR that re-blesses the Baseline.
export function renderBaselineDiff(oldBaseline, newBaseline) {
  if (!oldBaseline) {
    return 'Bootstrap: no prior Baseline. This PR seeds the first '
      + '`.security/baseline.json` from current live state.';
  }

  const lines = [];
  const plugins = setDiff(oldBaseline.activePlugins, newBaseline.activePlugins);
  for (const slug of plugins.removed) lines.push(`- expected plugin no longer blessed active: \`${slug}\``);
  for (const slug of plugins.added) lines.push(`- newly blessed active plugin: \`${slug}\``);

  const themes = setDiff(oldBaseline.activeThemes, newBaseline.activeThemes);
  for (const slug of themes.removed) lines.push(`- expected theme no longer blessed active: \`${slug}\``);
  for (const slug of themes.added) lines.push(`- newly blessed active theme: \`${slug}\``);

  const admins = setDiff(oldBaseline.administrators, newBaseline.administrators);
  for (const login of admins.removed) lines.push(`- administrator removed from the expected set: \`${login}\``);
  for (const login of admins.added) lines.push(`- administrator added to the expected set: \`${login}\``);

  lines.push(...optionDiffLines(oldBaseline.criticalOptions, newBaseline.criticalOptions));

  if (!lines.length) {
    return 'No change: the regenerated Baseline matches the committed one '
      + '(re-blessing is a no-op).';
  }
  return ['The following blessed state changes when this PR merges:', '', ...lines].join('\n');
}
