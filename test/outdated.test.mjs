// Issue #8 — report-only outdated (outdated-but-no-CVE) detection.
//
// Exercises the PURE decision: given an inventory item and a *recorded* wordpress.org
// plugin_information response, decide whether the installed version trails the latest
// version published on wordpress.org (`body.version`) and, if so, raise a *report-only*
// `outdated` Finding. This never trips the failing gate — the scanner must not cry wolf
// over a plugin that is merely behind but carries no known CVE (CONTEXT.md "Abandoned
// plugin" contrasts outdated; PRD user stories 23/24). The "latest version" signal is
// reused from the same wp.org response the Abandoned detector already fetches — no new
// data source. No network here: the live query lives behind src/wporg.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { outdatedFinding } from '../src/outdated.mjs';
import { isAlertWorthy } from '../src/matcher.mjs';

const here = dirname(fileURLToPath(import.meta.url));
function fixture(name) {
  return JSON.parse(readFileSync(join(here, 'fixtures', 'wporg', name), 'utf8'));
}

const LIVE = fixture('live.json'); // akismet, latest version 5.3
const CLOSED = fixture('closed.json');
const REMOVED = fixture('removed.json');

const akismetOld = {
  slug: 'akismet', kind: 'plugin', version: '5.1',
  path: '/site/wp-content/plugins/akismet', embedded: false,
};
const akismetCurrent = {
  slug: 'akismet', kind: 'plugin', version: '5.3',
  path: '/site/wp-content/plugins/akismet', embedded: false,
};

test('an installed version below the wp.org latest yields a report-only outdated Finding', () => {
  const f = outdatedFinding(akismetOld, LIVE);
  assert.ok(f, 'a plugin behind the latest is an outdated Finding');
  assert.equal(f.type, 'outdated');
  assert.equal(f.slug, 'akismet');
  assert.equal(f.version, '5.1', 'carries the installed version');
  assert.equal(f.kind, 'plugin');
  assert.equal(f.location, '/site/wp-content/plugins/akismet', 'carries the on-disk location');
  assert.equal(f.latest, '5.3', 'carries the latest available version for context');
});

test('the outdated remediation points at update (the update-flow domain), not removal', () => {
  const f = outdatedFinding(akismetOld, LIVE);
  assert.match(f.remediation, /update/i, 'an outdated plugin is updated');
  assert.doesNotMatch(f.remediation, /remov/i, 'never removed');
  assert.match(f.remediation, /5\.3/, 'names the target version');
});

test('an outdated Finding is REPORT-ONLY — it is never alert-worthy (no crying wolf)', () => {
  const f = outdatedFinding(akismetOld, LIVE);
  assert.equal(isAlertWorthy(f), false, 'outdated must never trip the failing gate');
});

test('a plugin already at (or above) the latest version yields NO Finding', () => {
  assert.equal(outdatedFinding(akismetCurrent, LIVE), null, 'at latest => not outdated');
  const newer = { ...akismetCurrent, version: '6.0' };
  assert.equal(outdatedFinding(newer, LIVE), null, 'ahead of wp.org => not outdated');
});

test('a closed/removed plugin yields NO outdated Finding (it is Abandoned, handled elsewhere)', () => {
  // The Abandoned detector owns closed/removed; outdated must not double-report or, worse,
  // tell a maintainer to "update" a plugin that has no update channel.
  assert.equal(outdatedFinding(akismetOld, CLOSED), null, 'closed => not an outdated verdict');
  assert.equal(outdatedFinding(akismetOld, REMOVED), null, 'removed => not an outdated verdict');
});

test('a missing/garbage response or missing latest version yields NO Finding (fail safe)', () => {
  assert.equal(outdatedFinding(akismetOld, null), null);
  assert.equal(outdatedFinding(akismetOld, undefined), null);
  assert.equal(outdatedFinding(akismetOld, { statusCode: 200, body: null }), null);
  // A live response with no `version` field (the latest is unknown) => no verdict.
  assert.equal(outdatedFinding(akismetOld, { statusCode: 200, body: { slug: 'akismet' } }), null);
});

test('a plugin with an unknown installed version yields NO Finding (nothing to compare)', () => {
  const noVersion = { ...akismetOld, version: null };
  assert.equal(outdatedFinding(noVersion, LIVE), null);
});

test('only plugins are evaluated for outdated — core/themes are skipped', () => {
  // wp.org plugin_information is plugin-specific; a theme/core slug must never be raised
  // as an "outdated plugin" off a plugin-API response.
  const core = { slug: 'wordpress', kind: 'core', version: '6.1', path: '/x', embedded: false };
  const theme = { slug: 'twentytwenty', kind: 'theme', version: '1.0', path: '/t', embedded: false };
  assert.equal(outdatedFinding(core, LIVE), null);
  assert.equal(outdatedFinding(theme, LIVE), null);
});
