// Issue #5 — Abandoned/closed plugin detection.
//
// Exercises the PURE decision: given an inventory item and a *recorded* wordpress.org
// plugin_information response (status + body), decide whether the plugin is closed or
// removed (hence has no update channel) and raise an Abandoned-plugin Finding. The
// remediation must point at *removal*, never *update*. No network here — the live
// query lives behind the thin impure edge in src/wporg.mjs and is exercised by a
// recorded transcript, not a live unit test. See ADR-0003 / CONTEXT.md "Abandoned
// plugin".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { abandonedFinding, isAbandonedResponse } from '../src/abandoned.mjs';
import { isAlertWorthy } from '../src/matcher.mjs';

const here = dirname(fileURLToPath(import.meta.url));
function fixture(name) {
  return JSON.parse(readFileSync(join(here, 'fixtures', 'wporg', name), 'utf8'));
}

const CLOSED = fixture('closed.json');
const REMOVED = fixture('removed.json');
const LIVE = fixture('live.json');

const bps = {
  slug: 'bulletproof-security', kind: 'plugin', version: '5.1',
  path: '/site/wp-content/plugins/bulletproof-security', embedded: false,
};
const akismet = {
  slug: 'akismet', kind: 'plugin', version: '5.3',
  path: '/site/wp-content/plugins/akismet', embedded: false,
};

test('a "closed" wp.org response (error field) produces an Abandoned Finding', () => {
  const f = abandonedFinding(bps, CLOSED);
  assert.ok(f, 'a closed plugin is a Finding');
  assert.equal(f.type, 'abandoned');
  assert.equal(f.slug, 'bulletproof-security');
  assert.equal(f.version, '5.1');
  assert.equal(f.kind, 'plugin');
  assert.equal(f.location, '/site/wp-content/plugins/bulletproof-security');
});

test('the Abandoned Finding remediation points at removal, never update', () => {
  const f = abandonedFinding(bps, CLOSED);
  assert.match(f.remediation, /remov/i, 'abandoned code is removed');
  assert.doesNotMatch(f.remediation, /update/i, 'and never updated');
});

test('a "removed" wp.org response (404 / not found) produces an Abandoned Finding', () => {
  const f = abandonedFinding(bps, REMOVED);
  assert.ok(f, 'a removed plugin is a Finding');
  assert.equal(f.type, 'abandoned');
  assert.match(f.remediation, /remov/i);
});

test('an Abandoned Finding is alert-worthy (trips the gate)', () => {
  const f = abandonedFinding(bps, CLOSED);
  assert.equal(isAlertWorthy(f), true);
});

test('a live/maintained plugin produces NO Abandoned Finding', () => {
  assert.equal(abandonedFinding(akismet, LIVE), null);
});

test('isAbandonedResponse: the closed/removed signal is decided purely', () => {
  assert.equal(isAbandonedResponse(CLOSED), true, 'error field => abandoned');
  assert.equal(isAbandonedResponse(REMOVED), true, 'non-200 / not found => abandoned');
  assert.equal(isAbandonedResponse(LIVE), false, 'a full plugin object => alive');
});

test('a missing/garbage response is NOT treated as abandoned (fail safe, no false alert)', () => {
  // A transport error or unparseable body must not masquerade as a closed plugin;
  // the impure edge surfaces those, and an absent verdict yields no Finding.
  assert.equal(abandonedFinding(bps, null), null);
  assert.equal(abandonedFinding(bps, undefined), null);
  assert.equal(abandonedFinding(bps, { statusCode: 200, body: null }), null);
});

test('only plugins are queried for abandonment — core/themes/drop-ins are skipped', () => {
  // wp.org plugin_information is plugin-specific; a theme or core slug must never be
  // raised as an "abandoned plugin" off a plugin-API miss.
  const core = { slug: 'wordpress', kind: 'core', version: '6.4', path: '/x', embedded: false };
  const theme = { slug: 'twentytwenty', kind: 'theme', version: '2.0', path: '/t', embedded: false };
  assert.equal(abandonedFinding(core, REMOVED), null);
  assert.equal(abandonedFinding(theme, REMOVED), null);
});
