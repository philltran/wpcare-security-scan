// Issue #10 — Drift baseline contract + baseline differ (mode 2, the PURE half).
//
// Exercises the PURE drift differ: given a *live-state snapshot* (what the future
// Terminus collector in #11 will produce) and the committed Baseline (the
// deliberately-blessed expected state, .security/baseline.json), decide the drift
// Findings. No network, no Terminus, no credentials here — the live reads are the
// follow-up slice; this is the fixture-pinned decision half.
//
// The four acceptance properties (PRD user stories 25–29):
//   1. a security control turned off (SSO plugin deactivated) -> a drift Finding,
//   2. a new/unexpected administrator account -> a drift Finding,
//   3. a changed critical option (with expected vs actual) -> a drift Finding,
//   4. a snapshot equal to a freshly-blessed Baseline -> NO drift.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { detectDrift, isDriftFinding } from '../src/drift.mjs';

const here = dirname(fileURLToPath(import.meta.url));
function fixture(name) {
  return JSON.parse(readFileSync(join(here, 'fixtures', 'drift', name), 'utf8'));
}

const BASELINE = fixture('baseline.json');
const CLEAN = fixture('snapshot-clean.json');
const SSO_OFF = fixture('snapshot-sso-off.json');
const NEW_ADMIN = fixture('snapshot-new-admin.json');
const CHANGED_OPTION = fixture('snapshot-changed-option.json');

test('a snapshot equal to a freshly-blessed Baseline yields NO drift', () => {
  // The clean snapshot reorders every list and option key vs the Baseline to prove
  // the differ is order-insensitive — a live read won't preserve Baseline ordering.
  assert.deepEqual(detectDrift(CLEAN, BASELINE), [], 'a blessed match is silent');
});

test('a deactivated security control (SSO plugin) produces a drift Finding', () => {
  const findings = detectDrift(SSO_OFF, BASELINE);
  assert.equal(findings.length, 1, 'exactly the one disabled control');
  const f = findings[0];
  assert.equal(f.type, 'security-control-disabled');
  assert.equal(f.slug, 'wp-saml-auth');
  assert.equal(f.kind, 'plugin');
  assert.equal(f.expected, 'active');
  assert.equal(f.actual, 'inactive');
  assert.match(f.remediation, /wp-saml-auth/);
});

test('the SSO drift Finding is alert-worthy and high severity', () => {
  const [f] = detectDrift(SSO_OFF, BASELINE);
  assert.equal(isDriftFinding(f), true);
  assert.equal(f.severity, 'high');
});

test('a new/unexpected administrator account produces a drift Finding', () => {
  const findings = detectDrift(NEW_ADMIN, BASELINE);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.type, 'unexpected-admin');
  assert.equal(f.slug, 'evil-backdoor', 'the account login rides the slug slot');
  assert.equal(f.severity, 'critical', 'post-compromise persistence is critical');
  assert.match(f.remediation, /evil-backdoor/);
});

test('a changed critical option produces a drift Finding carrying expected vs actual', () => {
  const findings = detectDrift(CHANGED_OPTION, BASELINE);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.type, 'changed-option');
  assert.equal(f.slug, 'users_can_register', 'the option name rides the slug slot');
  assert.equal(f.expected, '0');
  assert.equal(f.actual, '1');
  assert.match(f.remediation, /users_can_register/);
});

test('drift Findings carry the shared Finding fields the reporter renders', () => {
  // Additive to the v1 Finding shape (type/severity/slug/.../remediation) plus the
  // optional expected/actual; the reporter tolerates the missing version/cve/url.
  for (const f of detectDrift(SSO_OFF, BASELINE)) {
    assert.ok(typeof f.type === 'string');
    assert.ok(typeof f.severity === 'string');
    assert.ok(typeof f.slug === 'string');
    assert.ok(typeof f.location === 'string');
    assert.ok(typeof f.remediation === 'string');
  }
});

test('all three drift categories surface together, worst-severity first', () => {
  // A compromised site can drift on several axes at once; the differ must report
  // every axis, ordered most-severe-first like the vuln matcher.
  const messy = {
    activePlugins: ['akismet', 'wordpress-seo'], // wp-saml-auth deactivated
    activeThemes: ['twentytwentyfour'],
    administrators: ['alice', 'bob', 'evil-backdoor'], // rogue admin
    criticalOptions: {
      users_can_register: '1', // changed
      default_role: 'subscriber',
      siteurl: 'https://example.com',
    },
  };
  const findings = detectDrift(messy, BASELINE);
  assert.equal(findings.length, 3);
  assert.deepEqual(
    findings.map((f) => f.type),
    ['unexpected-admin', 'security-control-disabled', 'changed-option'],
    'critical admin, then high control, then medium option',
  );
});

test('a deactivated expected theme is also a disabled control', () => {
  const themeOff = { ...CLEAN, activeThemes: [] };
  const findings = detectDrift(themeOff, BASELINE);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'security-control-disabled');
  assert.equal(findings[0].slug, 'twentytwentyfour');
  assert.equal(findings[0].kind, 'theme');
});

test('extra active plugins NOT in the Baseline do not drift (Baseline lists expected, not exhaustive)', () => {
  // A newly-activated, expected plugin is a maintenance action, not a security
  // regression — drift watches for expected controls going AWAY, not for additions.
  const extra = { ...CLEAN, activePlugins: [...CLEAN.activePlugins, 'jetpack'] };
  assert.deepEqual(detectDrift(extra, BASELINE), [], 'an extra active plugin is not drift');
});

test('an option present in the snapshot but absent from the allow-list is ignored', () => {
  // The critical-options allow-list is curated (user story 27) — only the watched
  // options are diffed, so routine edits to unwatched options never cry wolf.
  const unwatched = {
    ...CLEAN,
    criticalOptions: { ...CLEAN.criticalOptions, blogname: 'Renamed Site' },
  };
  assert.deepEqual(detectDrift(unwatched, BASELINE), [], 'an unwatched option is not drift');
});

test('a missing/garbage snapshot or baseline fails safe (no Findings, no throw)', () => {
  assert.deepEqual(detectDrift(null, BASELINE), []);
  assert.deepEqual(detectDrift(CLEAN, null), []);
  assert.deepEqual(detectDrift(undefined, undefined), []);
  assert.deepEqual(detectDrift({}, {}), []);
});
