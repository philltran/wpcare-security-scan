// Issue #11 — pure Baseline helpers for the live Drift Detection edge.
//
// The collector edge (src/collector.mjs) is the IMPURE half and is not unit-tested;
// the testable value lives here in the pure helpers that read, seed, regenerate, and
// diff the committed .security/baseline.json. These pin ADR-0010's seeded allow-list
// and the PR-based re-bless content (the regenerated Baseline + a human-readable diff).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  SEEDED_CRITICAL_OPTIONS,
  loadBaseline,
  seedBaseline,
  buildBaselineFromSnapshot,
  renderBaselineDiff,
} from '../src/baseline.mjs';

function tmp() {
  return mkdtempSync(join(tmpdir(), 'wpcare-baseline-'));
}

test('loadBaseline reads and parses a committed .security/baseline.json', () => {
  const dir = tmp();
  try {
    const baseline = {
      version: 1,
      blessedAt: '2026-06-15T00:00:00Z',
      activePlugins: ['wp-saml-auth'],
      activeThemes: ['twentytwentyfour'],
      administrators: ['site-admin'],
      criticalOptions: { default_role: 'subscriber' },
    };
    writeFileSync(join(dir, 'baseline.json'), JSON.stringify(baseline), 'utf8');
    assert.deepEqual(loadBaseline(join(dir, 'baseline.json')), baseline);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadBaseline returns null when the Baseline file is absent (bootstrap)', () => {
  // No committed Baseline yet — bootstrap. Returns null rather than throwing so the
  // dispatch can regenerate one from scratch (ADR-0010: bootstrap is the same PR path).
  assert.equal(loadBaseline(join(tmp(), 'baseline.json')), null);
});

test('loadBaseline throws on a malformed (present-but-garbage) Baseline', () => {
  // A present-but-unparseable Baseline is an operator error, not bootstrap: fail loud
  // rather than silently treating a corrupt file as "no Baseline" and blessing live.
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'baseline.json'), '{ not json', 'utf8');
    assert.throws(() => loadBaseline(join(dir, 'baseline.json')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('SEEDED_CRITICAL_OPTIONS is exactly the five ADR-0010 privilege/hijack vectors', () => {
  assert.deepEqual(
    [...SEEDED_CRITICAL_OPTIONS].sort(),
    ['admin_email', 'default_role', 'home', 'siteurl', 'users_can_register'].sort(),
  );
});

test('seedBaseline builds a Baseline from live state with the seeded allow-list', () => {
  const snapshot = {
    activePlugins: ['akismet', 'wp-saml-auth'],
    activeThemes: ['twentytwentyfour'],
    administrators: ['site-admin'],
    criticalOptions: {
      default_role: 'subscriber',
      users_can_register: '0',
      siteurl: 'https://example.com',
      home: 'https://example.com',
      admin_email: 'ops@example.com',
    },
  };
  const baseline = seedBaseline(snapshot, { blessedAt: '2026-06-15T00:00:00Z' });
  assert.equal(baseline.version, 1);
  assert.equal(baseline.blessedAt, '2026-06-15T00:00:00Z');
  assert.deepEqual(baseline.activePlugins, ['akismet', 'wp-saml-auth']);
  assert.deepEqual(baseline.activeThemes, ['twentytwentyfour']);
  assert.deepEqual(baseline.administrators, ['site-admin']);
  // Only the five seeded allow-list keys are blessed — never every option live carries.
  assert.deepEqual(
    Object.keys(baseline.criticalOptions).sort(),
    ['admin_email', 'default_role', 'home', 'siteurl', 'users_can_register'].sort(),
  );
  assert.equal(baseline.criticalOptions.default_role, 'subscriber');
});

test('buildBaselineFromSnapshot preserves an existing Baseline allow-list (re-bless keeps opt-ins)', () => {
  // Re-blessing an existing Baseline must keep its curated allow-list — including an
  // opt-in key like wp_user_roles — rather than silently dropping it back to the seed.
  const prior = {
    version: 1,
    criticalOptions: { default_role: 'subscriber', wp_user_roles: 'a:1:{}' },
  };
  const snapshot = {
    activePlugins: ['akismet'],
    activeThemes: ['twentytwentyfour'],
    administrators: ['site-admin'],
    criticalOptions: {
      default_role: 'administrator', // drifted value to be re-blessed
      wp_user_roles: 'a:2:{}',       // opt-in key, new value
      blogname: 'noise',             // unwatched — must not enter the Baseline
    },
  };
  const next = buildBaselineFromSnapshot(snapshot, prior, { blessedAt: 'T' });
  assert.deepEqual(
    Object.keys(next.criticalOptions).sort(),
    ['default_role', 'wp_user_roles'],
    'the allow-list keys carry over from the prior Baseline, no unwatched key added',
  );
  assert.equal(next.criticalOptions.default_role, 'administrator', 're-blessed to live');
});

test('renderBaselineDiff summarizes drift being blessed away (the PR-body diff)', () => {
  const oldBaseline = {
    activePlugins: ['wp-saml-auth', 'akismet'],
    activeThemes: ['twentytwentyfour'],
    administrators: ['site-admin'],
    criticalOptions: { users_can_register: '0' },
  };
  const newBaseline = {
    activePlugins: ['akismet'], // wp-saml-auth dropped
    activeThemes: ['twentytwentyfour'],
    administrators: ['site-admin', 'new-admin'], // admin added
    criticalOptions: { users_can_register: '1' }, // changed
  };
  const diff = renderBaselineDiff(oldBaseline, newBaseline);
  assert.match(diff, /wp-saml-auth/, 'a removed expected plugin shows in the diff');
  assert.match(diff, /new-admin/, 'an added admin shows in the diff');
  assert.match(diff, /users_can_register/, 'a changed option shows in the diff');
});

test('renderBaselineDiff handles a bootstrap (no prior Baseline) with an empty diff', () => {
  const diff = renderBaselineDiff(null, {
    activePlugins: ['akismet'], activeThemes: [], administrators: ['a'], criticalOptions: {},
  });
  assert.equal(typeof diff, 'string');
  assert.match(diff, /bootstrap|no (prior|previous) baseline/i);
});
