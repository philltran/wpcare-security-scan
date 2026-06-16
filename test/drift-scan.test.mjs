// Issue #11 — the drift orchestrator (mode 2 pure spine), exercised end-to-end with
// the impure edges injected. The Terminus collector and the re-bless PR opener are the
// IMPURE halves (src/collector.mjs, src/rebless.mjs) and are NOT unit-tested; here the
// collector, the upserter, and the PR opener are injected fakes so the routing,
// failure semantics, the fail-on gate, and the update-baseline path are all pinned
// offline.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runDriftScan } from '../src/drift-scan.mjs';

const BASELINE = {
  version: 1,
  blessedAt: '2026-06-15T00:00:00Z',
  activePlugins: ['wp-saml-auth', 'akismet'],
  activeThemes: ['twentytwentyfour'],
  administrators: ['site-admin'],
  criticalOptions: { users_can_register: '0', default_role: 'subscriber' },
};

const CLEAN = {
  activePlugins: ['akismet', 'wp-saml-auth'],
  activeThemes: ['twentytwentyfour'],
  administrators: ['site-admin'],
  criticalOptions: { default_role: 'subscriber', users_can_register: '0' },
};

const SSO_OFF = { ...CLEAN, activePlugins: ['akismet'] }; // wp-saml-auth deactivated

function statelessUpserter() {
  const calls = [];
  return {
    calls,
    async upsertIssue(args) { calls.push(args); return { number: 11, priorBody: null }; },
  };
}

test('a snapshot matching the Baseline runs GREEN with zero drift Findings', async () => {
  const up = statelessUpserter();
  const result = await runDriftScan({
    repoSlug: 'acme/site',
    baseline: BASELINE,
    collectSnapshot: async () => CLEAN,
    upsertIssue: up.upsertIssue,
  });
  assert.equal(result.findings.length, 0);
  assert.equal(result.exitCode, 0, 'a blessed match is green');
  assert.equal(up.calls.length, 1, 'the issue is still upserted (report is complete)');
});

test('real drift produces Findings and fails the run (default fail-on)', async () => {
  const up = statelessUpserter();
  const result = await runDriftScan({
    repoSlug: 'acme/site',
    baseline: BASELINE,
    collectSnapshot: async () => SSO_OFF,
    upsertIssue: up.upsertIssue,
  });
  const f = result.findings.find((x) => x.type === 'security-control-disabled');
  assert.ok(f, 'the disabled SSO control is a Finding');
  assert.equal(result.exitCode, 1, 'new drift fails the run');
  assert.match(up.calls[0].body, /wp-saml-auth/, 'the drift is reported in the issue');
});

test('fail-on gates the failing status without narrowing the report', async () => {
  // The disabled-control drift is HIGH severity; a critical gate must not fail on it,
  // but the issue still files it.
  const up = statelessUpserter();
  const result = await runDriftScan({
    repoSlug: 'acme/site',
    baseline: BASELINE,
    failOn: 'critical',
    collectSnapshot: async () => SSO_OFF,
    upsertIssue: up.upsertIssue,
  });
  assert.ok(result.findings.some((x) => x.type === 'security-control-disabled'));
  assert.equal(result.exitCode, 0, 'a high drift Finding does not trip a critical gate');
  assert.match(up.calls[0].body, /wp-saml-auth/, 'still filed regardless of the gate');
});

test('an unscored-equivalent critical drift (rogue admin) fails even a high gate', async () => {
  const up = statelessUpserter();
  const result = await runDriftScan({
    repoSlug: 'acme/site',
    baseline: BASELINE,
    failOn: 'high',
    collectSnapshot: async () => ({ ...CLEAN, administrators: ['site-admin', 'evil'] }),
    upsertIssue: up.upsertIssue,
  });
  assert.ok(result.findings.some((x) => x.type === 'unexpected-admin'));
  assert.equal(result.exitCode, 1, 'a critical rogue-admin drift fails a high gate');
});

test('a collector error fails the run LOUDLY and emits ZERO Findings (never fabricate drift)', async () => {
  const up = statelessUpserter();
  await assert.rejects(
    () => runDriftScan({
      repoSlug: 'acme/site',
      baseline: BASELINE,
      collectSnapshot: async () => { throw new Error('terminus auth rejected'); },
      upsertIssue: up.upsertIssue,
    }),
    /terminus auth rejected|collector/i,
    'a bad read surfaces as a red run, not a silent green',
  );
  assert.equal(up.calls.length, 0, 'no issue upsert and no fabricated drift on a bad read');
});

test('a second identical run is GREEN (drift dedups across runs like vuln Findings)', async () => {
  // The deduped issue persists the drift Findings; an unchanged second run finds
  // nothing new/worsened and runs green even though the drift is still present/filed.
  const calls = [];
  let lastBody = null;
  const upsertIssue = async ({ title, body }) => {
    const priorBody = lastBody;
    lastBody = body;
    calls.push({ title, body });
    return { number: 11, priorBody };
  };
  const args = {
    repoSlug: 'acme/site',
    baseline: BASELINE,
    collectSnapshot: async () => SSO_OFF,
    upsertIssue,
  };
  const first = await runDriftScan(args);
  assert.equal(first.exitCode, 1, 'first sighting of drift alerts');
  const second = await runDriftScan(args);
  assert.equal(second.exitCode, 0, 'unchanged drift on a second run is green');
  assert.equal(second.findings.length, 1, 'the drift is still detected and rendered');
});

test('update-baseline opens a PR with the regenerated Baseline + diff and does NOT upsert an issue', async () => {
  const prCalls = [];
  const up = statelessUpserter();
  const result = await runDriftScan({
    repoSlug: 'acme/site',
    baseline: BASELINE,
    updateBaseline: true,
    collectSnapshot: async () => SSO_OFF, // a real drift to bless away
    upsertIssue: up.upsertIssue,
    openBaselinePr: async (pr) => { prCalls.push(pr); return { url: 'https://x/pull/1' }; },
  });
  assert.equal(result.mode, 'update-baseline');
  assert.equal(prCalls.length, 1, 'exactly one PR opened');
  assert.equal(up.calls.length, 0, 're-bless never upserts the alert issue');

  const pr = prCalls[0];
  // The PR carries the regenerated Baseline (live state blessed) and the diff body.
  assert.deepEqual(pr.baseline.activePlugins.sort(), ['akismet'], 'live state is blessed');
  assert.match(pr.diff, /wp-saml-auth/, 'the diff shows the drift being blessed away');
  assert.equal(typeof pr.baselineJson, 'string', 'serialized Baseline for the commit');
  assert.match(pr.baselineJson, /"blessedAt"/);
});

test('update-baseline bootstrap (no prior Baseline) opens a PR with an empty/seed diff', async () => {
  const prCalls = [];
  const result = await runDriftScan({
    repoSlug: 'acme/site',
    baseline: null, // bootstrap
    updateBaseline: true,
    collectSnapshot: async () => CLEAN,
    upsertIssue: statelessUpserter().upsertIssue,
    openBaselinePr: async (pr) => { prCalls.push(pr); return { url: 'https://x/pull/2' }; },
  });
  assert.equal(result.mode, 'update-baseline');
  assert.equal(prCalls.length, 1);
  assert.match(prCalls[0].diff, /bootstrap|no prior baseline/i);
});
