// Issue #11 — `mode: both` merges Vulnerability Scan + Drift Detection Findings into
// ONE deduped per-site issue and finalizes once (no double upsert, no clobbered state
// block). Exercised offline with the feed, the collector, and the upserter injected.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { runCombinedScan } from '../src/combined.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');

const BASELINE = {
  version: 1,
  activePlugins: ['wp-saml-auth'],
  activeThemes: ['twentytwentyfour'],
  administrators: ['site-admin'],
  criticalOptions: { users_can_register: '0' },
};

// wp-saml-auth deactivated => one drift Finding alongside the fixture's vuln Findings.
const DRIFTED_SNAPSHOT = {
  activePlugins: ['akismet'],
  activeThemes: ['twentytwentyfour'],
  administrators: ['site-admin'],
  criticalOptions: { users_can_register: '0' },
};

function cf7Feed(score) {
  return {
    'CVE-2020-35489': {
      id: 'CVE-2020-35489', cve: 'CVE-2020-35489', title: 'CF7',
      software: [{
        type: 'plugin', slug: 'contact-form-7',
        affected_versions: { '* - 5.3.1': { to_version: '5.3.2', to_inclusive: false } },
      }],
      cvss: { score }, references: ['https://x'],
    },
  };
}

function statelessUpserter() {
  const calls = [];
  return {
    calls,
    async upsertIssue(args) { calls.push(args); return { number: 11, priorBody: null }; },
  };
}

test('both mode reports vuln AND drift Findings in a single deduped issue', async () => {
  const up = statelessUpserter();
  const result = await runCombinedScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    baseline: BASELINE,
    fetchFeed: async () => cf7Feed(9.8),
    collectSnapshot: async () => DRIFTED_SNAPSHOT,
    upsertIssue: up.upsertIssue,
  });

  assert.equal(result.mode, 'both');
  assert.equal(up.calls.length, 1, 'exactly ONE issue upsert for both modes combined');

  const body = up.calls[0].body;
  assert.match(body, /contact-form-7/, 'the vuln Finding is in the combined issue');
  assert.match(body, /wp-saml-auth/, 'the drift Finding is in the combined issue');

  assert.ok(result.findings.some((f) => f.type === 'cve'), 'a vuln Finding is present');
  assert.ok(
    result.findings.some((f) => f.type === 'security-control-disabled'),
    'a drift Finding is present',
  );
  assert.equal(result.exitCode, 1, 'new combined Findings fail the run');
});

test('both mode fails LOUDLY when the collector errors (vuln work is not reported half-done)', async () => {
  const up = statelessUpserter();
  await assert.rejects(
    () => runCombinedScan({
      siteRoot: SITE,
      repoSlug: 'acme/site',
      baseline: BASELINE,
      fetchFeed: async () => cf7Feed(9.8),
      collectSnapshot: async () => { throw new Error('terminus auth rejected'); },
      upsertIssue: up.upsertIssue,
    }),
    /terminus auth rejected|collector/i,
  );
  assert.equal(up.calls.length, 0, 'no partial issue is filed when drift cannot be read');
});
