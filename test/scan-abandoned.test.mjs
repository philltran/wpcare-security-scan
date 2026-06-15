// Issue #5 — Abandoned detection wired end-to-end through the orchestrator.
//
// The per-slug wordpress.org lookup is an INJECTED impure edge (like fetchFeed), so
// the whole path — enumerate -> feed match -> abandoned lookup -> Findings -> one
// upserted issue -> gate — is exercised against a fixture tree with NO live network.
// The recorded wp.org responses are supplied by the injected fetchPluginInfo stub.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { runVulnScan } from '../src/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');
const FEED = JSON.parse(
  readFileSync(join(here, 'fixtures', 'wordfence-feed-slice.json'), 'utf8'),
);

function makeUpserter() {
  const calls = [];
  return {
    calls,
    async upsertIssue(args) { calls.push(args); return { number: 7 }; },
  };
}

// Recorded wp.org responses keyed by slug: akismet is closed, everything else is live.
function makeWporgStub(closedSlugs) {
  const closed = new Set(closedSlugs);
  const queried = [];
  return {
    queried,
    async fetchPluginInfo(slug) {
      queried.push(slug);
      if (closed.has(slug)) {
        return { statusCode: 200, body: { error: 'closed', slug, closed: true } };
      }
      return { statusCode: 200, body: { name: slug, slug, version: '1.0' } };
    },
  };
}

test('end-to-end: a closed plugin surfaces an Abandoned Finding (remediation = remove)', async () => {
  const upserter = makeUpserter();
  const wporg = makeWporgStub(['akismet']);

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    fetchPluginInfo: wporg.fetchPluginInfo,
    upsertIssue: upserter.upsertIssue,
  });

  const abandoned = result.findings.filter((f) => f.type === 'abandoned');
  assert.equal(abandoned.length, 1, 'exactly the closed plugin is abandoned');
  assert.equal(abandoned[0].slug, 'akismet');
  assert.match(abandoned[0].remediation, /remov/i);
  assert.doesNotMatch(abandoned[0].remediation, /update/i);

  // It is alert-worthy and lands in the one upserted issue + trips the gate.
  assert.equal(upserter.calls.length, 1);
  assert.match(upserter.calls[0].body, /akismet/);
  assert.equal(result.exitCode, 1);
});

test('only top-level plugin slugs are looked up — not core/themes/embedded', async () => {
  const upserter = makeUpserter();
  const wporg = makeWporgStub([]);

  await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    fetchPluginInfo: wporg.fetchPluginInfo,
    upsertIssue: upserter.upsertIssue,
  });

  // The fixture tree's top-level plugins get queried; core/themes/drop-ins do not,
  // and an embedded plugin (revslider) is handled by the embedded detector, not here.
  assert.ok(wporg.queried.includes('akismet'));
  assert.ok(wporg.queried.includes('contact-form-7'));
  assert.ok(!wporg.queried.includes('wordpress'), 'core is not a wp.org plugin lookup');
  assert.ok(!wporg.queried.includes('twentytwenty'), 'themes are not plugin lookups');
  assert.ok(!wporg.queried.includes('revslider'), 'embedded plugins are not re-queried');
});

test('a flaky wp.org lookup (rejection) never fires a false Abandoned alert', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    fetchPluginInfo: async () => { throw new Error('network blip'); },
    upsertIssue: upserter.upsertIssue,
  });

  assert.equal(
    result.findings.filter((f) => f.type === 'abandoned').length,
    0,
    'a lookup failure yields no abandoned Finding',
  );
  // The rest of the scan (CVE + embedded) still completes.
  assert.ok(result.findings.some((f) => f.type === 'cve'));
});

test('detection is skipped cleanly when no fetchPluginInfo is injected', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    // no fetchPluginInfo
    upsertIssue: upserter.upsertIssue,
  });

  assert.equal(result.findings.filter((f) => f.type === 'abandoned').length, 0);
});
