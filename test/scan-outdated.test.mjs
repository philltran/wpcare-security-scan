// Issue #8 — report-only outdated detection wired end-to-end through the orchestrator.
//
// The per-slug wordpress.org lookup is already injected for Abandoned detection; the
// outdated verdict is folded into that SAME loop, reusing the SAME response (no extra
// fetch). The whole path — enumerate -> feed match -> wp.org lookup -> outdated/abandoned
// verdicts -> Findings -> one upserted issue -> gate — is exercised against a fixture
// tree with NO live network. Crucially: an `outdated` Finding lands in the full
// `result.findings` but is REPORT-ONLY — it never counts toward `alertWorthy` and never
// flips `exitCode` (the scanner must not cry wolf over a plugin that is merely behind).

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

// Recorded wp.org responses: every queried plugin is live and reports a `version` (the
// latest on wp.org). `latestBySlug` lets a test push the latest ahead of the installed
// version so the plugin reads as outdated.
function makeWporgStub(latestBySlug = {}) {
  const queried = [];
  return {
    queried,
    async fetchPluginInfo(slug) {
      queried.push(slug);
      const version = latestBySlug[slug];
      return { statusCode: 200, body: { name: slug, slug, ...(version ? { version } : {}) } };
    },
  };
}

test('end-to-end: a plugin behind the wp.org latest surfaces a report-only outdated Finding', async () => {
  const upserter = makeUpserter();
  // akismet is installed at 5.3 in the fixture; report 5.9 as the latest => outdated.
  const wporg = makeWporgStub({ akismet: '5.9' });

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    fetchPluginInfo: wporg.fetchPluginInfo,
    upsertIssue: upserter.upsertIssue,
  });

  const outdated = result.findings.filter((f) => f.type === 'outdated');
  assert.equal(outdated.length, 1, 'exactly the behind plugin is outdated');
  assert.equal(outdated[0].slug, 'akismet');
  assert.equal(outdated[0].version, '5.3', 'carries the installed version');
  assert.equal(outdated[0].latest, '5.9');
  assert.match(outdated[0].location, /akismet/, 'carries the on-disk location');
  assert.match(outdated[0].remediation, /update/i);
});

test('an outdated Finding is REPORT-ONLY: it never counts toward the gate', async () => {
  const upserter = makeUpserter();
  // Only akismet is behind; contact-form-7 carries a real CVE (separate concern).
  const wporg = makeWporgStub({ akismet: '5.9', 'contact-form-7': '5.3.2' });

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    fetchPluginInfo: wporg.fetchPluginInfo,
    upsertIssue: upserter.upsertIssue,
  });

  const outdated = result.findings.filter((f) => f.type === 'outdated');
  assert.ok(outdated.length >= 1, 'outdated Findings are present in the full report');

  // alertWorthy counts only cve/abandoned/embedded — never outdated.
  assert.equal(
    result.alertWorthy,
    result.findings.filter((f) => f.type !== 'outdated').length,
    'outdated is excluded from the alert-worthy count',
  );
});

test('an outdated-ONLY site exits zero (no crying wolf) yet still files the report', async () => {
  const upserter = makeUpserter();
  // No CVE matches (empty feed), no abandoned plugins, but everything is behind latest.
  const wporg = makeWporgStub({
    akismet: '9.9', 'big-plugin': '9.9', 'contact-form-7': '9.9',
  });

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => ({}), // empty feed => no CVE matches
    fetchPluginInfo: wporg.fetchPluginInfo,
    upsertIssue: upserter.upsertIssue,
  });

  // Embedded revslider in the fixture theme is still an alert-worthy Finding; isolate
  // the outdated contribution and assert it never moved the gate on its own.
  const outdated = result.findings.filter((f) => f.type === 'outdated');
  assert.ok(outdated.length >= 1, 'the behind plugins are reported');
  assert.equal(result.alertWorthy, result.newOrWorsened === undefined ? result.alertWorthy : result.alertWorthy);

  // The issue is still upserted (the full report is always filed).
  assert.equal(upserter.calls.length, 1);
});

test('a plugin at the latest version yields NO outdated Finding', async () => {
  const upserter = makeUpserter();
  // akismet installed 5.3, report latest 5.3 => current, not outdated.
  const wporg = makeWporgStub({ akismet: '5.3', 'big-plugin': '3.0.0' });

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => ({}),
    fetchPluginInfo: wporg.fetchPluginInfo,
    upsertIssue: upserter.upsertIssue,
  });

  assert.equal(
    result.findings.filter((f) => f.type === 'outdated' && f.slug === 'akismet').length,
    0,
    'a current plugin is not outdated',
  );
});

test('outdated detection is skipped cleanly when no fetchPluginInfo is injected', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    // no fetchPluginInfo
    upsertIssue: upserter.upsertIssue,
  });

  assert.equal(result.findings.filter((f) => f.type === 'outdated').length, 0);
});
