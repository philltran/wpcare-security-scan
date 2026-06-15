// Issue #7 — the optional WPScan cross-reference, exercised through the orchestrator.
//
// Proves the two halves of the acceptance criteria at the seam:
//   1. No token (no fetchWpscanData injected) => behavior is UNCHANGED, zero secrets.
//   2. A token (fetchWpscanData injected) => WPScan data is cross-referenced through the
//      SAME matcher and can contribute additional Findings the Wordfence feed missed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { runVulnScan } from '../src/scan.mjs';
import { normalizeWpscanResponse } from '../src/wpscan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');
const FEED = JSON.parse(
  readFileSync(join(here, 'fixtures', 'wordfence-feed-slice.json'), 'utf8'),
);
const fixture = (name) =>
  JSON.parse(readFileSync(join(here, 'fixtures', 'wpscan', name), 'utf8'));

function makeUpserter() {
  const calls = [];
  return {
    calls,
    async upsertIssue(args) { calls.push(args); return { number: 42 }; },
  };
}

test('zero-secret default: with NO fetchWpscanData injected, the scan runs exactly as before', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    upsertIssue: upserter.upsertIssue,
    // no fetchWpscanData — the zero-secret path
  });

  // Identical to the established baseline: the one Wordfence CVE + the embedded revslider.
  const cve = result.findings.filter((f) => f.type === 'cve');
  assert.equal(cve.length, 1);
  assert.equal(cve[0].slug, 'contact-form-7');
  assert.equal(cve[0].cve, 'CVE-2020-35489');
  // No WPScan-only Finding appears when the edge is absent.
  assert.ok(!result.findings.some((f) => String(f.cve).startsWith('WPSCAN-')));
});

test('with a token: a WPScan-only CVE (no Wordfence record) becomes an additional Finding via the same matcher', async () => {
  const upserter = makeUpserter();

  // contact-form-7 is at 5.3.1 in the fixture site; WPScan also reports the < 5.4 XSS
  // (no CVE) which Wordfence's slice does not cover.
  const fetchWpscanData = async (slug) =>
    slug === 'contact-form-7' ? normalizeWpscanResponse(fixture('contact-form-7.json')) : {};

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    upsertIssue: upserter.upsertIssue,
    fetchWpscanData,
  });

  const cf7Cves = result.findings.filter(
    (f) => f.type === 'cve' && f.slug === 'contact-form-7',
  );
  // Two now: the shared CVE (Wordfence record kept) + the WPScan-only < 5.4 XSS.
  assert.equal(cf7Cves.length, 2, 'WPScan adds the Finding Wordfence missed');

  const shared = cf7Cves.find((f) => f.cve === 'CVE-2020-35489');
  assert.match(shared.url, /wordfence\.com/, 'shared CVE stays the Wordfence record');

  const wpscanOnly = cf7Cves.find((f) => String(f.cve).startsWith('WPSCAN-'));
  assert.ok(wpscanOnly, 'the no-CVE WPScan vuln surfaces as a Finding');
  assert.equal(wpscanOnly.fixed_in, '5.4');
  assert.equal(wpscanOnly.severity, 'unknown', 'no cvss => unknown severity (matcher default)');
  assert.match(wpscanOnly.url, /wpscan\.com/);
});

test('a flaky WPScan edge (rejection) never aborts the run — Wordfence findings still stand', async () => {
  const upserter = makeUpserter();

  const fetchWpscanData = async () => { throw new Error('429 rate limited'); };

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    upsertIssue: upserter.upsertIssue,
    fetchWpscanData,
  });

  // Unchanged from the zero-secret baseline — the cross-reference fails safe.
  const cve = result.findings.filter((f) => f.type === 'cve');
  assert.equal(cve.length, 1);
  assert.equal(cve[0].cve, 'CVE-2020-35489');
  assert.equal(upserter.calls.length, 1);
});
