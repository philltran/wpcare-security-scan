// WPScan cross-reference (issue #7) — the PURE normalization half.
//
// The live WPScan call is a thin impure edge (src/wpscan.mjs, mirroring src/feed.mjs
// and src/wporg.mjs) verified by recorded fixtures, not a live unit test. This module
// is the PURE part: a per-slug WPScan plugin response -> the SAME dataset shape the
// Wordfence normalizer produces, so it flows through the one shared matcher. Pinned by
// fixtures under test/fixtures/wpscan/, no network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  normalizeWpscanResponse,
  mergeDatasets,
  wpscanPluginUrl,
  WPSCAN_PLUGIN_BASE_URL,
} from '../src/wpscan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) =>
  JSON.parse(readFileSync(join(here, 'fixtures', 'wpscan', name), 'utf8'));

test('normalizes a WPScan plugin response to { slug -> [vuln records] }', () => {
  const bySlug = normalizeWpscanResponse(fixture('contact-form-7.json'));

  const records = bySlug['contact-form-7'];
  assert.ok(Array.isArray(records), 'keyed by plugin slug');
  assert.equal(records.length, 2, 'one record per vulnerability');
});

test('a WPScan vuln carrying a CVE surfaces a normalized CVE id', () => {
  const bySlug = normalizeWpscanResponse(fixture('contact-form-7.json'));
  const withCve = bySlug['contact-form-7'].find((r) => r.fixed_in === '5.3.2');

  assert.equal(withCve.cve, 'CVE-2020-35489', 'bare CVE number is prefixed CVE-');
  assert.equal(withCve.fixed_in, '5.3.2');
  assert.equal(withCve.cvss, '9.8', 'cvss score carried through for severity mapping');
  assert.match(withCve.url, /wpscan\.com/);
  assert.match(withCve.title, /Unrestricted File Upload/);
  assert.equal(withCve.affected_range, null, 'WPScan has no affected_range — below fixed_in is affected');
});

test('a WPScan vuln with no CVE carries a stable WPSCAN-<id> reference in the cve slot', () => {
  const bySlug = normalizeWpscanResponse(fixture('contact-form-7.json'));
  const noCve = bySlug['contact-form-7'].find((r) => r.fixed_in === '5.4');

  assert.equal(
    noCve.cve,
    'WPSCAN-a1b2c3d4-5678-90ab-cdef-000000000002',
    'no-CVE WPScan vuln keeps a stable non-CVE identity from the vuln id',
  );
  assert.equal(noCve.fixed_in, '5.4');
});

test('a WPScan vuln with no cvss maps to an unknown-severity record (null cvss)', () => {
  const bySlug = normalizeWpscanResponse(fixture('contact-form-7.json'));
  const noCvss = bySlug['contact-form-7'].find((r) => r.fixed_in === '5.4');
  assert.equal(noCvss.cvss, null, 'absent cvss => null (matcher maps to unknown)');
});

// The normalizers/merge return null-prototype maps (slugs are external and may collide
// with Object.prototype members; see src/wordfence.mjs). assert/strict's deepEqual checks
// prototypes, so spread to a plain object before comparing to {}.
test('a not-found / error response normalizes to an empty dataset (fail-safe)', () => {
  assert.deepEqual({ ...normalizeWpscanResponse(fixture('not-found.json')) }, {});
});

test('a null / garbage response normalizes to an empty dataset', () => {
  assert.deepEqual({ ...normalizeWpscanResponse(null) }, {});
  assert.deepEqual({ ...normalizeWpscanResponse('nope') }, {});
  assert.deepEqual({ ...normalizeWpscanResponse({}) }, {});
});

// --- the cross-source merge (maintainer decision: dedup by CVE, Wordfence wins;
//     ADD no-CVE WPScan entries keyed by WPSCAN-<id>) ---

const WORDFENCE_DS = {
  'contact-form-7': [
    {
      affected_range: '* - 5.3.1',
      fixed_in: '5.3.2',
      cvss: 9.8,
      cve: 'CVE-2020-35489',
      title: 'Contact Form 7 < 5.3.2 - Unrestricted File Upload',
      url: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/contact-form-7',
    },
  ],
};

test('merge: a CVE both sources cover keeps the Wordfence record (authoritative), drops the WPScan dup', () => {
  const wpscan = normalizeWpscanResponse(fixture('contact-form-7.json'));
  const merged = mergeDatasets(WORDFENCE_DS, wpscan);

  const cf7 = merged['contact-form-7'];
  const sameCve = cf7.filter((r) => r.cve === 'CVE-2020-35489');
  assert.equal(sameCve.length, 1, 'the shared CVE is present exactly once');
  assert.match(sameCve[0].url, /wordfence\.com/, 'and it is the Wordfence record');
});

test('merge: a no-CVE WPScan vuln is ADDED (a Finding Wordfence missed), keyed by WPSCAN-<id>', () => {
  const wpscan = normalizeWpscanResponse(fixture('contact-form-7.json'));
  const merged = mergeDatasets(WORDFENCE_DS, wpscan);

  const added = merged['contact-form-7'].find(
    (r) => r.cve === 'WPSCAN-a1b2c3d4-5678-90ab-cdef-000000000002',
  );
  assert.ok(added, 'the WPScan-only vuln is carried into the merged dataset');
  assert.equal(added.fixed_in, '5.4');
});

test('merge: a slug only WPScan knows about is added wholesale', () => {
  const wpscan = normalizeWpscanResponse(fixture('wpscan-only-plugin.json'));
  const merged = mergeDatasets(WORDFENCE_DS, wpscan);

  const niche = merged['some-niche-plugin'];
  assert.ok(Array.isArray(niche) && niche.length === 1, 'new slug folded in');
  assert.match(niche[0].cve, /^WPSCAN-/, 'its no-CVE vuln keeps the WPScan reference');
});

test('merge: an empty WPScan dataset returns the Wordfence dataset unchanged', () => {
  const merged = mergeDatasets(WORDFENCE_DS, {});
  assert.deepEqual({ ...merged }, WORDFENCE_DS);
});

test('merge: a missing Wordfence dataset still yields the WPScan entries', () => {
  const wpscan = normalizeWpscanResponse(fixture('wpscan-only-plugin.json'));
  const merged = mergeDatasets(undefined, wpscan);
  assert.ok(Array.isArray(merged['some-niche-plugin']));
});

test('merge: does not mutate the input Wordfence dataset', () => {
  const before = WORDFENCE_DS['contact-form-7'].length;
  const wpscan = normalizeWpscanResponse(fixture('contact-form-7.json'));
  mergeDatasets(WORDFENCE_DS, wpscan);
  assert.equal(WORDFENCE_DS['contact-form-7'].length, before, 'inputs untouched');
});

test('builds the per-slug WPScan plugin URL', () => {
  const url = wpscanPluginUrl('contact-form-7');
  assert.ok(url.startsWith(WPSCAN_PLUGIN_BASE_URL));
  assert.match(url, /\/contact-form-7$/);
});

test('encodes an odd slug so it cannot traverse the WPScan path', () => {
  const url = wpscanPluginUrl('../../etc/passwd');
  const parsed = new URL(url);
  // The hostile string is percent-encoded into a single path segment, not a traversal.
  assert.equal(parsed.hostname, 'wpscan.com');
  assert.doesNotMatch(parsed.pathname, /\/etc\/passwd$/);
  assert.match(parsed.pathname, /%2F/i);
});
