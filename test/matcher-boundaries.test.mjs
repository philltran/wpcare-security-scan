// Issue #4 — vuln matcher hardening: version-range boundaries + CVSS severity.
//
// Exercises the matcher's public interface with boundary-case fixtures around
// `fixed_in` (just below / exactly at / just above), CVSS-to-severity mapping
// including missing/edge scores, and most-severe-first ordering of Findings. Pure
// module: no network, no filesystem.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { matchVulnerabilities } from '../src/matcher.mjs';

// A single CVE record fixed in 5.3.2, critical CVSS.
const CF7_DATASET = {
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

function cf7At(version) {
  return {
    slug: 'contact-form-7', kind: 'plugin', version,
    path: '/site/wp-content/plugins/contact-form-7', embedded: false,
  };
}

test('boundary: version just below fixed_in is a Finding', () => {
  const findings = matchVulnerabilities([cf7At('5.3.1')], CF7_DATASET);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'cve');
});

test('boundary: version exactly at fixed_in yields no Finding (patched)', () => {
  assert.deepEqual(matchVulnerabilities([cf7At('5.3.2')], CF7_DATASET), []);
});

test('boundary: version just above fixed_in yields no Finding', () => {
  assert.deepEqual(matchVulnerabilities([cf7At('5.3.3')], CF7_DATASET), []);
});

test('boundary: a far-newer major version yields no Finding', () => {
  assert.deepEqual(matchVulnerabilities([cf7At('6.0')], CF7_DATASET), []);
});

test('boundary: a multi-segment patch just below fixed_in still matches', () => {
  // 5.3.1.9 < 5.3.2 — extra trailing segments must not flip the comparison.
  const findings = matchVulnerabilities([cf7At('5.3.1.9')], CF7_DATASET);
  assert.equal(findings.length, 1);
});

test('CVSS mapping: each band maps to its severity word', () => {
  const bands = [
    [9.8, 'critical'],
    [9.0, 'critical'],
    [7.5, 'high'],
    [7.0, 'high'],
    [5.0, 'medium'],
    [4.0, 'medium'],
    [2.1, 'low'],
    [0.1, 'low'],
  ];
  for (const [score, expected] of bands) {
    const dataset = {
      'contact-form-7': [{ ...CF7_DATASET['contact-form-7'][0], cvss: score }],
    };
    const [f] = matchVulnerabilities([cf7At('5.3.1')], dataset);
    assert.equal(f.severity, expected, `CVSS ${score} -> ${expected}`);
  }
});

test('CVSS mapping: a missing/non-numeric score maps to unknown', () => {
  for (const bad of [null, undefined, 'n/a', NaN]) {
    const dataset = {
      'contact-form-7': [{ ...CF7_DATASET['contact-form-7'][0], cvss: bad }],
    };
    const [f] = matchVulnerabilities([cf7At('5.3.1')], dataset);
    assert.equal(f.severity, 'unknown', `CVSS ${String(bad)} -> unknown`);
  }
});

test('ordering: Findings come back most-severe-first', () => {
  const dataset = {
    low: [{ affected_range: '* - 1', fixed_in: '2', cvss: 2.0, cve: 'CVE-LOW' }],
    crit: [{ affected_range: '* - 1', fixed_in: '2', cvss: 9.9, cve: 'CVE-CRIT' }],
    med: [{ affected_range: '* - 1', fixed_in: '2', cvss: 5.0, cve: 'CVE-MED' }],
    high: [{ affected_range: '* - 1', fixed_in: '2', cvss: 8.0, cve: 'CVE-HIGH' }],
  };
  const inv = ['low', 'crit', 'med', 'high'].map((slug) => ({
    slug, kind: 'plugin', version: '1', path: `/p/${slug}`, embedded: false,
  }));

  const findings = matchVulnerabilities(inv, dataset);
  assert.deepEqual(
    findings.map((f) => f.severity),
    ['critical', 'high', 'medium', 'low'],
  );
});

test('ordering: an embedded (medium) Finding sorts among CVE Findings by severity', () => {
  const dataset = {
    crit: [{ affected_range: '* - 1', fixed_in: '2', cvss: 9.9, cve: 'CVE-CRIT' }],
    low: [{ affected_range: '* - 1', fixed_in: '2', cvss: 2.0, cve: 'CVE-LOW' }],
  };
  const inv = [
    { slug: 'low', kind: 'plugin', version: '1', path: '/p/low', embedded: false },
    { slug: 'revslider', kind: 'plugin', version: '4.6.0', path: '/t/x/revslider', embedded: true },
    { slug: 'crit', kind: 'plugin', version: '1', path: '/p/crit', embedded: false },
  ];

  const findings = matchVulnerabilities(inv, dataset);
  // critical CVE, then the medium embedded, then the low CVE.
  assert.deepEqual(
    findings.map((f) => [f.type, f.severity]),
    [['cve', 'critical'], ['embedded', 'medium'], ['cve', 'low']],
  );
});

test('ordering: unknown-severity Findings sort last, after low', () => {
  const dataset = {
    unk: [{ affected_range: '* - 1', fixed_in: '2', cvss: null, cve: 'CVE-UNK' }],
    low: [{ affected_range: '* - 1', fixed_in: '2', cvss: 2.0, cve: 'CVE-LOW' }],
  };
  const inv = ['unk', 'low'].map((slug) => ({
    slug, kind: 'plugin', version: '1', path: `/p/${slug}`, embedded: false,
  }));

  const findings = matchVulnerabilities(inv, dataset);
  assert.deepEqual(findings.map((f) => f.severity), ['low', 'unknown']);
});
