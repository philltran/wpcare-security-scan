// Issue #13 — context-aware Embedded-plugin Finding severity.
//
// An Embedded plugin Finding defaults to `medium` (bundled, no update channel). But a
// bundled copy that *also* satisfies a known CVE is materially worse, so its severity
// escalates to the CVE's CVSS band when that band outranks the default. A bundled copy
// with no matching CVE keeps the `medium` default. Escalation reuses the #4
// CVSS->severity mapping and the `fixed_in` boundary logic — no parallel scheme.
//
// Pure module: no network, no filesystem. Boundary + escalation fixtures.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { matchVulnerabilities } from '../src/matcher.mjs';

// An embedded Slider Revolution bundled inside a premium theme (the real incident
// shape from ADR-0004), pinned at a version we can move across the `fixed_in` boundary.
function embeddedRevsliderAt(version) {
  return {
    slug: 'revslider', kind: 'plugin', version,
    path: '/site/wp-content/themes/premium-theme/revslider', embedded: true,
  };
}

// A CVE record for revslider, critical, fixed in 6.0.0.
const REVSLIDER_CRITICAL = {
  'revslider': [
    {
      affected_range: '* - 5.9.9',
      fixed_in: '6.0.0',
      cvss: 9.1,
      cve: 'CVE-REVSLIDER-CRIT',
      title: 'Slider Revolution < 6.0.0 - Arbitrary File Upload',
      url: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/revslider',
    },
  ],
};

test('escalation: an embedded copy matching a critical CVE escalates above the medium default', () => {
  const findings = matchVulnerabilities([embeddedRevsliderAt('4.6.0')], REVSLIDER_CRITICAL);

  const embedded = findings.find((f) => f.type === 'embedded');
  assert.ok(embedded, 'the embedded Finding is still emitted');
  assert.equal(
    embedded.severity,
    'critical',
    'the embedded Finding inherits the CVE severity, not a flat medium',
  );
});

test('escalation: an embedded copy with a HIGH CVE escalates to high', () => {
  const dataset = {
    'revslider': [{ ...REVSLIDER_CRITICAL.revslider[0], cvss: 7.5 }],
  };
  const findings = matchVulnerabilities([embeddedRevsliderAt('4.6.0')], dataset);
  const embedded = findings.find((f) => f.type === 'embedded');
  assert.equal(embedded.severity, 'high');
});

test('default: an embedded copy with NO matching CVE keeps the medium default', () => {
  const findings = matchVulnerabilities([embeddedRevsliderAt('4.6.0')], {});
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'embedded');
  assert.equal(findings[0].severity, 'medium');
});

test('boundary: an embedded copy AT/above fixed_in is not affected, keeps the medium default', () => {
  // 6.0.0 == fixed_in -> patched, no CVE satisfied -> the embedded Finding stays medium,
  // and no separate cve Finding is emitted.
  const findings = matchVulnerabilities([embeddedRevsliderAt('6.0.0')], REVSLIDER_CRITICAL);
  assert.equal(findings.length, 1, 'only the embedded Finding — the CVE is patched');
  assert.equal(findings[0].type, 'embedded');
  assert.equal(findings[0].severity, 'medium');
});

test('no de-escalation: an embedded copy matching a LOW CVE stays at the medium default', () => {
  // A low CVE (CVSS 2.x) ranks below the medium default. The embedded copy is never
  // *less* bad than a clean bundled copy, so its severity floors at medium.
  const dataset = {
    'revslider': [{ ...REVSLIDER_CRITICAL.revslider[0], cvss: 2.1 }],
  };
  const findings = matchVulnerabilities([embeddedRevsliderAt('4.6.0')], dataset);
  const embedded = findings.find((f) => f.type === 'embedded');
  assert.equal(embedded.severity, 'medium', 'a low CVE does not de-escalate below medium');
});

test('no de-escalation: an embedded copy matching an UNSCORED CVE stays at the medium default', () => {
  const dataset = {
    'revslider': [{ ...REVSLIDER_CRITICAL.revslider[0], cvss: null }],
  };
  const findings = matchVulnerabilities([embeddedRevsliderAt('4.6.0')], dataset);
  const embedded = findings.find((f) => f.type === 'embedded');
  assert.equal(embedded.severity, 'medium', 'an unknown-severity CVE does not de-escalate');
});

test('escalation: when several CVEs match, the embedded Finding takes the worst', () => {
  const dataset = {
    'revslider': [
      { affected_range: '* - 5.9.9', fixed_in: '6.0.0', cvss: 5.0, cve: 'CVE-MED' },
      { affected_range: '* - 5.9.9', fixed_in: '6.0.0', cvss: 9.8, cve: 'CVE-CRIT' },
      { affected_range: '* - 5.9.9', fixed_in: '6.0.0', cvss: 7.2, cve: 'CVE-HIGH' },
    ],
  };
  const findings = matchVulnerabilities([embeddedRevsliderAt('4.6.0')], dataset);
  const embedded = findings.find((f) => f.type === 'embedded');
  assert.equal(embedded.severity, 'critical', 'the worst matching CVE wins');
});

test('ordering: an escalated (critical) embedded Finding now sorts ABOVE a high CVE', () => {
  // Regression guard for the #4 most-severe-first ordering with the new severities.
  const dataset = {
    'revslider': [{ ...REVSLIDER_CRITICAL.revslider[0], cvss: 9.1 }],
    'other': [{ affected_range: '* - 1', fixed_in: '2', cvss: 7.5, cve: 'CVE-HIGH' }],
  };
  const inv = [
    { slug: 'other', kind: 'plugin', version: '1', path: '/p/other', embedded: false },
    embeddedRevsliderAt('4.6.0'),
  ];
  const findings = matchVulnerabilities(inv, dataset);
  // The escalated embedded (critical) leads; among the rest, the revslider CVE (critical)
  // and the embedded both outrank the high CVE.
  assert.equal(findings[0].severity, 'critical');
  assert.equal(findings[findings.length - 1].severity, 'high');
  // The embedded Finding is no longer pinned at medium between criticals and the high.
  const embedded = findings.find((f) => f.type === 'embedded');
  assert.equal(embedded.severity, 'critical');
});
