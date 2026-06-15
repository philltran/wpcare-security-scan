import { test } from 'node:test';
import assert from 'node:assert/strict';

import { matchVulnerabilities, isAlertWorthy } from '../src/matcher.mjs';

const DATASET = {
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

const cf7 = {
  slug: 'contact-form-7', kind: 'plugin', version: '5.3.1',
  path: '/site/wp-content/plugins/contact-form-7', embedded: false,
};
const akismet = {
  slug: 'akismet', kind: 'plugin', version: '5.3',
  path: '/site/wp-content/plugins/akismet', embedded: false,
};

test('emits one Known CVE Finding for a vulnerable inventory item', () => {
  const findings = matchVulnerabilities([cf7, akismet], DATASET);

  assert.equal(findings.length, 1, 'only the vulnerable plugin matches');
  const f = findings[0];
  assert.equal(f.type, 'cve');
  assert.equal(f.slug, 'contact-form-7');
  assert.equal(f.version, '5.3.1');
  assert.equal(f.kind, 'plugin');
  assert.equal(f.fixed_in, '5.3.2');
  assert.equal(f.cve, 'CVE-2020-35489');
  assert.equal(f.severity, 'critical');
  assert.equal(f.location, '/site/wp-content/plugins/contact-form-7');
  assert.match(f.url, /wordfence\.com/);
  assert.match(f.remediation, /5\.3\.2/);
});

test('does not match a version at or above fixed_in', () => {
  const patched = { ...cf7, version: '5.3.2' };
  assert.deepEqual(matchVulnerabilities([patched], DATASET), []);

  const newer = { ...cf7, version: '6.0' };
  assert.deepEqual(matchVulnerabilities([newer], DATASET), []);
});

test('a CVE Finding is alert-worthy', () => {
  const [f] = matchVulnerabilities([cf7], DATASET);
  assert.equal(isAlertWorthy(f), true);
});
