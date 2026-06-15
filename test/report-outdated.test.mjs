// Issue #8 — the full report renders every detected item, including report-only
// outdated, while the title + persisted state stay ALERT-worthy only.
//
// AC: "The report lists every detected item, including report-only outdated-no-CVE
// entries" and "Outdated-no-CVE Findings appear in the report but never trigger the
// failing workflow status." The failing status is gated elsewhere (scan.mjs via the
// differ over alert-worthy Findings); here we pin the *rendering* contract:
//   - the body shows alert-worthy Findings AND report-only outdated Findings,
//   - the persisted state block (which the differ reads back) carries ONLY the
//     alert-worthy Findings, so an outdated item can never be diffed into an alert,
//   - the title counts ONLY the alert-worthy Findings (outdated is not "alert-worthy").

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  renderIssueTitle,
  renderIssueBody,
  parsePersistedFindings,
} from '../src/report.mjs';
import { isAlertWorthy } from '../src/matcher.mjs';

const cve = {
  type: 'cve', severity: 'critical', slug: 'contact-form-7', version: '5.3.1',
  kind: 'plugin', location: 'wp-content/plugins/contact-form-7', fixed_in: '5.3.2',
  cve: 'CVE-2020-35489', url: 'https://www.wordfence.com/x',
  remediation: 'Update contact-form-7 to 5.3.2 or later.',
};

const outdated = {
  type: 'outdated', severity: 'none', slug: 'akismet', version: '5.1',
  kind: 'plugin', location: 'wp-content/plugins/akismet', latest: '5.9',
  remediation: 'Update akismet from 5.1 to 5.9 (the latest on wordpress.org). Report-only.',
};

test('the full report renders both the alert-worthy CVE and the report-only outdated item', () => {
  const body = renderIssueBody('acme/site', [cve, outdated]);
  assert.match(body, /contact-form-7/, 'the CVE is shown');
  assert.match(body, /akismet/, 'the report-only outdated item is shown too');
  assert.match(body, /OUTDATED/i, 'the outdated Finding is labeled');
  // The outdated item names its update target and reads as report-only.
  assert.match(body, /5\.9/);
  assert.match(body, /report-only/i, 'the section is flagged as non-alerting');
});

test('the persisted state block carries ONLY alert-worthy Findings, never outdated', () => {
  const body = renderIssueBody('acme/site', [cve, outdated]);
  const restored = parsePersistedFindings(body);
  assert.equal(restored.length, 1, 'only the alert-worthy Finding is persisted');
  assert.equal(restored[0].type, 'cve');
  assert.ok(
    !restored.some((f) => f.type === 'outdated'),
    'an outdated Finding can never be diffed back into an alert',
  );
});

test('the title counts only alert-worthy Findings — outdated is excluded', () => {
  // Two Findings in, but only one is alert-worthy, so the headline says 1.
  const title = renderIssueTitle([cve, outdated].filter(isAlertWorthy));
  assert.match(title, /\b1\b/);
});

test('a report-only-outdated-only run still renders the items but persists an empty state', () => {
  const body = renderIssueBody('acme/site', [outdated]);
  assert.match(body, /akismet/, 'the outdated item is in the full report');
  // No alert-worthy Findings => the persisted state (what the differ reads) is empty,
  // so the failing-status gate stays green even though the report is non-empty.
  assert.deepEqual(parsePersistedFindings(body), []);
});

test('backward compatible: an all-alert-worthy list round-trips exactly as before', () => {
  const body = renderIssueBody('acme/site', [cve]);
  const restored = parsePersistedFindings(body);
  assert.equal(restored.length, 1);
  assert.equal(restored[0].cve, 'CVE-2020-35489');
  assert.match(body, /contact-form-7/);
});
