import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ISSUE_LABEL,
  markerFor,
  renderIssueTitle,
  renderIssueBody,
  findMarkedIssue,
} from '../src/report.mjs';

const finding = {
  type: 'cve', severity: 'critical', slug: 'contact-form-7', version: '5.3.1',
  kind: 'plugin', location: 'wp-content/plugins/contact-form-7', fixed_in: '5.3.2',
  cve: 'CVE-2020-35489', url: 'https://www.wordfence.com/x',
  remediation: 'Update contact-form-7 to 5.3.2 or later.',
};

test('renders a stable hidden marker keyed to the site repo', () => {
  const m = markerFor('acme/site');
  assert.equal(m, markerFor('acme/site'), 'marker is deterministic per repo');
  assert.notEqual(m, markerFor('acme/other'), 'marker differs per repo');
  assert.match(m, /^<!--/, 'marker is an HTML comment so it stays hidden');
});

test('the rendered body embeds the marker and the Finding detail', () => {
  const body = renderIssueBody('acme/site', [finding]);
  assert.ok(body.includes(markerFor('acme/site')), 'body carries the dedup marker');
  assert.match(body, /contact-form-7/);
  assert.match(body, /CVE-2020-35489/);
  assert.match(body, /5\.3\.2/);
  assert.match(body, /critical/i);
});

test('the title summarizes the alert-worthy count', () => {
  assert.match(renderIssueTitle([finding]), /1/);
});

test('findMarkedIssue locates the one issue carrying the marker', () => {
  const marker = markerFor('acme/site');
  const issues = [
    { number: 1, body: 'unrelated' },
    { number: 7, body: `intro\n${marker}\nmore` },
  ];
  assert.equal(findMarkedIssue(issues, marker).number, 7);
  assert.equal(findMarkedIssue([], marker), null);
});

test('exposes a stable label for dedup', () => {
  assert.equal(typeof ISSUE_LABEL, 'string');
  assert.ok(ISSUE_LABEL.length > 0);
});
