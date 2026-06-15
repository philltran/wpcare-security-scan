// Finding differ / dedup — PURE. Alert only on the new/worsened subset.
//
//   diffFindings(priorFindings, currentFindings) -> [ Finding ]
//
// Fixture-driven, no network. A current Finding is in the subset when it is *new*
// (no prior Finding shares its identity) or *worsened* (a prior Finding shares its
// identity but the current severity outranks it). Identical Findings twice yield an
// empty subset — runs are idempotent and the gate stays green.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { diffFindings } from '../src/differ.mjs';

const cve = {
  type: 'cve', severity: 'high', slug: 'contact-form-7', version: '5.3.1',
  kind: 'plugin', location: 'wp-content/plugins/contact-form-7', fixed_in: '5.3.2',
  cve: 'CVE-2020-35489', url: 'https://example/x',
  remediation: 'Update contact-form-7 to 5.3.2 or later.',
};

test('identical Findings twice yield no new/worsened subset (idempotent)', () => {
  const subset = diffFindings([cve], [cve]);
  assert.deepEqual(subset, [], 'nothing new -> empty subset -> green run');
});

test('a brand-new Finding (no prior match) is in the subset', () => {
  const embedded = {
    type: 'embedded', severity: 'medium', slug: 'revslider', version: '4.6.0',
    kind: 'plugin', location: 'wp-content/themes/premium/revslider',
    remediation: 'Remove the embedded plugin.',
  };
  // Prior knew only the CVE; the embedded Finding is new this run.
  const subset = diffFindings([cve], [cve, embedded]);
  assert.equal(subset.length, 1);
  assert.equal(subset[0].slug, 'revslider');

  // First run ever (no prior state at all): every current Finding is new.
  assert.deepEqual(diffFindings([], [cve, embedded]), [cve, embedded]);
});

test('a severity increase on an existing Finding re-alerts; equal/lower does not', () => {
  const worse = { ...cve, severity: 'critical' }; // high -> critical: same identity
  const worsened = diffFindings([cve], [worse]);
  assert.equal(worsened.length, 1, 'a worsening re-alerts');
  assert.equal(worsened[0].severity, 'critical');

  // Same identity, severity unchanged: not in the subset (idempotent).
  assert.deepEqual(diffFindings([cve], [cve]), []);

  // Same identity, severity *dropped* (high -> medium): not an alert.
  const better = { ...cve, severity: 'medium' };
  assert.deepEqual(diffFindings([cve], [better]), []);
});

test('version is not part of identity — a still-vulnerable partial update does not re-alert', () => {
  // Same CVE/slug/location, only the installed version moved (5.3.1 -> 5.3.1.1),
  // still below fixed_in. Same unresolved Finding, no severity change => no alert.
  const bumped = { ...cve, version: '5.3.1.1' };
  assert.deepEqual(diffFindings([cve], [bumped]), []);
});

test('distinct CVEs against the same slug are distinct identities', () => {
  const otherCve = { ...cve, cve: 'CVE-2021-99999', severity: 'high' };
  // Prior knew the first CVE; the second is a genuinely new Finding for the same plugin.
  const subset = diffFindings([cve], [cve, otherCve]);
  assert.equal(subset.length, 1);
  assert.equal(subset[0].cve, 'CVE-2021-99999');
});
