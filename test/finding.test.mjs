// Issue #11 — the shared alert-worthy predicate that unifies vuln + drift Findings.
//
// Vuln-mode alert-worthy types (cve/abandoned/embedded) live in the matcher's
// ALERT_WORTHY set; drift types (security-control-disabled/unexpected-admin/
// changed-option) live in drift.mjs's isDriftFinding. The reporter must treat BOTH as
// alert-worthy so a drift Finding is persisted in the issue state block (and so dedups
// across runs — alert only on new/worsened) and counted in the title. This predicate
// is the single union the reporter uses; the vuln matcher's own contract is unchanged.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { isAlertWorthyFinding } from '../src/finding.mjs';

test('vuln alert-worthy types remain alert-worthy', () => {
  for (const type of ['cve', 'abandoned', 'embedded']) {
    assert.equal(isAlertWorthyFinding({ type }), true, type);
  }
});

test('drift types are alert-worthy through the shared predicate', () => {
  for (const type of ['security-control-disabled', 'unexpected-admin', 'changed-option']) {
    assert.equal(isAlertWorthyFinding({ type }), true, type);
  }
});

test('report-only and garbage are not alert-worthy', () => {
  assert.equal(isAlertWorthyFinding({ type: 'outdated' }), false);
  assert.equal(isAlertWorthyFinding(null), false);
  assert.equal(isAlertWorthyFinding({}), false);
});
