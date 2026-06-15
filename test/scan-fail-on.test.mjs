// Issue #9 — the `fail-on` severity threshold wired into the orchestrator.
//
// `fail-on` is the per-site knob the workflow sets to choose how loud the failing
// workflow status is. The deduped issue is ALWAYS updated in place with every current
// Finding regardless of `fail-on` (the report is complete) — `fail-on` only governs
// the failing *status* gate: the run fails iff at least one NEW or WORSENED alert-worthy
// Finding meets-or-exceeds the threshold severity.
//
//   - default ('low') preserves the prior contract: every new/worsened alert-worthy
//     Finding of a scored band low..critical trips the gate.
//   - raising the threshold (e.g. 'high') lets a fleet ratchet down noise: a new
//     medium-severity CVE is still filed in the issue but no longer fails the run.
//   - an UNSCORED CVE (severity 'unknown' — a CVE with no CVSS in the feed) always
//     meets any threshold: a security tool must not silently swallow a vuln it cannot
//     rank (fail-loud). Documented in ADR-0008.
//
// Pure-spine test: exercised through the public `runVulnScan` against the fixture tree
// with the feed and issue store injected — no live network or runner.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { runVulnScan } from '../src/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');

// A fresh stateless upserter per run: priorBody null => everything is "new", so the
// new/worsened subset is the full alert-worthy set and `fail-on` is the only variable.
function makeUpserter() {
  const calls = [];
  return {
    calls,
    async upsertIssue(args) { calls.push(args); return { number: 9, priorBody: null }; },
  };
}

// A raw Wordfence-feed record for contact-form-7 at a given CVSS score (or with the
// score field omitted entirely => severity 'unknown'). The orchestrator normalizes
// this raw shape before matching, exactly like the real feed.
function cf7Feed({ score } = {}) {
  const record = {
    id: 'CVE-2020-35489',
    cve: 'CVE-2020-35489',
    title: 'Contact Form 7 < 5.3.2',
    software: [{
      type: 'plugin',
      slug: 'contact-form-7',
      affected_versions: {
        '* - 5.3.1': { to_version: '5.3.2', to_inclusive: false },
      },
    }],
    references: ['https://example/x'],
  };
  if (score !== undefined) record.cvss = { score };
  return { 'CVE-2020-35489': record };
}

test('default fail-on (low): a new medium CVE + the medium embedded Finding fail the run', async () => {
  const upserter = makeUpserter();
  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    failOn: 'low',
    fetchFeed: async () => cf7Feed({ score: 5.0 }), // medium CVE
    upsertIssue: upserter.upsertIssue,
  });

  // The CVE (medium) and the embedded revslider (medium) are both new and both >= low.
  assert.ok(result.alertWorthy >= 2);
  assert.equal(result.exitCode, 1, 'a medium Finding trips the default low gate');
});

test('fail-on high: a new medium CVE is filed but does NOT fail the run', async () => {
  const upserter = makeUpserter();
  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    failOn: 'high',
    fetchFeed: async () => cf7Feed({ score: 5.0 }), // medium CVE, below the high bar
    upsertIssue: upserter.upsertIssue,
  });

  // Still detected and still filed in the deduped issue — the report is complete.
  assert.ok(
    result.findings.some((f) => f.type === 'cve' && f.slug === 'contact-form-7'),
    'the medium CVE is still detected',
  );
  assert.equal(upserter.calls.length, 1, 'the issue is upserted regardless of fail-on');
  assert.match(upserter.calls[0].body, /contact-form-7/, 'the medium CVE is still reported');

  // But nothing new/worsened meets the high threshold (CVE=medium, embedded=medium,
  // abandoned would be high but none here), so the failing status stays GREEN.
  assert.equal(result.exitCode, 0, 'a medium Finding does not trip the high gate');
});

test('fail-on critical: only a critical-or-worse new Finding fails the run', async () => {
  const upserter = makeUpserter();

  // A critical CVE (CVSS 9.8) against contact-form-7 => meets the critical bar.
  const crit = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site', failOn: 'critical',
    fetchFeed: async () => cf7Feed({ score: 9.8 }),
    upsertIssue: upserter.upsertIssue,
  });
  assert.equal(crit.exitCode, 1, 'a critical Finding trips the critical gate');

  // The same site with only a high CVE (CVSS 7.5) => below critical => GREEN.
  const high = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site', failOn: 'critical',
    fetchFeed: async () => cf7Feed({ score: 7.5 }),
    upsertIssue: makeUpserter().upsertIssue,
  });
  assert.equal(high.exitCode, 0, 'a high Finding does not trip the critical gate');
});

test('an UNSCORED CVE (severity unknown) fails even a high gate — fail loud, never swallow', async () => {
  const upserter = makeUpserter();
  const result = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site', failOn: 'high',
    fetchFeed: async () => cf7Feed({}), // no cvss => severity 'unknown'
    upsertIssue: upserter.upsertIssue,
  });

  const cve = result.findings.find((f) => f.type === 'cve' && f.slug === 'contact-form-7');
  assert.equal(cve.severity, 'unknown', 'an unscored CVE is severity unknown');
  assert.equal(result.exitCode, 1, 'an unscored CVE must fail even a high gate');
});

test('an unrecognized / missing fail-on falls back to the low default (no silent disarm)', async () => {
  const upserter = makeUpserter();

  // A garbage threshold must not disable the gate — it falls back to low.
  const result = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site', failOn: 'bogus',
    fetchFeed: async () => cf7Feed({ score: 5.0 }), // medium
    upsertIssue: upserter.upsertIssue,
  });
  assert.equal(result.exitCode, 1, 'a bogus threshold gates like low, not like off');

  // Omitting fail-on entirely also defaults to low.
  const omitted = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site',
    fetchFeed: async () => cf7Feed({ score: 5.0 }),
    upsertIssue: makeUpserter().upsertIssue,
  });
  assert.equal(omitted.exitCode, 1, 'a missing threshold defaults to low');
});
