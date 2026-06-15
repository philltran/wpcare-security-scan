// Issue #6 — the Finding differ wired into the orchestrator (the impure edge).
//
// The deduped issue is the persistence layer: each run reads the prior Findings out
// of the existing issue body, diffs them against the current scan, updates the issue
// in place, and gates the failing workflow status on ONLY the new/worsened subset.
// So a second run over an unchanged site is GREEN even though the (unchanged) Finding
// is still present and still rendered in the issue.
//
// The injected upsertIssue returns the *prior* body (the thin impure read) so the
// pure differ can run offline; the whole path is exercised against a fixture tree
// with no live network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { runVulnScan } from '../src/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');
const FEED = JSON.parse(
  readFileSync(join(here, 'fixtures', 'wordfence-feed-slice.json'), 'utf8'),
);

// A stateful upserter that behaves like the real GitHub issue: it remembers the body
// it last wrote and hands it back as the prior body on the next upsert (so the second
// run reads the first run's persisted Findings).
function makeStatefulUpserter() {
  const calls = [];
  let lastBody = null; // null on the very first run: no prior issue exists yet
  return {
    calls,
    async upsertIssue({ repoSlug, title, body }) {
      const priorBody = lastBody;
      lastBody = body;
      calls.push({ repoSlug, title, body });
      return { number: 7, priorBody };
    },
  };
}

test('first run alerts (everything is new); an identical second run is GREEN', async () => {
  const upserter = makeStatefulUpserter();
  const args = {
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    upsertIssue: upserter.upsertIssue,
  };

  // First run: no prior issue -> every alert-worthy Finding is new -> failing gate.
  const first = await runVulnScan(args);
  assert.ok(first.alertWorthy >= 2, 'CVE + embedded are alert-worthy');
  assert.equal(first.newOrWorsened, first.alertWorthy, 'first run: all are new');
  assert.equal(first.exitCode, 1, 'first run fails the workflow');

  // Second run over the unchanged site: same Findings, none new/worsened -> GREEN.
  const second = await runVulnScan(args);
  assert.ok(second.alertWorthy >= 2, 'the Findings are still present');
  assert.equal(second.newOrWorsened, 0, 'nothing new -> empty subset');
  assert.equal(second.exitCode, 0, 'a clean green run when nothing is new');

  // The issue is updated in place both times (one issue, two upserts), and still
  // renders the current Findings on the green run.
  assert.equal(upserter.calls.length, 2);
  assert.match(upserter.calls[1].body, /contact-form-7/);
  assert.match(upserter.calls[1].body, /revslider/);
});

// A raw Wordfence-feed record for contact-form-7 at a given CVSS score (the
// orchestrator normalizes this raw shape before matching, exactly like the real feed).
function cf7Feed(score) {
  return {
    'CVE-2020-35489': {
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
      cvss: { score },
      references: ['https://example/x'],
    },
  };
}

test('a worsened Finding re-alerts the next run (CVSS bump raises severity)', async () => {
  const upserter = makeStatefulUpserter();

  // Run 1: contact-form-7 5.3.1 matched at a medium-CVSS feed entry.
  const first = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site',
    fetchFeed: async () => cf7Feed(5.0), upsertIssue: upserter.upsertIssue,
  });
  assert.ok(first.newOrWorsened >= 1, 'first sighting alerts');

  // Run 2: same site, same CVE/slug/location, but the feed re-scored the CVE upward
  // (5.0 -> 9.8 => medium -> critical). Same identity, higher severity => re-alert.
  const second = await runVulnScan({
    siteRoot: SITE, repoSlug: 'acme/site',
    fetchFeed: async () => cf7Feed(9.8), upsertIssue: upserter.upsertIssue,
  });

  const worsenedCve = second.findings.find(
    (f) => f.type === 'cve' && f.slug === 'contact-form-7',
  );
  assert.equal(worsenedCve.severity, 'critical', 'the CVE was re-scored upward');
  assert.ok(second.newOrWorsened >= 1, 'a severity increase re-alerts');
  assert.equal(second.exitCode, 1, 'the worsening fails the workflow');
});
