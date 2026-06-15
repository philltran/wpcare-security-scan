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

function makeUpserter() {
  const calls = [];
  return {
    calls,
    async upsertIssue(args) { calls.push(args); return { number: 42 }; },
  };
}

test('end-to-end: fixture tree -> a CVE Finding AND the embedded revslider Finding, one upserted issue, failing gate', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    upsertIssue: upserter.upsertIssue,
  });

  const byType = (t) => result.findings.filter((f) => f.type === t);

  // the Known CVE against the top-level contact-form-7.
  const cve = byType('cve');
  assert.equal(cve.length, 1);
  assert.equal(cve[0].slug, 'contact-form-7');

  // the headline catch: the Slider Revolution bundled inside the theme, with no CVE.
  const embedded = byType('embedded');
  assert.ok(
    embedded.some((f) => f.slug === 'revslider'),
    'the embedded revslider is caught end-to-end',
  );

  // a single deduped issue upsert carrying the Findings.
  assert.equal(upserter.calls.length, 1);
  assert.equal(upserter.calls[0].repoSlug, 'acme/site');
  assert.match(upserter.calls[0].body, /contact-form-7/);
  assert.match(upserter.calls[0].body, /revslider/);

  // every alert-worthy Finding (CVE + embedded) trips the failing gate.
  assert.ok(result.alertWorthy >= 2);
  assert.equal(result.alertWorthy, result.findings.filter((f) => f.type !== 'outdated').length);
  assert.equal(result.exitCode, 1);
});

test('a site with no alert-worthy Findings exits zero and still upserts', async () => {
  // Point at a tree with no plugins/themes/embedded code and an empty feed.
  const cleanRoot = join(here, 'fixtures', 'empty-site');
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: cleanRoot,
    repoSlug: 'acme/site',
    fetchFeed: async () => ({}), // empty feed => no CVE matches
    upsertIssue: upserter.upsertIssue,
  });

  assert.equal(result.findings.length, 0);
  assert.equal(result.alertWorthy, 0);
  assert.equal(result.exitCode, 0);
  assert.equal(upserter.calls.length, 1);
});
