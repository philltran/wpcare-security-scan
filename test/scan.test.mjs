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

test('walking skeleton: fixture tree -> one CVE Finding, one upserted issue, failing gate', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => FEED,
    upsertIssue: upserter.upsertIssue,
  });

  // exactly one Known CVE Finding
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'cve');
  assert.equal(result.findings[0].slug, 'contact-form-7');

  // a single deduped issue upsert happened
  assert.equal(upserter.calls.length, 1);
  assert.equal(upserter.calls[0].repoSlug, 'acme/site');
  assert.match(upserter.calls[0].title, /1/);
  assert.match(upserter.calls[0].body, /contact-form-7/);

  // alert-worthy => failing exit code
  assert.equal(result.alertWorthy, 1);
  assert.equal(result.exitCode, 1);
});

test('a clean site exits zero and still upserts (issue closed/cleared in later slice)', async () => {
  const upserter = makeUpserter();

  const result = await runVulnScan({
    siteRoot: SITE,
    repoSlug: 'acme/site',
    fetchFeed: async () => ({}), // empty feed => no matches
    upsertIssue: upserter.upsertIssue,
  });

  assert.equal(result.findings.length, 0);
  assert.equal(result.alertWorthy, 0);
  assert.equal(result.exitCode, 0);
});
