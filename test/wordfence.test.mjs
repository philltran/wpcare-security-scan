import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { normalizeWordfenceFeed } from '../src/wordfence.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const FEED = JSON.parse(
  readFileSync(join(here, 'fixtures', 'wordfence-feed-slice.json'), 'utf8'),
);

test('normalizes the raw feed to { slug -> [vuln records] }', () => {
  const bySlug = normalizeWordfenceFeed(FEED);

  const records = bySlug['contact-form-7'];
  assert.ok(Array.isArray(records), 'keyed by plugin slug');
  assert.equal(records.length, 1);

  const v = records[0];
  assert.equal(v.affected_range, '* - 5.3.1');
  assert.equal(v.fixed_in, '5.3.2');
  assert.equal(v.cvss, 9.8);
  assert.equal(v.cve, 'CVE-2020-35489');
  assert.equal(v.title, 'Contact Form 7 < 5.3.2 - Unrestricted File Upload');
  assert.match(v.url, /wordfence\.com/);
});

test('returns an empty object for an empty feed', () => {
  assert.deepEqual(normalizeWordfenceFeed({}), {});
});
