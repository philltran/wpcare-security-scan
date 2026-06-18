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

test('returns an empty map for an empty feed', () => {
  // Spread to a plain object: the normalizer returns a null-prototype map (see below),
  // and assert/strict's deepEqual checks prototypes.
  assert.deepEqual({ ...normalizeWordfenceFeed({}) }, {});
});

test('a slug that collides with an Object.prototype member does not throw and is captured', () => {
  // Real-data regression: the live feed carries software slugs that shadow prototype
  // members (e.g. "constructor", "__proto__"). A plain {} map threw
  // "bySlug[slug].push is not a function"; the null-proto map handles them as plain keys.
  const feed = {
    'CVE-X': {
      cve: 'CVE-X',
      title: 't',
      cvss: { score: 5 },
      references: ['https://example.test'],
      software: [
        { slug: 'constructor', affected_versions: { '*': { to_version: '1.0', to_inclusive: false } } },
        { slug: '__proto__', affected_versions: { '*': { to_version: '2.0', to_inclusive: false } } },
        { slug: 'toString', affected_versions: { '*': { to_version: '3.0', to_inclusive: false } } },
      ],
    },
  };
  let bySlug;
  assert.doesNotThrow(() => { bySlug = normalizeWordfenceFeed(feed); });
  assert.ok(Array.isArray(bySlug.constructor) && bySlug.constructor[0].fixed_in === '1.0');
  assert.ok(Array.isArray(bySlug.__proto__) && bySlug.__proto__[0].fixed_in === '2.0');
  assert.ok(Array.isArray(bySlug.toString) && bySlug.toString[0].fixed_in === '3.0');
});
