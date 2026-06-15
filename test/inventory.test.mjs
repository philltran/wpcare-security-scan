import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { enumerateInventory } from '../src/inventory.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');

test('enumerates each top-level plugin as an Inventory item with slug and version', () => {
  const items = enumerateInventory(SITE);

  const topLevelPlugins = items.filter((i) => i.kind === 'plugin' && i.embedded === false);
  const bySlug = new Map(topLevelPlugins.map((i) => [i.slug, i]));
  assert.ok(topLevelPlugins.length >= 2, 'finds the top-level plugins');

  const cf7 = bySlug.get('contact-form-7');
  assert.ok(cf7, 'contact-form-7 enumerated');
  assert.equal(cf7.kind, 'plugin');
  assert.equal(cf7.version, '5.3.1');
  assert.equal(cf7.embedded, false);
  assert.ok(cf7.path.endsWith('wp-content/plugins/contact-form-7'));

  const akismet = bySlug.get('akismet');
  assert.ok(akismet, 'akismet enumerated');
  assert.equal(akismet.version, '5.3');
});

test('returns an empty list for a site with no plugins directory', () => {
  const items = enumerateInventory(join(here, 'fixtures', 'does-not-exist'));
  assert.deepEqual(items, []);
});
