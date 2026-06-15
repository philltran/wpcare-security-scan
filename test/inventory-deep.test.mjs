// Deep + embedded enumeration tests (issue #3) — the revslider-catching core.
//
// These exercise enumerateInventory() through its public interface against a fixture
// wp-content tree, asserting the highest-value behavior: a plugin bundled inside a
// theme is detected as an Embedded plugin, and every code surface (mu-plugins,
// drop-ins, inactive themes, core) is enumerated regardless of activation. See
// ADR-0004.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { enumerateInventory } from '../src/inventory.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = join(here, 'fixtures', 'site');

test('detects a plugin bundled inside a theme as an Embedded plugin (the revslider catch)', () => {
  const items = enumerateInventory(SITE);
  const embedded = items.filter((i) => i.embedded === true);

  const revslider = embedded.find((i) => i.slug === 'revslider');
  assert.ok(revslider, 'the bundled Slider Revolution is enumerated');
  assert.equal(revslider.kind, 'plugin');
  assert.equal(revslider.version, '4.6.0');
  assert.equal(revslider.embedded, true);
  assert.ok(
    revslider.path.includes(join('themes', 'premium-theme', 'revslider')),
    'path points at the nested location, not a top-level plugins/ path',
  );
});

test('enumerates mu-plugins, drop-ins, inactive themes, and core with the right kind and version', () => {
  const items = enumerateInventory(SITE);
  const bySlug = new Map(items.map((i) => [`${i.kind}:${i.slug}`, i]));

  // mu-plugin (single-file, no subdir, always loaded) — activation is irrelevant.
  const mu = bySlug.get('mu-plugin:forced-login');
  assert.ok(mu, 'mu-plugin enumerated');
  assert.equal(mu.kind, 'mu-plugin');
  assert.equal(mu.version, '2.1.0');
  assert.equal(mu.embedded, false);

  // drop-in (object-cache.php living directly in wp-content/).
  const dropin = bySlug.get('dropin:object-cache');
  assert.ok(dropin, 'drop-in enumerated');
  assert.equal(dropin.kind, 'dropin');
  assert.equal(dropin.version, '2.5.1');

  // an inactive theme is still enumerated (activation ignored).
  const inactiveTheme = bySlug.get('theme:twentytwenty');
  assert.ok(inactiveTheme, 'inactive theme enumerated');
  assert.equal(inactiveTheme.kind, 'theme');
  assert.equal(inactiveTheme.version, '2.3');

  // WordPress core, read from wp-includes/version.php.
  const core = bySlug.get('core:wordpress');
  assert.ok(core, 'core enumerated');
  assert.equal(core.kind, 'core');
  assert.equal(core.version, '6.4.2');
});

test('a legitimately vendored embedded copy surfaces as a triageable Finding, not a fatal error', () => {
  // big-plugin bundles a header-bearing helper deep in includes/ — a false-positive
  // "embedded copy". The walk must surface it (triageable downstream) and must never
  // throw or abort, even when a tree resembles an embedded plugin (ADR-0004).
  let items;
  assert.doesNotThrow(() => { items = enumerateInventory(SITE); });

  const libWidget = items.find((i) => i.slug === 'lib-widget');
  assert.ok(libWidget, 'the vendored helper is surfaced');
  assert.equal(libWidget.embedded, true, 'flagged embedded so a human can triage it');
  assert.equal(libWidget.kind, 'plugin');

  // the host plugin is still enumerated as an ordinary top-level item.
  const bigPlugin = items.find((i) => i.slug === 'big-plugin' && i.embedded === false);
  assert.ok(bigPlugin, 'the host plugin is enumerated normally alongside the embedded hit');
});

test('the embedded sniff is depth-bounded so a pathological tree cannot stall the scan', () => {
  // A header-bearing plugin buried below the recursion bound is NOT enumerated, and
  // the walk returns normally — the cost guard from ADR-0004 ("slightly more scan
  // logic") must never become an unbounded walk.
  const items = enumerateInventory(SITE);
  assert.equal(
    items.find((i) => i.slug === 'too-deep-plugin'),
    undefined,
    'a plugin nested past the depth bound is not enumerated',
  );
});
