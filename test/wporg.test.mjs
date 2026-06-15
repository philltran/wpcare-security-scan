// Issue #5 — the thin wordpress.org impure edge.
//
// The fetch itself (fetchPluginInfo) is verified by an example run / recorded
// transcript (test/fixtures/wporg/*.json drive the pure decision in abandoned.test.mjs),
// not a live unit test. The one piece of pure logic that lives in the edge — building
// the query URL — IS pinned here, because a slug flows untrusted into a URL and the
// encoding must hold. No network.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { pluginInfoUrl, WPORG_PLUGIN_INFO_URL } from '../src/wporg.mjs';

test('builds the plugin_information query URL for a slug', () => {
  const url = pluginInfoUrl('contact-form-7');
  assert.ok(url.startsWith(WPORG_PLUGIN_INFO_URL));
  const parsed = new URL(url);
  assert.equal(parsed.searchParams.get('action'), 'plugin_information');
  assert.equal(parsed.searchParams.get('request[slug]'), 'contact-form-7');
});

test('encodes an odd slug so it cannot break out of the query string', () => {
  const url = pluginInfoUrl('evil slug&action=hack');
  const parsed = new URL(url);
  // The whole hostile string lands in the slug param, not as a second action.
  assert.equal(parsed.searchParams.get('request[slug]'), 'evil slug&action=hack');
  assert.equal(parsed.searchParams.get('action'), 'plugin_information');
  assert.equal(parsed.hostname, 'api.wordpress.org');
});
