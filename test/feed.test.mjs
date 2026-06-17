// Wordfence v3 feed loader — the impure edge (src/feed.mjs). Its job is thin: send the
// Bearer token to the v3 URL and surface failures LOUD so a fetch problem never
// masquerades as a clean scan (the false-green trap). These cases pin that behavior with
// an injected fake client — no network. See ADR-0013.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { fetchWordfenceFeed, WORDFENCE_FEED_URL } from '../src/feed.mjs';

// Minimal stand-in for @actions/http-client's HttpClient: records the call and returns a
// canned getJson result.
function fakeClient(result) {
  const calls = [];
  return {
    calls,
    getJson(url, headers) {
      calls.push({ url, headers });
      return Promise.resolve(result);
    },
  };
}

test('the v3 URL is used and the token is sent as a Bearer header', async () => {
  const client = fakeClient({ statusCode: 200, result: { 'CVE-1': {} } });
  const feed = await fetchWordfenceFeed('tok-123', WORDFENCE_FEED_URL, client);
  assert.equal(client.calls.length, 1);
  assert.match(client.calls[0].url, /\/v3\/vulnerabilities\/production$/);
  assert.equal(client.calls[0].headers.Authorization, 'Bearer tok-123');
  assert.deepEqual(feed, { 'CVE-1': {} });
});

test('a missing token throws a clear configuration error before any request', async () => {
  const client = fakeClient({ statusCode: 200, result: {} });
  await assert.rejects(
    () => fetchWordfenceFeed('', WORDFENCE_FEED_URL, client),
    /token is required/i,
  );
  assert.equal(client.calls.length, 0, 'must not hit the network without a token');
});

test('a 429 is surfaced as a rate-limit error, never a clean/empty scan', async () => {
  const client = fakeClient({ statusCode: 429, result: null });
  await assert.rejects(
    () => fetchWordfenceFeed('tok', WORDFENCE_FEED_URL, client),
    /rate-limited.*429/is,
  );
});

test('any other non-2xx is surfaced as a status error', async () => {
  const client = fakeClient({ statusCode: 500, result: null });
  await assert.rejects(
    () => fetchWordfenceFeed('tok', WORDFENCE_FEED_URL, client),
    /HTTP 500/,
  );
});

test('a 2xx with a null body normalizes to an empty object (the plausibility floor is the orchestrator guard, issue #15)', async () => {
  const client = fakeClient({ statusCode: 200, result: null });
  const feed = await fetchWordfenceFeed('tok', WORDFENCE_FEED_URL, client);
  assert.deepEqual(feed, {});
});
