// wordpress.org plugin-info loader — the IMPURE edge for Abandoned/closed detection.
// Kept deliberately thin (mirrors src/feed.mjs): query the free, no-auth wordpress.org
// plugin_information endpoint for a single slug and hand the raw { statusCode, body }
// to the pure decision (src/abandoned.mjs). NO decision logic lives here.
//
// This edge is verified by an example run / recorded transcript (see
// test/fixtures/wporg/*.json), not a live unit test — the closed/removed -> Finding
// decision is the part pinned offline. See ADR-0003, CONTEXT.md "Abandoned plugin".
//
// The endpoint returns a full JSON plugin object (HTTP 200) for a live plugin, and an
// error for a gone one: a 404 ("Plugin not found.") for a removed plugin, or a 200
// body carrying {"error":"closed", ...} for a closed plugin. @actions/http-client's
// getJson does not throw on a non-2xx — it returns the status and a (possibly null)
// parsed result — so both signals are surfaced as data for the pure layer to read.

import { HttpClient } from '@actions/http-client';

export const WPORG_PLUGIN_INFO_URL =
  'https://api.wordpress.org/plugins/info/1.2/';

// Build the plugin_information query URL for a slug. Encoded so an odd slug can never
// break out of the query string.
export function pluginInfoUrl(slug, base = WPORG_PLUGIN_INFO_URL) {
  const u = new URL(base);
  u.searchParams.set('action', 'plugin_information');
  u.searchParams.set('request[slug]', String(slug ?? ''));
  return u.toString();
}

// Fetch one slug's plugin info. Returns { statusCode, body } — the raw shape the pure
// decision (isAbandonedResponse / abandonedFinding) consumes. A transport-level
// failure rejects; the caller decides whether a lookup miss should be fatal (it should
// not — a flaky lookup must not masquerade as a closed plugin, which is why the pure
// layer fail-safes an absent/garbage response to "not abandoned").
export async function fetchPluginInfo(slug, client = new HttpClient('wpcare-security-scan')) {
  const res = await client.getJson(pluginInfoUrl(slug));
  return { statusCode: res.statusCode, body: res.result ?? null };
}
