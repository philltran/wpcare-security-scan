// Vuln feed loader — the IMPURE edge. Kept deliberately thin: fetch the free,
// no-auth Wordfence Intelligence bulk JSON feed and hand the raw object to the pure
// normalizer (src/wordfence.mjs). No matching logic lives here. See ADR-0003.

import { HttpClient } from '@actions/http-client';

// The free "production" scanner feed. No auth/token required.
export const WORDFENCE_FEED_URL =
  'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production';

export async function fetchWordfenceFeed(url = WORDFENCE_FEED_URL) {
  const client = new HttpClient('wpcare-security-scan');
  const res = await client.getJson(url);
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new Error(`Wordfence feed fetch failed: HTTP ${res.statusCode}`);
  }
  return res.result || {};
}
