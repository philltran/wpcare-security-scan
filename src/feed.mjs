// Vuln feed loader — the IMPURE edge. Kept deliberately thin: fetch the free Wordfence
// Intelligence bulk JSON feed and hand the raw object to the pure normalizer
// (src/wordfence.mjs). No matching logic lives here. See ADR-0003 (amended by ADR-0013).
//
// As of 2026 the v1/v2 feeds are removed (HTTP 410) and the v3 production feed — still
// free for personal AND commercial use — requires a free registered API token
// (generated in a Wordfence account's Integrations section), sent as a Bearer token.
// ADR-0013 records why the no-auth premise of ADR-0003 no longer holds.

import { HttpClient } from '@actions/http-client';

// The free v3 "production" feed. Requires a (free) Bearer token; ~123 MB JSON.
export const WORDFENCE_FEED_URL =
  'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

// Fetch the v3 production feed with the free Wordfence Intelligence API token.
//
// Failure modes are surfaced LOUD and distinctly — a security scanner must never let a
// fetch problem masquerade as a clean site (the false-green trap):
//   - missing token        -> a clear configuration error (caught before the request)
//   - 429 (rate limited)    -> a distinct error naming the 1-req/30-min free-tier limit
//   - any other non-2xx     -> a status error
// The plausibility floor on the *parsed* feed (an empty/truncated 2xx body) is handled by
// the orchestrator guard tracked in issue #15, not here.
export async function fetchWordfenceFeed(
  token,
  url = WORDFENCE_FEED_URL,
  client = new HttpClient('wpcare-security-scan'),
) {
  if (!token) {
    throw new Error(
      'Wordfence Intelligence API token is required for the v3 feed (the free no-auth '
      + 'feed was removed). Generate a free token in your Wordfence account → Integrations '
      + 'and pass it as the wordfence-token input. See ADR-0013.',
    );
  }

  const res = await client.getJson(url, { Authorization: `Bearer ${token}` });

  if (res.statusCode === 429) {
    throw new Error(
      'Wordfence feed fetch was rate-limited (HTTP 429). The free tier allows 1 request '
      + 'per 30 minutes per token; a shared token across concurrent runs will collide. '
      + 'Use a per-repo token or stagger schedules (see ADR-0013). NOT treating this as a '
      + 'clean scan.',
    );
  }
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new Error(`Wordfence feed fetch failed: HTTP ${res.statusCode}`);
  }
  return res.result || {};
}
