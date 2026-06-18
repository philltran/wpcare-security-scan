// Vuln feed loader — the IMPURE edge. Kept deliberately thin: obtain the free Wordfence
// Intelligence bulk JSON feed and hand the raw object to the pure normalizer
// (src/wordfence.mjs). No matching logic lives here. See ADR-0003 (amended by ADR-0013).
//
// The feed can be sourced two ways (ADR-0014):
//   - fetchWordfenceFeed(token)  — fetch the v3 feed directly from Wordfence (Bearer auth).
//   - loadFeedFromFile(path)     — read a pre-fetched feed from disk, so the workflow can
//                                  cache it (actions/cache) or point at a mirror, avoiding
//                                  the per-run 123 MB download and the 1-req/30-min limit.
//
// As of 2026 the v1/v2 feeds are removed (HTTP 410) and the v3 production feed — still
// free for personal AND commercial use — requires a free registered API token
// (generated in a Wordfence account's Integrations section), sent as a Bearer token.
// ADR-0013 records why the no-auth premise of ADR-0003 no longer holds.

import { readFileSync } from 'node:fs';

import { HttpClient } from '@actions/http-client';

// The free v3 "production" feed. Requires a (free) Bearer token; ~123 MB JSON.
export const WORDFENCE_FEED_URL =
  'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

// Turn a status code into a LOUD, distinct error — a security scanner must never let a
// fetch problem masquerade as a clean site (the false-green trap). 429 is called out by
// name because it is the expected free-tier failure.
function failForStatus(statusCode, detail) {
  if (statusCode === 429) {
    throw new Error(
      'Wordfence feed fetch was rate-limited (HTTP 429: API key limit exceeded). The free '
      + 'tier allows 1 request per 30 minutes per token; concurrent or repeated runs on one '
      + 'token collide. Cache the feed (actions/cache + feed-path) or use a mirror / per-repo '
      + 'token — see ADR-0013/0014. NOT treating this as a clean scan.',
    );
  }
  const tail = detail ? ` — ${detail}` : '';
  throw new Error(`Wordfence feed fetch failed: HTTP ${statusCode ?? '?'}${tail}`);
}

// Fetch the v3 production feed with the free Wordfence Intelligence API token.
//
// @actions/http-client's getJson REJECTS on any non-2xx (it does not return the status),
// so the status is read off the thrown error; the post-call guard is belt-and-suspenders
// for a client that returns instead of throwing (e.g. the injected test fake).
export async function fetchWordfenceFeed(
  token,
  url = WORDFENCE_FEED_URL,
  client = new HttpClient('wpcare-security-scan'),
) {
  if (!token) {
    throw new Error(
      'Wordfence Intelligence API token is required for the v3 feed (the free no-auth '
      + 'feed was removed). Generate a free token in your Wordfence account → Integrations '
      + 'and pass it as the wordfence-token input, or pre-fetch the feed and pass feed-path. '
      + 'See ADR-0013/0014.',
    );
  }

  let res;
  try {
    res = await client.getJson(url, { Authorization: `Bearer ${token}` });
  } catch (err) {
    failForStatus(err && err.statusCode, err && err.message);
  }

  if (res.statusCode < 200 || res.statusCode >= 300) failForStatus(res.statusCode);
  return res.result || {};
}

// Read a pre-fetched feed from disk (the workflow fetched and/or cached it, or wrote a
// mirror copy there). No token needed — the credential, if any, lived in the workflow
// step that produced the file. A missing/unreadable/!JSON file fails LOUD (never a silent
// empty feed): a fetch problem must not read as a clean scan.
export function loadFeedFromFile(path, read = readFileSync) {
  let text;
  try {
    text = read(path, 'utf8');
  } catch (err) {
    throw new Error(
      `feed-path "${path}" could not be read (${err && err.message ? err.message : 'unknown error'}). `
      + 'The workflow step that fetches/caches the feed must populate it before the scan runs.',
    );
  }
  try {
    return JSON.parse(text) || {};
  } catch {
    throw new Error(
      `feed-path "${path}" is not valid JSON — the pre-fetched feed looks truncated or `
      + 'corrupt. NOT treating this as a clean scan.',
    );
  }
}
