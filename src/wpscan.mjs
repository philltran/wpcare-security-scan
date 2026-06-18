// WPScan cross-reference (issue #7).
//
// An OPTIONAL deepening of the Vulnerability Scan. Wordfence stays primary (ADR-0003);
// WPScan only fills in CVEs the free Wordfence feed missed, and ONLY when an operator
// supplies a `WPSCAN_API_TOKEN`. With no token the scan runs exactly as before, zero
// secrets — the orchestrator simply never injects this edge.
//
// This module has two halves, mirroring the Wordfence path (src/feed.mjs +
// src/wordfence.mjs) and the wordpress.org path (src/wporg.mjs + src/abandoned.mjs):
//
//   fetchWpscanPlugin(slug, token, client)  — the thin IMPURE edge (token-gated)
//   normalizeWpscanResponse(rawResponse)    — PURE: response -> the shared dataset shape
//
// The pure normalizer emits the SAME `{ slug -> [ { affected_range, fixed_in, cvss,
// cve, title, url } ] }` shape the Wordfence normalizer produces, so WPScan data flows
// through the one shared matcher (src/matcher.mjs) — never a parallel matching path.
// The live call is kept out of unit tests; the normalizer is pinned by recorded
// fixtures under test/fixtures/wpscan/.

import { HttpClient } from '@actions/http-client';

// The per-slug WPScan API v3 plugin endpoint. One call per plugin; the free tier is
// rate-limited to a low daily budget, which is exactly why WPScan is a cross-reference
// and not the fleet primary (ADR-0003).
export const WPSCAN_PLUGIN_BASE_URL = 'https://wpscan.com/api/v3/plugins/';

// Build the plugin URL for a slug. encodeURIComponent so an odd/hostile slug lands in a
// single percent-encoded path segment and can never traverse the API path.
export function wpscanPluginUrl(slug, base = WPSCAN_PLUGIN_BASE_URL) {
  return `${base}${encodeURIComponent(String(slug ?? ''))}`;
}

// Fetch one slug's WPScan record. Token-gated: the caller only invokes this when a
// token is present, but it is also defended here. The WPScan API authenticates with an
// `Authorization: Token token=<TOKEN>` header. The token is a secret — it is read from
// the Action input by the entrypoint and NEVER logged.
//
// Returns the parsed JSON body (the raw shape the pure normalizer consumes) or null.
// Fail-safe: a non-2xx (404 unknown plugin, 401 bad token, 429 budget exhausted, 5xx)
// yields null so a missing cross-reference never masquerades as data and never aborts
// the run — Wordfence remains authoritative.
export async function fetchWpscanPlugin(
  slug,
  token,
  client = new HttpClient('wpcare-security-scan'),
) {
  if (!token) return null;
  const headers = { Authorization: `Token token=${token}` };
  const res = await client.getJson(wpscanPluginUrl(slug), headers);
  if (res.statusCode < 200 || res.statusCode >= 300) return null;
  return res.result ?? null;
}

// Normalize a bare CVE reference into a canonical `CVE-<id>`. WPScan lists CVEs as bare
// numbers (e.g. "2020-35489"); the Wordfence feed uses the prefixed form
// ("CVE-2020-35489"), and cross-source dedup keys on the CVE, so the two must align.
function normalizeCve(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  if (!s) return null;
  return /^cve-/i.test(s) ? s.toUpperCase().replace(/^CVE-/, 'CVE-') : `CVE-${s}`;
}

function firstUrl(references) {
  const urls = references && Array.isArray(references.url) ? references.url : [];
  return urls.length ? urls[0] : null;
}

function firstCve(references) {
  const cves = references && Array.isArray(references.cve) ? references.cve : [];
  for (const c of cves) {
    const norm = normalizeCve(c);
    if (norm) return norm;
  }
  return null;
}

// The CVSS score, if present. WPScan often omits cvss entirely; an absent score must
// stay absent (null) so the matcher maps it to severity `unknown` rather than a scored
// band. Mirrors the Wordfence normalizer surfacing `cvss.score`.
function cvssScore(cvss) {
  if (!cvss || typeof cvss !== 'object') return null;
  return cvss.score ?? null;
}

// Per the maintainer decision (issue #7): a WPScan vuln with no CVE is STILL a real
// "Finding Wordfence missed", so it must keep a stable identity across runs. Carry the
// WPScan vuln id in the `cve` slot as `WPSCAN-<id>` — no schema change, and both
// report.mjs persistence and differ.findingIdentity stay correct. Rendered/labeled as
// a WPScan reference (not a CVE) downstream.
function identityFor(vuln) {
  const cve = firstCve(vuln.references);
  if (cve) return cve;
  if (vuln.id) return `WPSCAN-${vuln.id}`;
  return null;
}

// Cross-source merge — PURE. Fold a WPScan dataset into the primary Wordfence dataset
// per the maintainer decision for issue #7:
//
//   - Merge per slug. The merge key is the record's `cve` slot — a real CVE when one is
//     present, else the `WPSCAN-<id>` reference the normalizer parked there.
//   - Dedup by CVE, WORDFENCE WINS: if a Wordfence record already covers a CVE for a
//     slug, the WPScan duplicate is DROPPED (Wordfence metadata is authoritative,
//     ADR-0003).
//   - WPScan entries with NO CVE are STILL emitted — they are the real "Findings
//     Wordfence missed" — carried by their stable WPSCAN-<id> identity.
//
// Both datasets share one shape, so the merged dataset feeds the existing matcher
// unchanged: there is no parallel matching path. Returns a fresh object; the inputs are
// never mutated.
export function mergeDatasets(wordfence, wpscan) {
  const base = wordfence && typeof wordfence === 'object' ? wordfence : {};
  const extra = wpscan && typeof wpscan === 'object' ? wpscan : {};

  // Deep-ish copy of the per-slug arrays so the matcher can't be surprised by aliasing
  // and the caller's Wordfence dataset stays untouched. Null-prototype map — slugs are
  // external and may collide with Object.prototype members (see src/wordfence.mjs).
  const merged = Object.create(null);
  for (const [slug, records] of Object.entries(base)) {
    merged[slug] = Array.isArray(records) ? records.slice() : records;
  }

  for (const [slug, records] of Object.entries(extra)) {
    if (!Array.isArray(records)) continue;
    const list = (merged[slug] ||= []);
    // The CVE keys already claimed for this slug by Wordfence (and earlier WPScan
    // records) — a WPScan record sharing one is the dropped duplicate.
    const seen = new Set(list.map((r) => r && r.cve).filter(Boolean));
    for (const rec of records) {
      const key = rec && rec.cve;
      if (key && seen.has(key)) continue; // Wordfence already covers this CVE — drop dup
      list.push(rec);
      if (key) seen.add(key);
    }
  }

  return merged;
}

export function normalizeWpscanResponse(rawResponse) {
  // Null-prototype map — slugs are external and may collide with Object.prototype
  // members (see src/wordfence.mjs for the same fix and why).
  const bySlug = Object.create(null);
  if (!rawResponse || typeof rawResponse !== 'object') return bySlug;

  // An error/not-found body (e.g. { status:'error', error:'Not found' }) carries no
  // plugin record — fail-safe to an empty dataset.
  if (rawResponse.error || rawResponse.status === 'error') return bySlug;

  for (const [slug, record] of Object.entries(rawResponse)) {
    if (!slug || !record || typeof record !== 'object') continue;
    const vulns = Array.isArray(record.vulnerabilities) ? record.vulnerabilities : [];

    for (const vuln of vulns) {
      if (!vuln || typeof vuln !== 'object') continue;
      const cve = identityFor(vuln);
      if (!cve) continue; // no CVE and no id => no stable identity, skip

      const rec = {
        // WPScan exposes no lower bound — anything below fixed_in is affected, which is
        // exactly how the shared matcher already treats a record with only `fixed_in`.
        affected_range: null,
        fixed_in: vuln.fixed_in ?? null,
        cvss: cvssScore(vuln.cvss),
        cve,
        title: vuln.title ?? null,
        url: firstUrl(vuln.references),
      };
      (bySlug[slug] ||= []).push(rec);
    }
  }

  return bySlug;
}
