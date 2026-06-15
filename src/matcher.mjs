// Vuln matcher — pure, deep module.
//
//   matchVulnerabilities(inventory, normalizedDataset) -> [ Finding ]
//
// Decides version-range satisfaction and severity, emitting a Finding per matched
// inventory item. This slice does the thin single-match: a plugin is affected when
// its installed version is strictly below the CVE's `fixed_in` (the `old < fixed_in`
// half of the prior-art `old < fixed_in <= new` logic, ported — not imported — from
// pt-claude-skills). Issue #4 hardens range satisfaction (open-ended ranges,
// pre-releases, multiple disjoint ranges).
//
// Finding shape (the v1 contract):
//   { type, severity, slug, version, kind, location, fixed_in?, cve?, url?, remediation }
// Alert-worthy types: cve, abandoned, embedded. Report-only: outdated.

const ALERT_WORTHY = new Set(['cve', 'abandoned', 'embedded']);

export function isAlertWorthy(finding) {
  return Boolean(finding) && ALERT_WORTHY.has(finding.type);
}

// Numeric-triple version compare, ported from the prior-art classify_bump: strip
// non-numeric noise, compare segment by segment. Returns <0 / 0 / >0.
function verParts(v) {
  return String(v ?? '')
    .replace(/[^0-9.]/g, '')
    .split('.')
    .filter((p) => /^\d+$/.test(p))
    .map((p) => parseInt(p, 10));
}

function compareVersions(a, b) {
  const pa = verParts(a);
  const pb = verParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// installed strictly below fixed_in => still affected.
function isAffected(installed, fixedIn) {
  if (!fixedIn) return false;
  return compareVersions(installed, fixedIn) < 0;
}

// Map a CVSS base score to a severity band (CVSS v3.x qualitative ratings).
function severityFromCvss(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return 'unknown';
  if (n >= 9.0) return 'critical';
  if (n >= 7.0) return 'high';
  if (n >= 4.0) return 'medium';
  if (n > 0.0) return 'low';
  return 'none';
}

function remediationFor(slug, fixedIn) {
  return fixedIn
    ? `Update ${slug} to ${fixedIn} or later.`
    : `Update ${slug} to a patched version.`;
}

// An Embedded plugin (one detected nested inside another plugin or theme) is an
// alert-worthy Finding in its own right, independent of any CVE: it has no update
// channel and the site owner cannot patch it, so its remediation is *removal*, never
// *update* (ADR-0004, CONTEXT.md "Embedded plugin"). Emitted even when the slug has
// no matching CVE record. A false "embedded copy" (a legitimately vendored library)
// surfaces here as a triageable Finding a human resolves — it never aborts the run.
function embeddedFinding(item) {
  return {
    type: 'embedded',
    severity: 'medium',
    slug: item.slug,
    version: item.version,
    kind: item.kind,
    location: item.path,
    remediation:
      `Remove the embedded ${item.kind} "${item.slug}" (bundled at ${item.path}); `
      + 'it has no update channel and cannot be patched in place. '
      + 'If this is a legitimately vendored copy, triage and dismiss this Finding.',
  };
}

export function matchVulnerabilities(inventory, normalizedDataset) {
  const dataset = normalizedDataset || {};
  const findings = [];

  for (const item of Array.isArray(inventory) ? inventory : []) {
    if (item && item.embedded === true) {
      findings.push(embeddedFinding(item));
    }

    const records = dataset[item.slug];
    if (!Array.isArray(records)) continue;

    for (const vuln of records) {
      if (!isAffected(item.version, vuln.fixed_in)) continue;

      findings.push({
        type: 'cve',
        severity: severityFromCvss(vuln.cvss),
        slug: item.slug,
        version: item.version,
        kind: item.kind,
        location: item.path,
        fixed_in: vuln.fixed_in,
        cve: vuln.cve,
        url: vuln.url,
        remediation: remediationFor(item.slug, vuln.fixed_in),
      });
    }
  }

  return findings;
}
