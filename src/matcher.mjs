// Vuln matcher — pure, deep module.
//
//   matchVulnerabilities(inventory, normalizedDataset) -> [ Finding ]
//
// Decides version-range satisfaction and severity, emitting a Finding per matched
// inventory item. A plugin is affected at a CVE when its installed version is
// strictly below that CVE's `fixed_in` (the `old < fixed_in` boundary half of the
// prior-art `old < fixed_in <= new` logic, ported — not imported — from
// pt-claude-skills): below `fixed_in` is vulnerable; at or above is patched and
// yields no CVE Finding. Version comparison is segment-by-segment and tolerant of
// WordPress's loose, non-strict-semver version strings (see `compareVersions`).
//
// CVSS maps onto the Finding severity vocabulary (critical/high/medium/low/none,
// plus `unknown` for a missing score), and the full Finding list (CVE + embedded
// together) is returned most-severe-first via a stable sort so the worst Findings
// surface first while equal-severity Findings keep inventory order.
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
// A missing score (null/undefined/empty) is genuinely *unknown* — it is not the
// same as a scored 0.0 ("none"). Note `Number(null)` is 0 and `Number('')` is 0, so
// the absence is checked explicitly before coercing.
function severityFromCvss(score) {
  if (score === null || score === undefined || score === '') return 'unknown';
  const n = Number(score);
  if (!Number.isFinite(n)) return 'unknown';
  if (n >= 9.0) return 'critical';
  if (n >= 7.0) return 'high';
  if (n >= 4.0) return 'medium';
  if (n > 0.0) return 'low';
  return 'none';
}

// Severity ordering for surfacing the worst Findings first. Higher rank = more
// urgent. `unknown` and `none` rank below the scored bands so a confidently-low
// Finding still outranks an unscored one. Used by a *stable* sort, so Findings of
// equal severity keep their enumeration order (inventory order).
const SEVERITY_RANK = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  none: 1,
  unknown: 0,
};

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

// Order most-severe-first. Array.prototype.sort is stable in modern Node, so ties
// preserve insertion order — no extra index bookkeeping needed.
function bySeverityDesc(a, b) {
  return severityRank(b.severity) - severityRank(a.severity);
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

  // Surface the worst first: a stable, most-severe-first sort over the full Finding
  // list (CVE + embedded together), so a critical CVE leads and equal-severity
  // Findings retain inventory order.
  findings.sort(bySeverityDesc);

  return findings;
}
