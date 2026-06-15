// Reporter — pure rendering + issue-matching helpers.
//
// The impure edge (the Octokit list/create/update calls) lives in the issue
// upserter and is kept thin; everything here is pure so the dedup contract — one
// issue per site, found by a stable marker (label + a hidden marker in the body) —
// is pinned by tests.
//
//   ISSUE_LABEL                       — the label that feeds triage/ship-issues
//   markerFor(repoSlug)               — the stable hidden body marker for a site
//   renderIssueTitle(findings)        — issue title
//   renderIssueBody(repoSlug, fnds)   — issue body (carries the marker + state)
//   findMarkedIssue(issues, marker)   — the existing issue to upsert, or null
//   parsePersistedFindings(body)      — the prior Findings recovered from a body
//
// The deduped issue is the scanner's persistence layer: each run embeds the current
// alert-worthy Findings in the body as a hidden, machine-readable state block so the
// *next* run can read them back as the prior state and diff (alert only on the
// new/worsened subset; see src/differ.mjs). The block is a single HTML comment so it
// never renders to a human, mirroring the dedup marker's hidden-comment idiom.

// The dedup label. The exact name was flagged "deferred to implementation" in
// CONTEXT.md; this is the first concrete choice and stays stable across runs.
export const ISSUE_LABEL = 'security-scan';

// A stable, per-site hidden marker. Keyed to the site repo slug so a fleet that
// files into a shared tracker still dedups one issue per site. Hidden in an HTML
// comment so it never renders in the issue body.
export function markerFor(repoSlug) {
  return `<!-- wpcare-security-scan:${repoSlug || 'unknown'} -->`;
}

export function renderIssueTitle(findings) {
  const n = Array.isArray(findings) ? findings.length : 0;
  const noun = n === 1 ? 'Finding' : 'Findings';
  return `Security Scan: ${n} alert-worthy ${noun}`;
}

function renderFinding(f) {
  const lines = [
    `### ${f.slug} ${f.version ?? ''} — ${f.type.toUpperCase()}`,
    '',
    `- **Severity:** ${f.severity}`,
    `- **Kind:** ${f.kind}`,
    `- **Location:** \`${f.location}\``,
  ];
  if (f.cve) lines.push(`- **CVE:** ${f.cve}`);
  if (f.fixed_in) lines.push(`- **Fixed in:** ${f.fixed_in}`);
  if (f.url) lines.push(`- **Reference:** ${f.url}`);
  lines.push(`- **Remediation:** ${f.remediation}`);
  return lines.join('\n');
}

// The hidden, machine-readable state block. A single HTML comment wrapping a JSON
// array of the current Findings, fenced by a sentinel so the parser can recover it
// precisely without colliding with the dedup marker (also an HTML comment). Only the
// fields the differ needs to identify and rank a Finding are persisted — the body
// stays small and the human-readable prose remains the source of detail.
const STATE_OPEN = '<!-- wpcare-security-scan:state ';
const STATE_CLOSE = ' -->';
const STATE_RE = /<!-- wpcare-security-scan:state ([\s\S]*?) -->/;

function persistableFinding(f) {
  return {
    type: f.type,
    severity: f.severity,
    slug: f.slug,
    version: f.version,
    location: f.location,
    ...(f.cve ? { cve: f.cve } : {}),
  };
}

function renderState(findings) {
  const payload = JSON.stringify(findings.map(persistableFinding));
  return `${STATE_OPEN}${payload}${STATE_CLOSE}`;
}

export function renderIssueBody(repoSlug, findings) {
  const list = Array.isArray(findings) ? findings : [];
  const parts = [
    markerFor(repoSlug),
    '',
    'Automated WordPress security scan results. This issue is updated in place on '
      + 'each run; do not open a duplicate.',
    '',
    ...list.map(renderFinding),
  ];
  if (!list.length) {
    parts.push('No alert-worthy Findings in the latest scan.');
  }
  // The persisted state block always trails the body, even when empty, so the next
  // run reads an unambiguous prior set (an empty array, not "no state at all").
  parts.push('', renderState(list));
  return parts.join('\n');
}

// Recover the prior persisted Findings from a deduped issue body. Fail-safe: a
// missing body, no state block, or unparseable JSON yields an empty array (the next
// run treats every current Finding as new rather than crashing on a malformed issue).
export function parsePersistedFindings(body) {
  if (typeof body !== 'string') return [];
  const m = STATE_RE.exec(body);
  if (!m) return [];
  try {
    const parsed = JSON.parse(m[1]);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function findMarkedIssue(issues, marker) {
  const list = Array.isArray(issues) ? issues : [];
  for (const issue of list) {
    if (issue && typeof issue.body === 'string' && issue.body.includes(marker)) {
      return issue;
    }
  }
  return null;
}
