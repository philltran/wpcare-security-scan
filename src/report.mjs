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
//   renderIssueBody(repoSlug, fnds)   — issue body (carries the marker)
//   findMarkedIssue(issues, marker)   — the existing issue to upsert, or null

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
  return parts.join('\n');
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
