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

import { isAlertWorthy } from './matcher.mjs';

// The dedup label. The exact name was flagged "deferred to implementation" in
// CONTEXT.md; this is the first concrete choice and stays stable across runs.
export const ISSUE_LABEL = 'security-scan';

// A stable, per-site hidden marker. Keyed to the site repo slug so a fleet that
// files into a shared tracker still dedups one issue per site. Hidden in an HTML
// comment so it never renders in the issue body.
export function markerFor(repoSlug) {
  return `<!-- wpcare-security-scan:${repoSlug || 'unknown'} -->`;
}

// The title headlines the ALERT-worthy count only — report-only Findings (outdated)
// never inflate it. Tolerant of being handed the full Finding list or a pre-filtered
// alert-worthy list: it filters either way, so the headline is always the alert count.
export function renderIssueTitle(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const n = list.filter(isAlertWorthy).length;
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
  if (f.latest) lines.push(`- **Latest available:** ${f.latest}`);
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

// Render the full report. The body shows EVERY detected Finding so a maintainer has the
// complete picture (PRD user story 23): alert-worthy Findings first, then a clearly
// labeled report-only section for the rest (outdated-but-no-CVE; user story 24). Only
// the alert-worthy Findings are persisted in the hidden state block and counted by the
// title — a report-only Finding can therefore never be diffed back into an alert or trip
// the failing status. Tolerant of being handed the full list OR a pre-filtered
// alert-worthy list (a report-only section simply renders empty in the latter case), so
// existing callers keep working.
export function renderIssueBody(repoSlug, findings) {
  const list = Array.isArray(findings) ? findings : [];
  const alertWorthy = list.filter(isAlertWorthy);
  const reportOnly = list.filter((f) => !isAlertWorthy(f));

  const parts = [
    markerFor(repoSlug),
    '',
    'Automated WordPress security scan results. This issue is updated in place on '
      + 'each run; do not open a duplicate.',
    '',
  ];

  if (alertWorthy.length) {
    parts.push('## Alert-worthy Findings', '', ...alertWorthy.map(renderFinding));
  } else {
    parts.push('No alert-worthy Findings in the latest scan.');
  }

  // The full-report section: report-only Findings (outdated-but-no-CVE) are listed for
  // completeness but explicitly flagged as non-alerting so they never read as a fire.
  if (reportOnly.length) {
    parts.push(
      '',
      '## Report-only (not alerting)',
      '',
      'The items below are detected for completeness — they are **report-only** and do '
        + 'not fail the scan (no known CVE affects the installed version).',
      '',
      ...reportOnly.map(renderFinding),
    );
  }

  // The persisted state block always trails the body, even when empty, so the next run
  // reads an unambiguous prior set (an empty array, not "no state at all"). ONLY the
  // alert-worthy Findings are persisted, so the differ never re-alerts a report-only one.
  parts.push('', renderState(alertWorthy));
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
