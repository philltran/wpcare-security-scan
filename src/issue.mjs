// Issue upserter — the IMPURE edge that delivers the deduped per-site GitHub issue.
// One issue per site, found by a stable marker (label + a hidden body marker):
// created if absent, updated in place if present. Pure rendering and marker/match
// helpers live in src/report.mjs; this module is only the thin Octokit wiring.
//
// It also performs the thin impure *read* the differ depends on: the existing issue's
// body from BEFORE this run carries the previously-persisted Findings, so the upsert
// returns it as `priorBody` (null on the first run). The orchestrator parses it and
// diffs, alerting only on the new/worsened subset. Keep the read thin — all the diff
// logic stays pure in src/differ.mjs.

import { ISSUE_LABEL, markerFor, findMarkedIssue } from './report.mjs';

// Build an upsertIssue(args) closure bound to an authenticated Octokit client and a
// { owner, repo } target. `args` = { repoSlug, title, body }.
export function makeIssueUpserter(octokit, { owner, repo }) {
  return async function upsertIssue({ repoSlug, title, body }) {
    const marker = markerFor(repoSlug);

    // List open issues carrying our label, then match on the hidden marker so the
    // dedup is exact even if the label is shared across sites in one tracker.
    const open = await octokit.paginate(octokit.rest.issues.listForRepo, {
      owner, repo, state: 'open', labels: ISSUE_LABEL, per_page: 100,
    });
    const existing = findMarkedIssue(open, marker);

    if (existing) {
      // Capture the prior body BEFORE overwriting it — it holds the persisted Findings
      // the differ reads to alert only on the new/worsened subset.
      const priorBody = typeof existing.body === 'string' ? existing.body : null;
      const res = await octokit.rest.issues.update({
        owner, repo, issue_number: existing.number, title, body,
      });
      return {
        number: existing.number, created: false, url: res.data.html_url, priorBody,
      };
    }

    const res = await octokit.rest.issues.create({
      owner, repo, title, body, labels: [ISSUE_LABEL],
    });
    // First run for this site: no prior issue, so no prior Findings — all are new.
    return { number: res.data.number, created: true, url: res.data.html_url, priorBody: null };
  };
}
