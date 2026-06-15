// The Action entrypoint — thin glue only. Reads inputs, wires the real impure edges
// (feed fetch, Octokit issue upsert) into the pure orchestrator, then sets the
// failing workflow status from alert-worthy Findings. All logic is in testable
// modules; keep this file boring.

import * as core from '@actions/core';
import * as github from '@actions/github';

import { runVulnScan } from './scan.mjs';
import { fetchWordfenceFeed } from './feed.mjs';
import { makeIssueUpserter } from './issue.mjs';

export async function run() {
  const mode = core.getInput('mode') || 'vuln';
  if (mode !== 'vuln') {
    // Drift / both are later phases; this slice ships mode=vuln only.
    core.setFailed(`mode "${mode}" is not supported yet (this build ships mode=vuln).`);
    return;
  }

  const token = core.getInput('github-token', { required: true });
  // Optional path override for non-standard layouts; default to the checked-out repo.
  const siteRoot = core.getInput('site-path') || process.env.GITHUB_WORKSPACE || '.';

  const { owner, repo } = github.context.repo;
  const repoSlug = `${owner}/${repo}`;
  const octokit = github.getOctokit(token);

  const result = await runVulnScan({
    siteRoot,
    repoSlug,
    fetchFeed: () => fetchWordfenceFeed(),
    upsertIssue: makeIssueUpserter(octokit, { owner, repo }),
  });

  core.setOutput('finding-count', String(result.findings.length));
  core.setOutput('alert-count', String(result.alertWorthy));

  core.info(
    `Scanned ${result.inventory.length} inventory item(s); `
    + `${result.findings.length} Finding(s), ${result.alertWorthy} alert-worthy.`,
  );

  if (result.exitCode !== 0) {
    core.setFailed(
      `${result.alertWorthy} alert-worthy Finding(s) — see the security scan issue.`,
    );
  }
}

run().catch((err) => {
  core.setFailed(err instanceof Error ? err.message : String(err));
});
