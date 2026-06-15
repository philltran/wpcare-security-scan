// The Action entrypoint — thin glue only. Reads inputs, wires the real impure edges
// (feed fetch, Octokit issue upsert) into the pure orchestrator, then sets the
// failing workflow status from alert-worthy Findings. All logic is in testable
// modules; keep this file boring.

import * as core from '@actions/core';
import * as github from '@actions/github';

import { runVulnScan } from './scan.mjs';
import { fetchWordfenceFeed } from './feed.mjs';
import { fetchPluginInfo } from './wporg.mjs';
import { fetchWpscanPlugin, normalizeWpscanResponse } from './wpscan.mjs';
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

  // The `fail-on` severity threshold gates ONLY the failing workflow status; the issue
  // is always upserted with every Finding. An empty/unknown value defaults to `low`
  // inside runVulnScan (the gate is never silently disarmed). See scan.mjs.
  const failOn = core.getInput('fail-on') || 'low';

  // Optional WPScan cross-reference (issue #7). Zero-secret default: with NO token the
  // edge is simply not injected and the Vulnerability Scan runs exactly as before. The
  // token is a SECRET — it is read from the Action input only and never logged. When
  // present, mark it so the runner masks any accidental echo in logs.
  const wpscanToken = core.getInput('wpscan-token');
  let fetchWpscanData;
  if (wpscanToken) {
    core.setSecret(wpscanToken);
    fetchWpscanData = async (slug) =>
      normalizeWpscanResponse(await fetchWpscanPlugin(slug, wpscanToken));
  }

  const { owner, repo } = github.context.repo;
  const repoSlug = `${owner}/${repo}`;
  const octokit = github.getOctokit(token);

  const result = await runVulnScan({
    siteRoot,
    repoSlug,
    failOn,
    fetchFeed: () => fetchWordfenceFeed(),
    fetchPluginInfo: (slug) => fetchPluginInfo(slug),
    fetchWpscanData,
    upsertIssue: makeIssueUpserter(octokit, { owner, repo }),
  });

  core.setOutput('finding-count', String(result.findings.length));
  core.setOutput('alert-count', String(result.alertWorthy));
  core.setOutput('new-count', String(result.newOrWorsened));

  core.info(
    `Scanned ${result.inventory.length} inventory item(s); `
    + `${result.findings.length} Finding(s), ${result.alertWorthy} alert-worthy, `
    + `${result.newOrWorsened} new/worsened.`,
  );

  // The failing workflow status gates ONLY on the new/worsened subset, so an
  // unchanged site (its Findings already filed in the deduped issue) runs green.
  if (result.exitCode !== 0) {
    core.setFailed(
      `${result.newOrWorsened} new or worsened alert-worthy Finding(s) `
      + '— see the security scan issue.',
    );
  }
}

run().catch((err) => {
  core.setFailed(err instanceof Error ? err.message : String(err));
});
