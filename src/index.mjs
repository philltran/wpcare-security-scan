// The Action entrypoint — thin glue only. Reads inputs, wires the real impure edges
// (feed fetch, Octokit issue upsert, the Terminus drift collector, the re-bless PR
// opener) into the pure orchestrators, then sets the failing workflow status from
// alert-worthy Findings. All logic is in testable modules; keep this file boring.

import { join } from 'node:path';

import * as core from '@actions/core';
import * as github from '@actions/github';

import { runVulnScan } from './scan.mjs';
import { runDriftScan } from './drift-scan.mjs';
import { runCombinedScan } from './combined.mjs';
import { fetchWordfenceFeed, loadFeedFromFile } from './feed.mjs';
import { fetchPluginInfo } from './wporg.mjs';
import { fetchWpscanPlugin, normalizeWpscanResponse } from './wpscan.mjs';
import { makeIssueUpserter } from './issue.mjs';
import { makeSnapshotCollector } from './collector.mjs';
import { makeBaselinePrOpener } from './rebless.mjs';
import { loadBaseline, SEEDED_CRITICAL_OPTIONS } from './baseline.mjs';

const VALID_MODES = new Set(['vuln', 'drift', 'both']);
const BASELINE_PATH = '.security/baseline.json';

// Build the optional WPScan cross-reference edge from a token (issue #7). Zero-secret
// default: with NO token the edge is undefined and the scan runs unchanged. The token
// is a SECRET — masked so the runner scrubs any accidental echo.
function makeWpscanEdge(wpscanToken) {
  if (!wpscanToken) return undefined;
  core.setSecret(wpscanToken);
  return async (slug) => normalizeWpscanResponse(await fetchWpscanPlugin(slug, wpscanToken));
}

// Build the Terminus drift collector edge from the Pantheon inputs. The machine token
// is a SECRET — masked so it never surfaces in logs. The Baseline's criticalOptions
// keys drive which options the collector reads (so it reads only what the differ
// compares); with no Baseline yet (bootstrap) it reads the seeded allow-list so a
// re-bless can seed from a real snapshot.
function makeCollectorEdge({ site, env, token, baseline }) {
  const allowOptionNames = baseline && baseline.criticalOptions
    ? Object.keys(baseline.criticalOptions)
    : [...SEEDED_CRITICAL_OPTIONS];
  return makeSnapshotCollector({ site, env, token, allowOptionNames });
}

export async function run() {
  const mode = (core.getInput('mode') || 'vuln').trim().toLowerCase();
  if (!VALID_MODES.has(mode)) {
    core.setFailed(`mode "${mode}" is not supported (use vuln | drift | both).`);
    return;
  }

  const token = core.getInput('github-token', { required: true });
  const siteRoot = core.getInput('site-path') || process.env.GITHUB_WORKSPACE || '.';
  // The `fail-on` threshold gates ONLY the failing workflow status; an empty/unknown
  // value defaults to `low` inside the gate (never silently disarmed).
  const failOn = core.getInput('fail-on') || 'low';

  const { owner, repo } = github.context.repo;
  const repoSlug = `${owner}/${repo}`;
  const octokit = github.getOctokit(token);
  const upsertIssue = makeIssueUpserter(octokit, { owner, repo });
  const fetchWpscanData = makeWpscanEdge(core.getInput('wpscan-token'));

  // The feed source (ADR-0013/0014). `feed-path` reads a pre-fetched feed from disk so the
  // workflow can cache it (actions/cache) or point at a mirror — avoiding the 123 MB
  // per-run download and the 1-req/30-min v3 rate limit. With no feed-path, the Action
  // fetches the v3 feed directly and a free wordfence-token is REQUIRED for any mode that
  // runs the Vulnerability Scan (vuln | both), not for drift-only. The token is a SECRET.
  const feedPath = core.getInput('feed-path');
  const wordfenceToken = core.getInput('wordfence-token');
  if ((mode === 'vuln' || mode === 'both') && !feedPath && !wordfenceToken) {
    core.setFailed(
      'wordfence-token is required for mode vuln | both (the free no-auth Wordfence feed '
      + 'was removed): generate a free token in your Wordfence account → Integrations and '
      + 'pass it as wordfence-token, OR pre-fetch the feed and pass feed-path (ADR-0013/0014).',
    );
    return;
  }
  if (wordfenceToken) core.setSecret(wordfenceToken);
  // One feed source for every mode that needs it: a cached/mirrored file when feed-path is
  // set, else a direct Wordfence v3 fetch.
  const fetchFeed = feedPath
    ? () => loadFeedFromFile(feedPath)
    : () => fetchWordfenceFeed(wordfenceToken);

  // ── Drift wiring (mode drift | both, and the update-baseline dispatch) ──────────
  let driftEnv = null;
  if (mode === 'drift' || mode === 'both') {
    const pantheonSite = core.getInput('pantheon-site', { required: true });
    const pantheonEnv = core.getInput('pantheon-env') || 'live';
    const pantheonToken = core.getInput('pantheon-machine-token', { required: true });
    core.setSecret(pantheonToken);

    const baselinePath = join(siteRoot, BASELINE_PATH);
    // A present-but-malformed Baseline throws (operator error, fail loud); an absent
    // one is null (bootstrap — handled by the differ / re-bless).
    const baseline = loadBaseline(baselinePath);
    const collectSnapshot = makeCollectorEdge({
      site: pantheonSite, env: pantheonEnv, token: pantheonToken, baseline,
    });
    driftEnv = { baseline, collectSnapshot };
  }

  // ── The update-baseline dispatch: re-bless via a PR, never a scan ───────────────
  const updateBaseline = core.getBooleanInput('update-baseline');
  if (updateBaseline) {
    if (mode === 'vuln') {
      core.setFailed('update-baseline requires mode drift or both (it re-blesses the drift Baseline).');
      return;
    }
    const result = await runDriftScan({
      repoSlug,
      baseline: driftEnv.baseline,
      updateBaseline: true,
      collectSnapshot: driftEnv.collectSnapshot,
      openBaselinePr: makeBaselinePrOpener(octokit, { owner, repo }),
    });
    core.info(`Re-bless PR opened: ${result.pr && result.pr.url ? result.pr.url : '(see PRs)'}.`);
    core.setOutput('baseline-pr-url', result.pr && result.pr.url ? result.pr.url : '');
    return;
  }

  // ── The scan paths ──────────────────────────────────────────────────────────────
  let result;
  if (mode === 'vuln') {
    result = await runVulnScan({
      siteRoot, repoSlug, failOn, upsertIssue,
      fetchFeed,
      fetchPluginInfo: (slug) => fetchPluginInfo(slug),
      fetchWpscanData,
    });
  } else if (mode === 'drift') {
    result = await runDriftScan({
      repoSlug, failOn, upsertIssue,
      baseline: driftEnv.baseline,
      collectSnapshot: driftEnv.collectSnapshot,
    });
  } else {
    result = await runCombinedScan({
      siteRoot, repoSlug, failOn, upsertIssue,
      baseline: driftEnv.baseline,
      collectSnapshot: driftEnv.collectSnapshot,
      fetchFeed,
      fetchPluginInfo: (slug) => fetchPluginInfo(slug),
      fetchWpscanData,
    });
  }

  core.setOutput('finding-count', String(result.findings.length));
  core.setOutput('alert-count', String(result.alertWorthy));
  core.setOutput('new-count', String(result.newOrWorsened));

  core.info(
    `mode=${mode}: ${result.findings.length} Finding(s), ${result.alertWorthy} alert-worthy, `
    + `${result.newOrWorsened} new/worsened.`,
  );

  // The failing workflow status gates ONLY on the new/worsened subset, so an unchanged
  // site (its Findings already filed in the deduped issue) runs green.
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
