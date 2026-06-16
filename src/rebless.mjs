// Re-bless PR opener — the IMPURE edge that carries a regenerated Baseline into a PR
// (ADR-0010), never a blind direct commit. The pure half (regenerating the Baseline
// and rendering the diff) lives in src/baseline.mjs and src/drift-scan.mjs; this module
// is only the thin Octokit/git-data wiring and is NOT unit-tested.
//
// Why a PR, not a push: re-blessing a COMPROMISED live state would silently bless the
// compromise into the Baseline. The PR forces a human to eyeball the diff (in the PR
// body) before merging — merging IS the deliberate re-bless. Bootstrap (no prior
// Baseline) is the same path with a seed/empty diff. The elevated contents:write +
// pull-requests:write permissions are scoped to the dispatch job only.
//
// Implementation: commit the regenerated .security/baseline.json onto a fresh branch
// via the Git Data API (create blob -> tree -> commit -> ref), then open the PR. Using
// the API (not a local git checkout) keeps this independent of the runner's working
// tree and avoids shelling out to git.

const BASELINE_PATH = '.security/baseline.json';

// makeBaselinePrOpener(octokit, { owner, repo }) -> async ({ baselineJson, diff }) => { url }
//
// The returned closure is the `openBaselinePr` edge injected into runDriftScan.
export function makeBaselinePrOpener(octokit, { owner, repo }) {
  return async function openBaselinePr({ baselineJson, diff }) {
    // Anchor on the default branch's current tip.
    const { data: repoInfo } = await octokit.rest.repos.get({ owner, repo });
    const base = repoInfo.default_branch;
    const { data: baseRef } = await octokit.rest.git.getRef({
      owner, repo, ref: `heads/${base}`,
    });
    const baseSha = baseRef.object.sha;
    const { data: baseCommit } = await octokit.rest.git.getCommit({
      owner, repo, commit_sha: baseSha,
    });

    // A unique branch per dispatch so concurrent re-blesses don't collide.
    const branch = `wpcare/rebless-baseline-${Date.now()}`;

    // Blob -> tree (one file change on top of the base tree) -> commit -> branch ref.
    const { data: blob } = await octokit.rest.git.createBlob({
      owner, repo, content: baselineJson, encoding: 'utf-8',
    });
    const { data: tree } = await octokit.rest.git.createTree({
      owner,
      repo,
      base_tree: baseCommit.tree.sha,
      tree: [{ path: BASELINE_PATH, mode: '100644', type: 'blob', sha: blob.sha }],
    });
    const { data: commit } = await octokit.rest.git.createCommit({
      owner,
      repo,
      message: 'chore(security): re-bless drift Baseline from live state',
      tree: tree.sha,
      parents: [baseSha],
    });
    await octokit.rest.git.createRef({
      owner, repo, ref: `refs/heads/${branch}`, sha: commit.sha,
    });

    const body = [
      'Re-bless the drift Detection **Baseline** (`.security/baseline.json`) from current',
      'live state. Review the diff below before merging — **merging this PR is the',
      'deliberate re-bless**. Do not merge if any change is unexpected: that would bless a',
      'possible compromise into the Baseline.',
      '',
      '## Drift being blessed',
      '',
      diff,
    ].join('\n');

    const { data: pr } = await octokit.rest.pulls.create({
      owner,
      repo,
      title: 'chore(security): re-bless drift Baseline',
      head: branch,
      base,
      body,
    });

    return { url: pr.html_url, number: pr.number, branch };
  };
}
