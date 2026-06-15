// Issue upserter — the thin Octokit edge. Mocked at the boundary (a fake Octokit),
// not internally, so the dedup-and-persist contract is pinned without a live API:
// one issue per site found by the hidden marker, updated in place if present, and —
// for issue #6 — the existing issue's PRIOR body is returned so the orchestrator's
// pure differ can recover the previously persisted Findings and alert only on the
// new/worsened subset.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { makeIssueUpserter } from '../src/issue.mjs';
import { ISSUE_LABEL, markerFor } from '../src/report.mjs';

// A minimal fake Octokit: a paginate that returns a fixed issue list and rest stubs
// that record their calls.
function makeFakeOctokit({ existing = [] } = {}) {
  const calls = { update: [], create: [] };
  return {
    calls,
    paginate: async (_fn, _params) => existing,
    rest: {
      issues: {
        listForRepo: () => {},
        async update(args) {
          calls.update.push(args);
          return { data: { html_url: 'https://github.com/acme/site/issues/' + args.issue_number } };
        },
        async create(args) {
          calls.create.push(args);
          return { data: { number: 99, html_url: 'https://github.com/acme/site/issues/99' } };
        },
      },
    },
  };
}

const TARGET = { owner: 'acme', repo: 'site' };

test('updates the marked issue in place and returns its PRIOR body for the differ', async () => {
  const marker = markerFor('acme/site');
  const priorBody = `intro\n${marker}\n<!-- wpcare-security-scan:state [{"type":"cve"}] -->`;
  const octokit = makeFakeOctokit({
    existing: [{ number: 7, body: priorBody }],
  });
  const upsert = makeIssueUpserter(octokit, TARGET);

  const res = await upsert({ repoSlug: 'acme/site', title: 'T', body: 'new body' });

  assert.equal(res.created, false, 'an existing issue is updated in place');
  assert.equal(res.number, 7);
  assert.equal(res.priorBody, priorBody, 'the prior body is handed back for the diff');
  assert.equal(octokit.calls.update.length, 1, 'one in-place update, no duplicate');
  assert.equal(octokit.calls.create.length, 0);
});

test('on the first run (no marked issue) it creates one and reports no prior body', async () => {
  const octokit = makeFakeOctokit({ existing: [] });
  const upsert = makeIssueUpserter(octokit, TARGET);

  const res = await upsert({ repoSlug: 'acme/site', title: 'T', body: 'first body' });

  assert.equal(res.created, true);
  assert.equal(res.number, 99);
  assert.equal(res.priorBody, null, 'no prior issue => no prior Findings => all new');
  assert.equal(octokit.calls.create.length, 1);
  assert.deepEqual(octokit.calls.create[0].labels, [ISSUE_LABEL]);
});
