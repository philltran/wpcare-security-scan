// Issue #14 — guardrail the per-site workflow against `pull_request_target`.
//
// `pull_request_target` runs in the BASE repo's context with its read/write
// GITHUB_TOKEN and secrets in scope, but a fork PR's head is attacker-controlled —
// the classic Actions privilege-escalation foot-gun. The Action only reads files on
// disk and upserts an issue, so the per-site workflow uses `pull_request` (shift-left)
// and must never drift to `pull_request_target` as later slices add behavior that
// checks out, reads, or executes PR-supplied content.
//
// This is the feasible "CI/lint check": a PURE function over workflow YAML text that
// flags any `pull_request_target` trigger, kept in the existing `node --test` suite
// (no new dependency, no separate workflow job — matches how this repo tests itself).
// A `#`-comment mention (the README/examples deliberately name the forbidden trigger to
// explain WHY) is NOT a violation — only an actual trigger key is.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { findPullRequestTargetTrigger } from '../src/workflow-safety.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const EXAMPLES_DIR = join(HERE, '..', 'examples');

test('a workflow that triggers on pull_request_target is flagged', () => {
  const yaml = [
    'name: bad',
    'on:',
    '  pull_request_target:',
    'jobs: {}',
  ].join('\n');
  assert.equal(findPullRequestTargetTrigger(yaml), true);
});

test('the list/flow form of pull_request_target is flagged', () => {
  const yaml = 'on: [push, pull_request_target]\n';
  assert.equal(findPullRequestTargetTrigger(yaml), true);
});

test('a plain pull_request trigger is NOT flagged', () => {
  const yaml = [
    'name: good',
    'on:',
    '  pull_request:',
    'jobs: {}',
  ].join('\n');
  assert.equal(findPullRequestTargetTrigger(yaml), false);
});

test('a `#`-comment mention of pull_request_target is NOT flagged', () => {
  // The example workflows deliberately name the forbidden trigger in a comment to
  // explain the prohibition — that must not trip the guard.
  const yaml = [
    '# SECURITY: this uses `pull_request`, NOT `pull_request_target`.',
    'on:',
    '  pull_request:   # not pull_request_target',
    'jobs: {}',
  ].join('\n');
  assert.equal(findPullRequestTargetTrigger(yaml), false);
});

test('every shipped example workflow stays on pull_request, never pull_request_target', () => {
  const files = readdirSync(EXAMPLES_DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
  assert.ok(files.length > 0, 'expected at least one example workflow to guard');
  for (const file of files) {
    const yaml = readFileSync(join(EXAMPLES_DIR, file), 'utf8');
    assert.equal(
      findPullRequestTargetTrigger(yaml),
      false,
      `${file} must not use pull_request_target (issue #14)`,
    );
  }
});
