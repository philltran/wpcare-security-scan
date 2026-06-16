// Regression guard for the v0.12.1 fix: action.yml must contain NO `${{ }}` template
// expressions.
//
// The github-token / wpscan-token / pantheon-machine-token input descriptions once
// embedded literal `${{ secrets.* }}` example text. GitHub evaluates `${{ }}` anywhere in
// an action metadata file, and `secrets` is a workflow-only context, so the Action failed
// to load on first real use ("Unrecognized named-value: secrets"). This is a JS action
// (runs.using: node24) with no composite steps, so its metadata needs zero expressions —
// any `${{ }}` is the bug. Pinned here so it can never silently come back.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { findTemplateExpressions } from '../src/action-metadata-safety.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ACTION_YML = join(HERE, '..', 'action.yml');

test('a literal ${{ secrets.* }} in a description is flagged (the v0.12.1 regression)', () => {
  const yaml = "    description: 'Pass ${{ secrets.GITHUB_TOKEN }}.'\n";
  assert.deepEqual(findTemplateExpressions(yaml), ['${{ secrets.GITHUB_TOKEN }}']);
});

test('any ${{ }} expression is flagged, not just secrets', () => {
  assert.equal(findTemplateExpressions('${{ inputs.mode }}').length, 1);
  assert.equal(findTemplateExpressions('${{ github.event.number }}').length, 1);
});

test('plain text naming a secret (no braces) is NOT flagged', () => {
  // The fixed descriptions still NAME the secrets as guidance — that must stay clean.
  const yaml = 'Pass the workflow secrets.GITHUB_TOKEN; it is masked in logs.';
  assert.deepEqual(findTemplateExpressions(yaml), []);
});

test('an expression folded across lines is still caught', () => {
  const yaml = 'description: >-\n  pass ${{\n  secrets.WPSCAN_API_TOKEN }} here\n';
  assert.equal(findTemplateExpressions(yaml).length, 1);
});

test('the shipped action.yml contains no ${{ }} template expressions', () => {
  const yaml = readFileSync(ACTION_YML, 'utf8');
  const found = findTemplateExpressions(yaml);
  assert.deepEqual(
    found,
    [],
    `action.yml must not contain template expressions (this is a node action with no `
      + `composite steps) — found: ${found.join(', ')}`,
  );
});
