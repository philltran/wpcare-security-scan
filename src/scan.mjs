// Vulnerability Scan orchestrator — the pure spine that wires the module seams:
//
//   enumerate (pure) -> fetch feed (impure, injected) -> normalize (pure)
//     -> match (pure) -> render + upsert issue (impure, injected) -> exit gate
//
// The impure edges (feed fetch, issue upsert) are injected so this orchestrator is
// testable end-to-end against a fixture tree without a live network or runner. The
// thin entrypoint (index.mjs) supplies the real implementations.

import { enumerateInventory } from './inventory.mjs';
import { normalizeWordfenceFeed } from './wordfence.mjs';
import { matchVulnerabilities, isAlertWorthy } from './matcher.mjs';
import { renderIssueTitle, renderIssueBody } from './report.mjs';

export async function runVulnScan({
  siteRoot,
  repoSlug,
  fetchFeed,
  upsertIssue,
} = {}) {
  const inventory = enumerateInventory(siteRoot);

  const rawFeed = await fetchFeed();
  const dataset = normalizeWordfenceFeed(rawFeed);

  const findings = matchVulnerabilities(inventory, dataset);
  const alertWorthy = findings.filter(isAlertWorthy);

  const title = renderIssueTitle(alertWorthy);
  const body = renderIssueBody(repoSlug, alertWorthy);

  await upsertIssue({ repoSlug, title, body });

  return {
    inventory,
    findings,
    alertWorthy: alertWorthy.length,
    exitCode: alertWorthy.length > 0 ? 1 : 0,
  };
}
