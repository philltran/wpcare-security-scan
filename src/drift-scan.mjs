// Drift Detection orchestrator — the PURE spine of mode 2, mirroring runVulnScan.
//
//   collect live snapshot (impure, injected) -> detectDrift vs the Baseline (pure)
//     -> render + upsert the deduped issue (impure, injected) -> diff vs prior
//     persisted Findings (pure) -> fail-on gate (pure)
//
// The impure edges — the Terminus collector that PRODUCES the snapshot
// (src/collector.mjs) and the re-bless PR opener (src/rebless.mjs) — are injected, so
// this orchestrator is exercised end-to-end offline. The thin entrypoint (index.mjs)
// supplies the real implementations.
//
// Failure semantics (ADR-0010): the pure differ never throws and never fabricates
// drift from a bad read, but the impure collector surfacing an error must make the run
// RED, not a silent green — so a collector rejection propagates out of here loudly and
// NO issue is upserted (we have no trustworthy snapshot to report). detectDrift over a
// good-but-mismatched snapshot is the only source of Findings.
//
// The re-bless path (update-baseline=true) is a separate outcome: it regenerates the
// Baseline from live state and opens a PR carrying it + the diff, and deliberately does
// NOT upsert the alert issue — re-blessing is an operator action, not a scan.

import { detectDrift } from './drift.mjs';
import { finalizeFindings } from './report-gate.mjs';
import { buildBaselineFromSnapshot, renderBaselineDiff } from './baseline.mjs';

// Collect the live snapshot through the injected impure edge. A collector failure is
// re-thrown with context so the run fails loudly (ADR-0010) rather than silently
// scanning nothing; the pure differ is never handed a fabricated snapshot.
async function collect(collectSnapshot) {
  if (typeof collectSnapshot !== 'function') {
    throw new Error('drift collector is not configured (no collectSnapshot edge).');
  }
  let snapshot;
  try {
    snapshot = await collectSnapshot();
  } catch (err) {
    throw new Error(
      `drift collector failed to read live state: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
  if (!snapshot || typeof snapshot !== 'object') {
    throw new Error('drift collector returned no usable snapshot.');
  }
  return snapshot;
}

// Produce the drift Finding list: read live state (loud failure on a bad read — never
// a fabricated snapshot) and run the pure differ against the committed Baseline. With
// NO Baseline (bootstrap before the first re-bless) the differ yields no Findings — a
// missing Baseline is not itself drift. Exported so `both` mode can merge these with
// the vuln Findings into one deduped issue and finalize once.
export async function produceDriftFindings({ baseline, collectSnapshot } = {}) {
  const snapshot = await collect(collectSnapshot);
  return detectDrift(snapshot, baseline);
}

// The re-bless outcome: regenerate the Baseline from current live state and open a PR
// carrying it + the human-readable diff (ADR-0010). Never a blind direct write, and
// never an alert-issue upsert.
async function reBless({ collectSnapshot, baseline, openBaselinePr, blessedAt }) {
  if (typeof openBaselinePr !== 'function') {
    throw new Error('update-baseline requires an openBaselinePr edge.');
  }
  const snapshot = await collect(collectSnapshot);
  const nextBaseline = buildBaselineFromSnapshot(snapshot, baseline, { blessedAt });
  const diff = renderBaselineDiff(baseline, nextBaseline);
  // Pretty-print + trailing newline so the committed file is diff-friendly.
  const baselineJson = `${JSON.stringify(nextBaseline, null, 2)}\n`;

  const pr = await openBaselinePr({ baseline: nextBaseline, baselineJson, diff });
  return {
    mode: 'update-baseline',
    findings: [],
    alertWorthy: 0,
    newOrWorsened: 0,
    exitCode: 0,
    baseline: nextBaseline,
    pr: pr || null,
  };
}

export async function runDriftScan({
  repoSlug,
  baseline,
  failOn,
  updateBaseline = false,
  collectSnapshot,
  upsertIssue,
  openBaselinePr,
  blessedAt,
} = {}) {
  // Re-bless is a distinct outcome that short-circuits the alert path entirely.
  if (updateBaseline) {
    return reBless({ collectSnapshot, baseline, openBaselinePr, blessedAt });
  }

  // Read live state + diff vs the Baseline (loud failure on a bad read — no issue
  // upsert, no fabricated drift).
  const findings = await produceDriftFindings({ baseline, collectSnapshot });

  // Render + upsert the deduped issue, diff to new/worsened, apply the fail-on gate —
  // the shared tail every mode runs (src/report-gate.mjs).
  const finalized = await finalizeFindings({ repoSlug, findings, failOn, upsertIssue });

  return {
    mode: 'drift',
    ...finalized,
  };
}
