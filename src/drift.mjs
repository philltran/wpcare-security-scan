// Drift differ — PURE, deep module. The testable half of Drift Detection (mode 2).
//
//   detectDrift(snapshot, baseline) -> [ Finding ]
//   isDriftFinding(finding)          -> boolean
//
// Drift Detection diffs *live security-critical state* read off the running site
// against a committed, deliberately-blessed Baseline (.security/baseline.json,
// CONTEXT.md "Baseline"). The motivating incident: an attacker disabled the site's
// SSO plugin — drift is what catches that. This module is the PURE decision: given a
// live-state snapshot and the Baseline, it emits a drift Finding for an expected
// security control being turned off, a new/unexpected administrator account, and a
// changed critical option — and emits NOTHING when the snapshot matches a
// freshly-blessed Baseline (PRD user stories 25–29).
//
// The IMPURE half — the Terminus/WP-CLI reads that PRODUCE the snapshot, plus the
// credential and allow-list scoping — is the follow-up slice (#11). It is kept thin
// and is NOT unit-tested. This module defines the snapshot/Baseline SHAPE that #11's
// collector must fill, so it has a contract to populate.
//
// ── The Baseline contract (committed .security/baseline.json) ────────────────────
//   {
//     "version": 1,                       // contract version, for future migration
//     "blessedAt": "<ISO-8601>",          // when this Baseline was last re-blessed
//     "activePlugins":  [ "<slug>", ... ],// plugin slugs expected to stay ACTIVE
//     "activeThemes":   [ "<slug>", ... ],// theme slugs expected to stay ACTIVE
//     "administrators": [ "<login>", ...],// the full expected admin-account set
//     "criticalOptions": { "<name>": "<expected value>", ... } // curated allow-list
//   }
// The Baseline lists EXPECTED state, not exhaustive state: it watches for an expected
// control going AWAY and for a watched option CHANGING — not for additions (an extra
// active plugin is a maintenance action, an unwatched option is a routine edit). This
// is what keeps drift from crying wolf (user story 27).
//
// ── The live-state snapshot shape (what #11's collector produces) ────────────────
//   {
//     "activePlugins":  [ "<slug>", ... ],// from `wp plugin list --status=active`
//     "activeThemes":   [ "<slug>", ... ],// the active theme(s)
//     "administrators": [ "<login>", ...],// from `wp user list --role=administrator`
//     "criticalOptions": { "<name>": "<actual value>", ... } // `wp option get <name>`
//   }
// Values are compared as strings (WP-CLI emits option values as text), and lists are
// compared as SETS — order-insensitive, since a live read won't preserve Baseline
// ordering.
//
// ── How drift expresses itself as a Finding ──────────────────────────────────────
// Drift reuses the shared v1 Finding shape additively (mirroring how `outdated` added
// an optional `latest`, ADR-0007), so the SAME reporter renders it and no vuln-mode
// consumer changes:
//   { type, severity, slug, kind, location, expected?, actual?, remediation }
// New `type` values: 'security-control-disabled' | 'unexpected-admin' | 'changed-option'.
// The optional `expected`/`actual` strings carry the before/after for a changed option
// (and the active/inactive verdict for a disabled control). For an account or an option
// there is no plugin slug, so the account login / option name rides the `slug` slot and
// `location` records the live source (the admin set / the options table). Drift Findings
// are alert-worthy in drift mode via `isDriftFinding` here — they are deliberately NOT
// added to the vuln matcher's `ALERT_WORTHY` set, which is the vuln-mode contract.

const DRIFT_TYPES = new Set([
  'security-control-disabled',
  'unexpected-admin',
  'changed-option',
]);

export function isDriftFinding(finding) {
  return Boolean(finding) && DRIFT_TYPES.has(finding.type);
}

// Severity ordering for surfacing the worst drift first, aligned with the matcher's
// vocabulary. A rogue administrator (post-compromise persistence) is the most urgent;
// a disabled security control is next; a changed critical option is a notch below.
const SEVERITY_RANK = {
  critical: 5, high: 4, medium: 3, low: 2, none: 1, unknown: 0,
};

function asArray(v) {
  return Array.isArray(v) ? v : [];
}

function asStringSet(list) {
  return new Set(asArray(list).map((s) => String(s)));
}

// A disabled-control Finding for an expected plugin/theme that is no longer active.
function disabledControlFinding(slug, kind) {
  return {
    type: 'security-control-disabled',
    severity: 'high',
    slug,
    kind,
    location: `active_${kind}s`,
    expected: 'active',
    actual: 'inactive',
    remediation:
      `Re-activate the ${kind} "${slug}" — the Baseline expects it active but the live `
      + 'site has it disabled. If the deactivation was intentional, re-bless the Baseline '
      + 'so it stops alerting.',
  };
}

// An unexpected-admin Finding for an account present live but absent from the Baseline.
function unexpectedAdminFinding(login) {
  return {
    type: 'unexpected-admin',
    severity: 'critical',
    slug: login,
    kind: 'account',
    location: 'administrators',
    remediation:
      `Investigate the administrator account "${login}" — it is not in the Baseline's `
      + 'expected admin set. A new administrator can be post-compromise persistence: '
      + 'confirm it is legitimate, then either remove it or re-bless the Baseline.',
  };
}

// A changed-option Finding for a watched critical option whose live value drifted.
function changedOptionFinding(name, expected, actual) {
  return {
    type: 'changed-option',
    severity: 'medium',
    slug: name,
    kind: 'option',
    location: 'options',
    expected,
    actual,
    remediation:
      `Review the critical option "${name}": the Baseline expects "${expected}" but the `
      + `live value is "${actual}". If the change is intended, re-bless the Baseline; `
      + 'otherwise restore the expected value.',
  };
}

export function detectDrift(snapshot, baseline) {
  if (!snapshot || typeof snapshot !== 'object') return [];
  if (!baseline || typeof baseline !== 'object') return [];

  const findings = [];

  // 1. Expected active plugins/themes that are no longer active — a disabled control.
  const livePlugins = asStringSet(snapshot.activePlugins);
  for (const slug of asArray(baseline.activePlugins)) {
    if (!livePlugins.has(String(slug))) {
      findings.push(disabledControlFinding(String(slug), 'plugin'));
    }
  }
  const liveThemes = asStringSet(snapshot.activeThemes);
  for (const slug of asArray(baseline.activeThemes)) {
    if (!liveThemes.has(String(slug))) {
      findings.push(disabledControlFinding(String(slug), 'theme'));
    }
  }

  // 2. Administrator accounts present live but not in the expected set — a rogue admin.
  const expectedAdmins = asStringSet(baseline.administrators);
  for (const login of asArray(snapshot.administrators)) {
    if (!expectedAdmins.has(String(login))) {
      findings.push(unexpectedAdminFinding(String(login)));
    }
  }

  // 3. Watched critical options whose live value differs from the blessed value. Only
  // the allow-listed options are diffed (the Baseline's criticalOptions keys), so a
  // routine edit to an unwatched option never registers as drift (user story 27).
  const allowList =
    baseline.criticalOptions && typeof baseline.criticalOptions === 'object'
      ? baseline.criticalOptions
      : {};
  const liveOptions =
    snapshot.criticalOptions && typeof snapshot.criticalOptions === 'object'
      ? snapshot.criticalOptions
      : {};
  for (const name of Object.keys(allowList)) {
    const expected = String(allowList[name]);
    // A watched option missing live reads as an empty live value (the option was
    // deleted) — still a drift from the blessed value.
    const actual = name in liveOptions ? String(liveOptions[name]) : '';
    if (expected !== actual) {
      findings.push(changedOptionFinding(name, expected, actual));
    }
  }

  // Surface the worst first — a stable, most-severe-first sort so a rogue admin leads
  // and equal-severity drift keeps detection order (matching the vuln matcher's idiom).
  findings.sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));

  return findings;
}
