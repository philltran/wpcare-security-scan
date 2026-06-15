// Report-only outdated detector — PURE decision module.
//
//   outdatedFinding(item, wporgResponse) -> Finding | null
//
// A plugin whose installed version trails the latest version published on
// wordpress.org — but which carries no known CVE and is not closed/removed — is a
// *report-only* `outdated` Finding. It belongs in the full report so a maintainer has
// the complete picture, but it must NEVER trip the failing workflow status: a plugin
// that is merely behind is not a security alert, and treating it as one is crying wolf
// (PRD user stories 23/24, CONTEXT.md "Abandoned plugin" — outdated *can* still be
// updated, unlike abandoned). Its remediation therefore points at *update* (the
// `wordpress-maintenance-updates` / `wordpress-update-flow` domain), not removal.
//
// The "latest available version" signal is REUSED from the same wordpress.org
// plugin_information response the Abandoned detector already fetches (src/wporg.mjs):
// a live plugin object carries a `version` field (the latest on wp.org). No new data
// source — the orchestrator folds this verdict into the existing per-slug wp.org loop.
//
// This module is the PURE half: given the *recorded* { statusCode, body } response it
// decides the verdict, so it is pinned by fixtures with no network. Boundaries:
//   - non-plugin (core/theme/dropin)            => null (plugin_information is plugin-specific)
//   - closed/removed (the Abandoned signal)     => null (owned by src/abandoned.mjs)
//   - missing installed version / latest version => null (nothing to compare; fail safe)
//   - installed >= latest                        => null (already current or ahead)
//
// Finding shape (the v1 contract; report-only, so no fixed_in/cve/url — there is no CVE
// to point at, and `latest` carries the update target):
//   { type:'outdated', severity, slug, version, kind, location, latest, remediation }

import { compareVersions } from './matcher.mjs';
import { isAbandonedResponse } from './abandoned.mjs';

// The latest version wordpress.org publishes for a live plugin: its top-level `version`
// field. A non-string / empty value means the latest is unknown.
function latestVersion(response) {
  const body = response && typeof response === 'object' ? response.body : null;
  if (!body || typeof body !== 'object') return null;
  const v = body.version;
  return typeof v === 'string' && v.trim() !== '' ? v : null;
}

export function outdatedFinding(item, response) {
  if (!item || item.kind !== 'plugin') return null;
  if (!item.version) return null;

  // Closed/removed is the Abandoned detector's verdict, not ours — never tell a
  // maintainer to "update" a plugin that has no update channel.
  if (isAbandonedResponse(response)) return null;

  const latest = latestVersion(response);
  if (!latest) return null;

  // Affected only when strictly behind the latest. At or ahead => current, no Finding.
  if (compareVersions(item.version, latest) >= 0) return null;

  return {
    type: 'outdated',
    severity: 'none',
    slug: item.slug,
    version: item.version,
    kind: item.kind,
    location: item.path,
    latest,
    remediation:
      `Update ${item.slug} from ${item.version} to ${latest} (the latest on `
      + 'wordpress.org). Report-only: no known CVE affects the installed version, so '
      + 'this does not fail the scan — route it into the normal update flow.',
  };
}
