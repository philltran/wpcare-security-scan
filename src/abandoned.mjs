// Abandoned/closed plugin detector — PURE decision module.
//
//   isAbandonedResponse(wporgResponse) -> boolean
//   abandonedFinding(item, wporgResponse) -> Finding | null
//
// A plugin that has been *closed* or *removed* on wordpress.org has no update
// channel: the WordPress update screen will never flag it and the site owner cannot
// patch it. Its remediation is therefore *removal*, never *update* (CONTEXT.md
// "Abandoned plugin"; ADR-0003 names the data-source split).
//
// The live wordpress.org plugin_information query is a thin IMPURE edge (src/wporg.mjs,
// mirroring src/feed.mjs); it is verified by a recorded transcript, not a live unit
// test. This module is the PURE half: given the *recorded* response it decides the
// closed/removed signal and shapes the Finding, so the decision is pinned by fixtures
// with no network.
//
// The closed/removed signal, modeled the way the feed loader models its responses:
// wordpress.org's plugin_information endpoint returns a full plugin object (200, no
// `error`) for a live/maintained plugin, and an error for one that is gone — either a
// non-2xx status (e.g. 404 "Plugin not found.") or a 200 body carrying an `error`
// field (e.g. {"error":"closed", "closed":true}). Either signal => abandoned. Anything
// ambiguous (a missing/garbage response from a transport error) is deliberately NOT
// treated as abandoned, so a flaky lookup never fires a false alert.
//
// Finding shape (the v1 contract; same shape as the embedded Finding — no fixed_in /
// cve / url, since there is no patch to point at):
//   { type:'abandoned', severity, slug, version, kind, location, remediation }
// `abandoned` is one of the matcher's ALERT_WORTHY types, so the Finding trips the gate.

function isOk(statusCode) {
  return typeof statusCode === 'number' && statusCode >= 200 && statusCode < 300;
}

// Decide the closed/removed signal from a *recorded* wp.org response of the shape the
// thin edge returns: { statusCode, body }. Pure and fixture-driven.
export function isAbandonedResponse(response) {
  if (!response || typeof response !== 'object') return false;
  const { statusCode, body } = response;

  // A non-2xx status (404 "Plugin not found.", etc.) is a removed/unknown plugin.
  if (statusCode !== undefined && !isOk(statusCode)) return true;

  // A 2xx body carrying an `error` field (e.g. {"error":"closed"}) is a closed plugin.
  if (body && typeof body === 'object' && body.error) return true;

  // An explicit closed flag, defensively, even without the error string.
  if (body && typeof body === 'object' && body.closed === true) return true;

  return false;
}

// Build the Abandoned Finding for an item. Closed and removed plugins differ only in
// the human note; both are no-update-channel and resolved by removal.
function remediationFor(item, body) {
  const closedDate = body && typeof body === 'object' ? body.closed_date : null;
  const when = closedDate ? ` (closed ${closedDate})` : '';
  return (
    `Remove the plugin "${item.slug}"${when}: it has been closed or removed on `
    + 'wordpress.org and no longer receives security fixes, so it cannot be patched '
    + 'in place. Replace it with a maintained alternative or delete it.'
  );
}

export function abandonedFinding(item, response) {
  if (!item || item.kind !== 'plugin') return null;
  if (!isAbandonedResponse(response)) return null;

  const body = response && typeof response === 'object' ? response.body : null;

  return {
    type: 'abandoned',
    severity: 'high',
    slug: item.slug,
    version: item.version,
    kind: item.kind,
    location: item.path,
    remediation: remediationFor(item, body),
  };
}
