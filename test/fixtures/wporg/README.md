# Recorded wordpress.org plugin_information transcripts

These fixtures pin the **pure** Abandoned/closed decision (`src/abandoned.mjs`)
offline. The **impure** edge (`src/wporg.mjs` — the live wordpress.org query) is
deliberately *not* covered by a live unit test; it is verified by example run / a
recorded transcript, exactly as the Wordfence feed loader (`src/feed.mjs`) is.

Each file is a recorded `{ statusCode, body }` as `fetchPluginInfo()` returns it.

## How the responses were recorded

The wordpress.org plugin-information endpoint is free and needs no auth:

```
curl -s 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=<slug>'
```

- **`live.json`** — `request[slug]=akismet` (a maintained plugin): HTTP 200, a full
  plugin object (`name`, `version`, `download_link`, …), **no** `error` field.
  -> `isAbandonedResponse` is `false`, no Finding.
- **`closed.json`** — a plugin closed on wordpress.org: HTTP 200 with an `error`
  field (e.g. `{"error":"closed", "closed":true, "closed_date":"…"}`).
  -> `isAbandonedResponse` is `true`, an Abandoned Finding (remediation = remove).
- **`removed.json`** — a slug that no longer exists: HTTP 404 with
  `{"error":"Plugin not found."}`.
  -> `isAbandonedResponse` is `true`, an Abandoned Finding (remediation = remove).

The bodies here are trimmed/illustrative recordings (the live `live.json` object
carries far more fields); only the shape the decision reads — presence of `error` /
`closed` and the HTTP status — is load-bearing.

## Updating

If wordpress.org changes the closed/removed signal, re-record with the `curl` above
and adjust `src/abandoned.mjs` (the pure layer) plus `test/abandoned.test.mjs`. The
fetch in `src/wporg.mjs` stays thin — no decision logic belongs there.
