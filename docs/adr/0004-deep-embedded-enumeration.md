# 4. Enumerate the filesystem deeply, not WordPress's plugin list

Date: 2026-06-14

Status: Accepted

## Context

The incident's root cause was vulnerable code that was *present but not a
registered, active plugin* — a Slider Revolution bundled inside a premium theme.
`wp plugin list` and WordPress's update transient would never have seen it, which
is precisely why "we ran updates regularly" did not help.

## Decision

The **Vulnerability Scan** enumerates every code surface under `wp-content`
(plugins, mu-plugins, all themes including inactive, drop-ins) plus core, **and
recursively sniffs for plugin/theme headers nested inside other plugins or
themes**, reading the `Version:` header to identify **Embedded plugins**.
Activation status is ignored entirely.

## Consequences

- Catches the exact blind spot: bundled, inactive, no-update-channel code.
- Cost: recursive header sniffing occasionally flags a legitimately-vendored copy
  as an Embedded plugin, which a human must triage; slightly more scan logic than
  enumerating top-level directories only.
