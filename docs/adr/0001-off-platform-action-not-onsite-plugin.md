# 1. Scan off-platform from a GitHub Action, not an on-site WordPress plugin

Date: 2026-06-14

Status: Accepted

## Context

The obvious approach to "scan a WP site for security holes" is a security plugin
(e.g. Wordfence). But (a) the Wordfence plugin is paid and works poorly on
Pantheon; (b) anything running *on* the site can be disabled by the very
compromise it is meant to detect — exactly what happened when the attacker
disabled the SSO plugin; (c) on-site scanning adds runtime load, and Pantheon's
read-only-code + no-arbitrary-cron model is hostile to it. An on-site watcher's
only real edge is real-time latency, which is worthless against an attacker who
already has the access to switch it off.

## Decision

All scanning runs off-platform in a GitHub Action. The **Vulnerability Scan**
reads the git repo (the canonical code inventory on Pantheon). **Drift Detection**
reads live state via Terminus with its own credentials. Nothing is installed on
the WordPress site.

## Consequences

- Tamper-resistant: a site compromise cannot disable the scanner.
- No Pantheon runtime load; the Wordfence-on-Pantheon problem never arises.
- Cost: drift is caught at the next scheduled run, not in real time; live reads
  require a Pantheon machine token held as a CI secret.
