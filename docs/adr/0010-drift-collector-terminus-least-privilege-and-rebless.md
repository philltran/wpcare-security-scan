# 10. The drift collector edge: Terminus auth, user-scoped least privilege, the critical-options allow-list, and PR-based re-bless

Date: 2026-06-15

Status: Accepted (amended 2026-06-18 — see "Amendment: `terminus remote:wp` is SSH-key-gated")

## Context

ADR-0009 shipped the **pure** half of Drift Detection (mode 2): the Baseline file
shape, the live-state snapshot shape, and the pure `detectDrift` differ. This ADR
records the **impure edge** — issue #11 — that produces the snapshot from a live
Pantheon site and re-blesses the Baseline. #11 was held as HITL because it carries the
two security rulings the PRD deferred (CONTEXT.md "Deferred to the PRD / implementation"):
the **least-privilege scoping of the Pantheon machine token**, and the **exact
critical-options allow-list**. Both are settled here, plus the collector mechanism, the
re-bless mechanics, and the per-site wiring surface.

## Decision

### Collector mechanism — `terminus remote:wp` over SSH against **live**

The collector authenticates once with `terminus auth:login --machine-token=$TOKEN`, then
reads the snapshot with read-only WP-CLI verbs over SSH:

```
terminus remote:wp <site>.live -- plugin list --status=active --format=json   # activePlugins
terminus remote:wp <site>.live -- theme  list --status=active --format=json   # activeThemes
terminus remote:wp <site>.live -- user   list --role=administrator --format=json  # administrators
terminus remote:wp <site>.live -- option get <name>                           # one per allow-list key
```

We read **live**, because Drift Detection is defined as a diff of *live* state
(CONTEXT.md); `test`/`dev` are not authoritative. `terminus remote:wp` is the only
first-class off-platform way to run WP-CLI on Pantheon, so it is the mechanism.

### Least privilege is achieved by scoping the **user**, not the token

A Pantheon machine token **cannot be scoped or made read-only** — confirmed against the
Pantheon GitHub Actions stack (`terminus-github-actions`), which uses a full
`PANTHEON_MACHINE_TOKEN`. A machine token acts on behalf of the user that created it,
with that user's permissions, and `terminus remote:wp` is WP-CLI-over-SSH — effectively
arbitrary code execution on the site. So "least privilege" can only mean scoping the
*account*:

- **A dedicated, fleet-shared service-account user** owns the token (never a human's
  personal token) — clean revocation and audit, no blast radius into a person's other
  access. One shared account was chosen over per-site accounts for operational sanity
  (one token to rotate); the accepted cost is that a leaked token reaches every in-scope
  live site.
- **Role: Pantheon "Team Member"** — the lowest SSH-capable role. Any SSH-capable role
  can technically write, but Team Member excludes team-management, billing, and
  site-deletion powers, so a leaked token cannot add collaborators or destroy the team.
- **Confined to a dedicated org containing only in-scope sites** — caps the blast radius
  of the shared token to exactly the fleet being scanned.
- **Read-only is a collector-enforced convention, not a platform guarantee.** The
  collector issues only `plugin list` / `theme list` / `user list` / `option get`; the
  platform will not enforce this, so it is asserted in code and stated here.

A true platform-enforced read-only path would require a site-side signed REST endpoint
(a mu-plugin), which breaks ADR-0001 ("nothing runs on the site") and reintroduces a
per-site footprint. **Shelved as deferred** for any future site sensitive enough to
justify the footprint.

### The seeded critical-options allow-list

A new Baseline is seeded with five option names — the genuine privilege-escalation /
hijack vectors, not config noise:

| Option | Why watched |
| --- | --- |
| `default_role` | `subscriber`→`administrator` flip = takeover on next registration |
| `users_can_register` | `0`→`1` opens self-registration; lethal paired with the above |
| `siteurl` | injected-redirect / malware canary |
| `home` | front-end redirect hijack |
| `admin_email` | account-recovery / notification hijack |

`wp_user_roles` (capability definitions — a stealth escalation vector) is **opt-in**, not
seeded: it is a serialized blob that legitimately changes whenever a plugin adds a
capability, so under the snapshot's string-compare it would be noisy. `active_plugins` /
`template` / `stylesheet` are **excluded** as redundant — already covered by the
snapshot's `activePlugins` / `activeThemes`.

### The added-plugin gap is foreclosed by the host, not by the differ

ADR-0009's differ is intentionally asymmetric: a *removed/deactivated* expected plugin is
drift (`security-control-disabled`), but a *newly-added* active plugin is not (an extra
plugin is routine maintenance; user story 27). That would leave a gap — a rogue plugin
dropped onto live — except Pantheon's Test/Live filesystem is **read-only for code**:
all webroot code arrives only via git deploy, so the git repo is the *canonical* code
inventory and a live-only plugin cannot exist. No follow-up is needed. (Arbitrary PHP in
the writable `wp-content/uploads` dir is a web-shell, not a plugin, and is a non-goal for
both modes.)

### Re-bless is PR-based, never a blind write

`workflow_dispatch` with `update-baseline=true` regenerates `.security/baseline.json` from
current live state and **opens a PR** carrying it, with the **diff from the old Baseline in
the PR body** ("here is the drift you are about to bless away"). A human merging that PR
*is* the deliberate re-bless. A blind direct-commit was rejected because re-blessing a
*compromised* live state would silently bless the compromise into the Baseline; the PR
forces a human to eyeball the change first. Bootstrap (no prior Baseline) is the same path
with an empty diff. The elevated `contents: write` + `pull-requests: write` permissions are
scoped to the dispatch job only; normal scheduled/PR drift runs keep `issues: write` alone.

### Wiring surface and failure semantics

- New Action inputs: required `pantheon-site` (machine name) and `pantheon-machine-token`
  (secret), optional `pantheon-env` (default `live`) and `update-baseline` (boolean).
  Non-secret values live literally in the committed per-site workflow `with:` block; the
  token is a **GitHub Actions secret** named **`PANTHEON_WPCARE_MACHINE_TOKEN`**, defined
  once as an **org-level secret** scoped to the in-scope repos (matching the shared-account
  decision) — never a `.env` file, never a runner env var. Site identity is **explicit**, never derived from the repo name, because
  a wrong-guessed convention pointed at credentialed live access is a dangerous failure.
- **Three distinct outcomes:** live matches Baseline → green; real drift → Findings +
  failing status (per `fail-on`); **collector error** (auth rejected / SSH down / no usable
  snapshot) → **fail the run loudly, emit zero Findings.** ADR-0009's no-throw differ still
  prevents *fabricating* drift from a bad read, but the impure edge surfaces its own failure
  as a red run rather than a silent green — so a blind scanner is visible.

## Consequences

- The collector is a thin impure edge that produces the ADR-0009 snapshot shape and is not
  unit-tested; the pure differ remains the testable boundary.
- The shared service account is the single rotation chore and the single largest residual
  risk; its confinement to a dedicated org of in-scope sites is the mitigation of record.
- The re-bless PR path adds `pull-requests: write` to the dispatch job — the only place The
  Action needs more than `issues: write`.

## Amendment (2026-06-18): `terminus remote:wp` is SSH-key-gated — the machine token is not sufficient

The first live exercise of the collector (the real read path run against
`new-oakland.test`) surfaced an auth assumption this ADR got wrong. The original
"Collector mechanism" section implied `terminus auth:login --machine-token` is enough to
read live state. It is not.

`terminus remote:wp` connects over **SSH** to `appserver.<env>.<uuid>.drush.in:2222` and
authenticates with an **SSH key registered on the Pantheon account** — *not* the machine
token. The machine token authenticates the Pantheon **API** only (so `auth:whoami` and
`env:info` succeed while every `remote:wp` read fails `Permission denied (publickey)`
[Exit 255]). There is no SSH-free alternative: Pantheon exposes no API for arbitrary
WP-CLI, so `remote:wp`-over-SSH is the only mechanism, and it requires the key.

**Correction to the wiring surface.** The dedicated service account needs **both**
credentials, and they must belong to the **same** Pantheon user (auth:login picks the
account from the token; the subsequent SSH authenticates as that account's key):

1. A dedicated keypair (no passphrase — CI cannot supply one; RSA is known-good on
   drush.in).
2. Its **public** half registered on the service account once: `terminus ssh-key:add`.
3. Its **private** half stored as a second GitHub Actions secret —
   **`PANTHEON_SSH_PRIVATE_KEY`** — alongside `PANTHEON_WPCARE_MACHINE_TOKEN`.
4. A workflow step writes the private key to `~/.ssh/id_rsa` (mode 600) **before** the
   Action runs. No `ssh-keyscan` is needed: terminus auto-accepts the drush.in host key
   (observed — it adds it to `known_hosts` without a prompt), so the cold-runner host-key
   prompt is a non-issue.

**Two speculative risks this run retired:** the SSH host-key prompt does **not** hang a
cold runner (auto-accepted), and the collector's three concurrent `remote:wp` reads
(`Promise.all`) **fail fast rather than deadlock** — so no read-serialization change is
warranted.

**No collector code change.** `src/collector.mjs` shells `terminus`, which uses the
runner's ambient SSH; supplying the key is a workflow concern. A missing/invalid key
surfaces as the loud collector failure this ADR already specifies (red run, zero
Findings) — never a silent green.

**Validation-env refinement.** This ADR reads **live** as authoritative for production
drift, and that stands. But a Baseline is only meaningful diffed against the env it was
blessed from — `siteurl`/`home` and the active-plugin set legitimately differ per env
(observed: `test` had 8 active plugins and a `*.pantheonsite.io` URL vs other envs). So
**validation** runs against a non-live env (`test`/multidev) with a Baseline blessed from
*that same env*; the per-site workflow exposes `pantheon-env` as a dispatch input
(defaulting to `live`) so a non-live validation needs no file edit, and the schedule
keeps reading live.
