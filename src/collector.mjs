// Drift collector — the IMPURE edge of mode 2 (ADR-0010). Authenticates to Pantheon
// with a machine token (a repo/org SECRET, never logged) and reads security-critical
// live state via `terminus remote:wp` (WP-CLI over SSH) into the ADR-0009 snapshot
// shape the pure differ consumes. Kept deliberately thin and READ-ONLY — only `plugin
// list` / `theme list` / `user list` / `option get` — and NOT unit-tested; the pure
// differ (src/drift.mjs) and orchestrator (src/drift-scan.mjs) are the tested seams.
//
// Least privilege is the USER's, not the token's (ADR-0010): the token belongs to a
// shared Team-Member service account confined to a dedicated org of in-scope sites.
// The token itself cannot be scoped; "read-only" is this module's enforced convention,
// asserted by issuing only the four read verbs below.
//
// Untrusted input: `site` and `env` come from the per-site workflow `with:` block, not
// the network, but they are still interpolated into a child command — so they are
// passed as an argv array via execFile (never a shell string) and validated against a
// conservative allow-list pattern before use. The token is passed as a CLI flag value
// in the argv array (also never shell-interpolated) and is masked in logs by the
// caller (core.setSecret).

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

// Pantheon site machine names and env names are lowercase alphanumerics with hyphens
// (and env can be a multidev name). A conservative allow-list forecloses argument /
// command injection even though execFile already avoids the shell.
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/i;

function assertSafe(label, value) {
  if (typeof value !== 'string' || !SAFE_NAME.test(value)) {
    throw new Error(`drift collector: invalid ${label} "${value}".`);
  }
  return value;
}

// Run a terminus subcommand as an argv array (no shell). Stdout is returned trimmed.
async function terminus(args, { env } = {}) {
  const { stdout } = await execFileAsync('terminus', args, {
    env: { ...process.env, ...env },
    maxBuffer: 16 * 1024 * 1024, // a full plugin list on a big site is comfortably under this
  });
  return stdout;
}

// Run a read-only WP-CLI verb on the site over SSH and parse its JSON output. The
// `wpArgs` are fixed strings this module controls (the read verbs), never caller input
// beyond the validated site/env.
async function remoteWpJson(site, env, wpArgs) {
  const out = await terminus(['remote:wp', `${site}.${env}`, '--', ...wpArgs, '--format=json']);
  const trimmed = out.trim();
  if (!trimmed) return [];
  return JSON.parse(trimmed);
}

// Read a single option value as raw text (option values are compared as strings).
async function remoteWpOption(site, env, name) {
  // `option get` may exit non-zero for an absent option; treat that as an empty value
  // so the differ reads it as a deleted option rather than aborting the whole read.
  try {
    const out = await terminus(['remote:wp', `${site}.${env}`, '--', 'option', 'get', name]);
    return out.replace(/\n$/, '');
  } catch {
    return '';
  }
}

// Build the live-state snapshot (ADR-0009 shape) for `site`/`env`, blessing exactly the
// option names the Baseline's criticalOptions allow-list names — so the collector reads
// only what the differ will compare.
//
//   makeSnapshotCollector({ site, env, token, allowOptionNames }) -> async () => snapshot
//
// The returned closure is the `collectSnapshot` edge injected into runDriftScan. It
// performs the one-time auth on first call, then the four read families.
export function makeSnapshotCollector({ site, env = 'live', token, allowOptionNames = [] } = {}) {
  const safeSite = assertSafe('pantheon-site', site);
  const safeEnv = assertSafe('pantheon-env', env);
  if (!token || typeof token !== 'string') {
    throw new Error('drift collector: a Pantheon machine token is required.');
  }
  const optionNames = Array.isArray(allowOptionNames) ? allowOptionNames.map(String) : [];

  return async function collectSnapshot() {
    // Authenticate once. The token is an argv value (no shell), masked in logs by the
    // caller. terminus caches the session for the subsequent remote:wp calls.
    await terminus(['auth:login', `--machine-token=${token}`]);

    const [pluginList, themeList, adminList] = await Promise.all([
      remoteWpJson(safeSite, safeEnv, ['plugin', 'list', '--status=active', '--field=name']),
      remoteWpJson(safeSite, safeEnv, ['theme', 'list', '--status=active', '--field=name']),
      remoteWpJson(safeSite, safeEnv, ['user', 'list', '--role=administrator', '--field=user_login']),
    ]);

    const criticalOptions = {};
    for (const name of optionNames) {
      criticalOptions[name] = await remoteWpOption(safeSite, safeEnv, name);
    }

    return {
      activePlugins: (Array.isArray(pluginList) ? pluginList : []).map(String),
      activeThemes: (Array.isArray(themeList) ? themeList : []).map(String),
      administrators: (Array.isArray(adminList) ? adminList : []).map(String),
      criticalOptions,
    };
  };
}
