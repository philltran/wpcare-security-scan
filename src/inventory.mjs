// Inventory enumerator — pure, deep module (this slice: top-level plugins only).
//
//   enumerateInventory(siteRoot) -> [ { slug, kind, version, path, embedded } ]
//
// Reads the code tree on disk and returns one Inventory item per plugin found,
// reading the `Version:` header out of each plugin's main PHP file. Deeper surfaces
// (mu-plugins, themes incl. inactive, drop-ins, core, and Embedded plugins nested
// inside other plugins/themes) are thickened in later slices; the seam is the same.
//
// Ported (not imported) from the pt-claude-skills filesystem/header walk; see the
// repo README "Prior art to port" and ADR-0004.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';

// Read only the first 8KB of a file — WordPress plugin/theme headers live in the
// opening comment block, so there is no need to slurp large PHP files.
const HEADER_BYTES = 8 * 1024;

function isDir(p) {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

function isFile(p) {
  try { return statSync(p).isFile(); } catch { return false; }
}

// Pull a named header (e.g. `Version`) out of a WordPress file header block.
// WordPress matches headers case-insensitively at the start of a line, tolerating
// leading `*` / whitespace from the PHP doc-comment.
export function readHeaderField(text, field) {
  const re = new RegExp(`^[\\s*]*${field}\\s*:\\s*(.+)$`, 'im');
  const m = re.exec(text || '');
  return m ? m[1].trim() : null;
}

// Find a plugin's main PHP file: prefer `<slug>.php`, else the first .php whose
// header declares a `Plugin Name:` (WordPress's own heuristic), else the first .php.
function readPluginHeader(pluginDir, slug) {
  const preferred = join(pluginDir, `${slug}.php`);
  const candidates = [];
  if (isFile(preferred)) candidates.push(preferred);
  try {
    for (const fn of readdirSync(pluginDir)) {
      if (!fn.endsWith('.php')) continue;
      const full = join(pluginDir, fn);
      if (full !== preferred) candidates.push(full);
    }
  } catch { /* unreadable dir */ }

  let firstReadable = null;
  for (const file of candidates) {
    let text;
    try {
      text = readFileSync(file).subarray(0, HEADER_BYTES).toString('utf8');
    } catch { continue; }
    if (firstReadable === null) firstReadable = text;
    if (readHeaderField(text, 'Plugin Name')) return text;
  }
  return firstReadable;
}

export function enumerateInventory(siteRoot) {
  const pluginsDir = join(siteRoot, 'wp-content', 'plugins');
  if (!isDir(pluginsDir)) return [];

  const items = [];
  let entries = [];
  try { entries = readdirSync(pluginsDir); } catch { return []; }

  for (const slug of entries.sort()) {
    const pluginDir = join(pluginsDir, slug);
    if (!isDir(pluginDir)) continue;

    const header = readPluginHeader(pluginDir, slug);
    const version = header ? readHeaderField(header, 'Version') : null;

    items.push({
      slug,
      kind: 'plugin',
      version,
      path: pluginDir,
      embedded: false,
    });
  }

  return items;
}
