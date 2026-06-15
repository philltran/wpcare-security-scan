// Inventory enumerator — pure, deep module.
//
//   enumerateInventory(siteRoot) -> [ { slug, kind, version, path, embedded } ]
//
// Reads the code tree on disk and returns one Inventory item per plugin/theme/
// mu-plugin/drop-in/core surface found, reading the `Version:` header out of each
// plugin's main PHP file (and theme `style.css`). Crucially it walks `wp-content`
// *deeply* and recursively sniffs for plugin/theme headers nested inside another
// plugin or theme, marking those `embedded: true` — the bundled Slider Revolution
// blind spot (ADR-0004). Activation status is ignored entirely: this reads files,
// not WordPress's active-plugin list.
//
// Ported (not imported) from the pt-claude-skills filesystem/header walk; see the
// repo README "Prior art to port" and ADR-0004.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Read only the first 8KB of a file — WordPress plugin/theme headers live in the
// opening comment block, so there is no need to slurp large PHP files.
const HEADER_BYTES = 8 * 1024;

// How deep to recurse when sniffing for nested (embedded) headers inside a plugin
// or theme. Bounded so a pathological tree can never blow the stack or the loop —
// embedded copies live a handful of directories down, not dozens.
const MAX_EMBED_DEPTH = 8;

// Directories that never contain a distinct embedded plugin/theme of interest, and
// that bloat the walk. Skipped during the recursive nested sniff.
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', 'vendor', 'languages', 'assets']);

function isDir(p) {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

function isFile(p) {
  try { return statSync(p).isFile(); } catch { return false; }
}

function listDir(p) {
  try { return readdirSync(p); } catch { return []; }
}

function readHead(file) {
  try {
    return readFileSync(file).subarray(0, HEADER_BYTES).toString('utf8');
  } catch { return null; }
}

// Pull a named header (e.g. `Version`) out of a WordPress file header block.
// WordPress matches headers case-insensitively at the start of a line, tolerating
// leading `*` / whitespace from the PHP doc-comment.
export function readHeaderField(text, field) {
  const re = new RegExp(`^[\\s*]*${field}\\s*:\\s*(.+)$`, 'im');
  const m = re.exec(text || '');
  return m ? m[1].trim() : null;
}

// Does this header text declare a WordPress plugin? (its `Plugin Name:` header).
function pluginHeaderText(text) {
  return text && readHeaderField(text, 'Plugin Name') ? text : null;
}

// Find a plugin's main PHP file: prefer `<slug>.php`, else the first .php whose
// header declares a `Plugin Name:` (WordPress's own heuristic), else the first .php.
function readPluginHeader(pluginDir, slug) {
  const preferred = join(pluginDir, `${slug}.php`);
  const candidates = [];
  if (isFile(preferred)) candidates.push(preferred);
  for (const fn of listDir(pluginDir)) {
    if (!fn.endsWith('.php')) continue;
    const full = join(pluginDir, fn);
    if (full !== preferred) candidates.push(full);
  }

  let firstReadable = null;
  for (const file of candidates) {
    const text = readHead(file);
    if (text === null) continue;
    if (firstReadable === null) firstReadable = text;
    if (pluginHeaderText(text)) return text;
  }
  return firstReadable;
}

// Read a theme's `style.css` header block, if present.
function readThemeHeader(themeDir) {
  const style = join(themeDir, 'style.css');
  return isFile(style) ? readHead(style) : null;
}

// Recursively sniff a plugin/theme directory for *nested* plugin/theme headers — a
// plugin bundled inside a theme, or a theme inside a plugin. Each hit is an Embedded
// plugin Inventory item. The walk is bounded (depth + skip-list) and never throws:
// an unreadable subtree is silently skipped, so a false embedded copy is a triageable
// Finding downstream, never a fatal scan error (ADR-0004).
function sniffEmbedded(rootDir, items, depth = 0) {
  if (depth >= MAX_EMBED_DEPTH) return;

  for (const name of listDir(rootDir).sort()) {
    if (SKIP_DIRS.has(name)) continue;
    const childDir = join(rootDir, name);
    if (!isDir(childDir)) continue;

    // A nested directory carrying a theme header => embedded theme.
    const themeHeader = readThemeHeader(childDir);
    if (themeHeader) {
      items.push({
        slug: name,
        kind: 'theme',
        version: readHeaderField(themeHeader, 'Version'),
        path: childDir,
        embedded: true,
      });
    }

    // A nested directory carrying a plugin header => embedded plugin (revslider).
    const pluginHeader = readPluginHeader(childDir, name);
    if (pluginHeaderText(pluginHeader)) {
      items.push({
        slug: name,
        kind: 'plugin',
        version: readHeaderField(pluginHeader, 'Version'),
        path: childDir,
        embedded: true,
      });
    }

    sniffEmbedded(childDir, items, depth + 1);
  }
}

// Enumerate top-level plugin directories under wp-content/plugins, then recursively
// sniff each for embedded plugins/themes.
function enumeratePlugins(contentDir, items) {
  const dir = join(contentDir, 'plugins');
  if (!isDir(dir)) return;
  for (const slug of listDir(dir).sort()) {
    const pluginDir = join(dir, slug);
    if (!isDir(pluginDir)) continue;
    const header = readPluginHeader(pluginDir, slug);
    items.push({
      slug,
      kind: 'plugin',
      version: header ? readHeaderField(header, 'Version') : null,
      path: pluginDir,
      embedded: false,
    });
    sniffEmbedded(pluginDir, items);
  }
}

// Enumerate every theme under wp-content/themes (active or not — activation is
// irrelevant), then recursively sniff each for embedded plugins/themes.
function enumerateThemes(contentDir, items) {
  const dir = join(contentDir, 'themes');
  if (!isDir(dir)) return;
  for (const slug of listDir(dir).sort()) {
    const themeDir = join(dir, slug);
    if (!isDir(themeDir)) continue;
    const header = readThemeHeader(themeDir);
    if (header) {
      items.push({
        slug,
        kind: 'theme',
        version: readHeaderField(header, 'Version'),
        path: themeDir,
        embedded: false,
      });
    }
    sniffEmbedded(themeDir, items);
  }
}

// WordPress "must-use" plugins. They live in wp-content/mu-plugins and load on
// every request regardless of any activation list — exactly the kind of always-on
// code this scan must see. Both single-file (`*.php` directly in the dir) and
// subdirectory mu-plugins are enumerated; subdirectories are also sniffed for
// embedded plugins/themes.
function enumerateMuPlugins(contentDir, items) {
  const dir = join(contentDir, 'mu-plugins');
  if (!isDir(dir)) return;
  for (const name of listDir(dir).sort()) {
    const full = join(dir, name);
    if (isFile(full) && name.endsWith('.php')) {
      const text = readHead(full);
      items.push({
        slug: name.replace(/\.php$/, ''),
        kind: 'mu-plugin',
        version: text ? readHeaderField(text, 'Version') : null,
        path: full,
        embedded: false,
      });
    } else if (isDir(full)) {
      const header = readPluginHeader(full, name);
      items.push({
        slug: name,
        kind: 'mu-plugin',
        version: header ? readHeaderField(header, 'Version') : null,
        path: full,
        embedded: false,
      });
      sniffEmbedded(full, items);
    }
  }
}

// WordPress drop-ins: specially-named PHP files placed directly in wp-content/ that
// override core behavior (object cache, advanced cache, custom db layer, etc.). They
// are not registered plugins and never appear in the active-plugin list.
const DROPIN_FILES = [
  'object-cache.php',
  'advanced-cache.php',
  'db.php',
  'db-error.php',
  'install.php',
  'maintenance.php',
  'sunrise.php',
  'php-error.php',
  'fatal-error-handler.php',
];

function enumerateDropins(contentDir, items) {
  for (const name of DROPIN_FILES) {
    const full = join(contentDir, name);
    if (!isFile(full)) continue;
    const text = readHead(full);
    items.push({
      slug: name.replace(/\.php$/, ''),
      kind: 'dropin',
      version: text ? readHeaderField(text, 'Version') : null,
      path: full,
      embedded: false,
    });
  }
}

// WordPress core, read from wp-includes/version.php ($wp_version = '...';). Core has
// its own CVE stream and is enumerated regardless of anything else on disk.
function enumerateCore(siteRoot, items) {
  const versionFile = join(siteRoot, 'wp-includes', 'version.php');
  if (!isFile(versionFile)) return;
  const text = readHead(versionFile);
  const m = /\$wp_version\s*=\s*['"]([^'"]+)['"]/.exec(text || '');
  items.push({
    slug: 'wordpress',
    kind: 'core',
    version: m ? m[1] : null,
    path: versionFile,
    embedded: false,
  });
}

export function enumerateInventory(siteRoot) {
  const items = [];

  const contentDir = join(siteRoot, 'wp-content');
  if (isDir(contentDir)) {
    enumeratePlugins(contentDir, items);
    enumerateMuPlugins(contentDir, items);
    enumerateThemes(contentDir, items);
    enumerateDropins(contentDir, items);
  }

  enumerateCore(siteRoot, items);
  return items;
}
