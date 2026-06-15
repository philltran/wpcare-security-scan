# Agent roster

The curated list of installable domain-specialist agents this repo routes issues to.
Seeded by `triage --setup` (a scan of the installed agent plugins) and **hand-curated
after seeding** — trim entries that don't apply to this repo (e.g. drop
`wordpress-developer` in a Drupal-only repo). Re-running `triage --setup` re-seeds
the file from the current set of installed agents.

## accessibility

Use proactively after writing or modifying user-facing markup or UI components, or when the user asks to audit, check, or improve accessibility / a11y / WCAG conformance / screen-reader or keyboard support of a page, component, or theme.

## ai-developer

Use when the user asks to build, implement, add, or change an AI / LLM feature — a Claude-powered agent, a tool/function-calling integration, an MCP client or server, a multi-agent workflow, a RAG or retrieval-augmented feature, a prompt or system prompt, prompt/context caching, streaming, an eval harness or LLM-as-judge, or token/cost budgeting (Claude, Anthropic, Fable, Opus, Sonnet, Haiku, `anthropic`, `@anthropic-ai`, agent, tool use, function calling, RAG, prompt engineering). For another provider (OpenAI/GPT, Gemini, Llama, Mistral), this is not the agent.

## claude-skills-author

Use when the user asks to create, author, design, structure, scaffold, or review a new Claude Code skill, SKILL.md, slash command, or plugin — "write a skill", "build a skill", "scaffold a skill", "how should I structure this skill", "turn this into a skill", or "register this skill". Pairs the repo's house style with the write-a-skill capability skill.

## client-voice

Use proactively when drafting or replying to anything a client will read, or when the user asks to write, rewrite, soften, tighten, or on-brand a client message, proposal, update, or release note.

## code-reviewer

Use proactively after writing or modifying general application code, scripts, or library code, or when the user asks to review, audit, or sanity-check code that isn't Drupal- or WordPress-specific.

## ddev-engineer

Use when the user asks to set up, configure, fix, or change a DDEV environment — bump the PHP or Node version, add a service/add-on, add a post-start or post-import hook, set an env var, get a project to start, import a database, or run ddev composer / ddev drush (.ddev/config.yaml, config.*.yaml, .ddev/php/php.ini, ddev start/restart). DDEV only — not Lando.

## drupal-canvas-builder

Use when the user asks to build, create, add, or change a Drupal Canvas SDC, a `*.component.yml` / `*.twig` / `*.stories.twig`, a primitive or composite component, CVA variant styling, design tokens, or to extend a Mercury-derived Drupal theme.

## drupal-developer

Use when the user asks to build, implement, add, or change a Drupal module, hook, service, entity type, form, controller/route, plugin (block, field formatter/widget, queue worker), or config (PHP, *.module, *.install, *.services.yml, routing/config YAML, Twig).

## drupal-reviewer

Use proactively after writing or modifying Drupal code (PHP, *.module, *.install, *.services.yml, routing/config YAML, Twig), or when the user asks to review or audit Drupal code.

## frontend-developer

use when the user asks to build, implement, add, or change HTML/CSS or vanilla/TS browser JavaScript, lay out or make a page responsive, fix CSS layout, write an accessible component without a framework, add a custom element, or wire up a build. Not for React (use react-developer) or Drupal Canvas/SDC.

## github-actions-developer

Use when the user asks to build, write, add, or change a custom GitHub Action in Node/JavaScript/TypeScript, an `action.yml`, a `github-script` step, a Node script that runs in a workflow, the `@actions/*` toolkit, ncc/`dist` bundling, or to harden an Action against script injection or token over-privilege (GitHub Actions, `action.yml`, `@actions/core`, `@actions/github`, Octokit, github-script, ncc, dist, JS action, runner). For general application Node that is not a GitHub Action, or for pure-YAML CI orchestration with no Node, this is not the agent.

## gutenberg-blocks-developer

Use when the user asks to build, create, add, or change a custom Gutenberg block, a block.json, a static or dynamic block, an edit/save/render function, InnerBlocks or block context, a block variation or pattern, a block binding, the Interactivity API, or a block theme's theme.json. (For general WP PHP — hooks, CPTs, meta, REST, Settings API — use wordpress-developer; for reviewing existing code, wordpress-reviewer.)

## lando-engineer

Use when the user asks to set up, configure, fix, or change a Lando environment — pick or change the recipe, bump the PHP/database version, add a service/tooling command, add a proxy host, set an env var, get a project to start, import a database, or run lando composer / lando drush / lando wp (.lando.yml, .lando.local.yml, lando start/rebuild). Lando only — not DDEV.

## mac-developer

Use when the user asks to build, implement, add, or change a native macOS / Mac app feature, window, or menu; fix a SwiftUI/AppKit, lifecycle, sandbox/entitlements, or concurrency issue; wire up Keychain or Core Data/SwiftData; or set up signing, notarization, or Mac distribution (Swift, SwiftUI, AppKit, macOS, Xcode). Mobile apps — iOS, iPadOS, Android, and cross-platform — go to mobile-developer, not here; this agent owns native desktop macOS.

## marketing

Use proactively when drafting or shaping marketing content or strategy, or when the user asks to write a campaign, value proposition, positioning, messaging, content plan, editorial calendar, creative brief, marketing email, ad, or landing-page copy.

## mobile-developer

Use when the user asks to build, implement, add, or change a mobile app feature, screen, or component, fix a mobile navigation/state/lifecycle/ performance issue, add push notifications or offline support, or prepare a build for the App Store or Google Play (React Native, Flutter, Expo, SwiftUI, Jetpack Compose, iOS, Android). Native desktop macOS apps go to mac-developer, not here.

## node-developer

Use when the user asks to build, implement, add, or change a Node.js server, REST/HTTP API, CLI, script, library/package, or worker; fix an async/event-loop/streams/memory bug; wire up Express/Fastify/Koa, npm/pnpm/yarn packaging, or env/config; or harden a Node service (input validation, child_process/path-traversal safety, secrets) — Node.js, npm, Express, Fastify, server, CLI, package, TypeScript on the server. For browser/DOM JavaScript use the frontend-developer agent, for React use the react-developer agent, for Node written specifically as a GitHub Action use the github-actions-developer agent, and for Claude/Anthropic AI-app code use the ai-developer agent.

## productivity

Use proactively when a workflow is friction-heavy or a step keeps being repeated by hand, or when the user asks to set up a task/notes/inbox system, design or streamline a personal or team workflow or process, automate or script a repetitive chore, wire two tools together, reduce toil or busywork, or improve focus, async, or meeting habits.

## project-manager

Use proactively when work needs planning or sequencing, or when the user asks to scope a project, break work down, write a work breakdown or roadmap, estimate effort, plan a timeline or milestones, assess project risk and dependencies, prioritise a backlog, or produce a status report.

## qa

Use proactively before or after a change to plan what needs testing, or when the user asks for a test plan, test cases, QA pass, coverage assessment, exploratory charter, regression strategy, or help reproducing/triaging a bug.

## react-developer

Use when the user asks to build, implement, add, or change a React component or hook, lift or refactor state, fix a re-render or effect bug, add context/a reducer, or wire up data fetching with Suspense (JSX/TSX, .jsx/.tsx, function components, hooks).

## seo-geo

Use proactively after writing or modifying page content, metadata, or structured markup, or when the user asks to improve SEO, meta tags, structured data, search ranking, discoverability, or how the page is cited/summarized by AI answer engines, generative search, LLMs, or GEO.

## wordpress-developer

Use when the user asks to build, implement, add, or change a WordPress plugin or theme, a hook/action/filter, a custom post type or taxonomy, a meta field or option, a Settings-API admin page, a shortcode/block, or a REST route (PHP, functions.php, plugin files, theme templates).

## wordpress-reviewer

Use proactively after writing or modifying WordPress code (PHP, functions.php, plugin files, theme templates, REST handlers), or when the user asks to review, audit, or security-check WordPress code.
