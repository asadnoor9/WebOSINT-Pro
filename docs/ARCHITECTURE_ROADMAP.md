# WebOSINT Pro Architecture Roadmap

This roadmap keeps the existing CLI and module contracts working while the
project moves toward a production-grade external attack surface management
platform.

## Current State

- Single CLI entry point: `webosint.py`.
- Core orchestration lives in `core/controller.py`.
- Modules are loaded dynamically from `modules/*_module.py`.
- Reports are generated as JSON and HTML under `reports/`.
- Integrations are thin wrappers around external tools.
- Privacy helpers exist, but they are not wired into all request paths.
- No persistent database layer exists yet.
- No test suite or CI workflow exists yet.

## Key Risks Found

- Reporting imports use `reporting.*`, but the existing package is `reports`.
- README examples mention `--full` and `--mode`, but the CLI only accepts
  `--profile` and `--modules`.
- Some external integrations and modules use hardcoded `/tmp/*` paths, which is
  unsafe and breaks Windows compatibility.
- Several modules call blocking network and DNS APIs directly.
- The plugin registry loads modules but does not validate dependencies or offer
  lifecycle hooks.
- Safety validation exists in `core/safety.py`, but the main CLI still uses a
  separate confirmation prompt.
- Tests, CI, linting, Docker, packaging metadata, and pre-commit hooks are
  missing.

## Incremental Target Architecture

```text
webosint-pro/
  ai/                 AI-assisted analysis and rule-based fallback scoring
  core/               Engine, config, logging, async clients, plugin registry
  database/           SQLAlchemy persistence models and session helpers
  integrations/       External tool adapters with safe execution helpers
  modules/            Backward-compatible legacy modules
  plugins/            Third-party modules loaded by registry
  privacy/            Stealth, proxy, browser profile, and pacing controls
  reports/            Concrete report generators
  reporting/          Compatibility facade and report orchestration
  tests/              Unit tests for config, plugins, reports, safety
```

## Execution Phases

1. Stabilize core compatibility and add missing scaffolding.
2. Introduce async HTTP/DNS clients and migrate high-volume modules first.
3. Strengthen plugin lifecycle, dependency validation, and isolation.
4. Add SQLAlchemy persistence for scan history and findings.
5. Replace ad hoc output with Rich/Textual terminal UX.
6. Add bug bounty modules: cloud buckets, takeovers, GitHub leaks, CSP, crawling.
7. Add AI analysis adapters with deterministic offline fallback.
8. Add Docker, CI, linting, typing, tests, and packaging.

## Compatibility Policy

Existing modules that expose `class Module(BaseModule)` remain loadable. New
capabilities are introduced through shared core services so modules can migrate
one at a time.
