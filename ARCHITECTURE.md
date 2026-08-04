# WebOSINT Pro - Architecture

This document describes the platform architecture introduced in the 3.0 engine.
It is the reference for anyone extending, operating or reviewing the system.

## Design principles

1. **Modules never talk to each other.** A plugin receives a narrow `ScanContext`
   and returns findings. It cannot reach a sibling. Everything shared travels
   through the event bus or the shared cache.
2. **Nothing is asserted without evidence.** A finding that cannot point at what
   was observed is withheld, not downgraded.
3. **Work that cannot apply is not performed.** The scan plan is derived from the
   observed technology profile, and every skip is recorded with a reason.
4. **Failure is contained.** A broken plugin produces a failed outcome, never a
   failed scan.
5. **Backward compatibility.** The legacy `core/` and `modules/` packages still
   work exactly as before; the engine wraps them rather than replacing them.

## Layering

The `engine/` package is strictly layered. Each layer may import only from the
layers above it, which keeps the dependency graph acyclic and testable.

| Layer | Module | Responsibility |
| --- | --- | --- |
| 1 | `models` | Typed domain objects. No behaviour, no I/O. |
| 2 | `events` | In-process publish/subscribe bus. |
| 3 | `cache` | Deduplicating shared cache (DNS, HTTP, TLS). |
| 4 | `confidence` | Evidence-weighted scoring, false-positive estimation. |
| 5 | `fingerprint` | Technology detection and attack-surface classification. |
| 6 | `selection` | Technology-aware dynamic plugin selection. |
| 7 | `compliance` | CWE / OWASP / MITRE / PCI DSS / NIST mapping. |
| 8 | `plugins` | Plugin contract, registry, lifecycle. |
| 9 | `adapters` | Legacy module to plugin bridge. |
| 10 | `pipeline` | Staged scheduler and concurrent executor. |
| 11 | `correlation` | Cross-finding analysis and narrative generation. |
| 12 | `storage` | Persistence (SQLite default, PostgreSQL/MySQL supported). |
| 13 | `reporting` | Multi-audience, multi-format report generation. |
| 14 | `service` | Daemon supervision, health, metrics, log rotation. |
| 15 | `cli` | The `webosint` service-management commands. |
| -- | `runner` | The single seam where the engine meets the legacy scanner. |

## Scan pipeline

```
Target
  -> Normalize            bare hostname from any URL, port, userinfo or case
  -> Recon (sequential)   dns, ip, http, ssl - these feed everything downstream
  -> Fingerprint          technologies with versions, from headers/HTML/JS/cookies
  -> Classify surface     static site, SPA, dynamic app, API, CMS, CDN edge, ...
  -> Plan                 dynamic plugin selection, every decision explained
  -> Execute (parallel)   ThreadPoolExecutor, per-plugin deadline, adaptive width
  -> Validate             evidence-weighted confidence per finding
  -> Correlate            cross-plugin upgrades, exposure chains
  -> Analyse              executive / SOC / developer narratives
  -> Finalize             dedupe, aggregate risk, compliance mapping
  -> Report               JSON, Markdown, HTML, CSV, PDF, Excel
```

Recon runs sequentially because everything else depends on it. Everything after
the plan runs concurrently.

## Plugin contract

Every plugin implements the seven-stage lifecycle. Only `scan()` is mandatory;
the rest have sensible defaults.

```python
class MyPlugin(Plugin):
    name = "my-plugin"
    version = "1.0.0"
    description = "What this plugin looks for."
    requires = ["dnspython"]     # checked by load(), never at import time
    active = False               # True means it needs --active
    order = 100                  # lower runs earlier

    @classmethod
    def load(cls) -> bool: ...           # dependency check, no side effects
    def initialize(self, context): ...   # per-scan setup
    def scan(self, context): ...         # REQUIRED - returns list[Finding]
    def validate(self, findings, ctx): ...   # defaults to confidence scoring
    def correlate(self, findings, ctx): ...  # cross-reference other evidence
    def report(self, findings, ctx): ...     # optional structured summary
    def shutdown(self): ...              # always called, even after a failure
```

Registration is automatic. Drop a `*_plugin.py` file into `engine/builtin/` and
it is discovered; drop one anywhere else and load it with
`registry.load_from_path(...)`. When two plugins share a name the higher version
wins, which is the migration path from an adapted legacy module to a native one.

## Confidence engine

Confidence is derived from evidence, never assigned by hand.

- Each evidence kind has a **reliability weight**: DNS/TLS/certificate evidence
  is authoritative (1.0); an HTML body match is weak (0.6).
- Evidence combines with a **noisy-OR**, strongest first, so two indicators are
  worth more than one but ten weak ones never equal one strong one.
- **Repeated evidence of the same kind decays** (0.35 per repeat). Five HTML
  matches are still just "the HTML said so".
- **Diversity is rewarded.** A single evidence kind is capped at 0.72, which is
  deliberately below the 80% reporting threshold: one indicator can never on its
  own produce a reported finding.
- Findings below **80% confidence are suppressed**, not deleted; they remain in
  the result for analyst review and appear in no report.
- **90%+ with multi-indicator or active validation marks a finding verified.**

This is what removes the false positives seen previously: a SIEM detected only
by a page title now scores in the 50s and is withheld, while one confirmed by
favicon, API endpoint, JS bundle and headers scores in the 90s.

## Technology-aware selection

`selection.REQUIREMENTS` declares, per plugin, what must be true for it to run:
required technologies, applicable surfaces, forbidden technologies, and whether
it needs active mode. A statically hosted Next.js site therefore never runs
WordPress, PHP, database, SIEM, IDS or honeypot checks - which is the single
largest contributor to the drop in scan time, because those were the modules
that previously burned tens of minutes discovering nothing.

Every decision, positive or negative, is recorded and rendered in the technical
report, so a skipped check is always visible and justified.

## Shared cache

`SharedCache` is namespaced (`dns`, `http`, `tls`, ...) and implements
**single-flight coalescing**: when ten plugins request the same DNS record
simultaneously, one lookup is performed and the other nine wait for its result.
This is enforced by a test that runs ten concurrent callers and asserts exactly
one computation.

## Persistence

SQLAlchemy models cover targets, scans, findings, technologies, assets,
certificates, DNS records, reports and risk-score history. SQLite is the default
so the platform runs with no setup; set `WEBOSINT_DATABASE_URL` to a PostgreSQL
or MySQL DSN to use a server. If SQLAlchemy is not installed the engine falls
back to in-memory history rather than refusing to start.

## Service and boot

`engine/service.py` supplies the state machine (running, stopped, paused,
starting, stopping, restarting, failed, crashed, not started, disabled), health
checks, JSON log rotation at 10 MB with five backups, and runtime metrics
published atomically so `webosint status` can read them out-of-band.

| Platform | Mechanism | Install |
| --- | --- | --- |
| Linux | systemd | `sudo ./scripts/install-service.sh` |
| macOS | LaunchDaemon | `sudo launchctl load -w /Library/LaunchDaemons/pk.webosint.plist` |
| Windows | Service (NSSM or `sc.exe`) | `.\scripts\install-service.ps1` |

All three restart automatically after a crash with a backoff, and all three
start at boot.

## Threading model

A `ThreadPoolExecutor` runs plugins concurrently with a per-plugin deadline;
stalled plugins are abandoned rather than allowed to hold the scan open.
`AdaptiveConcurrency` widens the pool on clean runs and halves it when the error
rate exceeds 30%, so a struggling target is backed off instead of hammered.
`scan_many()` adds an outer pool for 10, 100 or 1000-target inventories, giving
each target its own pipeline and cache.

## Extending the platform

To add a detection:

1. Add a `Signature` to `engine/fingerprint.py` if it is a technology.
2. Otherwise write a plugin in `engine/builtin/` implementing `scan()`.
3. Return findings carrying real `Evidence`. Do not set confidence yourself -
   the engine scores it.
4. Add a `Requirement` in `engine/selection.py` so it only runs when relevant.
5. Add tags that map to controls in `engine/compliance.py`.
6. Write a test that proves a single weak indicator does **not** produce a
   reported finding.
