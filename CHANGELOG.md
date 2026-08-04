# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Durable distributed job queue (`engine.cluster`) with priority scheduling,
  leases, retries with exponential backoff, a dead-letter queue and
  duplicate suppression. Nothing dispatches to it yet; worker wiring lands next.

## [3.0.0]

### Added
- **Engine 3.0**: staged pipeline, plugin lifecycle, event bus and shared cache.
  Modules no longer call each other directly.
- **Technology-aware scanning**: fingerprints the target first and skips module
  families that cannot apply, which is the single largest speed win.
- **Confidence engine**: findings are scored and only reported above the
  reporting threshold, with the supporting evidence attached.
- **Report engine**: JSON, Markdown, HTML, CSV, PDF, Word and Excel output, with
  executive, technical, SOC, developer and risk-dashboard audiences.
- **Web dashboard** with background scans, live progress, adjustable scan speed,
  verbosity control, and in-portal report viewing and download.
- **Service management**: `webosint start|stop|restart|status|health|doctor`,
  plus systemd installation and start-on-boot support.
- **Host and infrastructure reporting**: operating system, network, ISP, exposed
  port versions, services and web-hosting stack.
- Scan history and inventory persistence.

### Fixed
- Email authentication results are now evaluated against the organisational
  domain, so SPF, DKIM and DMARC are no longer reported as missing on subdomains
  that legitimately inherit them.
- Next.js sites are fingerprinted correctly and no longer trigger WordPress,
  PHP or database probes.
- LAN access: the service unit no longer fails with a read-only runtime
  directory, and remote binding works as documented.
- Risk summary tables populate instead of rendering empty.

### Security
- Authorization gate, allowlist enforcement, private and reserved address
  blocking, SSRF-safe redirect handling, passive-by-default operation and
  TLS verification on by default.
- Redaction across every output path, configurable detail levels, no raw HTTP
  persistence, retention and cleanup, telemetry off by default.
- The web dashboard ships with authentication disabled by design; it is intended
  to be bound to localhost or protected at the network layer.
