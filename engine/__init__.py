"""
WebOSINT Pro engine.

The engine layer is the enterprise core of the platform. It is deliberately
independent of the legacy ``core``/``modules`` packages so both can coexist:
legacy modules are adapted into engine plugins rather than rewritten in place,
which preserves every existing capability while the new architecture takes over
orchestration, evidence handling, scoring, persistence, and reporting.

Layering (each layer may only import from the ones above it):

    models      typed domain objects, no behaviour
    events      in-process publish/subscribe bus
    cache       deduplicating shared cache (DNS/HTTP/TLS)
    confidence  evidence-weighted scoring and false-positive estimation
    fingerprint technology and attack-surface classification
    selection   technology-aware dynamic plugin selection
    plugins     plugin contract, registry, lifecycle
    adapters    legacy module -> plugin bridge
    pipeline    staged scheduler and executor
    storage     persistence (SQLite by default)
    reporting   multi-audience report generation
    service     daemon supervision and health
"""

__version__ = "3.0.0"

__all__ = ["__version__"]
