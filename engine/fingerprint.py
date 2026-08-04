"""
Technology fingerprinting and attack-surface classification.

Every signature contributes *evidence*, never a bare boolean, so downstream
scoring can weigh a header match differently from a body-text guess. A
technology is only asserted once its own evidence clears the confidence bar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from engine.confidence import evidence_strength
from engine.models import Evidence, EvidenceKind, Surface, Technology


@dataclass(frozen=True, slots=True)
class Signature:
    """One detection rule for one technology."""

    technology: str
    category: str
    kind: EvidenceKind
    pattern: str
    field: str = ""
    weight: float = 1.0
    version_group: int = 0

    def match(self, haystack: str) -> re.Match[str] | None:
        if not haystack:
            return None
        return re.search(self.pattern, haystack, re.IGNORECASE)


# --- Signature catalogue ----------------------------------------------------
# Kept declarative so new technologies are data, not code.

SIGNATURES: tuple[Signature, ...] = (
    # Edge / CDN / WAF
    Signature("Cloudflare", "cdn", EvidenceKind.HEADER, r"cloudflare", "server", 1.0),
    Signature("Cloudflare", "cdn", EvidenceKind.HEADER, r".+", "cf-ray", 1.0),
    Signature("Cloudflare", "cdn", EvidenceKind.COOKIE, r"__cf_bm|cf_clearance", "", 0.8),
    Signature("Akamai", "cdn", EvidenceKind.HEADER, r"akamai", "server", 1.0),
    Signature("Akamai", "cdn", EvidenceKind.HEADER, r".+", "x-akamai-transformed", 0.9),
    Signature("Fastly", "cdn", EvidenceKind.HEADER, r"fastly", "x-served-by", 0.9),
    Signature("Amazon CloudFront", "cdn", EvidenceKind.HEADER, r"cloudfront", "via", 1.0),
    Signature("Vercel", "hosting", EvidenceKind.HEADER, r"vercel", "server", 1.0),
    Signature("Vercel", "hosting", EvidenceKind.HEADER, r".+", "x-vercel-id", 1.0),
    Signature("Netlify", "hosting", EvidenceKind.HEADER, r"netlify", "server", 1.0),
    Signature("GitHub Pages", "hosting", EvidenceKind.HEADER, r"github\.com", "server", 0.9),
    Signature("Cloudflare Pages", "hosting", EvidenceKind.HEADER, r".+", "cf-pages", 1.0),
    # Web servers
    Signature("nginx", "web-server", EvidenceKind.HEADER, r"nginx(?:/([\d.]+))?", "server", 1.0, 1),
    Signature(
        "Apache", "web-server", EvidenceKind.HEADER, r"apache(?:/([\d.]+))?", "server", 1.0, 1
    ),
    Signature(
        "Microsoft IIS",
        "web-server",
        EvidenceKind.HEADER,
        r"microsoft-iis(?:/([\d.]+))?",
        "server",
        1.0,
        1,
    ),
    Signature("LiteSpeed", "web-server", EvidenceKind.HEADER, r"litespeed", "server", 1.0),
    Signature("Caddy", "web-server", EvidenceKind.HEADER, r"caddy", "server", 1.0),
    Signature("Envoy", "web-server", EvidenceKind.HEADER, r"envoy", "server", 0.9),
    # Languages / runtimes
    Signature("PHP", "language", EvidenceKind.HEADER, r"php(?:/([\d.]+))?", "x-powered-by", 1.0, 1),
    Signature("PHP", "language", EvidenceKind.COOKIE, r"PHPSESSID", "", 0.95),
    Signature("PHP", "language", EvidenceKind.FILE, r"\.php(?:$|\?)", "", 0.7),
    Signature("ASP.NET", "language", EvidenceKind.HEADER, r"asp\.net", "x-powered-by", 1.0),
    Signature("ASP.NET", "language", EvidenceKind.HEADER, r".+", "x-aspnet-version", 1.0),
    Signature("ASP.NET", "language", EvidenceKind.COOKIE, r"ASP\.NET_SessionId", "", 0.95),
    Signature("Node.js", "language", EvidenceKind.HEADER, r"express", "x-powered-by", 0.9),
    Signature("Java", "language", EvidenceKind.COOKIE, r"JSESSIONID", "", 0.9),
    Signature(
        "Python", "language", EvidenceKind.HEADER, r"(gunicorn|uvicorn|werkzeug)", "server", 0.9
    ),
    # Frameworks
    Signature("Next.js", "framework", EvidenceKind.HEADER, r".+", "x-nextjs-cache", 1.0),
    Signature("Next.js", "framework", EvidenceKind.HEADER, r"next\.?js", "x-powered-by", 1.0),
    Signature("Next.js", "framework", EvidenceKind.HTML, r"__NEXT_DATA__", "", 1.0),
    # Statically exported Next.js sites carry no __NEXT_DATA__ blob, so the
    # mount point and asset prefix are the reliable markers for them.
    Signature("Next.js", "framework", EvidenceKind.HTML, r'id="__next"', "", 0.9),
    Signature("Next.js", "framework", EvidenceKind.HTML, r"/_next/static/", "", 0.9),
    Signature("Next.js", "framework", EvidenceKind.JS, r"/_next/static/", "", 0.95),
    Signature(
        "React", "framework", EvidenceKind.HTML, r"data-reactroot|__REACT_DEVTOOLS", "", 0.85
    ),
    Signature("Nuxt", "framework", EvidenceKind.HTML, r"__NUXT__", "", 1.0),
    Signature("Vue.js", "framework", EvidenceKind.HTML, r"data-v-[0-9a-f]{8}", "", 0.8),
    Signature("Angular", "framework", EvidenceKind.HTML, r"ng-version=", "", 0.95),
    Signature("Laravel", "framework", EvidenceKind.COOKIE, r"laravel_session|XSRF-TOKEN", "", 0.9),
    Signature("Django", "framework", EvidenceKind.COOKIE, r"csrftoken|django_language", "", 0.9),
    Signature("Django", "framework", EvidenceKind.HTML, r"csrfmiddlewaretoken", "", 0.9),
    Signature(
        "Ruby on Rails", "framework", EvidenceKind.COOKIE, r"_rails_session|_session_id", "", 0.8
    ),
    Signature(
        "Spring Boot", "framework", EvidenceKind.HEADER, r".+", "x-application-context", 0.95
    ),
    Signature("Spring Boot", "framework", EvidenceKind.API, r"/actuator(?:/health)?", "", 0.9),
    Signature("Flask", "framework", EvidenceKind.HEADER, r"werkzeug", "server", 0.9),
    # CMS / commerce
    Signature("WordPress", "cms", EvidenceKind.HTML, r"/wp-content/|/wp-includes/", "", 1.0),
    Signature("WordPress", "cms", EvidenceKind.HEADER, r"wordpress", "x-powered-by", 0.9),
    Signature("WordPress", "cms", EvidenceKind.API, r"/wp-json", "", 0.95),
    Signature("Drupal", "cms", EvidenceKind.HEADER, r".+", "x-drupal-cache", 1.0),
    Signature("Drupal", "cms", EvidenceKind.HTML, r"/sites/default/files/", "", 0.85),
    Signature("Joomla", "cms", EvidenceKind.HTML, r"/media/jui/|joomla", "", 0.85),
    Signature("Magento", "cms", EvidenceKind.COOKIE, r"X-Magento-Vary", "", 0.95),
    Signature("Shopify", "cms", EvidenceKind.HEADER, r"shopify", "x-shopid", 1.0),
    # Object storage
    Signature("Amazon S3", "storage", EvidenceKind.HEADER, r"amazons3", "server", 1.0),
    Signature("Amazon S3", "storage", EvidenceKind.HEADER, r".+", "x-amz-request-id", 0.95),
    Signature("Google Cloud Storage", "storage", EvidenceKind.HEADER, r"gse|gws", "server", 0.7),
    Signature(
        "Azure Blob Storage", "storage", EvidenceKind.HEADER, r"blob", "x-ms-blob-type", 0.95
    ),
)

#: Technologies that imply others are present.
IMPLIES: dict[str, tuple[str, ...]] = {
    "wordpress": ("php",),
    "drupal": ("php",),
    "joomla": ("php",),
    "magento": ("php",),
    "laravel": ("php",),
    "django": ("python",),
    "flask": ("python",),
    "next.js": ("react", "node.js"),
    "nuxt": ("vue.js", "node.js"),
    "spring boot": ("java",),
    "asp.net": ("microsoft iis",),
}


@dataclass(slots=True)
class Observation:
    """Normalized input to the fingerprinter, assembled once per target."""

    url: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    body: str = ""
    scripts: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    dns_records: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)

    def header(self, name: str) -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return str(value)
        return ""

    def all_headers_text(self) -> str:
        return "\n".join(f"{k}: {v}" for k, v in self.headers.items())


def _haystack(signature: Signature, observation: Observation) -> str:
    if signature.field:
        return observation.header(signature.field)
    if signature.kind is EvidenceKind.HEADER:
        return observation.all_headers_text()
    if signature.kind is EvidenceKind.COOKIE:
        return observation.cookies
    if signature.kind is EvidenceKind.HTML:
        return observation.body
    if signature.kind is EvidenceKind.JS:
        return "\n".join(observation.scripts)
    if signature.kind in (EvidenceKind.API, EvidenceKind.FILE):
        return "\n".join(observation.endpoints + observation.scripts)
    return ""


def detect_technologies(
    observation: Observation, *, min_confidence: float = 60.0
) -> list[Technology]:
    """Return technologies supported by sufficient evidence."""
    collected: dict[str, Technology] = {}

    for signature in SIGNATURES:
        haystack = _haystack(signature, observation)
        match = signature.match(haystack)
        if not match:
            continue

        snippet = match.group(0)[:120]
        locator = signature.field or signature.kind.value
        evidence = Evidence(
            kind=signature.kind,
            summary=f"{signature.technology} signature matched in {locator}",
            value=snippet,
            locator=locator,
            weight=signature.weight,
        )

        tech = collected.get(signature.technology)
        if tech is None:
            tech = Technology(name=signature.technology, category=signature.category)
            collected[signature.technology] = tech
        tech.evidence.append(evidence)

        if signature.version_group and not tech.version:
            try:
                captured = match.group(signature.version_group)
            except IndexError:  # pragma: no cover - defensive
                captured = None
            if captured:
                tech.version = captured

    results: list[Technology] = []
    for tech in collected.values():
        tech.confidence = round(100.0 * evidence_strength(tech.evidence), 1)
        if tech.confidence >= min_confidence:
            results.append(tech)

    return sorted(results, key=lambda item: item.confidence, reverse=True)


def expand_implications(technologies: list[Technology]) -> set[str]:
    """Technology slugs including those logically implied by detections."""
    present = {tech.slug for tech in technologies}
    names = {tech.name.lower() for tech in technologies}
    for name in list(names):
        for implied in IMPLIES.get(name, ()):
            present.add(implied.replace(" ", "-"))
    return present


def classify_surface(
    observation: Observation, technologies: list[Technology]
) -> tuple[Surface, list[str]]:
    """Classify the attack surface and explain the reasoning."""
    names = {tech.name.lower() for tech in technologies}
    categories = {tech.category for tech in technologies}
    reasons: list[str] = []

    if categories & {"cms"}:
        reasons.append("A content management system was fingerprinted.")
        return Surface.CMS, reasons

    if "storage" in categories:
        reasons.append("Object-storage headers were observed.")
        return Surface.OBJECT_STORAGE, reasons

    body = observation.body or ""
    content_type = observation.header("content-type").lower()
    if "json" in content_type and not body.lstrip().startswith("<"):
        reasons.append("The root response is JSON rather than HTML.")
        return Surface.API, reasons

    static_hosts = {"cloudflare pages", "github pages", "netlify", "vercel"}
    is_static_host = bool(names & static_hosts)
    spa_frameworks = {"next.js", "nuxt", "react", "vue.js", "angular"}
    is_spa = bool(names & spa_frameworks)
    server_side = {"php", "asp.net", "java", "python", "ruby on rails", "laravel", "django"}
    is_dynamic = bool(names & server_side)

    if is_dynamic:
        reasons.append("A server-side runtime was fingerprinted.")
        return Surface.DYNAMIC_APP, reasons

    if is_static_host and is_spa:
        reasons.append("A static host is serving a client-rendered application.")
        return Surface.STATIC_SITE, reasons

    if is_spa:
        reasons.append("A client-side framework was fingerprinted.")
        return Surface.SPA, reasons

    if is_static_host:
        reasons.append("The response is served from a static hosting platform.")
        return Surface.STATIC_SITE, reasons

    if "cdn" in categories:
        reasons.append("Only CDN edge characteristics were observable.")
        return Surface.CDN_EDGE, reasons

    reasons.append("No decisive technology indicators were observed.")
    return Surface.UNKNOWN, reasons
