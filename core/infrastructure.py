"""
WebOSINT Pro - infrastructure roll-up.

Turns raw per-module findings into one flat "what is this host" view:
operating system, network/ISP ownership, exposed ports with service versions,
and the web server product. Read-only: it never performs network activity, it
only reshapes data other modules already collected.

Everything here is defensive. Module output shapes vary between plugins and
between scan modes, so each extractor tolerates missing or oddly typed data
and returns empty structures rather than raising.
"""

from __future__ import annotations

import re
from typing import Any

# "Apache/2.4.65", "nginx/1.24.0", "Microsoft-IIS/10.0"
PRODUCT_VERSION = re.compile(r"([A-Za-z][A-Za-z0-9_\-\.]*)/(\d[\w\.\-]*)")

# nmap: "443/tcp open  ssl/http Apache httpd 2.4.65 ((Unix) OpenSSL/3.5.5)"
NMAP_PORT_LINE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
    re.IGNORECASE,
)

# nmap: "Running (JUST GUESSING): Linux 4.X|5.X (93%)"
NMAP_OS_LINE = re.compile(r"^(?:Running|Aggressive OS guesses|OS details)[^:]*:\s*(.+)$")
NMAP_CPE_LINE = re.compile(r"^OS CPE:\s*(.+)$")
NMAP_DEVICE_LINE = re.compile(r"^Device type:\s*(.+)$")

# Well-known web server families, checked against the Server header.
SERVER_FAMILIES = [
    ("iis", "Microsoft IIS"),
    ("nginx", "nginx"),
    ("openresty", "OpenResty"),
    ("apache", "Apache HTTP Server"),
    ("litespeed", "LiteSpeed"),
    ("caddy", "Caddy"),
    ("tomcat", "Apache Tomcat"),
    ("jetty", "Jetty"),
    ("gunicorn", "Gunicorn"),
    ("cloudflare", "Cloudflare"),
    ("cloudfront", "Amazon CloudFront"),
    ("envoy", "Envoy"),
    ("kestrel", "Kestrel"),
]

# Ports worth calling out when they are reachable.
NOTABLE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, (str, int)) and value != "":
        return [value]
    return []


def _clean(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def parse_product(banner: str) -> tuple[str, str]:
    """Split a server banner into a friendly product name and a version."""
    text = _clean(banner)
    if not text:
        return "", ""

    lowered = text.lower()
    family = ""
    for needle, label in SERVER_FAMILIES:
        if needle in lowered:
            family = label
            break

    version = ""
    for name, found in PRODUCT_VERSION.findall(text):
        # Prefer the version attached to the identified family.
        if family and name.lower().replace("-", "") in family.lower().replace(" ", ""):
            version = found
            break
        if not version:
            version = found
            if not family:
                family = name

    # "Apache httpd 2.4.65" style, where the version is space separated.
    if not version:
        match = re.search(r"\b(\d+\.\d[\w\.\-]*)", text)
        if match:
            version = match.group(1)

    return family or text.split("/")[0].strip(), version


def extract_web_server(findings: dict[str, Any]) -> dict[str, Any]:
    """Web hosting type: IIS / nginx / Apache and the advertised version."""
    http = _as_dict(findings.get("http"))
    headers = _as_dict(http.get("headers"))

    # Header lookup is case-insensitive: servers disagree on capitalisation.
    lowered = {str(k).lower(): v for k, v in headers.items()}
    # Prefer the raw header: modules often store a cleaned family name
    # ("Apache") that has already lost the version ("Apache/2.4.65").
    banner = _clean(lowered.get("server")) or _clean(http.get("server"))
    product, version = parse_product(banner)

    powered = _clean(lowered.get("x-powered-by"))
    powered_product, powered_version = parse_product(powered) if powered else ("", "")

    tech = _as_dict(findings.get("tech")) or _as_dict(findings.get("webapp"))
    technologies = [
        _clean(item) if not isinstance(item, dict) else _clean(item.get("name"))
        for item in _as_list(tech.get("technologies"))
    ]

    return {
        "banner": banner,
        "product": product,
        "version": version,
        "powered_by": powered,
        "powered_by_product": powered_product,
        "powered_by_version": powered_version,
        "cdn": [_clean(c) for c in _as_list(http.get("cdn")) if _clean(c)],
        "technologies": [t for t in technologies if t],
        "status_code": http.get("status_code"),
        "final_url": _clean(http.get("final_url")) or _clean(http.get("base_url")),
        "version_disclosed": bool(version),
    }


def extract_network(findings: dict[str, Any]) -> dict[str, Any]:
    """ISP, organisation, ASN and geography for the resolved address."""
    ip_data = _as_dict(findings.get("ip"))
    resolved = [_clean(i) for i in _as_list(ip_data.get("resolved_ips")) if _clean(i)]
    if not resolved:
        resolved = [_clean(a) for a in _as_list(_as_dict(findings.get("dns")).get("A"))]

    primary = resolved[0] if resolved else ""
    detail = _as_dict(ip_data.get(primary)) if primary else {}
    geo = _as_dict(detail.get("geo"))

    asn = _clean(detail.get("asn")) or _clean(geo.get("as"))
    return {
        "primary_ip": primary,
        "resolved_ips": resolved,
        "ip_version": _clean(detail.get("version")),
        "isp": _clean(geo.get("isp")),
        "organization": _clean(geo.get("org")),
        "asn": asn,
        "country": _clean(geo.get("country")),
        "region": _clean(geo.get("regionName")) or _clean(geo.get("region")),
        "city": _clean(geo.get("city")),
        "timezone": _clean(geo.get("timezone")),
        "hosting_provider": bool(geo.get("hosting")),
        "proxy_or_vpn": bool(geo.get("proxy")),
        "mobile_network": bool(geo.get("mobile")),
        "blacklisted": bool(detail.get("blacklisted")),
        "reverse_dns": _clean(detail.get("reverse_dns")) or _clean(detail.get("ptr")),
        "latency": _clean(_as_dict(findings.get("ports")).get("latency")),
    }


def _parse_nmap_stdout(text: str) -> dict[str, Any]:
    """Pull ports and OS guesses out of raw nmap output."""
    services: list[dict[str, Any]] = []
    os_guesses: list[str] = []
    cpes: list[str] = []
    device_type = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        port_match = NMAP_PORT_LINE.match(line)
        if port_match:
            port, proto, state, service, version = port_match.groups()
            product, product_version = parse_product(version or "")
            services.append(
                {
                    "port": int(port),
                    "protocol": proto.lower(),
                    "state": state.lower(),
                    "service": service,
                    "product": product,
                    "version": product_version,
                    "banner": _clean(version),
                }
            )
            continue

        os_match = NMAP_OS_LINE.match(line)
        if os_match:
            os_guesses.extend(part.strip() for part in os_match.group(1).split(",") if part.strip())
            continue

        cpe_match = NMAP_CPE_LINE.match(line)
        if cpe_match:
            cpes.extend(cpe_match.group(1).split())
            continue

        device_match = NMAP_DEVICE_LINE.match(line)
        if device_match:
            device_type = device_match.group(1).strip()

    return {
        "services": services,
        "os_guesses": os_guesses,
        "cpes": cpes,
        "device_type": device_type,
    }


def _normalize_port_entry(key: Any, value: Any) -> dict[str, Any] | None:
    """Accept the several shapes modules use to describe one port."""
    try:
        port = int(str(key).split("/")[0])
    except (TypeError, ValueError):
        return None

    if isinstance(value, dict):
        banner = _clean(value.get("version")) or _clean(value.get("product"))
        product, version = parse_product(banner)
        return {
            "port": port,
            "protocol": _clean(value.get("protocol")) or "tcp",
            "state": _clean(value.get("state")) or "open",
            "service": _clean(value.get("service")) or _clean(value.get("name")),
            "product": _clean(value.get("product")) or product,
            "version": _clean(value.get("version_number")) or version,
            "banner": banner,
        }

    text = _clean(value)
    product, version = parse_product(text)
    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "service": text,
        "product": product,
        "version": version,
        "banner": text,
    }


def extract_services(findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Exposed ports with service names and versions, merged and de-duplicated."""
    ports_data = _as_dict(findings.get("ports"))
    merged: dict[tuple[int, str], dict[str, Any]] = {}

    def absorb(entry: dict[str, Any] | None) -> None:
        if not entry:
            return
        key = (entry["port"], entry["protocol"])
        current = merged.get(key)
        if current is None:
            merged[key] = entry
            return
        # Keep the richest description of the same port.
        for field in ("service", "product", "version", "banner"):
            if not current.get(field) and entry.get(field):
                current[field] = entry[field]

    raw_ports = ports_data.get("ports")
    if isinstance(raw_ports, dict):
        for key, value in raw_ports.items():
            absorb(_normalize_port_entry(key, value))
    elif isinstance(raw_ports, list):
        for item in raw_ports:
            if isinstance(item, dict):
                absorb(_normalize_port_entry(item.get("port", item.get("number")), item))
            else:
                absorb(_normalize_port_entry(item, ""))

    for item in _as_list(ports_data.get("open_ports")):
        if isinstance(item, dict):
            absorb(_normalize_port_entry(item.get("port", item.get("number")), item))
        else:
            absorb(_normalize_port_entry(item, ""))

    stdout = _clean(ports_data.get("nmap_stdout"))
    if stdout:
        for entry in _parse_nmap_stdout(stdout)["services"]:
            absorb(entry)

    services = sorted(merged.values(), key=lambda row: (row["port"], row["protocol"]))
    for row in services:
        row["notable"] = row["port"] in NOTABLE_PORTS
        row["common_name"] = NOTABLE_PORTS.get(row["port"], "")
    return services


# Banner substrings that hint at the underlying OS when no nmap fingerprint exists.
OS_BANNER_HINTS: list[tuple[str, str]] = [
    ("ubuntu", "Ubuntu Linux"),
    ("debian", "Debian Linux"),
    ("centos", "CentOS Linux"),
    ("red hat", "Red Hat Linux"),
    ("rhel", "Red Hat Linux"),
    ("fedora", "Fedora Linux"),
    ("alpine", "Alpine Linux"),
    ("amazon linux", "Amazon Linux"),
    ("suse", "SUSE Linux"),
    ("oracle linux", "Oracle Linux"),
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("darwin", "macOS / Darwin"),
    ("win64", "Windows"),
    ("win32", "Windows"),
    ("windows", "Windows"),
    ("microsoft-iis", "Windows"),
    ("unix", "Unix-like"),
    ("linux", "Linux"),
]


def _infer_os_from_banners(findings: dict[str, Any]) -> list[str]:
    """Best-effort OS hints from passive banners.

    Server headers such as "Apache/2.4.65 (Unix)" or "Microsoft-IIS/10.0" leak
    the OS family without sending a single extra packet. This is weaker than an
    nmap fingerprint, so callers must label the source as "banner".
    """
    server = extract_web_server(findings)
    haystack = " ".join(
        str(value)
        for value in (
            server.get("banner"),
            server.get("product"),
            server.get("powered_by"),
        )
        if value
    ).lower()
    hints: list[str] = []
    for token, label in OS_BANNER_HINTS:
        if token in haystack and label not in hints:
            hints.append(label)
    return hints


def extract_os(findings: dict[str, Any]) -> dict[str, Any]:
    """Operating system guesses. Always low confidence unless nmap ran actively."""
    ports_data = _as_dict(findings.get("ports"))
    parsed = _parse_nmap_stdout(_clean(ports_data.get("nmap_stdout")))

    guesses: list[str] = []
    for item in _as_list(ports_data.get("os_guess")):
        if isinstance(item, dict):
            name = _clean(item.get("name")) or _clean(item.get("os"))
            accuracy = _clean(item.get("accuracy"))
            guesses.append(f"{name} ({accuracy}%)" if name and accuracy else name)
        else:
            guesses.append(_clean(item))
    guesses.extend(parsed["os_guesses"])

    # De-duplicate while preserving order.
    seen: set[str] = set()
    fingerprinted = [g for g in guesses if g and not (g in seen or seen.add(g))]

    # Fall back to banner inference so the section is never simply blank.
    inferred = [] if fingerprinted else _infer_os_from_banners(findings)
    unique = fingerprinted or inferred

    if fingerprinted:
        source = _clean(ports_data.get("scanner")) or "nmap"
        note = (
            "OS detection is a heuristic guess and is unreliable behind a CDN, "
            "proxy, or load balancer."
        )
    elif inferred:
        source = "banner"
        note = (
            "Inferred from service banners only, not an active fingerprint. "
            "Run the ports module with nmap installed for a real OS fingerprint."
        )
    else:
        source = ""
        note = (
            "No OS fingerprint available. Enable the ports module in active mode "
            "with nmap installed to fingerprint the operating system."
        )

    return {
        "guesses": unique,
        "best_guess": unique[0] if unique else "",
        "device_type": parsed["device_type"],
        "cpes": parsed["cpes"],
        "source": source,
        "note": note,
    }


def extract_tls(findings: dict[str, Any]) -> dict[str, Any]:
    ssl_data = _as_dict(findings.get("ssl"))
    protocols = _as_dict(ssl_data.get("protocols"))
    cipher = _as_dict(ssl_data.get("cipher_info"))
    return {
        "enabled_protocols": sorted(name for name, on in protocols.items() if on),
        "disabled_protocols": sorted(name for name, on in protocols.items() if not on),
        "cipher": _clean(cipher.get("name")),
        "cipher_bits": cipher.get("bits"),
        "weak_cipher": bool(cipher.get("weak")),
    }


def build_infrastructure(findings: dict[str, Any]) -> dict[str, Any]:
    """Assemble the full infrastructure view from raw module findings."""
    findings = _as_dict(findings)
    services = extract_services(findings)
    return {
        "network": extract_network(findings),
        "operating_system": extract_os(findings),
        "web_server": extract_web_server(findings),
        "services": services,
        "tls": extract_tls(findings),
        "exposed_port_count": sum(1 for s in services if s.get("state") == "open"),
        "notable_services": [s for s in services if s.get("notable")],
    }
