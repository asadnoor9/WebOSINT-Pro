"""
WebOSINT Pro - Mail Security Module
MX, SPF, DKIM, DMARC validation.

Mail authentication is published at the *organizational* (registrable) domain.
A host such as ``asadnoor.example.pk`` legitimately carries no SPF/DKIM/DMARC
records of its own, so this module resolves the parent domain as well and
reports inherited policy instead of raising false "missing record" findings.
"""

import dns.resolver

from core.base_module import BaseModule

DKIM_SELECTORS = [
    "default",
    "google",
    "mail",
    "k1",
    "k2",
    "selector1",
    "selector2",
    "dkim",
    "smtp",
    "email",
    "s1",
    "s2",
    "mxvault",
    "mandrill",
    "sendgrid",
    "mailjet",
    "amazonses",
    "pm",
    "mta",
    "zmail",
    "zoho",
]

# Two-label public suffixes needed to find the registrable domain correctly
# (e.g. "foo.example.com.pk" -> "example.com.pk", not "com.pk").
MULTI_PART_SUFFIXES = {
    "ac.uk",
    "co.uk",
    "gov.uk",
    "me.uk",
    "net.uk",
    "org.uk",
    "sch.uk",
    "com.pk",
    "edu.pk",
    "gov.pk",
    "net.pk",
    "org.pk",
    "com.au",
    "edu.au",
    "gov.au",
    "net.au",
    "org.au",
    "co.in",
    "firm.in",
    "gen.in",
    "ind.in",
    "net.in",
    "org.in",
    "ac.za",
    "co.za",
    "gov.za",
    "net.za",
    "org.za",
    "ac.jp",
    "co.jp",
    "go.jp",
    "ne.jp",
    "or.jp",
    "co.kr",
    "co.nz",
    "co.il",
    "co.th",
    "co.id",
    "co.ke",
    "com.ar",
    "com.br",
    "com.cn",
    "com.co",
    "com.eg",
    "com.hk",
    "com.mx",
    "com.my",
    "com.ng",
    "com.pe",
    "com.ph",
    "com.sa",
    "com.sg",
    "com.tr",
    "com.tw",
    "com.ua",
    "com.uy",
    "com.vn",
    "edu.sg",
    "gov.sg",
    "edu.pl",
    "gov.pl",
    "net.pl",
    "org.pl",
}


def registrable_domain(host: str) -> str:
    """Return the organizational domain for ``host``."""
    host = (host or "").strip().rstrip(".").lower()
    labels = [label for label in host.split(".") if label]
    if len(labels) < 3:
        return ".".join(labels)
    # Bare IPv4 addresses have no registrable domain.
    if all(label.isdigit() for label in labels):
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Module(BaseModule):
    NAME = "mail"
    DESCRIPTION = "Mail security: MX, SPF, DKIM, DMARC validation"

    def run(self):
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        # Bound total DNS work so a blackholed resolver cannot stall the scan.
        resolver.lifetime = max(self.timeout, self.timeout * 2)

        org = registrable_domain(self.target)
        is_subdomain = bool(org) and org != self.target.lower().rstrip(".")

        results["scanned_domain"] = self.target
        results["organizational_domain"] = org
        results["is_subdomain"] = is_subdomain

        # ---- MX: does this exact host receive mail? ----
        own_mx = self._get_mx(resolver, self.target)
        org_mx = self._get_mx(resolver, org) if is_subdomain else own_mx
        sends_mail = bool(own_mx)
        results["mx_records"] = own_mx or org_mx
        results["mx_source"] = self.target if own_mx else (org if org_mx else None)
        results["receives_mail_directly"] = sends_mail

        # ---- SPF (not inherited by subdomains, but reported for context) ----
        spf = self._get_spf(resolver, self.target)
        if not spf.get("found") and is_subdomain:
            parent_spf = self._get_spf(resolver, org)
            if parent_spf.get("found"):
                parent_spf["inherited_from"] = org
                parent_spf["applies_to_scanned_host"] = False
                spf = parent_spf
        results["spf"] = spf

        if spf.get("found") and spf.get("all_mechanism") == "+all":
            results["_risk_spf_permissive"] = "critical"
        elif not spf.get("found"):
            results["_risk_no_spf"] = "high"
        elif spf.get("inherited_from"):
            # Parent publishes SPF; the scanned host does not. Only a real
            # concern if this host is used to send or receive mail.
            if sends_mail:
                results["_risk_no_spf"] = "high"
            else:
                results["_risk_subdomain_no_spf"] = "low"
                results["subdomain_hardening"] = (
                    f"{self.target} publishes no SPF of its own. The parent domain "
                    f"{org} is correctly configured. For defence in depth, publish "
                    f'a null MX and "v=spf1 -all" on this non-sending host.'
                )

        # ---- DMARC (subdomains DO inherit the parent policy per RFC 7489) ----
        dmarc = self._get_dmarc(resolver, self.target)
        if not dmarc.get("found") and is_subdomain:
            parent_dmarc = self._get_dmarc(resolver, org)
            if parent_dmarc.get("found"):
                parent_dmarc["inherited_from"] = org
                parent_dmarc["applies_to_scanned_host"] = True
                # A subdomain is governed by sp= when present.
                parent_dmarc["effective_policy"] = parent_dmarc.get(
                    "subdomain_policy", parent_dmarc.get("policy")
                )
                dmarc = parent_dmarc
        dmarc.setdefault("effective_policy", dmarc.get("policy"))
        results["dmarc"] = dmarc

        effective_policy = dmarc.get("effective_policy")
        if not dmarc.get("found"):
            results["_risk_no_dmarc"] = "high"
        elif effective_policy == "none":
            results["_risk_dmarc_policy_none"] = "medium"

        # ---- DKIM ----
        dkim = self._probe_dkim(resolver, self.target)
        if not dkim.get("found") and is_subdomain:
            parent_dkim = self._probe_dkim(resolver, org)
            if parent_dkim.get("found"):
                parent_dkim["inherited_from"] = org
                dkim = parent_dkim
        results["dkim"] = dkim
        if not dkim.get("found") and sends_mail:
            results["_risk_no_dkim"] = "medium"

        results["mta_sts"] = self._check_mta_sts(org if is_subdomain else self.target)
        results["bimi"] = self._check_bimi(resolver, org if is_subdomain else self.target)

        # ---- Spoofing assessment, based on the *effective* policy ----
        weak_spf = spf.get("all_mechanism") in ["+all", "?all"]
        can_spoof = (
            not spf.get("found") or weak_spf or not dmarc.get("found") or effective_policy == "none"
        )
        if can_spoof:
            results["email_spoofing_risk"] = "HIGH"
            results["_risk_email_spoofing"] = "high"
        elif is_subdomain and not sends_mail:
            results["email_spoofing_risk"] = "LOW"
            results["spoofing_note"] = (
                f"Authentication is published at {org} and inherited by this host "
                f"(DMARC policy: {effective_policy})."
            )
        else:
            results["email_spoofing_risk"] = "LOW"

        return results

    def _get_mx(self, resolver, domain):
        if not domain:
            return []
        try:
            answers = resolver.resolve(domain, "MX")
            return sorted(
                [{"priority": r.preference, "host": str(r.exchange)} for r in answers],
                key=lambda x: x["priority"],
            )
        except Exception:
            return []

    def _get_spf(self, resolver, domain):
        result = {"found": False, "record": None, "all_mechanism": None, "issues": []}
        if not domain:
            return result
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["found"] = True
                    result["record"] = txt
                    result["domain"] = domain

                    for part in txt.split():
                        if part.endswith("all"):
                            result["all_mechanism"] = part

                    if result["all_mechanism"] == "+all":
                        result["issues"].append("+all allows anyone to send as this domain")
                    elif result["all_mechanism"] == "?all":
                        result["issues"].append("?all is neutral and provides no protection")
                    elif result["all_mechanism"] == "~all":
                        result["issues"].append("~all softfails; -all is stricter")
                    elif result["all_mechanism"] == "-all":
                        result["issues"].append("OK: -all enforces SPF rejection")
                    break
        except Exception:
            pass
        return result

    def _get_dmarc(self, resolver, domain):
        result = {"found": False, "record": None, "policy": None, "issues": []}
        if not domain:
            return result
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    result["found"] = True
                    result["record"] = txt
                    result["domain"] = domain

                    tags = {}
                    for part in txt.split(";"):
                        part = part.strip()
                        if "=" in part:
                            k, v = part.split("=", 1)
                            tags[k.strip()] = v.strip()

                    result["policy"] = tags.get("p", "none")
                    result["subdomain_policy"] = tags.get("sp", tags.get("p", "none"))
                    result["pct"] = tags.get("pct", "100")
                    result["rua"] = tags.get("rua", "")
                    result["ruf"] = tags.get("ruf", "")
                    result["adkim"] = tags.get("adkim", "r")
                    result["aspf"] = tags.get("aspf", "r")

                    if result["policy"] == "none":
                        result["issues"].append("Policy=none: monitoring only, emails not rejected")
                    if result["pct"] != "100":
                        result["issues"].append(
                            f"pct={result['pct']}: DMARC only applied to {result['pct']}% of mail"
                        )
                    break
        except Exception:
            pass
        return result

    def _probe_dkim(self, resolver, domain):
        result = {"found": False, "selectors": []}
        if not domain:
            return result
        for selector in DKIM_SELECTORS:
            query = f"{selector}._domainkey.{domain}"
            try:
                answers = resolver.resolve(query, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        result["found"] = True
                        result["domain"] = domain
                        result["selectors"].append(
                            {
                                "selector": selector,
                                "record": txt[:200],
                            }
                        )
                        break
            except Exception:
                pass
        return result

    def _check_mta_sts(self, domain):
        result = {"found": False}
        if not domain:
            return result
        try:
            r = self.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
            if r and r.status_code == 200:
                result["found"] = True
                result["domain"] = domain
                result["policy"] = r.text[:500]
        except Exception:
            pass
        return result

    def _check_bimi(self, resolver, domain):
        result = {"found": False}
        if not domain:
            return result
        try:
            answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=BIMI1" in txt:
                    result["found"] = True
                    result["domain"] = domain
                    result["record"] = txt
        except Exception:
            pass
        return result
