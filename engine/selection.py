"""
Technology-aware dynamic plugin selection.

The legacy scanner ran everything that was ticked, which wasted most of its
runtime probing for stacks that could not possibly be present (WordPress paths
on a static Next.js export, IIS checks against nginx). Selection turns the
observed technology profile into an execution plan, and records *why* each
plugin was kept or dropped so the decision is auditable.

Skipping is always evidence-based and reversible: ``--force-all`` disables
gating entirely for operators who want exhaustive coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from engine.models import Surface, Technology


@dataclass(frozen=True, slots=True)
class Requirement:
    """Preconditions that make a plugin worth running.

    ``any_technology``  - run if any of these are present.
    ``any_surface``     - run if the surface is one of these.
    ``forbidden``       - never run if any of these are present.
    ``always``          - baseline plugins that always run.
    """

    any_technology: frozenset[str] = frozenset()
    any_surface: frozenset[Surface] = frozenset()
    forbidden: frozenset[str] = frozenset()
    always: bool = False
    active_only: bool = False


#: Server-side stacks. If none are present, server-side app probing is futile.
SERVER_SIDE = frozenset(
    {"php", "asp.net", "java", "python", "node.js", "ruby-on-rails", "laravel", "django"}
)

#: Static hosting platforms that cannot execute server-side code.
STATIC_HOSTS = frozenset({"cloudflare-pages", "github-pages", "netlify", "vercel"})


#: The execution plan catalogue. Baseline plugins always run because they are
#: what *produces* the technology profile in the first place.
REQUIREMENTS: dict[str, Requirement] = {
    "dns": Requirement(always=True),
    "ip": Requirement(always=True),
    "http": Requirement(always=True),
    "ssl": Requirement(always=True),
    "whois": Requirement(always=True),
    "mail": Requirement(always=True),
    "osint": Requirement(always=True),
    "subdomains": Requirement(always=True),
    "javascript": Requirement(always=True),
    "cve": Requirement(always=True),
    # Technology-gated.
    "webapp": Requirement(
        any_technology=SERVER_SIDE | {"wordpress", "drupal", "joomla", "magento"},
        any_surface=frozenset({Surface.DYNAMIC_APP, Surface.CMS, Surface.UNKNOWN}),
    ),
    "database": Requirement(
        any_technology=SERVER_SIDE,
        any_surface=frozenset({Surface.DYNAMIC_APP, Surface.CMS}),
        active_only=True,
    ),
    "api": Requirement(
        any_surface=frozenset(
            {Surface.API, Surface.SPA, Surface.DYNAMIC_APP, Surface.CMS, Surface.UNKNOWN}
        ),
    ),
    "dirs": Requirement(
        any_surface=frozenset(
            {Surface.DYNAMIC_APP, Surface.CMS, Surface.UNKNOWN, Surface.NETWORK_HOST}
        ),
        active_only=True,
    ),
    "websocket": Requirement(
        any_technology={"node.js", "java", "python", "asp.net"},
        any_surface=frozenset({Surface.SPA, Surface.API, Surface.DYNAMIC_APP}),
        active_only=True,
    ),
    "ports": Requirement(
        any_surface=frozenset({Surface.NETWORK_HOST, Surface.DYNAMIC_APP, Surface.UNKNOWN}),
        active_only=True,
    ),
    # Infrastructure probing is pointless behind a CDN edge: it profiles the
    # provider, not the customer.
    "siem": Requirement(
        any_surface=frozenset({Surface.NETWORK_HOST, Surface.DYNAMIC_APP}),
        forbidden=STATIC_HOSTS,
        active_only=True,
    ),
    "honeypot": Requirement(
        any_surface=frozenset({Surface.NETWORK_HOST, Surface.DYNAMIC_APP}),
        forbidden=STATIC_HOSTS,
        active_only=True,
    ),
    "ids": Requirement(
        any_surface=frozenset({Surface.NETWORK_HOST, Surface.DYNAMIC_APP}),
        forbidden=STATIC_HOSTS,
        active_only=True,
    ),
    "waf": Requirement(
        any_surface=frozenset(
            {Surface.DYNAMIC_APP, Surface.CMS, Surface.API, Surface.NETWORK_HOST}
        ),
        active_only=True,
    ),
}


@dataclass(slots=True)
class Decision:
    """Why a plugin will or will not run."""

    plugin: str
    selected: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"plugin": self.plugin, "selected": self.selected, "reason": self.reason}


@dataclass(slots=True)
class Plan:
    """The resolved execution plan for one target."""

    selected: list[str] = field(default_factory=list)
    skipped: list[Decision] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "selected": list(self.selected),
            "skipped": [item.to_dict() for item in self.skipped],
            "decisions": [item.to_dict() for item in self.decisions],
        }


def build_plan(
    candidates: list[str],
    technologies: list[Technology],
    surface: Surface,
    *,
    active: bool = False,
    force_all: bool = False,
) -> Plan:
    """Resolve which plugins should run against this target."""
    from engine.fingerprint import expand_implications

    present = expand_implications(technologies)
    plan = Plan()

    for name in candidates:
        requirement = REQUIREMENTS.get(name)

        if force_all:
            decision = Decision(name, True, "Gating disabled by force-all.")
        elif requirement is None:
            decision = Decision(name, True, "No gating rule defined; running by default.")
        elif requirement.always:
            decision = Decision(name, True, "Baseline plugin.")
        elif requirement.active_only and not active:
            decision = Decision(name, False, "Requires active mode.")
        elif requirement.forbidden & present:
            blocker = ", ".join(sorted(requirement.forbidden & present))
            decision = Decision(
                name, False, f"Not meaningful for this surface ({blocker} detected)."
            )
        else:
            tech_ok = (
                bool(requirement.any_technology & present) if requirement.any_technology else None
            )
            surface_ok = surface in requirement.any_surface if requirement.any_surface else None

            if tech_ok is None and surface_ok is None:
                decision = Decision(name, True, "No preconditions.")
            elif tech_ok or surface_ok:
                why = []
                if tech_ok:
                    matched = ", ".join(sorted(requirement.any_technology & present))
                    why.append(f"technology match ({matched})")
                if surface_ok:
                    why.append(f"surface is {surface.value}")
                decision = Decision(name, True, "Selected: " + " and ".join(why) + ".")
            else:
                expected = ", ".join(sorted(requirement.any_technology)) or surface.value
                decision = Decision(
                    name,
                    False,
                    f"No evidence of the required stack ({expected}); surface is {surface.value}.",
                )

        plan.decisions.append(decision)
        if decision.selected:
            plan.selected.append(decision.plugin)
        else:
            plan.skipped.append(decision)

    return plan
