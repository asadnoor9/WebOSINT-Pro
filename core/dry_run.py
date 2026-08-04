"""
WebOSINT Pro - Dry-run plumbing.

With ``--dry-run`` the tool prints exactly what network requests and
subprocess/socket calls each selected module *would* make, without performing
any of them. This lets an operator preview the footprint of a scan against an
authorized target before sending a single packet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence


@dataclass
class PlannedAction:
    kind: str  # "http" | "exec" | "socket"
    detail: str


@dataclass
class DryRunRecorder:
    logger: Any = None
    actions: list[PlannedAction] = field(default_factory=list)

    def _announce(self, line: str) -> None:
        print(f"  {line}")
        if self.logger is not None:
            try:
                self.logger.debug(line)
            except Exception:  # pragma: no cover - logger is best-effort
                pass

    def record_http(self, method: str, url: str, **kwargs: Any) -> None:
        detail = f"{method.upper()} {url}"
        self.actions.append(PlannedAction("http", detail))
        self._announce(f"[DRY-RUN] HTTP: {detail}")

    def record_subprocess(self, cmd: Sequence[str]) -> None:
        detail = " ".join(str(c) for c in cmd)
        self.actions.append(PlannedAction("exec", detail))
        self._announce(f"[DRY-RUN] EXEC: {detail}")

    def record_socket(self, host: str, port: int) -> None:
        detail = f"connect {host}:{port}"
        self.actions.append(PlannedAction("socket", detail))
        self._announce(f"[DRY-RUN] SOCKET: {detail}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "planned_actions": [
                {"kind": a.kind, "detail": a.detail} for a in self.actions
            ],
            "count": len(self.actions),
        }


class DryRunSession:
    """A drop-in stand-in for ``requests.Session`` used in dry-run mode.

    Every request is recorded and ``None`` is returned instead of a real
    response, so calling code must already treat ``None`` as "no response".
    """

    def __init__(self, recorder: DryRunRecorder, user_agent: str | None = None) -> None:
        self._recorder = recorder
        self.headers: dict[str, str] = {}
        if user_agent:
            self.headers["User-Agent"] = user_agent

    def request(self, method: str, url: str, **kwargs: Any) -> None:
        self._recorder.record_http(method, url, **kwargs)
        return None

    def get(self, url: str, **kwargs: Any) -> None:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> None:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> None:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:  # pragma: no cover - trivial
        pass
