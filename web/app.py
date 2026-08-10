"""
WebOSINT Pro - local web interface.

A thin UI over the exact same pipeline the CLI uses. Every scan still passes
through SafetyController: authorization must be asserted, the target must be
re-typed to confirm, internal/reserved ranges stay blocked, and active modules
stay behind an explicit opt-in.

The server binds to 127.0.0.1 by default. When it is exposed to a LAN it
requires a bearer token (see webserve.py --lan / --auth-token).

Scans always run on a background worker thread, so closing the browser tab
never stops a scan. Job state is in-memory only and is lost on restart.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.cli import MODULE_HELP, parse_args
from core.config import ACTIVE_MODULES, PROFILE_SETTINGS, Config
from core.logger import setup_logger
from core.paths import ensure_all, reports_dir
from core.redaction import DetailLevel, Redactor
from core.retention import RetentionPolicy
from core.safety import SafetyController, SafetyPolicy, normalize_host

FORMATS = [
    ("json", "JSON", "Machine-readable, full detail"),
    ("html", "Web page (HTML)", "Styled, self-contained report"),
    ("markdown", "Markdown", "Plain text, diff friendly"),
    ("csv", "CSV", "One row per finding, opens in Excel"),
    ("docx", "Word (.docx)", "Needs the reports extra"),
    ("pdf", "PDF", "Needs the reports extra"),
]

MIME = {
    "json": "application/json",
    "html": "text/html",
    "md": "text/markdown",
    "csv": "text/csv",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}

# Formats that are safe and useful to render inline in the portal.
VIEWABLE = {"html", "md", "json", "csv"}

# Scan speed presets. Higher speed means more concurrent requests and less
# delay, which is noisier and more likely to trip rate limits or WAFs.
SPEED_PRESETS: dict[str, dict[str, Any]] = {
    "slow": {
        "label": "Slow",
        "threads": 2,
        "delay": 2.0,
        "rate_limit": 5,
        "timeout": 20,
        "hint": "Lowest noise. Best for production targets.",
    },
    "normal": {
        "label": "Normal",
        "threads": 5,
        "delay": 0.5,
        "rate_limit": 15,
        "timeout": 15,
        "hint": "Balanced default.",
    },
    "fast": {
        "label": "Fast",
        "threads": 12,
        "delay": 0.0,
        "rate_limit": 30,
        "timeout": 10,
        "hint": "Noticeable in logs. Use on targets you own.",
    },
    "turbo": {
        "label": "Turbo",
        "threads": 24,
        "delay": 0.0,
        "rate_limit": 60,
        "timeout": 8,
        "hint": "Very noisy. Expect blocking and false negatives.",
    },
}
DEFAULT_SPEED = "normal"

# Web verbosity -> log level shown in the portal.
TRACE_LEVEL = 5
VERBOSITY_LEVELS: dict[int, dict[str, Any]] = {
    0: {"label": "Quiet", "level": logging.ERROR, "hint": "Errors only"},
    1: {"label": "Normal", "level": logging.INFO, "hint": "Module progress"},
    2: {"label": "Verbose", "level": logging.DEBUG, "hint": "Findings and decisions"},
    3: {"label": "Debug", "level": TRACE_LEVEL, "hint": "Per-request detail"},
}
DEFAULT_VERBOSITY = 1

# Per-job ring buffer. Bounded so a long scan cannot exhaust memory.
MAX_LOG_LINES = 500


class JobLogHandler(logging.Handler):
    """Capture log records for one job.

    The "webosint" logger already carries a RedactionFilter on the logger
    itself, so records reaching this handler are redacted before we see them.
    """

    def __init__(self, job: Job, level: int) -> None:
        super().__init__(level=level)
        self.job = job

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            return
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        self.job.add_log(record.levelname, stamp, message)


@dataclass
class Job:
    """In-memory record of one scan. Never persisted."""

    id: str
    target: str
    mode: str
    status: str = "queued"
    message: str = ""
    speed: str = DEFAULT_SPEED
    verbosity: int = DEFAULT_VERBOSITY
    formats: list[str] = field(default_factory=list)
    started: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    infrastructure: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    progress: dict[str, Any] = field(default_factory=dict)
    logs: deque = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))
    log_total: int = 0
    cancel: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_log(self, level: str, time_str: str, message: str) -> None:
        with self.lock:
            self.logs.append({"level": level, "time": time_str, "message": message})
            self.log_total += 1

    def set_progress(self, payload: dict[str, Any]) -> None:
        with self.lock:
            self.progress = payload

    def tail(self, offset: int) -> list[dict[str, Any]]:
        """Return log lines the client has not seen yet."""
        with self.lock:
            buffered = list(self.logs)
            total = self.log_total
        dropped = total - len(buffered)
        if offset >= total:
            return []
        start = max(0, offset - dropped)
        return buffered[start:]

    def public(self, log_offset: int = 0) -> dict[str, Any]:
        with self.lock:
            progress = dict(self.progress)
            total = self.log_total
        return {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "message": self.message,
            "speed": self.speed,
            "verbosity": self.verbosity,
            "started": self.started,
            "finished": self.finished,
            "summary": self.summary,
            "findings": self.findings,
            "infrastructure": self.infrastructure,
            "errors": self.errors,
            "progress": progress,
            "logs": self.tail(log_offset),
            "log_total": total,
            "artifacts": [
                {
                    "index": i,
                    "name": a["name"],
                    "ext": a["ext"],
                    "size": a["size"],
                    "viewable": a["ext"] in VIEWABLE,
                }
                for i, a in enumerate(self.artifacts)
            ],
        }


JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _checked(form, name: str) -> bool:
    return form.get(name) in ("on", "true", "1", "yes")


def _int(form, name: str, default: int | None = None) -> int | None:
    raw = (form.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def resolve_speed(name: str | None) -> tuple[str, dict[str, Any]]:
    key = (name or DEFAULT_SPEED).strip().lower()
    if key not in SPEED_PRESETS:
        key = DEFAULT_SPEED
    return key, SPEED_PRESETS[key]


def resolve_verbosity(value: Any) -> int:
    try:
        level = int(value)
    except (TypeError, ValueError):
        return DEFAULT_VERBOSITY
    return level if level in VERBOSITY_LEVELS else DEFAULT_VERBOSITY


def build_config(form, formats: list[str]) -> Config:
    """Translate the form into the same argparse namespace the CLI produces."""
    args = parse_args([])

    args.target = (form.get("target") or "").strip()
    args.confirm_target = (form.get("confirm_target") or "").strip()
    args.authorized = _checked(form, "authorized")
    args.active = _checked(form, "active")
    args.allow_private = _checked(form, "allow_private")
    args.insecure_tls = _checked(form, "insecure_tls")
    args.keep_raw = _checked(form, "keep_raw")

    args.profile = form.get("profile") or "safe"
    args.detail = form.get("detail") or "standard"

    selected = form.getlist("modules") if hasattr(form, "getlist") else []
    args.modules = ",".join(selected) if selected else "all"

    # The web layer writes every requested format itself, so the controller
    # is told "all" only when more than one was picked.
    args.output = formats[0] if len(formats) == 1 else "all"
    args.output_dir = str(reports_dir() / "web")

    # Speed preset supplies the pacing defaults; explicit fields still win so
    # an operator can hand-tune a preset.
    _, preset = resolve_speed(form.get("speed"))
    args.threads = _int(form, "threads", preset["threads"])
    args.timeout = _int(form, "timeout", preset["timeout"])
    args.rate_limit = _int(form, "rate_limit", preset["rate_limit"])
    args.delay = preset["delay"]
    args.retention_days = _int(form, "retention_days", 30)

    args.quiet = True  # the server console stays silent; the browser is the console
    args.no_color = True
    return Config(args)


def authorize(cfg: Config) -> tuple[SafetyController | None, str]:
    """Same gate as the CLI, returning a message instead of printing."""
    if not cfg.authorized:
        return None, "Authorization checkbox is required before any scan can start."

    if not cfg.confirm_target:
        return None, "Type the target again in the confirmation field."

    if normalize_host(cfg.confirm_target) != normalize_host(cfg.target):
        return None, "The confirmation does not match the target. Scan aborted."

    policy = SafetyPolicy(
        authorized=True,
        confirmed=True,
        active=cfg.active,
        allow_private=cfg.allow_private,
        insecure_tls=cfg.insecure_tls,
        max_redirects=cfg.max_redirects,
        allowlist=(),
        telemetry=False,
    )
    controller = SafetyController(policy)
    result = controller.validate(cfg.target)
    if not result.allowed:
        return None, " ".join(result.errors) or "Target rejected by the safety policy."
    return controller, " ".join(result.warnings)


def collect_artifacts(paths: list[str], formats: list[str]) -> list[dict[str, Any]]:
    """Register produced report files.

    Must be given real on-disk paths (ScanController.report_paths), never the
    redacted paths in results["reports"], which will not exist on disk.
    """
    wanted = {"markdown": "md"}
    exts = {wanted.get(f, f) for f in formats}
    artifacts: list[dict[str, Any]] = []
    for path in sorted(paths or []):
        ext = os.path.splitext(path)[1].lstrip(".").lower()
        if ext in exts and os.path.exists(path):
            artifacts.append(
                {
                    "name": os.path.basename(path),
                    "path": os.path.abspath(path),
                    "ext": ext,
                    "size": os.path.getsize(path),
                }
            )
    return artifacts


def run_job(job: Job, cfg: Config, controller: SafetyController, formats: list[str]) -> None:
    """Execute the scan on a worker thread and collect the artifacts."""
    from core.controller import ScanController

    handler: JobLogHandler | None = None
    log = logging.getLogger("webosint")
    try:
        job.status = "running"
        cfg.safety = controller
        cfg.redactor = Redactor(
            level=DetailLevel.parse(cfg.detail),
            keep_raw=cfg.keep_raw,
            extra_secrets=tuple(s for s in (cfg.shodan_key, cfg.nvd_key) if s),
        )
        cfg.retention = RetentionPolicy(
            reports_days=cfg.retention_days,
            logs_days=cfg.log_retention_days,
            enabled=cfg.cleanup,
        )
        logger = setup_logger(
            verbose=0,
            quiet=True,
            log_dir=cfg.log_dir,
            session_id=cfg.session_id,
            redactor=cfg.redactor,
            write_files=cfg.write_log_file,
        )

        # Mirror log output into the job so the portal can show it live.
        handler = JobLogHandler(job, VERBOSITY_LEVELS[job.verbosity]["level"])
        log.addHandler(handler)

        cfg.progress_callback = job.set_progress

        scan = ScanController(cfg, logger, safety=controller, cancel_event=job.cancel)
        results = scan.run()

        job.summary = results.get("summary", {}) or {}
        job.findings = results.get("normalized_findings", []) or []
        job.infrastructure = results.get("infrastructure", {}) or {}
        job.errors = results.get("errors", {}) or {}

        # Real paths, not the redacted results["reports"] list.
        job.artifacts = collect_artifacts(getattr(scan, "report_paths", []), formats)

        job.status = "cancelled" if job.cancel.is_set() else "done"
    except Exception as exc:  # never leak a traceback to the browser
        redactor = getattr(cfg, "redactor", None)
        job.message = redactor.exception(exc) if redactor else "Scan failed."
        job.status = "failed"
    finally:
        if handler is not None:
            log.removeHandler(handler)
        job.finished = datetime.now().isoformat(timespec="seconds")


def create_app(auth_token: str | None = None) -> Any:
    try:
        from flask import (
            Flask,
            abort,
            jsonify,
            make_response,
            redirect,
            render_template,
            request,
            send_file,
            url_for,
        )
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError(
            "The web interface needs Flask. Install the extra: pip install '.[web]'"
        ) from exc

    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)
    # output/ is git-ignored, so a fresh checkout has no reports, logs or
    # cache directory. Create them once at startup rather than letting the
    # first scan fail on a missing path.
    ensure_all()

    modules = [
        {"name": name, "desc": desc, "active": name in ACTIVE_MODULES}
        for name, desc in MODULE_HELP.items()
    ]
    speeds = [
        {"key": key, "label": val["label"], "hint": val["hint"]}
        for key, val in SPEED_PRESETS.items()
    ]
    verbosities = [
        {"key": key, "label": val["label"], "hint": val["hint"]}
        for key, val in sorted(VERBOSITY_LEVELS.items())
    ]

    def page_args(**extra: Any) -> dict[str, Any]:
        base = {
            "modules": modules,
            "profiles": sorted(PROFILE_SETTINGS.keys()),
            "formats": FORMATS,
            "speeds": speeds,
            "verbosities": verbosities,
            "default_speed": DEFAULT_SPEED,
            "default_verbosity": DEFAULT_VERBOSITY,
            "jobs": recent_jobs(10),
        }
        base.update(extra)
        return base

    def recent_jobs(limit: int | None = None) -> list[Job]:
        with _JOBS_LOCK:
            items = sorted(JOBS.values(), key=lambda j: j.started, reverse=True)
        return items[:limit] if limit else items

    if auth_token:

        @app.before_request
        def require_token():
            # The icon is not sensitive and is needed by the 401 page itself.
            if request.path in ("/favicon.ico", "/static/favicon.svg"):
                return None

            if request.cookies.get("wo_token") and secrets.compare_digest(
                request.cookies.get("wo_token", ""), auth_token
            ):
                return None

            supplied = request.args.get("token") or ""
            header = request.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                supplied = header[7:].strip()

            if supplied and secrets.compare_digest(supplied, auth_token):
                response = make_response(redirect(request.path))
                response.set_cookie(
                    "wo_token",
                    auth_token,
                    httponly=True,
                    samesite="Strict",
                    secure=request.is_secure,
                )
                return response

            body = (
                "<!doctype html><title>401</title>"
                "<body style='font-family:sans-serif;background:#0f1419;color:#e6edf3;padding:40px'>"
                "<h1>Access token required</h1>"
                "<p>Append <code>?token=YOUR_TOKEN</code> to the URL, or send an "
                "<code>Authorization: Bearer</code> header.</p></body>"
            )
            return body, 401

    @app.get("/")
    def index():
        return render_template("index.html", **page_args())

    @app.post("/scan")
    def scan():
        form = request.form
        formats = form.getlist("formats") or ["json"]
        speed, _ = resolve_speed(form.get("speed"))
        verbosity = resolve_verbosity(form.get("verbosity"))

        try:
            cfg = build_config(form, formats)
        except ValueError as exc:
            return render_template(
                "index.html", **page_args(error=f"Invalid configuration: {exc}")
            ), 400

        if not cfg.target:
            return render_template("index.html", **page_args(error="A target is required.")), 400

        controller, message = authorize(cfg)
        if controller is None:
            return render_template("index.html", **page_args(error=message)), 403

        job = Job(
            id=uuid.uuid4().hex[:12],
            target=cfg.target,
            mode="active" if cfg.active else "passive",
            message=message,
            speed=speed,
            verbosity=verbosity,
            formats=list(formats),
        )
        with _JOBS_LOCK:
            JOBS[job.id] = job

        thread = threading.Thread(target=run_job, args=(job, cfg, controller, formats), daemon=True)
        thread.start()
        return redirect(url_for("results", job_id=job.id))

    @app.get("/jobs")
    def jobs_index():
        return render_template("jobs.html", jobs=recent_jobs())

    @app.get("/scan/<job_id>")
    def results(job_id: str):
        job = JOBS.get(job_id)
        if job is None:
            abort(404)
        return render_template("results.html", job=job)

    @app.get("/api/scan/<job_id>")
    def api_status(job_id: str):
        job = JOBS.get(job_id)
        if job is None:
            abort(404)
        try:
            offset = int(request.args.get("log_offset", 0))
        except ValueError:
            offset = 0
        return jsonify(job.public(max(0, offset)))

    @app.post("/scan/<job_id>/cancel")
    def cancel(job_id: str):
        job = JOBS.get(job_id)
        if job is None:
            abort(404)
        job.cancel.set()
        return redirect(url_for("results", job_id=job_id))

    def _artifact(job_id: str, index: int) -> dict[str, Any]:
        job = JOBS.get(job_id)
        if job is None or index < 0 or index >= len(job.artifacts):
            abort(404)
        # Serve only paths this job registered - never a user-supplied path.
        artifact = job.artifacts[index]
        # The file may be gone: retention pruned it, output/ was cleaned, or
        # the checkout was replaced. Job state is in memory and outlives the
        # files, so report a stale link as 404 instead of a 500 crash page.
        if not os.path.isfile(artifact["path"]):
            abort(404)
        return artifact

    @app.get("/download/<job_id>/<int:index>")
    def download(job_id: str, index: int):
        artifact = _artifact(job_id, index)
        return send_file(
            artifact["path"],
            as_attachment=True,
            download_name=artifact["name"],
            mimetype=MIME.get(artifact["ext"], "application/octet-stream"),
        )

    @app.get("/view/<job_id>/<int:index>")
    def view(job_id: str, index: int):
        """Render a report inline in the portal."""
        artifact = _artifact(job_id, index)
        if artifact["ext"] not in VIEWABLE:
            abort(404)
        response = send_file(
            artifact["path"],
            as_attachment=False,
            download_name=artifact["name"],
            mimetype=MIME.get(artifact["ext"], "text/plain"),
        )
        # Report content is derived from scan output. Drop it into an opaque
        # origin so it can never read this app's cookies or call its routes.
        response.headers["Content-Security-Policy"] = "sandbox"
        return response

    @app.route("/favicon.ico")
    def favicon():
        return app.send_static_file("favicon.svg")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
