#!/usr/bin/env python3
"""
WebOSINT Pro - local web interface launcher.

Starts a small Flask UI that drives the same scan pipeline as the CLI,
including the mandatory authorization gate.

    python webserve.py                  # http://127.0.0.1:8000
    python webserve.py --lan            # reachable on your LAN, no token
    python webserve.py --lan --auth     # reachable on your LAN, token required
    python webserve.py --lan --self-signed
    python webserve.py --lan --background   # detach and keep running
    python webserve.py --status             # is the background server up?
    python webserve.py --stop               # stop the background server

Binding to a non-loopback address exposes a scan launcher, so it still requires
an explicit opt-in (--lan or --allow-remote). Token authentication is off by
default; turn it on with --auth or by supplying --auth-token.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import socket
import sys

from core import daemon as daemonlib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def primary_lan_ip() -> str:
    """Best-effort primary LAN address. No packets are actually sent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webserve.py", description="Run the WebOSINT Pro web interface."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument(
        "--lan",
        action="store_true",
        help="Bind to 0.0.0.0 so other machines on your network can reach the UI",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Permit binding to a non-loopback address",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("WEBOSINT_WEB_TOKEN", ""),
        help="Require this bearer token to use the UI (default: no token)",
    )
    parser.add_argument(
        "--auth",
        action="store_true",
        help="Generate a random access token and require it",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Force the token off, ignoring --auth / --auth-token (this is the default)",
    )
    parser.add_argument("--tls-cert", default="", help="Path to a TLS certificate (PEM)")
    parser.add_argument("--tls-key", default="", help="Path to the matching TLS private key")
    parser.add_argument(
        "--self-signed",
        action="store_true",
        help="Serve HTTPS with an ad-hoc self-signed certificate (needs cryptography)",
    )
    parser.add_argument(
        "--background",
        "--daemon",
        dest="background",
        action="store_true",
        help="Detach and keep running after the terminal closes",
    )
    parser.add_argument("--stop", action="store_true", help="Stop the background server and exit")
    parser.add_argument(
        "--status", action="store_true", help="Report background server status and exit"
    )
    parser.add_argument(
        "--pid-file", default="", help="PID file path (default: ~/.webosint/webosint-web.pid)"
    )
    parser.add_argument(
        "--log-file",
        default="",
        help="Log file for background mode (default: ~/.webosint/webosint-web.log)",
    )
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    pid_file = args.pid_file or str(daemonlib.default_pid_file())
    log_file = args.log_file or str(daemonlib.default_log_file())

    if args.stop:
        stopped, message = daemonlib.stop(pid_file)
        print(message)
        return 0 if stopped else 1

    if args.status:
        running, pid = daemonlib.status(pid_file)
        if running:
            print(f"WebOSINT web interface is running (PID {pid}).")
            print("    Log: " + log_file)
            return 0
        print("WebOSINT web interface is not running.")
        return 1

    running, existing_pid = daemonlib.status(pid_file)
    if running and args.background:
        print(f"[!] Already running in the background (PID {existing_pid}).")
        print("    Use --stop first, or --status to check on it.")
        return 1

    host = "0.0.0.0" if args.lan else args.host

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host in ("localhost", "")

    if not loopback and not (args.lan or args.allow_remote):
        print(
            "[!] Refusing to bind to a non-loopback address.\n"
            "    The UI can launch scans, so exposing it needs an explicit opt-in.\n"
            "    Use --lan (recommended) or --allow-remote."
        )
        return 2

    # Token auth is opt-in: supply --auth-token (or WEBOSINT_WEB_TOKEN), or use
    # --auth to have one generated. --no-auth always wins.
    token = "" if args.no_auth else args.auth_token.strip()
    if args.auth and not args.no_auth and not token:
        token = secrets.token_urlsafe(24)

    ssl_context = None
    scheme = "http"
    if args.tls_cert and args.tls_key:
        ssl_context = (args.tls_cert, args.tls_key)
        scheme = "https"
    elif args.self_signed:
        ssl_context = "adhoc"
        scheme = "https"

    try:
        from web.app import create_app

        app = create_app(auth_token=token or None)
    except RuntimeError as exc:
        print("[!] " + str(exc))
        return 1

    shown = primary_lan_ip() if host == "0.0.0.0" else host
    url = scheme + "://" + shown + ":" + str(args.port)

    print("    WebOSINT Pro web interface")
    print("    Local:   " + scheme + "://127.0.0.1:" + str(args.port))
    if not loopback:
        print("    Network: " + url)
    if token:
        print("\n    Access token required. Open this URL on the other machine:")
        print("    " + url + "/?token=" + token)
        print("    The token is then stored in a cookie for that browser.")
    elif not loopback:
        print("\n[!] WARNING: exposed to the network with no authentication.")
        print("    Anyone who can reach this port can launch scans. Use --auth to")
        print("    require a token, and keep this on trusted, isolated networks only.")
    if ssl_context == "adhoc":
        print("\n[i] Self-signed certificate: your browser will warn once. That is expected.")
    if not loopback and scheme == "http":
        print("[i] Traffic is plain HTTP. Use --self-signed or --tls-cert for encryption.")

    if args.background:
        print("\n    Authorized targets only.")
        print("    Detaching into the background.")
        print("    Log:  " + log_file)
        print("    Stop: python webserve.py --stop\n")
        sys.stdout.flush()
        daemonlib.daemonize(log_file, pid_file)
    else:
        print("\n    Authorized targets only. Press Ctrl+C to stop.\n")

    # debug/reloader stays off: it would expose an interactive debugger.
    try:
        app.run(
            host=host,
            port=args.port,
            debug=args.debug,
            use_reloader=False,
            threaded=True,
            ssl_context=ssl_context,
        )
    finally:
        if args.background:
            daemonlib.remove_pid_file(pid_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
