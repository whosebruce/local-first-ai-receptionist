#!/usr/bin/env python3
"""Loopback signing ingress for transports that cannot send HMAC headers.

The receptionist's `/inbound` webhook requires an HMAC-SHA256 signature over
the exact raw request body in the `X-Hook-Signature` header. There is no
query-token authentication and no fallback. Transport bridges such as
BlueBubbles can only POST a plain webhook URL, so this shim provides the
practical local ingress path WITHOUT weakening that boundary:

    BlueBubbles server ── plain POST (loopback, same machine) ──▶ this shim
    this shim ── same raw bytes + X-Hook-Signature ──▶ receptionist /inbound

Invariants (enforced in code, not advisory):

* The shim binds loopback ONLY; there is deliberately no LAN listen option.
  The unsigned hop must never cross a network.
* The forward URL must be loopback, or a private-LAN IP with
  `--allow-private-lan` (the signed hop may cross a trusted LAN because the
  signature authenticates the exact bytes). Public, link-local, unspecified,
  and DNS-name targets are refused, and the URL must carry no query string —
  nothing token-like can ever ride in a URL.
* The body is forwarded byte-for-byte and signed with `inbound_hmac_secret`
  from the receptionist's `secrets.json` (mode 0600 enforced, symlink
  refused). The secret is never logged, echoed, or placed in a URL.
* Incoming query strings are dropped, request bodies are size-bounded, and
  bodies/secrets never appear in log output.

Usage (on the machine running the BlueBubbles server):

    python3 scripts/bluebubbles_ingress.py \
        --forward-url http://127.0.0.1:8080/inbound
    # then point the BlueBubbles webhook at http://127.0.0.1:8091/

This file is standalone stdlib-only so it can be copied by itself to the
transport machine. On the receptionist's own machine the default reads
`inbound_hmac_secret` from the local `secrets.json` in place. If the
receptionist runs elsewhere, provision a DEDICATED mode-0600 JSON file
containing ONLY `inbound_hmac_secret` and pass it via `--secrets-file`;
NEVER copy the full `secrets.json` off the receptionist host. Least
privilege: the full bundle also holds the relay/Discord-hook secrets and
the contact-fingerprint key, none of which the transport machine needs, so
a compromise there must cost only the one inbound signing key.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import stat
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("receptionist-ingress")

SIGNATURE_HEADER = "X-Hook-Signature"
MAX_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_SECRETS = "~/.local/state/ai-receptionist/secrets.json"


def load_inbound_secret(path: str | os.PathLike) -> str:
    """Load `inbound_hmac_secret`, failing closed on a symlink or a
    group/world-accessible file (same policy as the receptionist's loader)."""
    path = Path(path).expanduser()
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise PermissionError(f"secrets file {path.name} is a symlink; refusing to load")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"secrets file {path.name} is group/world accessible (mode {oct(mode)}); "
            "run: chmod 600 on it and retry")
    secret = str(json.loads(path.read_text()).get("inbound_hmac_secret") or "")
    if not secret:
        raise ValueError("inbound_hmac_secret missing from secrets file; "
                         "generate secrets with scripts/generate_secrets.py")
    return secret


def validate_listen_host(host: str) -> None:
    """Loopback only — no opt-out. The unsigned hop never crosses a network."""
    if host == "localhost":
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"listen host must be a loopback IP or 'localhost', got {host!r}")
    if not addr.is_loopback:
        raise ValueError(
            "the shim accepts UNSIGNED posts, so it must listen on loopback only; "
            f"refusing to bind {host}")


def validate_forward_url(url: str, allow_private_lan: bool) -> None:
    """Forward target: loopback, or private-LAN IP with explicit opt-in.
    Public / link-local / unspecified / DNS-name / query-carrying URLs are
    refused, mirroring the receptionist's own endpoint policy."""
    match = re.match(r"^http://([^/:?#\[\]]+)(:\d+)?(/[^?#]*)?$", url)
    if not match:
        raise ValueError(
            "forward URL must be plain http:// to an IP or 'localhost' with no "
            f"query string, got {url!r}")
    host = match.group(1)
    if host == "localhost":
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"forward URL host must be an IP or 'localhost' (no DNS): {host!r}")
    if addr.is_loopback:
        return
    if addr.is_global:
        raise ValueError(f"forward URL host {host} is globally routable; refused")
    if addr.is_link_local or addr.is_unspecified:
        raise ValueError(f"forward URL host {host} is link-local/unspecified; refused")
    if addr.is_private and allow_private_lan:
        return
    raise ValueError(
        f"forward URL host {host} is not loopback; a trusted-LAN receptionist "
        "requires --allow-private-lan, and public targets are never allowed")


def make_handler(secret: str, forward_url: str, timeout: int = 30):
    class Handler(BaseHTTPRequestHandler):
        server_version = "receptionist-ingress"

        def log_message(self, fmt, *args):
            line = fmt % args
            # Never write a (misconfigured) query token to the log.
            line = re.sub(r"token=[^&\s\"]+", "token=[REDACTED]", line)
            log.info("ingress %s", line)

        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if urlparse(self.path).path == "/health":
                self._json(200, {"status": "ok", "service": "receptionist-ingress"})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
            if length <= 0 or length > MAX_BODY_BYTES:
                self._json(400, {"error": "missing or oversized body"})
                return
            raw = self.rfile.read(length)
            # Sign the exact bytes; forward them unmodified. The incoming
            # query string (if any) is dropped — never appended to the target.
            signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            request = urllib.request.Request(
                forward_url, data=raw, method="POST",
                headers={"Content-Type": self.headers.get("Content-Type")
                         or "application/json",
                         SIGNATURE_HEADER: signature})
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    body = response.read(65536)
                    code = response.status
            except urllib.error.HTTPError as exc:
                body = exc.read(65536) or b"{}"
                code = exc.code
            except Exception as exc:
                self._json(502, {"error": "forward failed: " + type(exc).__name__})
                return
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--secrets-file",
                        default=os.environ.get("RECEPTIONIST_HOME",
                                               "~/.local/state/ai-receptionist")
                        + "/secrets.json",
                        help=f"path to secrets.json (default: {DEFAULT_SECRETS})")
    parser.add_argument("--listen-host", default="127.0.0.1",
                        help="loopback only; non-loopback is refused")
    parser.add_argument("--listen-port", type=int, default=8091)
    parser.add_argument("--forward-url", required=True,
                        help="the receptionist /inbound URL, e.g. "
                             "http://127.0.0.1:8080/inbound")
    parser.add_argument("--allow-private-lan", action="store_true",
                        help="allow a private-LAN forward target (signed hop only)")
    args = parser.parse_args(argv)

    validate_listen_host(args.listen_host)
    validate_forward_url(args.forward_url, args.allow_private_lan)
    handler = make_handler(load_inbound_secret(args.secrets_file), args.forward_url)

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), handler)
    log.info("receptionist-ingress listening on %s:%s -> %s (loopback unsigned hop, "
             "signed forward)", args.listen_host, args.listen_port, args.forward_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
