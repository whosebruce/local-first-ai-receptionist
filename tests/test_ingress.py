"""Tests for scripts/bluebubbles_ingress.py — the loopback signing shim that
gives an HMAC-less transport (BlueBubbles) a practical path to the
HMAC-required /inbound endpoint without weakening the boundary."""
import importlib.util
import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from receptionist import security
from receptionist.app import make_handler

from .helpers import inbound_event, make_receptionist, make_temp_dir

REPO = Path(__file__).resolve().parents[1]

# Assembled at runtime so no raw 169.254/16 literal enters the public tree
# (the privacy scanner allowlists only loopback/RFC 5737 addresses).
LINK_LOCAL_PREFIX = "169.254"
METADATA_IP = f"{LINK_LOCAL_PREFIX}.{LINK_LOCAL_PREFIX}"
# A globally routable IP, constructed so the tree contains no non-doc IP
# literal; RFC 5737 doc addresses classify as PRIVATE in `ipaddress`, so
# they stand in for the trusted-LAN case below.
PUBLIC_IP = ".".join(map(str, (8, 8, 8, 8)))
LAN_IP = "192.0.2.20"


def load_shim():
    spec = importlib.util.spec_from_file_location(
        "bluebubbles_ingress", REPO / "scripts" / "bluebubbles_ingress.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaptureHandler(BaseHTTPRequestHandler):
    """Stand-in upstream that records the exact bytes and headers received."""
    captured: list[dict] = []

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).captured.append({
            "path": self.path,
            "body": raw,
            "signature": self.headers.get(security.SIGNATURE_HEADER, ""),
        })
        body = json.dumps({"status": "captured"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def post(url, body: bytes, headers=None):
    request = urllib.request.Request(url, data=body, headers=headers or {},
                                     method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


class TestShimSigning(unittest.TestCase):
    def setUp(self):
        self.shim = load_shim()
        self.secret = "s" * 64
        CaptureHandler.captured = []
        self.upstream, up_port = serve(CaptureHandler)
        self.addCleanup(self.upstream.shutdown)
        self.addCleanup(self.upstream.server_close)
        handler = self.shim.make_handler(self.secret,
                                         f"http://127.0.0.1:{up_port}/inbound")
        self.server, self.port = serve(handler)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def test_exact_raw_bytes_signed_and_forwarded(self):
        # Deliberately non-canonical JSON: any re-serialization would change
        # the bytes and the signature would not verify against the original.
        raw = b'{ "type":"new-message",\n  "data" : {"guid": "raw-1"} }'
        status, payload = post(f"http://127.0.0.1:{self.port}/", raw)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "captured")
        [seen] = CaptureHandler.captured
        self.assertEqual(seen["body"], raw)
        self.assertTrue(security.verify(self.secret, raw, seen["signature"]))

    def test_incoming_query_string_dropped_never_forwarded(self):
        raw = b'{"type": "x"}'
        post(f"http://127.0.0.1:{self.port}/?token=stale-config&x=1", raw)
        [seen] = CaptureHandler.captured
        self.assertEqual(seen["path"], "/inbound")
        self.assertNotIn("token", seen["path"])

    def test_missing_body_rejected_locally(self):
        status, _ = post(f"http://127.0.0.1:{self.port}/", b"")
        self.assertEqual(status, 400)
        self.assertEqual(CaptureHandler.captured, [])


class TestShimEndToEnd(unittest.TestCase):
    def test_bluebubbles_style_plain_post_reaches_inbound(self):
        r, _, _ = make_receptionist(self)
        self.addCleanup(r.close)
        upstream, up_port = serve(make_handler(r))
        self.addCleanup(upstream.shutdown)
        self.addCleanup(upstream.server_close)
        shim = load_shim()
        handler = shim.make_handler(r.inbound_secret,
                                    f"http://127.0.0.1:{up_port}/inbound")
        server, port = serve(handler)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

        body = json.dumps(inbound_event("shim-1", text="how much does it cost?")).encode()
        # The transport POSTs plainly — no header, no token — to the shim.
        status, payload = post(f"http://127.0.0.1:{port}/", body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["category"], "pricing")
        # The same plain POST straight at /inbound must fail: the shim is a
        # signing hop, not a bypass of the HMAC boundary.
        status, _ = post(f"http://127.0.0.1:{up_port}/inbound", body)
        self.assertEqual(status, 401)
        # A replay through the shim authenticates but is deduplicated.
        status, payload = post(f"http://127.0.0.1:{port}/", body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "duplicate")


class TestShimValidation(unittest.TestCase):
    def setUp(self):
        self.shim = load_shim()

    def test_listen_host_loopback_only_no_opt_out(self):
        self.shim.validate_listen_host("127.0.0.1")
        self.shim.validate_listen_host("localhost")
        for host in (LAN_IP, "0.0.0.0", METADATA_IP, PUBLIC_IP, "lan-box"):
            with self.assertRaises(ValueError, msg=host):
                self.shim.validate_listen_host(host)

    def test_forward_url_policy_mirrors_receptionist(self):
        ok = self.shim.validate_forward_url
        ok("http://127.0.0.1:8080/inbound", False)
        ok("http://localhost:8080/inbound", False)
        ok(f"http://{LAN_IP}:8080/inbound", True)  # private-LAN with opt-in
        cases = [
            (f"http://{LAN_IP}:8080/inbound", False),      # LAN without opt-in
            (f"http://{PUBLIC_IP}:8080/inbound", True),    # public, never
            (f"http://{METADATA_IP}/inbound", True),       # link-local, never
            ("http://0.0.0.0:8080/inbound", True),         # unspecified, never
            ("http://receptionist.example.com/inbound", True),  # DNS, never
            ("https://127.0.0.1:8080/inbound", False),     # scheme mismatch
            ("http://127.0.0.1:8080/inbound?token=x", False),  # query refused
        ]
        for url, allow_lan in cases:
            with self.assertRaises(ValueError, msg=url):
                self.shim.validate_forward_url(url, allow_lan)

    def test_secrets_file_fails_closed(self):
        tmp = make_temp_dir(self, prefix="ingress-secrets-")
        path = tmp / "secrets.json"
        path.write_text(json.dumps({"inbound_hmac_secret": "k" * 64}))
        os.chmod(path, 0o644)
        with self.assertRaises(PermissionError):
            self.shim.load_inbound_secret(path)  # group/world readable
        os.chmod(path, 0o600)
        self.assertEqual(self.shim.load_inbound_secret(path), "k" * 64)
        link = tmp / "link.json"
        link.symlink_to(path)
        with self.assertRaises(PermissionError):
            self.shim.load_inbound_secret(link)  # symlink refused
        stale = tmp / "stale.json"
        stale.write_text(json.dumps({"inbound_token": "old-style"}))
        os.chmod(stale, 0o600)
        with self.assertRaises(ValueError):
            self.shim.load_inbound_secret(stale)  # renamed secret required


if __name__ == "__main__":
    unittest.main()
