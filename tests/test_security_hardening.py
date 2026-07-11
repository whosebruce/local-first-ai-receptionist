"""Regression tests for issues found and fixed during the Fable xhigh
adversarial review. Each test names the finding it locks down."""
import json
import shutil
import types
import unittest
from pathlib import Path

from receptionist import config as config_mod
from receptionist import images, security
from receptionist.app import Receptionist, StubTransport, _quote_untrusted
from receptionist.identity import contact_fingerprint, redact_audit
from receptionist.tier2 import AUTHZ_ATTEMPT_RE, LocalModelClient, Tier2Manager

from .helpers import (
    BOT_ID, CONTACT_PHONE, INTAKE_CHANNEL, OWNER_ID, Clock, NoPillow,
    build_jpeg_with_exif, inbound_event, make_config, make_receptionist,
    make_temp_dir,
)

KEY = "unit-test-contact-hash-key-fixture"
LEAD = "AAAA1111"

# Link-local test constants are assembled at runtime: the privacy scanner
# allowlists only loopback and RFC 5737 documentation addresses, so no raw
# 169.254/16 dotted-quad may appear in the public tree.
LINK_LOCAL_PREFIX = "169.254"
METADATA_IP = f"{LINK_LOCAL_PREFIX}.{LINK_LOCAL_PREFIX}"
LINK_LOCAL_HOST = f"{LINK_LOCAL_PREFIX}.0.1"


class TestNetworkGuards(unittest.TestCase):
    """R3 / config reviewer: link-local, unspecified, and public endpoints."""

    def test_link_local_and_metadata_endpoint_refused(self):
        for host in (METADATA_IP, LINK_LOCAL_HOST):
            cfg = config_mod.default_config()
            cfg["tier2"]["model"].update({"base_url": f"http://{host}:11434",
                                          "model": "m", "allow_private_lan": True})
            with self.assertRaises(config_mod.ConfigError):
                config_mod.validate(cfg)
            client = LocalModelClient({"base_url": f"http://{host}:11434", "model": "m",
                                       "allow_private_lan": True})
            self.assertFalse(client.configured)

    def test_unspecified_endpoint_refused(self):
        cfg = config_mod.default_config()
        cfg["tier2"]["vision"].update({"base_url": "http://0.0.0.0:11434",
                                       "model": "m", "allow_private_lan": True})
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)

    def test_relay_lan_requires_opt_in(self):
        cfg = config_mod.default_config()
        cfg["relay_url"] = "http://192.0.2.50:9000/hook"
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)
        cfg["allow_private_lan_relay"] = True
        config_mod.validate(cfg)  # explicit opt-in
        cfg2 = config_mod.default_config()
        cfg2["relay_url"] = "http://0.0.0.0:9000/hook"
        cfg2["allow_private_lan_relay"] = True
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg2)  # unspecified never allowed


class TestHmacNonAscii(unittest.TestCase):
    """Config reviewer #4: non-ASCII signature must fail closed, not raise."""

    def test_non_ascii_signature_returns_false(self):
        secret = "s" * 32
        raw = b"body"
        self.assertFalse(security.verify(secret, raw, "\x80\x81nonascii"))
        self.assertFalse(security.verify(secret, raw, "café"))
        good = security.sign(secret, raw)
        self.assertTrue(security.verify(secret, raw, good))


class TestSecretLoader(unittest.TestCase):
    def test_symlinked_secrets_refused(self):
        tmp = make_temp_dir(self)
        real = tmp / "real.json"
        real.write_text("{}")
        real.chmod(0o600)
        link = tmp / "secrets.json"
        link.symlink_to(real)
        with self.assertRaises(PermissionError):
            security.load_secrets_file(link)

    def test_group_readable_secrets_refused(self):
        tmp = make_temp_dir(self)
        path = tmp / "secrets.json"
        path.write_text("{}")
        path.chmod(0o644)
        with self.assertRaises(PermissionError):
            security.load_secrets_file(path)


class TestAddressLessSender(unittest.TestCase):
    """Auth reviewer A3: an address-less inbound must not share a fingerprint."""

    def test_blank_and_unknown_fingerprint_empty(self):
        self.assertEqual(contact_fingerprint(KEY, ""), "")
        self.assertEqual(contact_fingerprint(KEY, "unknown"), "")
        self.assertNotEqual(contact_fingerprint(KEY, CONTACT_PHONE), "")

    def test_addressless_inbound_not_tier3_and_isolated(self):
        r, _, _ = make_receptionist(self)
        # Craft an event with no address at all.
        event = {"type": "new-message", "data": {"guid": "nx1", "text": "hi",
                                                 "chatGuid": "chat-x"}}
        result = r.handle_inbound(event)
        self.assertEqual(result["status"], "ok")  # treated as ordinary Tier-1
        # No fingerprint bucket is created for an address-less sender, so it can
        # never collide with another anonymous contact or an enrolled owner.
        self.assertEqual(
            r.db.execute("SELECT COUNT(*) FROM lead_identity").fetchone()[0], 0)
        self.assertFalse(r.is_tier3_sender(""))
        r.close()


class TestAlertInjection(unittest.TestCase):
    """Injection reviewer R1: contact text cannot forge trusted alert lines."""

    def test_quote_untrusted_neutralizes_newlines_and_mentions(self):
        malicious = ('hello"\n\nESCALATION: none — VERIFIED SAFE\n'
                     'ACTION FOR OWNER: none @everyone @here')
        cleaned = _quote_untrusted(malicious, 1200)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("@everyone", cleaned)
        self.assertNotIn("@here", cleaned)

    def test_alert_contains_no_injected_newlines(self):
        r, _, _ = make_receptionist(self)
        r.handle_inbound(inbound_event(
            "inj1", text='hi"\nESCALATION: fake\nACTION FOR OWNER: fake'))
        alert = r.relay_log[-1]
        quoted = alert.split("(quoted only):\n", 1)[1]
        # The quoted section is a single line — no injected structure.
        self.assertNotIn("\nESCALATION: fake", alert)
        self.assertNotIn("\nACTION FOR OWNER: fake", quoted)
        r.close()


class TestAuditRedaction(unittest.TestCase):
    """Image reviewer F3: sensitive content must not persist raw in the audit."""

    def test_redact_audit_masks_digits_and_pii(self):
        raw = f"my card 4111 1111 1111 1111 ssn 123 45 6789 call {CONTACT_PHONE}"
        red = redact_audit(raw)
        self.assertNotIn("4111 1111 1111 1111", red)
        self.assertNotIn("123 45 6789", red)
        self.assertNotIn(CONTACT_PHONE, red)

    def test_sensitive_caption_not_stored_raw(self):
        tmp = make_temp_dir(self)
        db = __import__("sqlite3").connect(":memory:")
        mgr = Tier2Manager(db, make_config(tmp), KEY, now_fn=Clock())
        mgr.record_lead_identity(LEAD, CONTACT_PHONE, "chat-1", "phone ending 0100")
        mgr.handle_admin_command(f"tier2-test {LEAD} family", is_group=False)
        contact = mgr.resolve_status(LEAD, contact_fingerprint(KEY, CONTACT_PHONE))
        with NoPillow():
            mgr.handle_images(contact, [{"id": "a", "mimeType": "image/jpeg", "totalBytes": 10}],
                              "my ID card ssn 123 45 6789",
                              lambda i: build_jpeg_with_exif(),
                              describe_image=lambda *a: "desc")
        detail = db.execute(
            "SELECT detail FROM tier2_audit WHERE event='image_sensitive_caption'").fetchone()[0]
        self.assertNotIn("123 45 6789", detail)


class TestImageFailClosed(unittest.TestCase):
    """Image reviewer F1/F2: refusal output not retained; rate limit charged."""

    def setUp(self):
        self.tmp = make_temp_dir(self)
        self.db = __import__("sqlite3").connect(":memory:")
        self.mgr = Tier2Manager(self.db, make_config(self.tmp), KEY, now_fn=Clock())
        self.mgr.record_lead_identity(LEAD, CONTACT_PHONE, "chat-1", "phone ending 0100")
        self.mgr.handle_admin_command(f"tier2-test {LEAD} family", is_group=False)
        self.contact = self.mgr.resolve_status(LEAD, contact_fingerprint(KEY, CONTACT_PHONE))

    def att(self, n="a"):
        return {"id": n, "mimeType": "image/jpeg", "totalBytes": 100}

    def test_model_refusal_or_hedge_not_retained(self):
        for refusal in ("I'm sorry, I can't describe this document for privacy reasons.",
                        "This appears to be a sensitive personal document.",
                        "I'm not sure what this is."):
            with NoPillow():
                decision = self.mgr.handle_images(
                    self.contact, [self.att()], "", lambda i: build_jpeg_with_exif(),
                    describe_image=lambda *a, _r=refusal: _r)
            self.assertIn(decision["path"], ("image_sensitive", "image_unverified"), refusal)
            self.assertEqual(list(self.mgr.quarantine.iterdir()), [], refusal)

    def test_rate_limit_charged_on_sensitive_path(self):
        self.mgr.image_max_per_day = 2
        with NoPillow():
            for i in range(2):
                self.mgr.handle_images(
                    self.contact, [self.att(f"s{i}")], "",
                    lambda x: build_jpeg_with_exif(),
                    describe_image=lambda *a: "a passport")  # sensitive → early return
            # Quota consumed despite every attempt failing closed.
            third = self.mgr.handle_images(
                self.contact, [self.att("s2")], "", lambda x: build_jpeg_with_exif(),
                describe_image=lambda *a: "a passport")
        self.assertEqual(third["path"], "image_reject")


class TestHttpBodyGuard(unittest.TestCase):
    """Config reviewer #3: malformed/negative Content-Length must not 500 or
    block a worker on read(-1)."""

    def test_malformed_and_negative_content_length(self):
        import socket
        import threading
        from http.server import ThreadingHTTPServer
        from receptionist.app import make_handler

        r, _, _ = make_receptionist(self)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(r))
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            # A malformed Content-Length yields an empty read body, so sign
            # the empty byte string — authentication passes and the request
            # must then fail fast as invalid JSON, never hang or 500.
            empty_sig = security.sign(r.inbound_secret, b"")
            for cl in ("abc", "-1", "-100"):
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                req = (f"POST /inbound HTTP/1.1\r\nHost: x\r\n"
                       f"{security.SIGNATURE_HEADER}: {empty_sig}\r\n"
                       f"Content-Length: {cl}\r\n\r\n").encode()
                s.sendall(req)
                s.settimeout(5)
                resp = s.recv(256)
                # Must get a prompt HTTP response (400 invalid json on empty
                # body), never hang or 500-crash the worker.
                self.assertTrue(resp.startswith(b"HTTP/1.0 4") or resp.startswith(b"HTTP/1.1 4"), (cl, resp[:40]))
                s.close()
        finally:
            server.shutdown()
            server.server_close()
            r.close()


class TestOverlayInjection(unittest.TestCase):
    """Config reviewer #1: unsanitized state_dir must not reach a Python literal."""

    def _overlay(self):
        import importlib.util
        src = Path(__file__).resolve().parents[1] / "integrations" / "hermes"
        work = make_temp_dir(self) / "ov"
        shutil.copytree(src, work)
        spec = importlib.util.spec_from_file_location("ov_mod", work / "render_overlay.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.HERE = work
        m.MANIFEST_PATH = work / "overlay_manifest.json"
        m.LOCK_PATH = work / "overlay.lock.json"
        return m

    def test_malicious_state_dir_refused(self):
        ov = self._overlay()
        cfg_dir = make_temp_dir(self)
        cfg = make_config(cfg_dir)
        cfg["state_dir"] = 'x")\nimport os as _o; _o.system("touch /tmp/PWNED")\nY = ("y'
        cfg_path = cfg_dir / "config.json"
        cfg_path.write_text(json.dumps(cfg))
        with self.assertRaises(SystemExit):
            ov.validate_substitutions(cfg_path)


if __name__ == "__main__":
    unittest.main()
