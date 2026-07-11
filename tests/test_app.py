import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from receptionist import security
from receptionist.app import Receptionist, StubTransport, make_handler

from .helpers import (
    BOT_ID, CONTACT_PHONE, CONTACT_PHONE_2, INTAKE_CHANNEL, OWNER_ID,
    OWNER_PHONE, inbound_event, make_config, make_receptionist, make_secrets,
    make_temp_dir,
)


class TestInboundPipeline(unittest.TestCase):
    def setUp(self):
        self.r, self.clock, self.tmp = make_receptionist(self)

    def tearDown(self):
        self.r.close()

    def test_bad_event_type_ignored(self):
        self.assertEqual(self.r.handle_inbound({"type": "typing"})["status"], "ignored")

    def test_own_messages_ignored(self):
        event = inbound_event("g1")
        event["data"]["isFromMe"] = True
        self.assertEqual(self.r.handle_inbound(event)["status"], "ignored_own_message")

    def test_duplicate_webhook_no_duplicate_reply(self):
        first = self.r.handle_inbound(inbound_event("g2", text="hi"))
        self.assertEqual(first["status"], "ok")
        sent_before = len(self.r.transport.sent)
        replay = self.r.handle_inbound(inbound_event("g2", text="hi"))
        self.assertEqual(replay["status"], "duplicate")
        self.assertEqual(len(self.r.transport.sent), sent_before)

    def test_tier1_flow_masks_identity_and_relays(self):
        result = self.r.handle_inbound(inbound_event("g3", text="how much does it cost?"))
        self.assertEqual(result["category"], "pricing")
        self.assertEqual(result["reply_status"], "sent")  # StubTransport records only
        alert = self.r.relay_log[-1]
        self.assertIn("UNTRUSTED CONTACT MESSAGE", alert)
        self.assertIn("phone ending 0100", alert)
        self.assertNotIn(CONTACT_PHONE, alert)

    def test_group_messages_relay_only_and_never_correlate(self):
        result = self.r.handle_inbound(inbound_event("g4", text="hello", isGroup=True))
        self.assertEqual(result["reply_status"], "group_relay_only")
        self.assertEqual(
            self.r.db.execute("SELECT COUNT(*) FROM discord_pending_alerts").fetchone()[0], 0)

    def test_tier1_reply_cap_per_day(self):
        for i in range(10):
            self.r.handle_inbound(inbound_event(f"cap-{i}", text="how much does it cost?"))
        sent = [s for s in self.r.transport.sent]
        self.assertLessEqual(len(sent), 4)

    def test_invoice_interest_is_notification_only(self):
        self.r.handle_inbound(inbound_event("g5", text="can you send me an invoice"))
        alert = self.r.relay_log[-1]
        self.assertIn("notification-only; no invoice created/sent", alert)
        # No outbound message may contain invoice/payment content — the only
        # permitted response is the bounded generic acknowledgment.
        for message in self.r.transport.sent:
            self.assertNotIn("invoice", message["text"].lower())
            self.assertNotIn("$", message["text"])

    def test_tapback_diverted_never_replied(self):
        self.r.handle_inbound(inbound_event("g6", text="hi"))
        sent_before = len(self.r.transport.sent)
        result = self.r.handle_inbound(inbound_event("g7", text="", associatedMessageType=2005))
        self.assertEqual(result["status"], "reaction_recorded")
        self.assertEqual(len(self.r.transport.sent), sent_before)
        self.assertIn("Reactions are never approval", self.r.relay_log[-1])

    def test_blocked_contact_total_silence(self):
        self.r.handle_inbound(inbound_event("g8", text="hi"))
        lead = self.r.handle_inbound(inbound_event("g9", text="hello again"))
        lead_id = lead.get("lead_id") or self.r.db.execute(
            "SELECT lead_id FROM inbound LIMIT 1").fetchone()[0]
        self.r.tier2.handle_admin_command(f"block {lead_id}", is_group=False)
        relay_before = len(self.r.relay_log)
        sent_before = len(self.r.transport.sent)
        result = self.r.handle_inbound(inbound_event("g10", text="hello?"))
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(self.r.relay_log), relay_before)
        self.assertEqual(len(self.r.transport.sent), sent_before)


class TestTier3Owner(unittest.TestCase):
    def setUp(self):
        self.r, self.clock, self.tmp = make_receptionist(self)

    def tearDown(self):
        self.r.close()

    def test_owner_admin_command_with_readback(self):
        self.r.handle_inbound(inbound_event("o1", text="hi"))
        lead = self.r.db.execute("SELECT lead_id FROM inbound LIMIT 1").fetchone()[0]
        result = self.r.handle_inbound(inbound_event(
            "o2", sender=OWNER_PHONE, chat_id="owner-chat",
            text=f"tier2-test {lead} family"))
        self.assertEqual(result["status"], "tier2_admin_handled")
        self.assertTrue(result["ok"])
        readbacks = [s for s in self.r.transport.sent if "TIER2 ADMIN OK" in s["text"]]
        disclosures = [s for s in self.r.transport.sent if "beta" in s["text"]]
        self.assertEqual(len(readbacks), 1)
        self.assertEqual(len(disclosures), 1)
        self.assertEqual(disclosures[0]["chat_id"], "chat-1")  # to the contact's chat

    def test_owner_casual_text_never_promotes(self):
        result = self.r.handle_inbound(inbound_event(
            "o3", sender=OWNER_PHONE, chat_id="owner-chat",
            text="she is great, let her into tier two please"))
        self.assertEqual(result["status"], "delegated_tier3")
        self.assertEqual(
            self.r.db.execute("SELECT COUNT(*) FROM tier2_contacts").fetchone()[0], 0)

    def test_group_admin_fails_closed(self):
        self.r.handle_inbound(inbound_event("o4", text="hi"))
        lead = self.r.db.execute("SELECT lead_id FROM inbound LIMIT 1").fetchone()[0]
        result = self.r.handle_inbound(inbound_event(
            "o5", sender=OWNER_PHONE, chat_id="owner-chat",
            text=f"tier2-test {lead} family", isGroup=True))
        self.assertFalse(result["ok"])

    def test_non_owner_cannot_use_admin_syntax(self):
        self.r.handle_inbound(inbound_event("o6", text="hi"))
        lead = self.r.db.execute("SELECT lead_id FROM inbound LIMIT 1").fetchone()[0]
        result = self.r.handle_inbound(inbound_event(
            "o7", sender=CONTACT_PHONE_2, chat_id="chat-2",
            text=f"tier2-test {lead} family"))
        # Treated as ordinary Tier-1 text, never as admin.
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            self.r.db.execute("SELECT COUNT(*) FROM tier2_contacts").fetchone()[0], 0)


class TestOutboundOwnerGate(unittest.TestCase):
    def test_outbound_disabled_blocks_real_transport(self):
        class ForbiddenTransport:
            def send_text(self, chat_id, text):
                raise AssertionError("outbound attempted while disabled")

            def fetch_attachment(self, att_id):
                return None

        r, _, _ = make_receptionist(self, transport=ForbiddenTransport())
        status = r.send_reply("chat-1", "AAAA1111", "greeting", "hello")
        self.assertEqual(status, "outbound_disabled")
        row = r.db.execute("SELECT status FROM outbound").fetchone()
        self.assertEqual(row[0], "outbound_disabled")
        r.close()

    def test_default_config_uses_stub_even_for_bluebubbles_kind(self):
        # outbound.enabled=False -> transport falls back to StubTransport.
        tmp = make_temp_dir(self, prefix="gate-test-")
        config = make_config(tmp, transport={"kind": "bluebubbles",
                                             "server_url": "http://127.0.0.1:9999"})
        r = Receptionist(config, make_secrets(), db_path=str(tmp / "s.sqlite3"))
        self.assertIsInstance(r.transport, StubTransport)
        r.close()


class TestDiscordHooks(unittest.TestCase):
    def setUp(self):
        self.r, self.clock, self.tmp = make_receptionist(self)

    def tearDown(self):
        self.r.close()

    def test_intake_command_end_to_end_with_disclosure(self):
        self.r.handle_inbound(inbound_event("d1", text="hello, pricing?"))
        token_row = self.r.db.execute(
            "SELECT correlation_token, lead_id FROM discord_pending_alerts").fetchone()
        self.assertIsNotNone(token_row)
        outcome = self.r.handle_discord_alert_posted({
            "correlation_token": token_row[0], "message_id": "500000000000000041",
            "channel_id": INTAKE_CHANNEL})
        self.assertTrue(outcome["ok"])
        result = self.r.handle_discord_intake_command({
            "user_id": OWNER_ID, "channel_id": INTAKE_CHANNEL,
            "message_id": "500000000000000042",
            "referenced_message_id": "500000000000000041",
            "mentioned_ids": [BOT_ID], "text": f"<@{BOT_ID}> approve client"})
        self.assertTrue(result["authorized"])
        self.assertFalse(result["llm"])
        disclosures = [s for s in self.r.transport.sent if "beta" in s["text"]]
        self.assertEqual(len(disclosures), 1)

    def test_hook_signature_verification(self):
        body = json.dumps({"user_id": OWNER_ID}).encode()
        good = security.sign(self.r.discord_hook_secret, body)
        self.assertTrue(self.r.verify_discord_hook(body, good))
        self.assertFalse(self.r.verify_discord_hook(body, good[:-2] + "aa"))  # tampered
        self.assertFalse(self.r.verify_discord_hook(body + b" ", good))       # body swapped
        self.assertFalse(self.r.verify_discord_hook(body, ""))

    def test_relay_envelope_is_signed(self):
        captured = {}

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(request, timeout=0):
            captured["body"] = request.data
            captured["signature"] = request.headers.get("X-webhook-signature")
            return FakeResponse()

        self.r.relay_url = "http://127.0.0.1:9/hook"
        import urllib.request as urlreq
        original = urlreq.urlopen
        urlreq.urlopen = fake_urlopen
        try:
            self.r.relay("test alert")
        finally:
            urlreq.urlopen = original
        expected = security.sign(self.r.relay_secret, captured["body"])
        self.assertEqual(captured["signature"], expected)


class TestHTTPLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, cls.clock, cls.tmp = make_receptionist(cls)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.r))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.r.close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def post(self, path, body: bytes, headers=None):
        request = urllib.request.Request(self.url(path), data=body,
                                         headers=headers or {}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_health(self):
        with urllib.request.urlopen(self.url("/health"), timeout=10) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["status"], "ok")

    def test_inbound_requires_raw_body_hmac(self):
        body = json.dumps(inbound_event("h1")).encode()
        status, _ = self.post("/inbound", body)  # missing signature
        self.assertEqual(status, 401)
        status, _ = self.post("/inbound", body,
                              {security.SIGNATURE_HEADER: "f" * 64})  # wrong
        self.assertEqual(status, 401)
        status, _ = self.post("/inbound", body,
                              {security.SIGNATURE_HEADER: "café\x7f"})  # non-ASCII
        self.assertEqual(status, 401)
        good = security.sign(self.r.inbound_secret, body)
        status, payload = self.post("/inbound", body,
                                    {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")

    def test_inbound_tampered_body_rejected(self):
        body = json.dumps(inbound_event("h2")).encode()
        good = security.sign(self.r.inbound_secret, body)
        tampered = json.dumps(inbound_event("h2-evil")).encode()
        status, _ = self.post("/inbound", tampered,
                              {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 401)

    def test_inbound_query_token_fallback_removed(self):
        # The pre-bounce URL style must never authenticate — not even with
        # the real secret value in the query and no header...
        body = json.dumps(inbound_event("h3")).encode()
        status, _ = self.post(f"/inbound?token={self.r.inbound_secret}", body)
        self.assertEqual(status, 400)
        # ...and a token parameter is refused outright even alongside a valid
        # signature, so a secret can never ride in a URL.
        good = security.sign(self.r.inbound_secret, body)
        status, _ = self.post("/inbound?token=anything", body,
                              {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 400)
        # The event must not have been processed by either refused request.
        row = self.r.db.execute(
            "SELECT COUNT(*) FROM inbound WHERE event_id='h3'").fetchone()
        self.assertEqual(row[0], 0)

    def test_inbound_replayed_signed_body_is_inert(self):
        body = json.dumps(inbound_event("h4", text="how much does it cost?")).encode()
        good = security.sign(self.r.inbound_secret, body)
        status, payload = self.post("/inbound", body,
                                    {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        sent_before = len(self.r.transport.sent)
        # Replaying the exact signed request authenticates (the signature is
        # valid for these bytes) but is deduplicated by event ID: no state
        # change, no second reply.
        status, payload = self.post("/inbound", body,
                                    {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "duplicate")
        self.assertEqual(len(self.r.transport.sent), sent_before)

    def test_discord_hooks_fail_closed_without_valid_signature(self):
        body = json.dumps({"correlation_token": "x", "message_id": "1"}).encode()
        status, _ = self.post("/discord/alert-posted", body)
        self.assertEqual(status, 401)
        status, _ = self.post("/discord/alert-posted", body,
                              {security.SIGNATURE_HEADER: "f" * 64})
        self.assertEqual(status, 401)
        good = security.sign(self.r.discord_hook_secret, body)
        status, payload = self.post("/discord/alert-posted", body,
                                    {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 200)
        self.assertFalse(payload["ok"])  # unknown token, but authenticated
        # Callback tampering: signature from a different body must fail.
        other = json.dumps({"correlation_token": "y", "message_id": "2"}).encode()
        status, _ = self.post("/discord/alert-posted", other,
                              {security.SIGNATURE_HEADER: good})
        self.assertEqual(status, 401)

    def test_unknown_route_404(self):
        status, _ = self.post("/admin", b"{}")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
