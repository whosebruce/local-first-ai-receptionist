import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from receptionist import security
from receptionist.app import Receptionist, StubTransport, make_handler

from .helpers import (
    BOT_ID, CONTACT_PHONE, CONTACT_PHONE_2, FAMILY_CHANNEL, GUILD_ID,
    INTAKE_CHANNEL, OWNER_ID,
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

    def test_reviewed_thread_reply_sends_once_and_verifies(self):
        first = self.r.handle_inbound(inbound_event("dr1", text="hello"))
        lead = first["lead_id"]
        self.assertTrue(self.r.tier2.handle_admin_command(
            f"tier2 {lead} family", is_group=False)["ok"])
        thread_id = "510000000000000061"
        self.r.discord.record_thread(lead, "family", FAMILY_CHANNEL, thread_id)
        payload = {
            "user_id": OWNER_ID, "guild_id": GUILD_ID,
            "channel_id": thread_id, "parent_channel_id": FAMILY_CHANNEL,
            "message_id": "500000000000000061",
            "text": "reply Reviewed fixture response",
        }
        sent_before = len(self.r.transport.sent)
        result = self.r.handle_discord_contact_reply(payload)
        self.assertTrue(result["authorized"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(self.r.transport.sent), sent_before + 1)
        self.assertNotIn("chat_id", result)
        self.assertNotIn("message", result)
        duplicate = self.r.handle_discord_contact_reply(payload)
        self.assertFalse(duplicate["authorized"])
        self.assertEqual(duplicate["reason"], "duplicate_reply")
        self.assertEqual(len(self.r.transport.sent), sent_before + 1)

    def test_reviewed_reply_send_without_source_readback_is_not_verified(self):
        class SendOnlyTransport:
            def __init__(self):
                self.sent = []

            def send_text(self, chat_id, text):
                self.sent.append((chat_id, text))
                return {"ok": True, "message_id": "synthetic-send-only"}

            def fetch_attachment(self, attachment_id):
                return None

        transport = SendOnlyTransport()
        r, _, _ = make_receptionist(
            self, transport=transport, outbound={"enabled": True})
        try:
            lead = r.handle_inbound(inbound_event("dr2", text="hello"))["lead_id"]
            self.assertTrue(r.tier2.handle_admin_command(
                f"tier2 {lead} family", is_group=False)["ok"])
            thread_id = "510000000000000062"
            r.discord.record_thread(lead, "family", FAMILY_CHANNEL, thread_id)
            result = r.handle_discord_contact_reply({
                "user_id": OWNER_ID, "guild_id": GUILD_ID,
                "channel_id": thread_id, "parent_channel_id": FAMILY_CHANNEL,
                "message_id": "500000000000000062", "text": "reply One attempt",
            })
            self.assertTrue(result["authorized"])
            self.assertFalse(result["verified"])
            self.assertEqual(result["status"], "sent_unverified")
            self.assertIn("do not retry automatically", result["readback"])
        finally:
            r.close()

    def test_reviewed_reply_verification_does_not_hold_database_lock(self):
        verify_started = threading.Event()
        release_verify = threading.Event()

        class BlockingVerifyTransport:
            def send_text(self, chat_id, text):
                return {"ok": True, "message_id": "synthetic-blocking-verify"}

            def fetch_attachment(self, attachment_id):
                return None

            def verify_sent(self, chat_id, text, message_id, *, not_before_ms):
                verify_started.set()
                release_verify.wait(5)
                return True

        r, _, _ = make_receptionist(
            self, transport=BlockingVerifyTransport(), outbound={"enabled": True})
        try:
            lead = r.handle_inbound(inbound_event("dr3", text="hello"))["lead_id"]
            self.assertTrue(r.tier2.handle_admin_command(
                f"tier2 {lead} family", is_group=False)["ok"])
            thread_id = "510000000000000063"
            r.discord.record_thread(lead, "family", FAMILY_CHANNEL, thread_id)
            outcome = {}

            def run_reply():
                outcome.update(r.handle_discord_contact_reply({
                    "user_id": OWNER_ID, "guild_id": GUILD_ID,
                    "channel_id": thread_id, "parent_channel_id": FAMILY_CHANNEL,
                    "message_id": "500000000000000063", "text": "reply One attempt",
                }))

            worker = threading.Thread(target=run_reply)
            worker.start()
            self.assertTrue(verify_started.wait(2))
            # The verifier is blocked, but unrelated inbound DB work must still proceed.
            concurrent = r.handle_inbound(inbound_event(
                "dr4", sender=CONTACT_PHONE_2, chat_id="chat-2", text="hello"))
            self.assertEqual(concurrent["status"], "ok")
            release_verify.set()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertTrue(outcome["verified"])
        finally:
            release_verify.set()
            r.close()

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


class TestOwnerSeenCheck(unittest.TestCase):
    def setUp(self):
        self.r, self.clock, self.tmp = make_receptionist(
            self, owner_seen_check={"enabled": True, "delay_seconds": 180})

    def tearDown(self):
        self.r.close()

    def test_one_delayed_seen_check_for_a_new_undecided_lead(self):
        result = self.r.handle_inbound(inbound_event("sc1", text="hello"))
        lead = result["lead_id"]
        self.assertEqual(self.r.db.execute(
            "SELECT COUNT(*) FROM owner_seen_checks").fetchone()[0], 1)
        self.r.handle_inbound(inbound_event("sc2", text="hello again"))
        self.assertEqual(self.r.db.execute(
            "SELECT COUNT(*) FROM owner_seen_checks").fetchone()[0], 1)
        before = len(self.r.relay_log)
        self.clock.advance(179)
        self.r.sweep()
        self.assertEqual(len(self.r.relay_log), before)
        self.clock.advance(1)
        self.r.sweep()
        self.assertIn("OWNER SEEN-CHECK", self.r.relay_log[-1])
        self.assertIn(lead, self.r.relay_log[-1])
        self.assertNotIn(CONTACT_PHONE, self.r.relay_log[-1])
        self.r.sweep()
        self.assertEqual(sum("OWNER SEEN-CHECK" in m for m in self.r.relay_log), 1)

    def test_any_tier_decision_suppresses_seen_check(self):
        result = self.r.handle_inbound(inbound_event("sc3", text="hello"))
        lead = result["lead_id"]
        self.assertTrue(self.r.tier2.handle_admin_command(
            f"block {lead}", is_group=False)["ok"])
        self.clock.advance(180)
        self.r.sweep()
        status = self.r.db.execute(
            "SELECT status FROM owner_seen_checks WHERE lead_id=?", (lead,)).fetchone()[0]
        self.assertEqual(status, "cancelled_decided")
        self.assertFalse(any("OWNER SEEN-CHECK" in m for m in self.r.relay_log))


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

    def test_contact_reply_endpoint_is_hmac_authenticated_and_fail_closed(self):
        body = json.dumps({
            "user_id": OWNER_ID, "guild_id": GUILD_ID,
            "channel_id": "510000000000000071",
            "parent_channel_id": FAMILY_CHANNEL,
            "message_id": "500000000000000071", "text": "reply hello",
        }).encode()
        status, _ = self.post("/discord/contact-reply", body)
        self.assertEqual(status, 401)
        signature = security.sign(self.r.discord_hook_secret, body)
        status, payload = self.post(
            "/discord/contact-reply", body,
            {security.SIGNATURE_HEADER: signature})
        self.assertEqual(status, 200)
        self.assertFalse(payload["authorized"])
        self.assertEqual(payload["reason"], "unknown_thread")

    def test_unknown_route_404(self):
        status, _ = self.post("/admin", b"{}")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
