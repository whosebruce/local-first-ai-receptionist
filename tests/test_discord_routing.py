import sqlite3
import unittest

from receptionist.discord_routing import DiscordRouter
from receptionist.tier2 import COHORT_TEST, Tier2Manager

from .helpers import (
    BOT_ID, CLIENT_CHANNEL, CONTACT_PHONE, CONTACT_PHONE_2, FAMILY_CHANNEL,
    GUILD_ID, INTAKE_CHANNEL, OTHER_CHANNEL, OTHER_USER, OWNER_ID, Clock, make_config,
    make_temp_dir,
)

KEY = "unit-test-contact-hash-key-fixture"
LEAD = "AAAA1111"
ALERT_MSG = "500000000000000001"
CMD_MSG = "500000000000000002"


class RouterFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = make_temp_dir(self, prefix="discord-test-")
        self.clock = Clock()
        self.db = sqlite3.connect(":memory:")
        config = make_config(self.tmp)
        self.tier2 = Tier2Manager(self.db, config, KEY, now_fn=self.clock)
        self.router = DiscordRouter(self.db, config, self.tier2)
        self.fingerprint = self.tier2.record_lead_identity(
            LEAD, CONTACT_PHONE, "chat-1", "phone ending 0100")

    def open_alert(self, message_id=ALERT_MSG, lead=LEAD, fingerprint=None):
        token = self.router.register_pending_alert(
            lead, fingerprint if fingerprint is not None else self.fingerprint,
            None, "intake", INTAKE_CHANNEL)
        outcome = self.router.confirm_alert_posted(token, message_id)
        self.assertTrue(outcome["ok"])
        return message_id

    def command(self, *, text="<@100000000000000003> approve family",
                user_id=OWNER_ID, channel_id=INTAKE_CHANNEL,
                message_id=CMD_MSG, ref=ALERT_MSG,
                mentions=(BOT_ID,), is_dm=False, is_group=False):
        return self.router.handle_intake_command(
            user_id=user_id, channel_id=channel_id, message_id=message_id,
            referenced_message_id=ref, mentioned_ids=list(mentions),
            raw_text=text, is_dm=is_dm, is_group=is_group)


class TestRejectionMatrix(RouterFixture):
    def assert_rejected(self, result, reason):
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], reason)
        self.assertFalse(result["llm"])
        self.assertIsNone(self.tier2.resolve_status(LEAD, self.fingerprint))

    def test_wrong_user(self):
        self.open_alert()
        self.assert_rejected(self.command(user_id=OTHER_USER), "not_owner")

    def test_wrong_channel(self):
        self.open_alert()
        self.assert_rejected(self.command(channel_id=OTHER_CHANNEL), "wrong_channel")

    def test_dm_and_group(self):
        self.open_alert()
        self.assert_rejected(self.command(is_dm=True), "dm_not_allowed")
        self.assert_rejected(self.command(message_id="500000000000000009", is_group=True),
                             "group_not_allowed")

    def test_missing_mention(self):
        self.open_alert()
        self.assert_rejected(self.command(mentions=()), "no_mention")

    def test_wrong_bot_mentioned(self):
        self.open_alert()
        self.assert_rejected(self.command(mentions=(OTHER_USER,)), "no_mention")

    def test_missing_reply_reference(self):
        self.open_alert()
        self.assert_rejected(self.command(ref=None), "no_reply_reference")

    def test_ordinary_prose_is_not_a_command(self):
        self.open_alert()
        self.assert_rejected(
            self.command(text=f"<@{BOT_ID}> she seems nice, let her in"), "not_a_command")

    def test_approve_all_and_bare_approve_fail(self):
        self.open_alert()
        self.assert_rejected(self.command(text=f"<@{BOT_ID}> approve all"), "not_a_command")
        self.assert_rejected(
            self.command(text=f"<@{BOT_ID}> approve", message_id="500000000000000010"),
            "not_a_command")

    def test_permanent_tier2_and_unblock_not_exposed(self):
        self.open_alert()
        self.assert_rejected(self.command(text=f"<@{BOT_ID}> tier2 family"), "not_a_command")
        self.assert_rejected(
            self.command(text=f"<@{BOT_ID}> unblock", message_id="500000000000000011"),
            "not_a_command")

    def test_extra_words_fail(self):
        self.open_alert()
        self.assert_rejected(
            self.command(text=f"<@{BOT_ID}> approve family please"), "not_a_command")

    def test_forged_reference(self):
        self.open_alert()
        self.assert_rejected(self.command(ref="666000000000000666"),
                             "forged_or_unknown_reference")

    def test_fingerprint_mismatch_refused(self):
        self.open_alert()
        # Identity changed after the alert was posted (new number, same lead).
        self.tier2.record_lead_identity(LEAD, CONTACT_PHONE_2, "chat-1", "phone ending 0101")
        result = self.command()
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "fingerprint_mismatch")


class TestReplayAndResolveOnce(RouterFixture):
    def test_duplicate_command_message_is_inert(self):
        self.open_alert()
        first = self.command()
        self.assertTrue(first["authorized"])
        replay = self.command()  # same message_id redelivered
        self.assertEqual(replay["reason"], "duplicate_command")
        self.assertFalse(replay["resolved"])
        # Still exactly one active grant, unchanged.
        contact = self.tier2.resolve_status(LEAD, self.fingerprint)
        self.assertEqual(contact["category"], "family")

    def test_resolve_once_blocks_second_distinct_command(self):
        self.open_alert()
        self.assertTrue(self.command()["authorized"])
        second = self.command(message_id="500000000000000012",
                              text=f"<@{BOT_ID}> block")
        self.assertFalse(second["authorized"])
        self.assertEqual(second["reason"], "already_resolved")
        self.assertIsNotNone(self.tier2.resolve_status(LEAD, self.fingerprint))

    def test_cohort_full_reopens_alert_for_retry(self):
        self.tier2.test_cohort_max = 0
        self.open_alert()
        result = self.command(text=f"<@{BOT_ID}> approve family test")
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "action_failed")
        status = self.db.execute(
            "SELECT status FROM discord_alerts WHERE alert_message_id=?", (ALERT_MSG,)).fetchone()
        self.assertEqual(status[0], "open")  # owner can retry after freeing a slot
        # ... but the SAME command message can never re-run.
        retry_same = self.command()
        self.assertEqual(retry_same["reason"], "duplicate_command")


class TestApprovalSemantics(RouterFixture):
    def test_approve_maps_to_standing_cohort_by_default(self):
        self.open_alert()
        result = self.command()
        self.assertTrue(result["authorized"])
        self.assertTrue(result["resolved"])
        contact = self.tier2.resolve_status(LEAD, self.fingerprint)
        self.assertEqual(contact["cohort"], "standing")
        self.assertIn("standing Tier-2", result["readback"])

    def test_explicit_test_suffix_maps_to_temporary_cohort(self):
        self.open_alert()
        result = self.command(text=f"<@{BOT_ID}> approve family test")
        self.assertTrue(result["authorized"])
        contact = self.tier2.resolve_status(LEAD, self.fingerprint)
        self.assertEqual(contact["cohort"], COHORT_TEST)
        self.assertIn("24h", result["readback"])

    def test_tier1_and_block_work_against_correlated_lead_only(self):
        self.open_alert()
        self.command()  # promote
        alert2 = "500000000000000021"
        self.open_alert(message_id=alert2)
        result = self.router.handle_intake_command(
            user_id=OWNER_ID, channel_id=INTAKE_CHANNEL,
            message_id="500000000000000022", referenced_message_id=alert2,
            mentioned_ids=[BOT_ID], raw_text=f"<@{BOT_ID}> tier1")
        self.assertTrue(result["authorized"])
        self.assertIsNone(self.tier2.resolve_status(LEAD, self.fingerprint))

    def test_expired_cohort_membership_is_gone_before_next_decision(self):
        self.open_alert()
        self.command(text=f"<@{BOT_ID}> approve family test")
        self.clock.advance(86401)
        self.assertIsNone(self.tier2.resolve_status(LEAD, self.fingerprint))

    def test_router_has_no_contact_send_capability(self):
        import inspect
        source = inspect.getsource(type(self.router).__module__ and __import__(
            "receptionist.discord_routing", fromlist=["x"]))
        for forbidden in ("send_text", "send_reply", "message/text", "chatGuid"):
            self.assertNotIn(forbidden, source)


class TestReviewedContactReplies(RouterFixture):
    THREAD = "510000000000000009"

    def activate(self):
        admin = self.tier2.handle_admin_command(f"tier2 {LEAD} family", is_group=False)
        self.assertTrue(admin["ok"])
        self.router.record_thread(LEAD, "family", FAMILY_CHANNEL, self.THREAD)

    def reply(self, **overrides):
        values = {
            "user_id": OWNER_ID, "guild_id": GUILD_ID,
            "channel_id": self.THREAD, "parent_channel_id": FAMILY_CHANNEL,
            "message_id": "500000000000000071", "raw_text": "reply Reviewed hello",
            "is_dm": False, "is_group": False,
        }
        values.update(overrides)
        return self.router.handle_contact_reply(**values)

    def test_exact_reply_preserves_body_and_binds_active_thread(self):
        self.activate()
        result = self.reply(raw_text="RePlY First line\nSecond line")
        self.assertTrue(result["authorized"])
        self.assertEqual(result["message"], "First line\nSecond line")
        self.assertEqual(result["chat_id"], "chat-1")
        self.assertFalse(result["llm"])

    def test_reply_rejects_wrong_user_guild_parent_and_thread(self):
        self.activate()
        cases = [
            ({"user_id": OTHER_USER}, "not_owner"),
            ({"guild_id": "900000000000000099"}, "wrong_guild"),
            ({"parent_channel_id": CLIENT_CHANNEL}, "wrong_parent_channel"),
            ({"channel_id": "510000000000000099"}, "unknown_thread"),
        ]
        for index, (kwargs, reason) in enumerate(cases):
            kwargs["message_id"] = f"50000000000000008{index}"
            self.assertEqual(self.reply(**kwargs)["reason"], reason)

    def test_reply_rejects_identity_drift_inactive_and_oversize(self):
        self.activate()
        self.tier2.record_lead_identity(
            LEAD, CONTACT_PHONE_2, "chat-1", "phone ending 0101")
        self.assertEqual(self.reply()["reason"], "fingerprint_mismatch")
        # Restore, then downgrade.
        self.tier2.record_lead_identity(LEAD, CONTACT_PHONE, "chat-1", "phone ending 0100")
        self.assertTrue(self.tier2.handle_admin_command(f"tier1 {LEAD}", is_group=False)["ok"])
        self.assertEqual(self.reply(message_id="500000000000000091")["reason"], "lead_not_active")
        self.activate()
        self.assertEqual(
            self.reply(message_id="500000000000000092", raw_text="reply " + "x" * 4001)["reason"],
            "message_too_long",
        )

    def test_reply_rejects_chat_and_category_binding_drift(self):
        self.activate()
        self.tier2.record_lead_identity(
            LEAD, CONTACT_PHONE, "changed-chat", "phone ending 0100")
        self.assertEqual(
            self.reply(message_id="500000000000000093")["reason"],
            "chat_binding_mismatch",
        )
        self.tier2.record_lead_identity(
            LEAD, CONTACT_PHONE, "chat-1", "phone ending 0100")
        self.db.execute(
            "UPDATE tier2_contacts SET category='client' WHERE lead_id=?", (LEAD,))
        self.db.commit()
        self.assertEqual(
            self.reply(message_id="500000000000000094")["reason"],
            "category_binding_mismatch",
        )

    def test_reply_is_replay_safe_and_stores_no_raw_body(self):
        self.activate()
        body = "private reviewed fixture body"
        first = self.reply(raw_text="reply " + body)
        self.assertTrue(first["authorized"])
        self.router.complete_contact_reply(
            "500000000000000071", "verified", "Verified once", "synthetic-message-id")
        duplicate = self.reply(raw_text="reply " + body)
        self.assertFalse(duplicate["authorized"])
        self.assertEqual(duplicate["reason"], "duplicate_reply")
        row = self.db.execute(
            "SELECT message_sha256,message_length,readback FROM discord_contact_replies"
        ).fetchone()
        self.assertEqual(row[1], len(body))
        self.assertEqual(row[2], "Verified once")
        dump = "\n".join(self.db.iterdump())
        self.assertNotIn(body, dump)


class TestRoutingPlans(RouterFixture):
    def test_tier1_routes_to_intake(self):
        plan = self.router.plan_outbound(LEAD, None, promoted=False)
        self.assertEqual(plan["kind"], "intake")
        self.assertEqual(plan["channel_id"], INTAKE_CHANNEL)

    def test_promoted_routes_to_category_with_stable_thread(self):
        plan = self.router.plan_outbound(LEAD, "client", promoted=True)
        self.assertEqual(plan["channel_id"], CLIENT_CHANNEL)
        self.assertIsNone(plan["thread_id"])
        self.assertEqual(plan["thread_name"], f"Lead {LEAD} - client")
        # Bind a thread via callback, then the plan must reuse it.
        token = self.router.register_pending_alert(LEAD, "", "client", "category", CLIENT_CHANNEL)
        self.router.confirm_alert_posted(token, "500000000000000031",
                                         channel_id=CLIENT_CHANNEL,
                                         thread_id="510000000000000001")
        plan2 = self.router.plan_outbound(LEAD, "client", promoted=True)
        self.assertEqual(plan2["thread_id"], "510000000000000001")
        self.assertIsNone(plan2["thread_name"])

    def test_thread_reuse_survives_restart(self):
        token = self.router.register_pending_alert(LEAD, "", "family", "category", FAMILY_CHANNEL)
        self.router.confirm_alert_posted(token, "500000000000000032",
                                         channel_id=FAMILY_CHANNEL,
                                         thread_id="510000000000000002")
        # New router over the same DB simulates a service restart.
        config = make_config(self.tmp)
        router2 = DiscordRouter(self.db, config, self.tier2)
        plan = router2.plan_outbound(LEAD, "family", promoted=True)
        self.assertEqual(plan["thread_id"], "510000000000000002")

    def test_thread_names_carry_no_raw_identity(self):
        plan = self.router.plan_outbound(LEAD, "family", promoted=True)
        self.assertNotIn(CONTACT_PHONE, str(plan))
        self.assertNotIn("0100", plan["thread_name"])

    def test_unknown_correlation_token_writes_nothing(self):
        outcome = self.router.confirm_alert_posted("no-such-token", "500000000000000033")
        self.assertFalse(outcome["ok"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM discord_alerts").fetchone()[0], 0)

    def test_pending_prune_is_idempotent_and_kills_stale_correlations(self):
        self.router.register_pending_alert(LEAD, self.fingerprint, None, "intake", INTAKE_CHANNEL)
        self.clock.advance(7200)
        self.assertEqual(self.router.prune_pending(3600), 1)
        self.assertEqual(self.router.prune_pending(3600), 0)


if __name__ == "__main__":
    unittest.main()
