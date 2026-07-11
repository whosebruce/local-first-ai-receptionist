"""Local Discord Tier-1 intake approvals and Tier-2 category routing.

This module is the deterministic edge that connects a locally hosted Discord
bot (the owner's own bot — never an external/hosted integration) to the
tool-isolated receptionist. Everything security-relevant is deterministic and
lives OUTSIDE any model:

  * A new Tier-1 contact's mirrored message is routed to a private intake
    channel. The Discord message ID of that intake alert is persisted as a
    replay-resistant correlation to the stable lead ID + keyed fingerprint.
  * Only the configured owner user can change a lead's trust, by replying to
    a genuine, unresolved intake alert with an exact `@bot approve
    family|client|vendor`, `@bot tier1`, or `@bot block` command. Nothing
    else — not ordinary prose, not a forged/copied/cross-channel/deleted/
    expired/resolved reference, not another user, DM, group, or missing
    mention — can change trust.
  * Approvals map conservatively to the temporary 24-hour `tier2-test`
    cohort, never to standing Tier 2. Permanent promotion and `unblock` are
    not exposed through Discord at all.
  * After promotion, mirrored messages route by category into the matching
    private channel and a stable per-lead thread reused across restarts.

The Discord bot is a thin transport: it posts what this module decides and
forwards the owner's intake replies here. It never invokes an LLM for a
command, and there is NO path in this module that sends anything back to the
contact — Discord threads are internal audit/follow-up lanes only.
"""
from __future__ import annotations

import hmac
import logging
import re
import uuid
from typing import Any, Callable

log = logging.getLogger("receptionist.discord")

# Exact, case-insensitive intake command grammar. `approve all`, a bare
# `approve`, permanent `tier2`, `unblock`, and any extra words fail closed.
_APPROVE_RE = re.compile(r"^approve\s+(family|client|vendor)$", re.I)
_TIER1_RE = re.compile(r"^tier1$", re.I)
_BLOCK_RE = re.compile(r"^block$", re.I)

_CATEGORIES = ("family", "client", "vendor")


def _new_token() -> str:
    return uuid.uuid4().hex


class DiscordRouter:
    """Deterministic correlation, authorization, and routing over the shared
    receptionist SQLite DB. Reuses Tier2Manager for every trust change so the
    Discord lane can never bypass the vetted promotion/downgrade/block logic.
    """

    def __init__(
        self,
        db,
        config: dict[str, Any],
        tier2_manager,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self.db = db
        self.tier2 = tier2_manager
        dcfg = (config.get("discord") or {})
        self.enabled = bool(dcfg.get("enabled", False))
        self.owner_user_id = str(dcfg.get("owner_user_id") or "")
        self.bot_user_id = str(dcfg.get("bot_user_id") or "")
        self.guild_id = str(dcfg.get("guild_id") or "")
        self.intake_channel_id = str(dcfg.get("intake_channel_id") or "")
        cat = dcfg.get("category_channels") or {}
        self.category_channels = {k: str(v) for k, v in cat.items() if k in _CATEGORIES}
        # Reuse the manager's clock so tests and the live service agree.
        self.now_fn = now_fn or getattr(tier2_manager, "now_fn", None) or __import__("time").time
        self._ensure_schema()

    # ---------- schema ----------

    def _ensure_schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS discord_pending_alerts (
                correlation_token TEXT PRIMARY KEY, created_at INTEGER NOT NULL,
                kind TEXT NOT NULL, lead_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                category_hint TEXT, channel_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS discord_alerts (
                alert_message_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL,
                lead_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                category_hint TEXT, channel_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                resolved_at INTEGER, resolution TEXT
            );
            CREATE TABLE IF NOT EXISTS discord_threads (
                lead_id TEXT PRIMARY KEY, category TEXT NOT NULL,
                channel_id TEXT NOT NULL, thread_id TEXT NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS discord_commands (
                message_id TEXT PRIMARY KEY, ts INTEGER NOT NULL,
                alert_message_id TEXT, action TEXT, lead_id TEXT,
                ok INTEGER NOT NULL, readback TEXT
            );
            CREATE TABLE IF NOT EXISTS discord_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                event TEXT NOT NULL, lead_id TEXT, detail TEXT
            );
            """
        )
        self.db.commit()

    def _now(self) -> int:
        return int(self.now_fn())

    def _audit(self, event: str, lead: str | None, detail: str = "") -> None:
        self.db.execute(
            "INSERT INTO discord_audit(ts,event,lead_id,detail) VALUES(?,?,?,?)",
            (self._now(), event, lead, (detail or "")[:400]),
        )
        self.db.commit()

    # ---------- outbound routing ----------

    def plan_outbound(self, lead: str, category: str | None, promoted: bool) -> dict[str, Any]:
        """Decide where a mirrored inbound message should be posted.

        Tier-1 (not promoted) -> the private intake channel. Promoted -> the
        category channel plus a stable per-lead thread (reused across messages
        and restarts). Thread/channel names never contain raw phone/email
        values — only the non-identifying 8-char lead ID and the category.
        """
        if not promoted or category not in self.category_channels:
            return {
                "kind": "intake",
                "channel_id": self.intake_channel_id,
                "thread_id": None,
                "thread_name": None,
                "category": None,
            }
        channel_id = self.category_channels[category]
        existing = self.get_thread(lead)
        thread_id = existing["thread_id"] if existing else None
        return {
            "kind": "category",
            "channel_id": channel_id,
            "thread_id": thread_id,
            "thread_name": None if thread_id else f"Lead {lead} - {category}",
            "category": category,
        }

    def register_pending_alert(
        self, lead: str, fingerprint: str, category_hint: str | None,
        kind: str, channel_id: str,
    ) -> str:
        """Reserve a correlation token before the bot posts the alert; the
        real Discord message ID is bound later via confirm_alert_posted()."""
        token = _new_token()
        self.db.execute(
            "INSERT INTO discord_pending_alerts(correlation_token,created_at,kind,lead_id,"
            "fingerprint,category_hint,channel_id) VALUES(?,?,?,?,?,?,?)",
            (token, self._now(), kind, lead, fingerprint or "", category_hint, channel_id),
        )
        self.db.commit()
        return token

    def confirm_alert_posted(
        self, correlation_token: str, message_id: str,
        channel_id: str | None = None, thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Bind the posted Discord message ID (and any created thread) to the
        pending correlation. Intake alerts become reply-correlatable here;
        category posts record/refresh the stable per-lead thread."""
        row = self.db.execute(
            "SELECT kind,lead_id,fingerprint,category_hint,channel_id FROM "
            "discord_pending_alerts WHERE correlation_token=?",
            (correlation_token,),
        ).fetchone()
        if not row:
            return {"ok": False, "reason": "unknown_token"}
        kind, lead, fingerprint, category_hint, ch = row
        self.db.execute(
            "DELETE FROM discord_pending_alerts WHERE correlation_token=?", (correlation_token,)
        )
        now = self._now()
        if kind == "intake":
            if message_id:
                self.db.execute(
                    "INSERT OR IGNORE INTO discord_alerts(alert_message_id,created_at,lead_id,"
                    "fingerprint,category_hint,channel_id,status) VALUES(?,?,?,?,?,?, 'open')",
                    (str(message_id), now, lead, fingerprint or "", category_hint, channel_id or ch),
                )
            self.db.commit()
            self._audit("intake_alert_posted", lead, str(message_id))
            return {"ok": True, "kind": "intake", "lead_id": lead}
        if thread_id:
            self.record_thread(lead, category_hint or "", channel_id or ch, str(thread_id))
        self.db.commit()
        self._audit("category_post", lead, f"thread={thread_id}")
        return {"ok": True, "kind": "category", "lead_id": lead}

    def prune_pending(self, max_age_seconds: int) -> int:
        """Drop correlation tokens the bot never confirmed. Idempotent."""
        cutoff = self._now() - int(max_age_seconds)
        cur = self.db.execute("DELETE FROM discord_pending_alerts WHERE created_at < ?", (cutoff,))
        self.db.commit()
        return cur.rowcount

    # ---------- per-lead thread persistence ----------

    def get_thread(self, lead: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT lead_id,category,channel_id,thread_id FROM discord_threads WHERE lead_id=?",
            (lead,),
        ).fetchone()
        if not row:
            return None
        return {"lead_id": row[0], "category": row[1], "channel_id": row[2], "thread_id": row[3]}

    def record_thread(self, lead: str, category: str, channel_id: str, thread_id: str) -> None:
        now = self._now()
        self.db.execute(
            "INSERT INTO discord_threads(lead_id,category,channel_id,thread_id,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?) ON CONFLICT(lead_id) DO UPDATE SET"
            " category=excluded.category, channel_id=excluded.channel_id,"
            " thread_id=excluded.thread_id, updated_at=excluded.updated_at",
            (lead, category, channel_id, str(thread_id), now, now),
        )
        self.db.commit()

    # ---------- command parsing ----------

    def _strip_mentions(self, text: str) -> str:
        """Remove the bot's mention tokens and collapse whitespace. Discord
        delivers mentions as <@id>/<@!id>."""
        t = text or ""
        if self.bot_user_id:
            t = re.sub(rf"<@!?{re.escape(self.bot_user_id)}>", " ", t)
        t = re.sub(r"<@!?\d+>", " ", t)  # any other mention chip
        return " ".join(t.split())

    def parse_command(self, text: str) -> dict[str, Any] | None:
        """Return {'action','category'} for an exact command, else None."""
        cmd = self._strip_mentions(text)
        if not cmd:
            return None
        m = _APPROVE_RE.match(cmd)
        if m:
            return {"action": "approve", "category": m.group(1).lower()}
        if _TIER1_RE.match(cmd):
            return {"action": "tier1", "category": None}
        if _BLOCK_RE.match(cmd):
            return {"action": "block", "category": None}
        return None

    def _self_mentioned(self, mentioned_ids: Any) -> bool:
        if not self.bot_user_id:
            return False
        ids = {str(x) for x in (mentioned_ids or [])}
        return self.bot_user_id in ids

    # ---------- command interception (deterministic, no LLM) ----------

    def handle_intake_command(
        self, *,
        user_id: str,
        channel_id: str,
        message_id: str,
        referenced_message_id: str | None,
        mentioned_ids: Any,
        raw_text: str,
        is_dm: bool = False,
        is_group: bool = False,
    ) -> dict[str, Any]:
        """Deterministically authorize and execute an intake reply-command.

        Fails closed on every deviation. Returns a dict with a `readback` the
        bot posts back into the intake channel and `llm=False` so the bot
        never routes an intake command to a model. Never contacts the lead.
        """
        result = {
            "authorized": False, "action": None, "lead_id": None,
            "resolved": False, "reason": "", "readback": "", "llm": False,
        }
        mid = str(message_id or "")
        if not mid:
            result["reason"] = "missing_message_id"
            result["readback"] = "Intake command ignored (missing message id)."
            return result

        # Idempotency / replay guard on the command message itself: a replayed
        # delivery returns the prior outcome and never re-executes.
        prior = self.db.execute(
            "SELECT ok,readback,action,lead_id FROM discord_commands WHERE message_id=?", (mid,)
        ).fetchone()
        if prior is not None:
            self._audit("command_duplicate", prior[3], mid)
            return {
                "authorized": bool(prior[0]), "action": prior[2], "lead_id": prior[3],
                "resolved": False, "reason": "duplicate_command",
                "readback": prior[1] or "", "llm": False,
            }

        def _finish(reason: str, readback: str, ok: bool, action=None, lead=None, resolved=False):
            # Record every processed command message id exactly once so replays
            # are inert. Rejections are recorded too (idempotent rejection).
            self.db.execute(
                "INSERT OR IGNORE INTO discord_commands(message_id,ts,alert_message_id,action,lead_id,ok,readback)"
                " VALUES(?,?,?,?,?,?,?)",
                (mid, self._now(), str(referenced_message_id or ""), action, lead, 1 if ok else 0, readback[:800]),
            )
            self.db.commit()
            result.update({
                "authorized": ok, "action": action, "lead_id": lead,
                "resolved": resolved, "reason": reason, "readback": readback,
            })
            return result

        # 1. Structural authorization — all outside any model.
        if is_dm:
            self._audit("reject_dm", None, mid)
            return _finish("dm_not_allowed", "Intake commands must be sent in the intake channel, not a DM.", False)
        if is_group:
            self._audit("reject_group", None, mid)
            return _finish("group_not_allowed", "Intake commands are not accepted from group contexts.", False)
        if not self.intake_channel_id or str(channel_id) != self.intake_channel_id:
            self._audit("reject_channel", None, f"ch={channel_id}")
            return _finish("wrong_channel", "Intake commands are only accepted in the intake channel.", False)
        if not self.owner_user_id or str(user_id) != self.owner_user_id:
            self._audit("reject_user", None, str(user_id))
            return _finish("not_owner", "Only the owner can approve or change a lead's tier.", False)
        if not self._self_mentioned(mentioned_ids):
            self._audit("reject_no_mention", None, mid)
            return _finish("no_mention", "Please @mention the bot in your approval reply.", False)
        if not referenced_message_id:
            self._audit("reject_no_reference", None, mid)
            return _finish("no_reply_reference", "Reply directly to the intake alert you want to act on.", False)

        # 2. Exact command grammar (before any correlation lookup).
        parsed = self.parse_command(raw_text)
        if parsed is None:
            self._audit("reject_not_command", None, self._strip_mentions(raw_text)[:120])
            return _finish(
                "not_a_command",
                "Unrecognized command. Reply with exactly `@bot approve family`, "
                "`@bot approve client`, `@bot approve vendor`, `@bot tier1`, or `@bot block`.",
                False,
            )

        # 3. Correlation lookup — the referenced message must be a genuine,
        #    still-open intake alert this service posted.
        ref = str(referenced_message_id)
        alert = self.db.execute(
            "SELECT lead_id,fingerprint,category_hint,status FROM discord_alerts WHERE alert_message_id=?",
            (ref,),
        ).fetchone()
        if not alert:
            self._audit("reject_forged_reference", None, ref)
            return _finish(
                "forged_or_unknown_reference",
                "That reply doesn't reference a known intake alert, so nothing was changed.",
                False, action=parsed["action"],
            )
        lead, fingerprint, category_hint, status = alert
        if status != "open":
            self._audit("reject_resolved_reference", lead, ref)
            return _finish(
                "already_resolved",
                f"Intake alert for lead {lead} was already handled; reply to a fresh alert to make another change.",
                False, action=parsed["action"], lead=lead,
            )

        # 4. Verify the lead still exists and its identity binding is intact.
        identity = self.db.execute(
            "SELECT fingerprint FROM lead_identity WHERE lead_id=?", (lead,)
        ).fetchone()
        if not identity:
            self._audit("reject_unknown_lead", lead, ref)
            return _finish("unknown_lead", f"Lead {lead} is no longer known; nothing changed.", False,
                           action=parsed["action"], lead=lead)
        if fingerprint and not (identity[0] and hmac.compare_digest(str(identity[0]), str(fingerprint))):
            # The alert was bound to a fingerprint, but the lead's current
            # identity is now empty or different: trust is never inherited
            # across a changed/cleared number or handle. (An alert with no
            # stored fingerprint — an unkeyed deployment — still fails closed
            # for `approve` downstream, which requires the contact hash key.)
            self._audit("reject_fingerprint_mismatch", lead, ref)
            return _finish("fingerprint_mismatch",
                           f"Lead {lead}'s identity changed since that alert; approval refused.",
                           False, action=parsed["action"], lead=lead)

        # 5. Atomically claim the alert (resolve-once). A concurrent duplicate
        #    that slips past the command-id guard loses this race and fails.
        claimed = self.db.execute(
            "UPDATE discord_alerts SET status='resolving', resolved_at=? WHERE alert_message_id=? AND status='open'",
            (self._now(), ref),
        )
        self.db.commit()
        if claimed.rowcount != 1:
            self._audit("reject_race", lead, ref)
            return _finish("already_resolved", f"Intake alert for lead {lead} was already handled.",
                           False, action=parsed["action"], lead=lead)

        # 6. Execute via the vetted Tier2Manager admin path. Approvals map to
        #    the temporary tier2-test cohort ONLY — never standing tier2.
        if parsed["action"] == "approve":
            admin_cmd = f"tier2-test {lead} {parsed['category']}"
        elif parsed["action"] == "tier1":
            admin_cmd = f"tier1 {lead}"
        else:
            admin_cmd = f"block {lead}"
        admin = self.tier2.handle_admin_command(admin_cmd, is_group=False)
        ok = bool(admin and admin.get("ok"))

        if not ok:
            # Authorized and well-formed but the action could not complete
            # (e.g. cohort full). Re-open the alert so the owner can retry;
            # the command message id is still recorded, so THIS message won't
            # re-run.
            self.db.execute(
                "UPDATE discord_alerts SET status='open', resolved_at=NULL WHERE alert_message_id=?",
                (ref,),
            )
            self.db.commit()
            self._audit("command_action_failed", lead, admin_cmd)
            readback = (admin or {}).get("readback") or "That change could not be completed."
            return _finish("action_failed", readback, False, action=parsed["action"], lead=lead)

        # 7. Success: finalize resolve-once and record the outcome.
        self.db.execute(
            "UPDATE discord_alerts SET status='resolved', resolved_at=?, resolution=? WHERE alert_message_id=?",
            (self._now(), parsed["action"], ref),
        )
        self.db.commit()
        self._audit("command_ok", lead, admin_cmd)
        readback = self._success_readback(parsed, lead)
        outcome = _finish("ok", readback, True, action=parsed["action"], lead=lead, resolved=True)
        # Surface disclosure/thread hints for the caller (bot) without letting
        # them influence authorization.
        outcome["disclosure"] = bool(admin.get("send_disclosure"))
        outcome["category"] = parsed["category"]
        outcome["admin"] = admin
        return outcome

    def _success_readback(self, parsed: dict[str, Any], lead: str) -> str:
        if parsed["action"] == "approve":
            return (
                f"OK: lead {lead} -> temporary Tier-2 {parsed['category']} (tier2-test). "
                "Expires after 24h of inactivity based only on the contact's inbound messages; "
                "reply `@bot tier1` (replying to a fresh alert) or send `tier1 " + lead +
                "` from the owner line to downgrade. This is not a standing promotion."
            )
        if parsed["action"] == "tier1":
            return f"OK: lead {lead} downgraded to Tier 1; bounded context cleared."
        return f"OK: lead {lead} blocked; the assistant will not reply to this contact."
