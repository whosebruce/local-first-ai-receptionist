"""Tests for the Hermes overlay generator: validated substitution, clean
applicability checks, backup/rollback, fail-closed drift detection, and the
fail-closed behavior of the rendered hooks (forged routes, callback tampering,
shim/import/config failures)."""
import asyncio
import importlib.util
import json
import shutil
import types
import unittest
from pathlib import Path

from .helpers import (
    BOT_ID, CLIENT_CHANNEL, FAMILY_CHANNEL, INTAKE_CHANNEL, OTHER_CHANNEL,
    VENDOR_CHANNEL, make_config, make_temp_dir,
)

REPO = Path(__file__).resolve().parents[1]
OVERLAY_SRC = REPO / "integrations" / "hermes"

ADAPTER_BODY = '''\
class DiscordAdapter:
    async def on_message(self, message):
        if not self.should_respond(message):
            return
        await self._handle_message(message, role_authorized=True)
'''

WEBHOOK_BODY = '''\
class WebhookAdapter:
    async def _direct_deliver(self, content, payload):
        result = await self._send_via_platform(content, payload)
        return result
'''


def load_overlay_module(workdir: Path):
    """Import a private copy of render_overlay bound to a temp work dir so
    tests never write into the repository tree."""
    work_overlay = workdir / "hermes-overlay"
    shutil.copytree(OVERLAY_SRC, work_overlay)
    spec = importlib.util.spec_from_file_location(
        f"render_overlay_{workdir.name}", work_overlay / "render_overlay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE = work_overlay
    module.MANIFEST_PATH = work_overlay / "overlay_manifest.json"
    module.LOCK_PATH = work_overlay / "overlay.lock.json"
    return module


class OverlayFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = make_temp_dir(self, prefix="overlay-test-")
        self.overlay = load_overlay_module(self.tmp)
        self.hermes = self.tmp / "hermes"
        (self.hermes / "plugins/platforms/discord").mkdir(parents=True)
        (self.hermes / "gateway/platforms").mkdir(parents=True)
        self.adapter = self.hermes / "plugins/platforms/discord/adapter.py"
        self.webhook = self.hermes / "gateway/platforms/webhook.py"
        self.adapter.write_text(ADAPTER_BODY)
        self.webhook.write_text(WEBHOOK_BODY)
        self.state = self.tmp / "state"
        self.state.mkdir(mode=0o700)
        config = make_config(self.state)
        (self.state / "config.json").write_text(json.dumps(config))
        (self.state / "secrets.json").write_text(json.dumps(
            {"discord_hook_secret": "test-hook-secret-not-real"}))

    def args(self, **extra):
        return types.SimpleNamespace(
            hermes_root=str(self.hermes),
            receptionist_config=str(self.state / "config.json"), **extra)

    def render(self):
        self.overlay.render(self.args())

    def apply(self):
        self.overlay.apply(self.args())


class TestRenderValidation(OverlayFixture):
    def test_render_substitutes_validated_config(self):
        self.render()
        rendered = (self.overlay.HERE / "rendered" / "receptionist_intake_hook.py").read_text()
        self.assertIn(INTAKE_CHANNEL, rendered)
        self.assertNotIn("{{", rendered)
        lock = json.loads(self.overlay.LOCK_PATH.read_text())
        self.assertEqual(len(lock["targets"]), 2)

    def test_render_fails_closed_on_bad_channel_id(self):
        config = json.loads((self.state / "config.json").read_text())
        config["discord"]["intake_channel_id"] = "not-a-snowflake"
        (self.state / "config.json").write_text(json.dumps(config))
        with self.assertRaises(SystemExit):
            self.render()
        self.assertFalse(self.overlay.LOCK_PATH.exists())

    def test_render_fails_closed_on_missing_or_ambiguous_anchor(self):
        self.adapter.write_text("def nothing(): pass\n")
        with self.assertRaises(SystemExit):
            self.render()
        self.adapter.write_text(ADAPTER_BODY + ADAPTER_BODY)  # anchor twice
        with self.assertRaises(SystemExit):
            self.render()


class TestApplyRollbackDrift(OverlayFixture):
    def test_apply_backs_up_and_inserts_markers_and_compiles(self):
        self.render()
        original = self.adapter.read_text()
        self.apply()
        patched = self.adapter.read_text()
        self.assertIn("receptionist-overlay:discord-intake:begin", patched)
        self.assertIn(INTAKE_CHANNEL, patched)
        compile(patched, str(self.adapter), "exec")  # still valid python
        compile(self.webhook.read_text(), str(self.webhook), "exec")
        backups = list(self.adapter.parent.glob("adapter.py.overlay-backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), original)

    def test_double_apply_fails_closed(self):
        self.render()
        self.apply()
        # A second apply must fail against the drifted (already-patched) file.
        with self.assertRaises(SystemExit):
            self.apply()

    def test_upstream_drift_fails_closed_with_no_changes(self):
        self.render()
        self.adapter.write_text(ADAPTER_BODY + "\n# upstream update\n")
        drifted = self.adapter.read_text()
        with self.assertRaises(SystemExit):
            self.apply()
        self.assertEqual(self.adapter.read_text(), drifted)  # untouched
        self.assertNotIn("receptionist-overlay", self.webhook.read_text())

    def test_partial_precondition_failure_touches_nothing(self):
        self.render()
        self.webhook.write_text(WEBHOOK_BODY + "\n# drift on second target\n")
        with self.assertRaises(SystemExit):
            self.apply()
        # First target must ALSO be untouched (all-or-nothing staging).
        self.assertNotIn("receptionist-overlay", self.adapter.read_text())

    def test_rollback_restores_original(self):
        self.render()
        original = self.adapter.read_bytes()
        self.apply()
        self.overlay.rollback(self.args())
        self.assertEqual(self.adapter.read_bytes(), original)

    def test_verify_reports_states(self):
        self.render()
        with self.assertRaises(SystemExit) as ctx:
            self.overlay.verify(self.args())
        self.assertEqual(ctx.exception.code, 0)  # pristine
        self.apply()
        with self.assertRaises(SystemExit) as ctx:
            self.overlay.verify(self.args())
        self.assertEqual(ctx.exception.code, 0)  # applied
        self.overlay.rollback(self.args())
        self.adapter.write_text(ADAPTER_BODY + "\n# upstream\n")
        with self.assertRaises(SystemExit) as ctx:
            self.overlay.verify(self.args())
        self.assertEqual(ctx.exception.code, 1)  # drifted -> fail


class FakeSendResult:
    def __init__(self, success=True, message_id="500000000000000090"):
        self.success = success
        self.message_id = message_id


class FakeAdapter:
    def __init__(self, fail=False):
        self.posts = []
        self.fail = fail
        self._client = None

    async def send(self, channel_id, content, metadata=None, reply_to=None):
        if self.fail:
            return FakeSendResult(success=False)
        self.posts.append({"channel_id": channel_id, "content": content,
                           "metadata": metadata or {}})
        return FakeSendResult()


class TestRenderedHooksFailClosed(OverlayFixture):
    def setUp(self):
        super().setUp()
        self.render()
        rendered = self.overlay.HERE / "rendered"
        for name in ("receptionist_intake_hook", "receptionist_delivery_hook"):
            spec = importlib.util.spec_from_file_location(
                f"{name}_{self.tmp.name}", rendered / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            setattr(self, name.split("_")[1] + "_hook", module)
        self.cfg = {
            "enabled": True,
            "intake_channel_id": INTAKE_CHANNEL,
            "category_channels": {"family": FAMILY_CHANNEL, "client": CLIENT_CHANNEL,
                                  "vendor": VENDOR_CHANNEL},
            "hook_secret": "test-hook-secret-not-real",
        }

    # -- delivery hook: forged/invalid routes fall back to legacy --

    def route(self, **overrides):
        base = {"correlation_token": "tok-1", "kind": "intake",
                "channel_id": INTAKE_CHANNEL}
        base.update(overrides)
        return base

    def test_valid_routes_accepted(self):
        self.assertIsNotNone(self.delivery_hook.validate_route(self.route(), self.cfg))
        category = self.route(kind="category", channel_id=FAMILY_CHANNEL,
                              category="family", thread_name="Lead AAAA1111 - family")
        self.assertIsNotNone(self.delivery_hook.validate_route(category, self.cfg))

    def test_forged_routes_rejected(self):
        cases = [
            self.route(channel_id=OTHER_CHANNEL),                       # forged intake channel
            self.route(kind="category", channel_id=OTHER_CHANNEL,
                       category="family", thread_name="x"),             # forged category channel
            self.route(kind="category", channel_id=CLIENT_CHANNEL,
                       category="family", thread_name="x"),             # category/channel mismatch
            self.route(kind="category", channel_id=FAMILY_CHANNEL,
                       category="family"),                              # no thread info
            self.route(kind="category", channel_id=FAMILY_CHANNEL,
                       category="family", thread_id="../etc/passwd"),   # non-numeric thread
            self.route(correlation_token=""),
            self.route(kind="broadcast"),
            self.route(channel_id="not-digits"),
            "not-a-dict",
        ]
        for case in cases:
            self.assertIsNone(self.delivery_hook.validate_route(case, self.cfg), case)

    def test_delivery_without_route_uses_legacy(self):
        adapter = FakeAdapter()
        result = asyncio.run(self.delivery_hook.maybe_route_delivery(
            adapter, "alert", {"type": "receptionist.inbound"}, config=self.cfg))
        self.assertIsNone(result)
        self.assertEqual(adapter.posts, [])

    def test_delivery_posts_and_fires_signed_callback(self):
        adapter = FakeAdapter()
        callbacks = []
        result = asyncio.run(self.delivery_hook.maybe_route_delivery(
            adapter, "alert body",
            {"type": "receptionist.inbound", "route": self.route()},
            config=self.cfg, post_callback_fn=lambda cfg, p: callbacks.append(p)))
        self.assertIsNotNone(result)
        self.assertEqual(adapter.posts[0]["channel_id"], INTAKE_CHANNEL)
        self.assertEqual(callbacks[0]["correlation_token"], "tok-1")

    def test_delivery_pre_post_failure_falls_back_to_legacy(self):
        adapter = FakeAdapter(fail=True)
        result = asyncio.run(self.delivery_hook.maybe_route_delivery(
            adapter, "alert",
            {"type": "receptionist.inbound", "route": self.route()},
            config=self.cfg, post_callback_fn=lambda cfg, p: None))
        self.assertIsNone(result)  # caller must run legacy delivery

    def test_callback_failure_does_not_undo_delivery(self):
        adapter = FakeAdapter()

        def broken_callback(cfg, payload):
            raise OSError("receptionist down")
        result = asyncio.run(self.delivery_hook.maybe_route_delivery(
            adapter, "alert",
            {"type": "receptionist.inbound", "route": self.route()},
            config=self.cfg, post_callback_fn=broken_callback))
        self.assertIsNotNone(result)
        self.assertEqual(len(adapter.posts), 1)

    def test_unreadable_config_falls_back_to_legacy(self):
        adapter = FakeAdapter()
        result = asyncio.run(self.delivery_hook.maybe_route_delivery(
            adapter, "alert",
            {"type": "receptionist.inbound", "route": self.route()},
            config={"enabled": True}))  # missing hook_secret/intake -> declined
        self.assertIsNone(result)
        self.assertEqual(adapter.posts, [])

    # -- intake hook: candidate gating + fail-closed forwarding --

    def message(self, channel=INTAKE_CHANNEL, ref=True, mentions=(BOT_ID,)):
        class TextChannel:
            pass

        msg = types.SimpleNamespace()
        msg.channel = TextChannel()
        msg.channel.id = int(channel)
        msg.author = types.SimpleNamespace(id=int("900000000000000001"))
        msg.id = 500000000000000050
        msg.reference = types.SimpleNamespace(message_id=500000000000000051) if ref else None
        msg.mentions = [types.SimpleNamespace(id=int(m)) for m in mentions]
        msg.content = "approve family"
        msg.guild = object()
        return msg

    def test_should_forward_only_reply_with_mention_in_intake(self):
        extract = self.intake_hook.extract_fields
        self.assertTrue(self.intake_hook.should_forward(extract(self.message()), BOT_ID))
        self.assertFalse(self.intake_hook.should_forward(
            extract(self.message(channel=OTHER_CHANNEL)), BOT_ID))
        self.assertFalse(self.intake_hook.should_forward(
            extract(self.message(ref=False)), BOT_ID))
        self.assertFalse(self.intake_hook.should_forward(
            extract(self.message(mentions=())), BOT_ID))

    def test_forward_error_swallows_command_fail_closed(self):
        # No receptionist is listening; _post raises -> the hook must still
        # report the message as handled (so the caller returns before any LLM)
        # with authorized=False and no state change.
        adapter = FakeAdapter()
        result = asyncio.run(self.intake_hook.maybe_handle_intake(
            adapter, self.message(), BOT_ID))
        self.assertIsNotNone(result)
        self.assertTrue(result["handled"])
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "forward_error")
        self.assertFalse(result["llm"])

    def test_non_candidate_is_left_to_normal_path(self):
        adapter = FakeAdapter()
        result = asyncio.run(self.intake_hook.maybe_handle_intake(
            adapter, self.message(channel=OTHER_CHANNEL), BOT_ID))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
