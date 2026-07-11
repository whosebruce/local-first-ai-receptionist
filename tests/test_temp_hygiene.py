"""Temp-artifact hygiene: a test/verify run must leave zero debris behind.

Every fixture root is created through ``helpers.make_temp_dir`` (or
``tempfile.TemporaryDirectory``), which registers removal via
``addCleanup``/``addClassCleanup`` — callbacks unittest runs on every
outcome, including failures and errors. These regressions re-run one
representative test per fixture surface under an isolated temp root and
assert the root is empty afterwards, so a reintroduced ``mkdtemp`` without
teardown fails deterministically instead of silently polluting the
operator's temp directory on each ``scripts/verify.sh`` run.
"""
import os
import tempfile
import unittest
from pathlib import Path

from .helpers import make_receptionist, make_temp_dir

# Every temp-dir prefix any fixture in this suite may create. Kept in sync
# with helpers.make_temp_dir call sites; the assertions below are stricter
# (the isolated root must be completely empty), this list only sharpens the
# failure message when a project-prefixed root survives.
PROJECT_PREFIXES = (
    "receptionist-test-", "ingress-secrets-", "overlay-test-",
    "tier2-test-", "gate-test-", "discord-test-",
)

# One representative test per distinct fixture shape: instance-level
# make_receptionist (setUp), class-level make_receptionist (setUpClass +
# addClassCleanup), in-test make_temp_dir for each project prefix, multiple
# dirs in one test, and quarantine/state writes inside a fixture root.
REPRESENTATIVE_TESTS = (
    "tests.test_app.TestInboundPipeline.test_bad_event_type_ignored",
    "tests.test_app.TestHTTPLayer.test_health",
    "tests.test_app.TestOutboundOwnerGate.test_default_config_uses_stub_even_for_bluebubbles_kind",
    "tests.test_tier2.TestAdminCommands.test_exact_promotion_with_readback_and_disclosure",
    "tests.test_overlay.TestRenderValidation.test_render_substitutes_validated_config",
    "tests.test_ingress.TestShimValidation.test_secrets_file_fails_closed",
    "tests.test_security_hardening.TestSecretLoader.test_symlinked_secrets_refused",
    "tests.test_security_hardening.TestImageFailClosed.test_model_refusal_or_hedge_not_retained",
    "tests.test_security_hardening.TestOverlayInjection.test_malicious_state_dir_refused",
    "tests.test_discord_routing.TestRejectionMatrix.test_wrong_user",
    "tests.test_e2e_synthetic.TestSyntheticEndToEnd.test_group_chat_never_enters_tier2",
)


class TestNoTempArtifactsLeaked(unittest.TestCase):
    def _run_under_isolated_root(self, suite):
        """Run a suite with tempfile pointed at a fresh, isolated root and
        return (result, surviving_entries). The isolated root itself is a
        TemporaryDirectory, so this regression cannot leak either."""
        with tempfile.TemporaryDirectory(prefix="temp-hygiene-audit-") as root:
            saved = tempfile.tempdir
            tempfile.tempdir = root
            try:
                result = unittest.TestResult()
                suite.run(result)
            finally:
                tempfile.tempdir = saved
            survivors = sorted(entry.name for entry in Path(root).iterdir())
            return result, survivors

    def _assert_no_survivors(self, survivors):
        prefixed = [name for name in survivors
                    if name.startswith(PROJECT_PREFIXES)]
        self.assertEqual(prefixed, [],
                         f"project-prefixed fixture roots survived: {prefixed}")
        self.assertEqual(survivors, [],
                         f"temp artifacts survived the run: {survivors}")

    def test_representative_fixtures_leave_temp_root_empty(self):
        suite = unittest.defaultTestLoader.loadTestsFromNames(REPRESENTATIVE_TESTS)
        result, survivors = self._run_under_isolated_root(suite)
        self.assertEqual(result.testsRun, len(REPRESENTATIVE_TESTS))
        self.assertTrue(
            result.wasSuccessful(),
            "representative tests failed under the isolated temp root: "
            f"{[(str(t), e.splitlines()[-1]) for t, e in result.failures + result.errors]}")
        self._assert_no_survivors(survivors)

    def test_fixture_roots_removed_even_when_the_test_fails(self):
        # Defined locally so discovery can never collect it as a real test.
        class DeliberateFailure(unittest.TestCase):
            def test_fails_after_creating_fixture_roots(inner):
                make_receptionist(inner)
                make_temp_dir(inner, prefix="ingress-secrets-")
                make_temp_dir(inner, prefix="overlay-test-")
                inner.fail("deliberate: cleanup must run on failure paths too")

        suite = unittest.TestSuite([
            DeliberateFailure("test_fails_after_creating_fixture_roots")])
        result, survivors = self._run_under_isolated_root(suite)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(len(result.failures), 1)  # it failed as designed...
        self.assertEqual(result.errors, [])
        self._assert_no_survivors(survivors)       # ...and still cleaned up

    def test_make_temp_dir_creates_under_configured_tempdir(self):
        # Guards the audit mechanism itself: fixture roots must honor the
        # process tempdir, or an isolated-root audit would prove nothing.
        with tempfile.TemporaryDirectory(prefix="temp-hygiene-audit-") as root:
            saved = tempfile.tempdir
            tempfile.tempdir = root
            try:
                created = make_temp_dir(self)
                self.assertEqual(created.parent, Path(root))
                self.assertTrue(created.is_dir())
            finally:
                tempfile.tempdir = saved
        # The enclosing TemporaryDirectory removed root (and the fixture in
        # it); our own registered cleanup must then tolerate the missing dir.
        self.assertFalse(os.path.exists(created))


if __name__ == "__main__":
    unittest.main()
