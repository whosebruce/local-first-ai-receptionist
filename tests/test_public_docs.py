"""Regression tests for public-doc release claims: the README's privacy claim
must stay precise about the optional Discord mirror, the agent runbook must
never solicit the owner's phone/email into agent chat, public links must be
real, not placeholders, no source file or operator doc may make an
unconditional all-local claim, and cross-machine ingress instructions must
provision a dedicated single-key secrets file, never the full bundle.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = (REPO / "README.md").read_text()
AGENT_INSTALL = (REPO / "AGENT_INSTALL.md").read_text()
HERMES_DOC = (REPO / "docs" / "HERMES-INTEGRATION.md").read_text()


class TestReadmePrivacyClaim(unittest.TestCase):
    def test_no_absolute_nothing_ever_leaves_claim(self):
        # The optional Discord mirror sends masked identity + message content
        # to Discord, so an unconditional "nothing ever leaves" claim is false.
        self.assertNotRegex(
            README, r"(?is)(nothing|never)[^.]{0,120}\bleaves?\s+your\s+machine")

    def test_discord_mirror_disclosure_is_present(self):
        self.assertRegex(README, r"(?i)discord'?s?\s+servers")
        self.assertRegex(README, r"(?i)not end-to-end encrypted")

    def test_real_public_clone_url(self):
        self.assertIn(
            "https://github.com/whosebruce/local-first-ai-receptionist", README)
        self.assertNotIn("your-fork-or-local-path", README)


class TestAgentRunbookOwnerPII(unittest.TestCase):
    def interview_questions(self) -> list:
        interview = AGENT_INSTALL.split("## Step 2")[1].split("## Step 3")[0]
        # Numbered questions plus their wrapped continuation lines.
        return re.findall(r"(?ms)^\d+\..*?(?=^\d+\.|^\*\*|\Z)", interview)

    def test_interview_never_requests_owner_contact_address(self):
        questions = self.interview_questions()
        self.assertTrue(questions, "step-2 interview questions not found")
        for question in questions:
            self.assertNotRegex(
                question, r"(?i)\b(phone|e-?mail)\b",
                "the step-2 interview must not ask for the owner's phone/email")

    def test_no_echo_enrollment_is_the_only_path(self):
        self.assertRegex(
            AGENT_INSTALL, r"(?i)never ask for[^.]{0,120}\bphone\b")
        self.assertIn("--add-tier3", AGENT_INSTALL)
        self.assertRegex(AGENT_INSTALL, r"(?i)no-echo")
        self.assertIn("the owner types the address at the hidden prompt",
                      AGENT_INSTALL)

    def test_pasted_address_must_be_refused(self):
        self.assertRegex(
            AGENT_INSTALL,
            r"(?i)pastes an address into chat[^.]*do not use, store, or repeat")


class TestHermesAndPublicLinks(unittest.TestCase):
    def test_real_hermes_agent_url(self):
        self.assertIn("https://github.com/NousResearch/hermes-agent", HERMES_DOC)

    def test_no_placeholder_github_link(self):
        self.assertNotIn("](https://github.com/)", HERMES_DOC)


class TestTransportHmacDocs(unittest.TestCase):
    """Verifier-bounce-2 regression: operator-facing docs must describe the
    mandatory raw-body HMAC ingress and never instruct query-token auth."""

    TRANSPORT = (REPO / "docs" / "TRANSPORT.md").read_text()

    def operator_docs(self):
        # security/FABLE-XHIGH-REVIEW.md is excluded: it documents the
        # removed query-token design as review history.
        paths = [REPO / "README.md", REPO / "AGENT_INSTALL.md",
                 REPO / "SECURITY.md", REPO / "THREAT-MODEL.md",
                 REPO / "ARCHITECTURE.md"]
        paths += sorted((REPO / "docs").glob("*.md"))
        return paths

    def test_no_query_token_instructions_in_operator_docs(self):
        for path in self.operator_docs():
            text = path.read_text()
            self.assertNotIn("?token=", text, path.name)
            self.assertNotIn("inbound_token", text, path.name)

    def test_inbound_hmac_boundary_documented(self):
        self.assertIn("X-Hook-Signature", self.TRANSPORT)
        self.assertRegex(self.TRANSPORT, r"(?i)HMAC-SHA256[^.]*raw request body")
        self.assertRegex(self.TRANSPORT,
                         r"(?i)no\s+URL/query-token authentication and no fallback")

    def test_signing_shim_documented_as_ingress_path(self):
        self.assertIn("scripts/bluebubbles_ingress.py", self.TRANSPORT)
        self.assertRegex(self.TRANSPORT, r"(?i)binds \*\*loopback only\*\*")


class TestNoUnconditionalAllLocalClaims(unittest.TestCase):
    """Verifier-bounce-3 regression: no source file or operator doc may make
    an unconditional all-local claim — an explicitly configured owner alert
    relay / Discord mirror sends masked identity + message content
    off-machine, so every claim must be conditioned on the default config."""

    CLAIM = re.compile(
        r"(?is)\b(nothing|never)\b[^.]{0,120}\bleaves?\s+(the|your|this)\s+machines?\b")

    def claim_surfaces(self) -> list:
        # security/FABLE-XHIGH-REVIEW.md is excluded: it quotes the removed
        # false claims as review history. Tests are excluded: they contain
        # the forbidden pattern itself.
        paths = [REPO / "README.md", REPO / "AGENT_INSTALL.md",
                 REPO / "SECURITY.md", REPO / "THREAT-MODEL.md",
                 REPO / "ARCHITECTURE.md", REPO / "CONTRIBUTING.md",
                 REPO / "CHANGELOG.md", REPO / "security" / "README.md"]
        paths += sorted((REPO / "docs").glob("*.md"))
        paths += sorted((REPO / "src" / "receptionist").glob("*.py"))
        paths += sorted((REPO / "scripts").glob("*.py"))
        paths += sorted((REPO / "integrations" / "hermes").glob("*.py"))
        return paths

    def test_no_unconditional_all_local_claim_in_source_or_docs(self):
        surfaces = self.claim_surfaces()
        self.assertGreater(len(surfaces), 20, "claim surfaces not found")
        for path in surfaces:
            match = self.CLAIM.search(path.read_text())
            self.assertIsNone(
                match,
                f"unconditional all-local claim in {path.name}: "
                f"{match.group(0)[:80] if match else ''!r}")

    def test_app_module_claim_is_conditional_and_precise(self):
        app = (REPO / "src" / "receptionist" / "app.py").read_text()
        docstring = app.split('"""')[1]
        self.assertRegex(docstring, r"(?i)default configuration")
        self.assertRegex(docstring,
                         r"(?i)owner alert relay\s*/\s*Discord mirror")
        self.assertRegex(docstring, r"(?i)masked\s+contact\s+identities")
        self.assertRegex(docstring, r"(?i)Discord'?s?\s+servers")
        self.assertRegex(docstring, r"(?i)not end-to-end encrypted")


class TestCrossMachineLeastPrivilege(unittest.TestCase):
    """Verifier-bounce-3 regression: cross-machine ingress instructions must
    provision a dedicated mode-0600 JSON containing only `inbound_hmac_secret`
    and must never recommend copying the full secrets bundle off the
    receptionist host; the same-machine default stays the local secrets file."""

    TRANSPORT = (REPO / "docs" / "TRANSPORT.md").read_text()
    SHIM = (REPO / "scripts" / "bluebubbles_ingress.py").read_text()

    def test_transport_doc_requires_dedicated_single_key_file(self):
        self.assertRegex(self.TRANSPORT,
                         r"(?is)dedicated[^.]{0,80}mode.0600[^.]{0,80}only")
        self.assertIn('{ "inbound_hmac_secret":', self.TRANSPORT)
        self.assertRegex(
            self.TRANSPORT,
            r"(?i)never copy the full `secrets\.json` to another machine")
        self.assertRegex(self.TRANSPORT, r"(?i)least privilege")

    def test_shim_docstring_requires_dedicated_single_key_file(self):
        self.assertRegex(
            self.SHIM,
            r"(?is)dedicated mode.0600 JSON file\s+containing only\s+`inbound_hmac_secret`")
        self.assertRegex(self.SHIM,
                         r"(?is)never copy the\s+full `secrets\.json`")
        self.assertRegex(self.SHIM, r"(?i)least\s+privilege")

    def test_same_machine_default_preserved(self):
        self.assertRegex(self.TRANSPORT,
                         r"(?is)same machine the default is unchanged")
        self.assertRegex(
            self.SHIM,
            r"(?is)receptionist'?s own machine the default reads\s+"
            r"`inbound_hmac_secret` from the local `secrets\.json` in place")

    def test_no_full_bundle_copy_instruction_anywhere(self):
        # The historical instruction was "a mode-0600 copy of `secrets.json`";
        # no operator doc or the shim may instruct copying the full bundle.
        paths = [REPO / "README.md", REPO / "AGENT_INSTALL.md",
                 REPO / "SECURITY.md", REPO / "THREAT-MODEL.md",
                 REPO / "ARCHITECTURE.md",
                 REPO / "scripts" / "bluebubbles_ingress.py"]
        paths += sorted((REPO / "docs").glob("*.md"))
        for path in paths:
            self.assertNotRegex(path.read_text(),
                                r"(?is)copy of\s+`?secrets\.json`?",
                                path.name)


if __name__ == "__main__":
    unittest.main()
