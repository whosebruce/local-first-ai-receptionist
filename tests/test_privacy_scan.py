"""Regression tests for security/privacy_scan.py index and history modes.

The scanner must scan the EXACT Git index (`git show :<path>` bytes for every
index entry — not `git diff --cached`, which is empty right after a commit)
and the full reachable history (every blob reachable from any ref plus every
commit's author/committer identity and message). These tests build disposable
git repositories and prove that content visible only in the index, or only in
an earlier commit, is still caught.

They also prove the operator-local pattern mechanism: the scanner ships with
generic built-ins only, and an optional gitignored
`security/local-patterns.json` catches operator-specific labels in every mode
without those labels — or the patterns themselves — appearing in tracked
files or in any scan report output.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCANNER = REPO / "security" / "privacy_scan.py"

# Trigger values are assembled at runtime so that this test file itself stays
# clean under the very scanner it exercises.
PRIVATE_HOME_PATH = "/" + "home" + "/" + "alice" + "/private-notes"
PRIVATE_IPV4 = "10." + "20.30.40"
PERSONAL_EMAIL = "jane.doe" + "@" + "gmail.com"
BARE_ACCOUNT_MARKER = "whose" + "bru" + "ce"
PUBLIC_REPO_URL = "https://github.com/whosebruce/local-first-ai-receptionist"
PUBLIC_NOREPLY = "whosebruce@users.noreply.github.com"
# Another person's GitHub noreply identity: same provider domain, different
# username. Only the exact PUBLIC_NOREPLY identity may pass.
OTHER_NOREPLY = "mallory" + "@users.noreply." + "github.com"
# Link-local addresses, assembled so no raw 169.254/16 dotted-quad appears
# in this file: the metadata constant and an arbitrary neighbor.
LINK_LOCAL_PREFIX = "169.254"
METADATA_IP = f"{LINK_LOCAL_PREFIX}.{LINK_LOCAL_PREFIX}"
LINK_LOCAL_HOST = f"{LINK_LOCAL_PREFIX}.7.9"
# Synthetic stand-ins for an operator's private labels (vault/host/service
# names), assembled at runtime like the other trigger values so nothing
# label-shaped sits in this tracked file.
OPERATOR_VAULT_LABEL = "acme" + "-secret" + "-vault"
OPERATOR_HOST_LABEL = "acme" + "-internal" + "-host"
OPERATOR_REGEXES = [OPERATOR_VAULT_LABEL, OPERATOR_HOST_LABEL + "-[0-9]+"]


def check_counts(report: dict) -> dict:
    return {c["check"]: c["count"] for c in report["checks"]}


class GitRepoCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name)
        # Isolate from the host's global/system git config (signing, hooks).
        self.env = {**os.environ, "HOME": str(self.repo), "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q")
        self.git("config", "user.name", "Example Tester")
        self.git("config", "user.email", "tester@example.com")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *argv: str) -> None:
        subprocess.run(["git", "-C", str(self.repo), *argv],
                       check=True, capture_output=True, env=self.env)

    def write(self, name: str, content: str) -> None:
        (self.repo / name).write_text(content)

    def scan(self, *argv: str) -> dict:
        out_file = self.repo / "scan-report.json"
        proc = subprocess.run(
            [sys.executable, str(SCANNER), "--repo", str(self.repo),
             "--output", str(out_file), *argv],
            capture_output=True, text=True, env=self.env)
        report = json.loads(out_file.read_text())
        report["_exit_code"] = proc.returncode
        report["_raw_report_text"] = out_file.read_text()
        report["_stdout"] = proc.stdout
        report["_stderr"] = proc.stderr
        return report


class TestIndexScan(GitRepoCase):
    def test_full_index_scanned_when_nothing_newly_staged(self):
        # Regression: right after a commit `git diff --cached` is empty; the
        # index mode must still scan every index entry, not zero files.
        self.write("clean.txt", "loopback only: 127.0.0.1\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean")
        report = self.scan("--mode", "index")
        self.assertEqual(report["mode"], "index")
        self.assertGreaterEqual(report["files_scanned"], 1)
        self.assertTrue(report["all_pass"])
        self.assertEqual(report["_exit_code"], 0)

    def test_staged_flag_is_full_index_alias(self):
        self.write("clean.txt", "nothing private\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean")
        report = self.scan("--staged")
        self.assertEqual(report["mode"], "index")
        self.assertGreaterEqual(report["files_scanned"], 1)

    def test_index_only_content_is_caught(self):
        # Stage private content, then revert the working-tree copy so the
        # private bytes exist ONLY as the staged blob.
        self.write("clean.txt", "fine\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean")
        self.write("leak.txt", f"state at {PRIVATE_HOME_PATH}\n")
        self.git("add", "leak.txt")
        self.write("leak.txt", "nothing to see in the working tree\n")

        tree_report = self.scan("--mode", "working-tree")
        self.assertTrue(tree_report["all_pass"],
                        "working tree must look clean in this scenario")
        index_report = self.scan("--mode", "index")
        self.assertFalse(index_report["all_pass"])
        self.assertNotEqual(index_report["_exit_code"], 0)
        counts = check_counts(index_report)
        self.assertGreaterEqual(counts["home_absolute_path"], 1)
        locations = [c["locations"] for c in index_report["checks"]
                     if c["check"] == "home_absolute_path"][0]
        self.assertTrue(any(loc.startswith("leak.txt:") for loc in locations))


class TestHistoryScan(GitRepoCase):
    def test_removed_but_reachable_content_is_caught(self):
        self.write("leak.txt", f"gateway at {PRIVATE_IPV4}\n")
        self.git("add", "leak.txt")
        self.git("commit", "-q", "-m", "add")
        self.git("rm", "-q", "leak.txt")
        self.git("commit", "-q", "-m", "remove")

        self.assertTrue(self.scan("--mode", "working-tree")["all_pass"])
        self.assertTrue(self.scan("--mode", "index")["all_pass"])
        history_report = self.scan("--mode", "history")
        self.assertFalse(history_report["all_pass"])
        self.assertGreaterEqual(check_counts(history_report)["ipv4_non_doc"], 1)

    def test_commit_identity_and_message_are_scanned(self):
        self.write("clean.txt", "fine\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean",
                 "--author", f"Jane Doe <{PERSONAL_EMAIL}>")
        history_report = self.scan("--mode", "history")
        self.assertFalse(history_report["all_pass"])
        counts = check_counts(history_report)
        self.assertGreaterEqual(counts["email_non_doc"], 1)
        locations = [c["locations"] for c in history_report["checks"]
                     if c["check"] == "email_non_doc"][0]
        self.assertTrue(any(loc.startswith("commit:") for loc in locations))

    def test_neutral_noreply_identity_is_allowed(self):
        self.write("clean.txt", "fine\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean",
                 "--author", f"Bruce Works LLC <{PUBLIC_NOREPLY}>")
        self.assertTrue(self.scan("--mode", "history")["all_pass"])


class TestExactAllowlists(GitRepoCase):
    """Negative regressions for the verifier-bounce-2 tightening: only the
    exact public noreply identity and only loopback/RFC 5737 doc IPs pass."""

    def test_other_github_noreply_identity_is_a_finding(self):
        self.write("clean.txt", "fine\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean",
                 "--author", f"Mallory <{OTHER_NOREPLY}>")
        report = self.scan("--mode", "history")
        self.assertFalse(report["all_pass"],
                         "a different noreply username must not be allowlisted")
        counts = check_counts(report)
        self.assertGreaterEqual(counts["email_non_doc"], 1)
        locations = [c["locations"] for c in report["checks"]
                     if c["check"] == "email_non_doc"][0]
        self.assertTrue(any(loc.startswith("commit:") for loc in locations))

    def test_other_noreply_identity_in_file_body_is_a_finding(self):
        self.write("notes.md", f"thanks to <{OTHER_NOREPLY}> for the report\n")
        self.git("add", "notes.md")
        report = self.scan("--mode", "index")
        self.assertFalse(report["all_pass"])
        self.assertGreaterEqual(check_counts(report)["email_non_doc"], 1)

    def test_link_local_addresses_are_findings(self):
        self.write("infra.md",
                   f"metadata at {METADATA_IP}, neighbor {LINK_LOCAL_HOST}\n")
        self.git("add", "infra.md")
        for mode in ("working-tree", "index"):
            report = self.scan("--mode", mode)
            self.assertFalse(report["all_pass"],
                             f"{mode}: 169.254/16 must not be allowlisted")
            self.assertGreaterEqual(check_counts(report)["ipv4_non_doc"], 2, mode)

    def test_loopback_and_doc_ips_still_allowed(self):
        self.write("examples.md",
                   "hosts: 127.0.0.1, 192.0.2.7, 198.51.100.9, 203.0.113.5\n")
        self.git("add", "examples.md")
        self.git("commit", "-q", "-m", "examples")
        for mode in ("working-tree", "index", "history"):
            self.assertTrue(self.scan("--mode", mode)["all_pass"], mode)


class TestLocalPatternsFile(GitRepoCase):
    """Regressions for the verifier-bounce-5 correction: operator-specific
    private labels are never built into the scanner. They live in an optional
    gitignored security/local-patterns.json, which must catch operator labels
    in every mode without the labels (or the patterns) entering tracked files
    or scan reports."""

    def write_local_patterns(self, patterns) -> None:
        (self.repo / "security").mkdir(exist_ok=True)
        (self.repo / "security" / "local-patterns.json").write_text(
            json.dumps({"patterns": patterns}))

    def test_local_patterns_catch_operator_labels_in_all_modes(self):
        self.write_local_patterns(OPERATOR_REGEXES)
        self.write("infra.md",
                   f"notes live in {OPERATOR_VAULT_LABEL}\n"
                   f"deployed on {OPERATOR_HOST_LABEL}-07\n")
        self.git("add", "infra.md")
        self.git("commit", "-q", "-m", "infra")
        for mode in ("working-tree", "index", "history"):
            report = self.scan("--mode", mode)
            self.assertFalse(report["all_pass"], mode)
            self.assertNotEqual(report["_exit_code"], 0, mode)
            self.assertGreaterEqual(
                check_counts(report)["local_private_pattern"], 2, mode)
            locations = [c["locations"] for c in report["checks"]
                         if c["check"] == "local_private_pattern"][0]
            self.assertTrue(all("infra.md" in loc for loc in locations), mode)

    def test_labels_and_patterns_never_appear_in_report_output(self):
        self.write_local_patterns(OPERATOR_REGEXES)
        self.write("infra.md", f"vault: {OPERATOR_VAULT_LABEL}\n")
        self.git("add", "infra.md")
        report = self.scan("--mode", "index")
        self.assertFalse(report["all_pass"])
        for output in (report["_raw_report_text"], report["_stdout"],
                       report["_stderr"]):
            self.assertNotIn(OPERATOR_VAULT_LABEL, output)
            self.assertNotIn(OPERATOR_HOST_LABEL, output)
            for pattern in OPERATOR_REGEXES:
                self.assertNotIn(pattern, output)

    def test_local_patterns_file_itself_is_never_content_scanned(self):
        # The file's own pattern strings match themselves, so a clean result
        # proves the local file is excluded from content scanning.
        self.write_local_patterns(OPERATOR_REGEXES)
        self.write("clean.txt", "loopback only: 127.0.0.1\n")
        self.git("add", "clean.txt")
        self.git("commit", "-q", "-m", "clean")
        for mode in ("working-tree", "index", "history"):
            self.assertTrue(self.scan("--mode", mode)["all_pass"], mode)

    def test_missing_local_patterns_file_scans_with_builtins_only(self):
        self.write("clean.txt", "fine\n")
        self.git("add", "clean.txt")
        report = self.scan("--mode", "working-tree")
        self.assertTrue(report["all_pass"])
        self.assertEqual(report["_exit_code"], 0)

    def test_malformed_local_patterns_file_fails_closed(self):
        for bad in ('{not json', '{"patterns": []}', '{"patterns": ["("]}',
                    '{"patterns": "x"}', '{"nopatterns": ["x"]}'):
            with self.subTest(bad=bad):
                (self.repo / "security").mkdir(exist_ok=True)
                (self.repo / "security" / "local-patterns.json").write_text(bad)
                report = self.scan("--mode", "working-tree")
                self.assertFalse(report["all_pass"])
                self.assertNotEqual(report["_exit_code"], 0)
                self.assertEqual(
                    check_counts(report)["local_patterns_file_invalid"], 1)

    def test_tracked_local_patterns_file_is_a_finding(self):
        self.write_local_patterns(OPERATOR_REGEXES)
        self.git("add", "security/local-patterns.json")
        report = self.scan("--mode", "index")
        self.assertFalse(report["all_pass"])
        counts = check_counts(report)
        self.assertGreaterEqual(counts["local_patterns_file_tracked"], 1)
        # Flagged for presence, not content-scanned: its own patterns match
        # its own bytes, so zero here proves the content was not scanned.
        self.assertEqual(counts["local_private_pattern"], 0)
        self.git("commit", "-q", "-m", "oops")
        history = self.scan("--mode", "history")
        self.assertFalse(history["all_pass"])
        self.assertGreaterEqual(
            check_counts(history)["local_patterns_file_tracked"], 1)

    def test_shipped_example_is_valid_gitignored_and_synthetic(self):
        # The tracked template must parse, its regexes must compile, the real
        # local file path must be gitignored in this repository, and no
        # example placeholder may match any tracked file (proving the
        # placeholders are synthetic, not real labels).
        example = json.loads(
            (REPO / "security" / "local-patterns.example.json").read_text())
        patterns = example["patterns"]
        self.assertTrue(patterns)
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
        ignored = subprocess.run(
            ["git", "-C", str(REPO), "check-ignore", "-q",
             "security/local-patterns.json"], capture_output=True)
        self.assertEqual(ignored.returncode, 0,
                         "security/local-patterns.json must be gitignored")
        tracked = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z"],
            capture_output=True, check=True).stdout.decode().split("\0")
        for name in filter(None, tracked):
            if name == "security/local-patterns.example.json":
                continue  # the template necessarily contains its own patterns
            text = (REPO / name).read_text(errors="replace")
            for pattern in compiled:
                self.assertIsNone(pattern.search(text),
                                  f"{pattern.pattern} matched tracked {name}")


class TestPublicUrlCarveout(GitRepoCase):
    def test_carveout_is_exact(self):
        # The repository's own public URL is allowed; the same account marker
        # anywhere outside that exact URL / noreply identity is a finding.
        self.write("readme.md", f"clone from {PUBLIC_REPO_URL}\n")
        self.git("add", "readme.md")
        self.assertTrue(self.scan("--mode", "index")["all_pass"])

        self.write("notes.md", f"ping {BARE_ACCOUNT_MARKER} about this\n")
        self.git("add", "notes.md")
        report = self.scan("--mode", "index")
        self.assertFalse(report["all_pass"])
        self.assertGreaterEqual(
            check_counts(report)["account_marker_outside_public_exception"], 1)


if __name__ == "__main__":
    unittest.main()
