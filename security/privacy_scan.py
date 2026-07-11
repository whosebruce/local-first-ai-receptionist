#!/usr/bin/env python3
"""Deterministic privacy/secret scanner for the public tree.

Scans for private data that must never be published and writes a
machine-readable report to security/privacy-scan.json containing pass/fail
checks and ZERO secret values. Exit code is non-zero if any check fails.

Modes (--mode):
  working-tree  every file in the working tree (default)
  index         every file in the Git index, read as the exact staged bytes
                via `git show :<path>` — NOT `git diff --cached`, so the full
                index is scanned even when nothing is newly staged
  history       every blob reachable from any ref/commit in history, plus
                every reachable commit's author/committer identity and full
                message — catches content that was committed and later
                removed, and non-neutral commit identities
  all           all three of the above in one report

`--staged` is a deprecated alias for `--mode index` and scans the full index.

Allowlist policy: only clearly synthetic placeholders pass — loopback,
RFC 5737 documentation IPs, example.com/.org/.net, and obviously fake IDs
(the reserved fixture patterns used by the test suite). Link-local
(169.254/16) is NOT allowlisted. The only permitted real-world identifiers
are this repository's own public home
(github.com/whosebruce/local-first-ai-receptionist) and its exact
GitHub-provided noreply commit identity — not the noreply domain as a
whole. Any other match is a finding. Findings report file + line + a
category label only; the offending value itself is never written to the
report.

Built-in detectors are GENERIC only (home paths, non-documentation IPs,
emails/phones, platform IDs, secret shapes, binaries, and the exact
public-repo exceptions above). Operator-specific private labels — hostnames,
vault or ledger names, internal service names, task-ID prefixes — are never
embedded in this source: they belong in the optional, gitignored
`security/local-patterns.json` (case-insensitive regexes; see
`security/local-patterns.example.json`). When present it is applied in every
mode; it is never content-scanned itself; a malformed file fails the scan
closed; and its appearance in the Git index or reachable history is a
finding. This scanner has NO self-exemptions: every detector applies to
every scanned file, including this one.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_REPO = Path(__file__).resolve().parents[1]

# ---- allowlisted synthetic placeholders (documentation / fixtures) ----------
DOC_IPV4 = {
    # Loopback, RFC 5737 documentation ranges, unspecified, and broadcast
    # ONLY. Link-local (169.254/16) is deliberately NOT allowlisted: a
    # link-local literal can encode real local metadata/infrastructure, so
    # tests that need one must assemble it at runtime instead of embedding
    # a dotted-quad in the public tree.
    re.compile(r"^127\."), re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^192\.0\.2\."), re.compile(r"^198\.51\.100\."),
    re.compile(r"^203\.0\.113\."), re.compile(r"^255\.255\.255\.255$"),
}
# Obviously-fake fixture platform IDs contain a long run of zeros, which real
# (timestamp-derived) Discord snowflakes effectively never do. Used by the
# test fixtures and documentation examples.
FAKE_SNOWFLAKE = re.compile(r"0{8,}")
# Fictional phone range reserved for examples: +1 555 555 01XX.
FICTIONAL_PHONE = re.compile(r"^\+?1?555555\d{4}$")
DOC_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")

# The single intentionally-public exception set: the repository's own
# publication URL and its EXACT GitHub-provided noreply commit identity,
# which by construction contains no personal contact data. Only this one
# exact address is allowed — any other `users.noreply.github.com` identity
# would reveal a different person's GitHub username and is a finding, as is
# this account marker appearing anywhere outside these two exact strings.
PUBLIC_REPO_URL = "github.com/whosebruce/local-first-ai-receptionist"
PUBLIC_NOREPLY_EMAIL = "whosebruce@users.noreply.github.com"
# The bare account marker is DERIVED from the identifiers above (never kept
# as a separate literal); it may appear only inside those two exact strings —
# anywhere else it is a finding.
PUBLIC_ACCOUNT_MARKER = PUBLIC_NOREPLY_EMAIL.split("@", 1)[0]

# ---- detectors --------------------------------------------------------------
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")
SNOWFLAKE_RE = re.compile(r"(?<!\d)\d{17,20}(?!\d)")
HOME_PATH_RE = re.compile(r"/home/[A-Za-z0-9._-]+")
# High-entropy secret shapes: hex >=32, or key=value with a long token.
HEX_SECRET_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
ASSIGN_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|bearer|hmac|private[_-]?key)"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9+/_\-]{16,})[\"']?")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GIT_CRED_URL_RE = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")

# ---- operator-local private patterns (optional, never committed) ------------
# Operator-specific private labels are deliberately NOT built in: embedding
# them here would publish the very identifiers this scan exists to catch.
# Instead, an operator may provide security/local-patterns.json — a
# gitignored, local-only JSON file of case-insensitive regexes (a synthetic
# template ships as security/local-patterns.example.json). The file is
# optional; when present its patterns are applied to every scanned line in
# every mode. Matches are reported as category/file/line only — neither the
# pattern text nor the matched value is ever written to the report. The file
# itself is never content-scanned (it deliberately contains the operator's
# private labels), a present-but-unusable file fails the scan closed, and the
# file appearing in the Git index or reachable history is itself a finding.
LOCAL_PATTERNS_REL = "security/local-patterns.json"


def load_local_patterns(repo: Path) -> tuple[list, bool]:
    """Compile the optional operator-local pattern file.

    Returns (patterns, invalid). A missing file is fine — the scan simply
    runs with the generic built-ins. A file that exists but cannot be used
    (unreadable, malformed JSON, wrong shape, empty pattern list, or a regex
    that does not compile) returns invalid=True so every mode fails closed
    via `local_patterns_file_invalid` rather than silently scanning without
    the operator's patterns.
    """
    path = repo / LOCAL_PATTERNS_REL
    if not path.exists():
        return [], False
    try:
        raw = json.loads(path.read_text())["patterns"]
        if not isinstance(raw, list) or not raw or \
                not all(isinstance(p, str) and p.strip() for p in raw):
            raise ValueError("patterns must be a non-empty list of regex strings")
        return [re.compile(p, re.IGNORECASE) for p in raw], False
    except (OSError, ValueError, KeyError, TypeError, re.error):
        return [], True

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "rendered", "node_modules"}
# Binary/generated artifacts should not exist in the public tree at all.
BINARY_SUFFIXES = {".pyc", ".sqlite3", ".sqlite3-shm", ".sqlite3-wal", ".log",
                   ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip",
                   ".gz", ".tar", ".so", ".o", ".bin", ".key", ".pem"}


def _git(repo: Path, *argv: str) -> bytes:
    out = subprocess.run(["git", "-C", str(repo), *argv], capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"git {argv[0]} failed: {out.stderr.decode(errors='replace').strip()}")
    return out.stdout


# ---- content sources: (label, logical_path, content_bytes) ------------------
def iter_working_tree(repo: Path):
    for path in sorted(repo.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            rel = str(path.relative_to(repo))
            try:
                data = path.read_bytes()
            except OSError:
                data = None
            yield rel, rel, data


def iter_index(repo: Path):
    """Every file in the Git index, read as the exact staged blob bytes."""
    names = [n for n in _git(repo, "ls-files", "--cached", "-z").decode().split("\0") if n]
    for name in names:
        try:
            data = _git(repo, "show", f":{name}")
        except RuntimeError:
            data = None
        yield name, name, data


def iter_history(repo: Path):
    """Every blob reachable from any ref, plus commit identity/message text."""
    listing = _git(repo, "rev-list", "--objects", "--all").decode(errors="replace")
    candidates = {}
    for line in listing.splitlines():
        parts = line.split(" ", 1)
        sha = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        if sha and sha not in candidates:
            candidates[sha] = name
    if candidates:
        batch = subprocess.run(
            ["git", "-C", str(repo), "cat-file",
             "--batch-check=%(objectname) %(objecttype)"],
            input="\n".join(candidates).encode(), capture_output=True)
        for line in batch.stdout.decode(errors="replace").splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1] == "blob":
                sha = fields[0]
                logical = candidates[sha] or sha
                yield f"history:{sha[:12]}:{logical}", logical, _git(repo, "cat-file", "blob", sha)
    # Commit metadata: author/committer identities and the full message.
    raw = _git(repo, "log", "--all",
               "--format=%H%x00%an <%ae>%x00%cn <%ce>%x00%B%x01").decode(errors="replace")
    for record in raw.split("\x01"):
        record = record.strip("\n")
        if not record:
            continue
        sha, author, committer, message = record.split("\x00", 3)
        text = f"author {author}\ncommitter {committer}\n{message}"
        yield f"commit:{sha[:12]}", f"commit:{sha[:12]}", text.encode()


def _is_allowed_ipv4(value: str) -> bool:
    return any(pat.match(value) for pat in DOC_IPV4)


def _is_allowed_email(value: str) -> bool:
    # Documentation domains, or the one exact public noreply identity —
    # never the whole noreply domain, which would hide other usernames.
    lowered = value.lower()
    return lowered.split("@")[-1] in DOC_EMAIL_DOMAINS or lowered == PUBLIC_NOREPLY_EMAIL


def _is_allowed_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return bool(FICTIONAL_PHONE.match(("+" if value.strip().startswith("+") else "") + digits) or
                FICTIONAL_PHONE.match(digits))


def _is_allowed_snowflake(value: str) -> bool:
    # A long internal zero run marks the obviously-fake fixture IDs; real
    # timestamp-derived snowflakes effectively never contain one.
    return bool(FAKE_SNOWFLAKE.search(value))


def _public_exception_spans(line: str) -> list[tuple[int, int]]:
    lowered = line.lower()
    spans = []
    for allowed in (PUBLIC_REPO_URL, PUBLIC_NOREPLY_EMAIL):
        start = 0
        while True:
            i = lowered.find(allowed, start)
            if i < 0:
                break
            spans.append((i, i + len(allowed)))
            start = i + 1
    return spans


def scan_text(label: str, text: str, findings: list[dict],
              local_patterns: list) -> None:
    def add(category: str, lineno: int) -> None:
        findings.append({"category": category, "file": label, "line": lineno})

    for lineno, line in enumerate(text.splitlines(), 1):
        allowed_spans = _public_exception_spans(line)
        for value in IPV4_RE.findall(line):
            octets = value.split(".")
            if any(int(o) > 255 for o in octets):
                continue  # version string, not an IP
            if not _is_allowed_ipv4(value):
                add("ipv4_non_doc", lineno)
        for value in IPV6_RE.findall(line):
            if value.lower() not in ("::1",):
                add("ipv6", lineno)
        for value in EMAIL_RE.findall(line):
            if not _is_allowed_email(value):
                add("email_non_doc", lineno)
        for value in PHONE_RE.findall(line):
            if not _is_allowed_phone(value):
                add("phone_non_fiction", lineno)
        for value in SNOWFLAKE_RE.findall(line):
            if not _is_allowed_snowflake(value):
                add("platform_id_non_fake", lineno)
        if HOME_PATH_RE.search(line):
            add("home_absolute_path", lineno)
        for m in HEX_SECRET_RE.findall(line):
            # Allow obviously-constructed test placeholders like "k"*32 or
            # repeated single chars; a genuine secret is high-variety hex.
            if len(set(m.lower())) > 4:
                add("hex_secret", lineno)
        assign = ASSIGN_SECRET_RE.search(line)
        if assign:
            token = assign.group(2)
            placeholders = {"", "changeme", "test", "example", "yourtokenhere"}
            if token.lower() not in placeholders and len(set(token)) > 4 and \
                    not token.lower().startswith(("test-", "not-", "fake-", "your")):
                add("assigned_secret", lineno)
        if PEM_RE.search(line):
            add("private_key_block", lineno)
        if AWS_KEY_RE.search(line):
            add("aws_access_key", lineno)
        if GIT_CRED_URL_RE.search(line):
            add("git_credential_url", lineno)
        # The derived public account marker is permitted only inside the
        # exact public repo URL or the exact GitHub noreply identity.
        lowered = line.lower()
        start = 0
        while True:
            i = lowered.find(PUBLIC_ACCOUNT_MARKER, start)
            if i < 0:
                break
            if not any(i >= s and i + len(PUBLIC_ACCOUNT_MARKER) <= e
                       for s, e in allowed_spans):
                add("account_marker_outside_public_exception", lineno)
            start = i + 1
        for pattern in local_patterns:
            if pattern.search(line):
                add("local_private_pattern", lineno)


CATEGORIES = [
    "account_marker_outside_public_exception", "local_private_pattern",
    "local_patterns_file_invalid", "local_patterns_file_tracked",
    "email_non_doc", "phone_non_fiction",
    "ipv4_non_doc", "ipv6", "platform_id_non_fake", "home_absolute_path",
    "hex_secret", "assigned_secret", "private_key_block", "aws_access_key",
    "git_credential_url", "generated_or_binary_artifact",
    "unreadable_or_binary",
]


def run_mode(repo: Path, mode: str, local_patterns: list,
             patterns_invalid: bool) -> dict:
    sources = {"working_tree": iter_working_tree,
               "index": iter_index,
               "history": iter_history}[mode]
    findings: list[dict] = []
    if patterns_invalid:
        findings.append({"category": "local_patterns_file_invalid",
                         "file": LOCAL_PATTERNS_REL, "line": 0})
    count = 0
    for label, logical_path, data in sources(repo):
        if logical_path == LOCAL_PATTERNS_REL:
            if mode == "working_tree":
                # Operator-local config: gitignored, not part of the
                # publication surface, and never content-scanned (it
                # deliberately contains the operator's private labels; it is
                # also excluded from files_scanned for cross-host
                # comparability of reports).
                continue
            # …but staged or historically reachable copies are a leak.
            count += 1
            findings.append({"category": "local_patterns_file_tracked",
                             "file": label, "line": 0})
            continue
        count += 1
        suffix = Path(logical_path).suffix.lower()
        if suffix in BINARY_SUFFIXES:
            findings.append({"category": "generated_or_binary_artifact",
                             "file": label, "line": 0})
            continue
        if Path(logical_path).name == "privacy-scan.json":
            continue
        if data is None:
            findings.append({"category": "unreadable_or_binary", "file": label, "line": 0})
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append({"category": "unreadable_or_binary", "file": label, "line": 0})
            continue
        scan_text(label, text, findings, local_patterns)

    checks = []
    for category in CATEGORIES:
        hits = [f for f in findings if f["category"] == category]
        checks.append({
            "check": category,
            "pass": len(hits) == 0,
            "count": len(hits),
            "locations": [f"{h['file']}:{h['line']}" for h in hits[:50]],
        })
    return {
        "mode": mode,
        "files_scanned": count,
        "all_pass": all(c["pass"] for c in checks),
        "total_findings": len(findings),
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["working-tree", "index", "history", "all"],
                        default="working-tree",
                        help="working-tree (default), index (exact `git show :path` "
                             "bytes of every index entry), history (every reachable "
                             "blob + commit identities/messages), or all")
    parser.add_argument("--staged", action="store_true",
                        help="deprecated alias for --mode index (full index scan)")
    parser.add_argument("--repo", default=str(DEFAULT_REPO),
                        help="repository root to scan (default: this repo)")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    mode = "index" if args.staged else args.mode
    modes = ["working_tree", "index", "history"] if mode == "all" else [mode.replace("-", "_")]

    local_patterns, patterns_invalid = load_local_patterns(repo)
    reports = {m: run_mode(repo, m, local_patterns, patterns_invalid) for m in modes}
    if len(reports) == 1:
        body = next(iter(reports.values()))
        report = {"scanner": "privacy_scan.py", **body}
    else:
        report = {
            "scanner": "privacy_scan.py",
            "mode": "all",
            "all_pass": all(r["all_pass"] for r in reports.values()),
            "total_findings": sum(r["total_findings"] for r in reports.values()),
            "modes": reports,
        }

    out_path = Path(args.output) if args.output else repo / "security" / "privacy-scan.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    summary = {"all_pass": report["all_pass"], "total_findings": report["total_findings"],
               "mode": report["mode"]}
    for m, r in (reports.items() if len(reports) > 1 else []):
        summary[f"files_scanned_{m}"] = r["files_scanned"]
    if len(reports) == 1:
        summary["files_scanned"] = report["files_scanned"]
    print(json.dumps(summary))
    for r in reports.values():
        for check in r["checks"]:
            if not check["pass"]:
                print(f"FAIL [{r['mode']}] {check['check']} x{check['count']}: "
                      f"{check['locations'][:10]}", file=sys.stderr)
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
