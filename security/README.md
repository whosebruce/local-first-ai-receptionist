# Security artifacts

- `privacy_scan.py` — deterministic privacy/secret scanner. Scans for private
  data that must never be published and writes `privacy-scan.json` (pass/fail
  checks, zero secret values). Run it before every commit:

  ```bash
  python3 security/privacy_scan.py                 # working tree (default)
  python3 security/privacy_scan.py --mode index    # exact Git index: `git show :<path>` bytes of EVERY index entry
  python3 security/privacy_scan.py --mode history  # every reachable blob + commit identities/messages
  python3 security/privacy_scan.py --mode all      # all three in one report
  ```

  The index mode reads the full index, not `git diff --cached`, so it scans
  every entry even right after a commit (`--staged` remains as a deprecated
  alias for it). The history mode catches content that was committed and
  later removed, and non-neutral commit identities. Regression coverage lives
  in `tests/test_privacy_scan.py`.

  Exit code is non-zero if any check fails. Only clearly synthetic
  placeholders are allowlisted (loopback, RFC 5737 documentation IPs,
  example.com/.org/.net, and obviously-fake fixture IDs — link-local
  169.254/16 is deliberately not allowlisted), plus exactly two
  intentionally public identifiers: this repository's own clone URL and its
  exact GitHub-provided noreply commit identity (never the noreply domain
  as a whole, which would hide other usernames; no personal contact data).
  Tests that need a link-local or foreign-noreply value assemble it at
  runtime so the tree itself stays clean.

  Built-in detectors are generic only: home paths, non-documentation IPs,
  emails/phones, platform IDs, secret shapes, binary/generated artifacts,
  and the two exact public-repo exceptions above (whose bare account marker
  is derived from them, never kept as a separate literal). The scanner has
  no self-exemptions — every detector applies to every scanned file,
  including the scanner's own source, which by design contains no private
  labels to exempt.

- `local-patterns.example.json` — template for operator-specific detection.
  Operator-private labels (internal hostnames, note-vault or ledger names,
  internal service names, task-ID prefixes) are never embedded in the
  committed scanner: publishing detector patterns would publish the very
  identifiers the scan exists to catch. Copy the template to
  `security/local-patterns.json` (gitignored — never commit it) and replace
  the synthetic placeholders with your own case-insensitive regexes. When
  present, the file is applied in every scan mode; matches are reported as
  category/file/line only (neither patterns nor matched values are ever
  written to a report); the file itself is never content-scanned; a
  malformed file fails the scan closed; and the file appearing in the Git
  index or reachable history is itself reported as a finding
  (`local_patterns_file_tracked`). Regression coverage:
  `tests/test_privacy_scan.py::TestLocalPatternsFile`.

- `privacy-scan.json` — the latest machine-readable scan report.

- `FABLE-XHIGH-REVIEW.md` — the adversarial vulnerability/privacy review
  (threat surfaces, findings, severity, fixes applied, residual risks, and
  exact test evidence).

See `../SECURITY.md` and `../THREAT-MODEL.md` for the overall posture.
