# Contributing

Thanks for your interest. Ground rules keep this project trustworthy:

## Non-negotiable invariants

Pull requests that weaken any of these will be declined:

1. No code path may give an inbound contact access to tools of any kind.
2. Trust changes only through exact owner commands bound to lead ID + keyed
   fingerprint; never through message content, names, reactions, or model
   output.
3. Outbound sending stays behind the manual owner gate and disabled by
   default; installers/tests/agents must never enable it.
4. Model endpoints stay local-only (loopback default, LAN opt-in, globally
   routable refused in code). No external AI credentials, no telemetry.
5. Fail closed: new failure modes must reject/escalate, never pass through.
6. No raw contact identity at rest, in logs, or in thread/channel names.

## Practicalities

- Python 3.10+, standard library only for runtime code. New hard
  dependencies need a very good reason.
- Every behavior change needs a deterministic test; security-relevant changes
  need an abuse test (what does the attacker try, and why does it fail?).
- Run `./scripts/verify.sh` (all tests, network-guarded) and
  `python3 security/privacy_scan.py` before submitting; both must pass.
- Never include real phone numbers, emails, addresses, platform IDs, or
  secrets in code, tests, fixtures, or docs. Use the synthetic fixtures in
  `tests/helpers.py` (fictional 555-01XX numbers, example.com, and the
  obviously fake ID pattern) so the privacy scanner stays clean.
- Keep documentation claims precise; do not describe anything as "secure"
  without stating the boundary that makes it so.
