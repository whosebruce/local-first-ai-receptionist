# Changelog

## 1.0.0 — 2026-07-11

Initial public release.

- Tiered, tool-isolated receptionist: deterministic Tier 1, bounded no-tools
  Tier 2 with explicit promotion registry, keyed-fingerprint Tier 3.
- Temporary `tier2-test` cohort with sliding 24-hour inbound-only inactivity
  TTL, conservative cap, one-time disclosure, automatic downgrade.
- Fail-closed image pipeline: allowlisted types, metadata stripping,
  classification required before retention, quarantine with deterministic
  retention.
- iMessage tapback handling; reactions are never authorization.
- Optional local-Discord intake approvals and category/thread routing with
  replay-resistant correlations and exact command grammar.
- Local-only model client (loopback default, LAN opt-in, public refused).
- Owner-gated outbound (disabled by default), HMAC-SHA256 raw-body signatures
  on every internal webhook including the transport `/inbound` ingress (no
  URL/query-token authentication, no fallback), a loopback-only signing shim
  for HMAC-less transports such as BlueBubbles (cross-machine deployments
  provision a dedicated single-key mode-0600 secrets file — never a copy of
  the full bundle), locally generated secrets, hardened systemd template.
- Conditional, precise privacy claims everywhere — source docstrings
  included: default configuration is all-local; an explicitly configured
  owner alert relay / Discord mirror sends masked identities plus message
  content off-machine and is disclosed as such (regression-enforced).
- Version-pinned, fail-closed Hermes gateway overlay generator.
- 198 deterministic offline tests, including abuse/security and synthetic
  end-to-end suites, run under a no-network guard.
- Self-cleaning test fixtures: every fixture root is created through a
  cleanup-registered helper (removal runs on pass, failure, and error), so a
  full test or `scripts/verify.sh` run leaves zero temp-directory debris on
  the operator host — regression-enforced by re-running representative
  fixtures under an isolated temp root and asserting nothing survives.
- Deterministic privacy scanner covering the working tree, the exact Git
  index (`git show :<path>` bytes of every entry), and all reachable history
  including commit identities/messages, with regression coverage for
  index-only and history-only leaks and for the public-doc privacy claims.
  Allowlists are exact-and-synthetic only: loopback/RFC 5737 documentation
  IPs (link-local 169.254/16 excluded) and the repository's own clone URL
  plus its exact noreply commit identity (never the noreply domain as a
  whole), with negative regression tests. Built-in detectors are generic
  only and the scanner has no self-exemptions; operator-specific private
  labels live in an optional gitignored `security/local-patterns.json`
  (synthetic template shipped as `security/local-patterns.example.json`),
  applied in every scan mode with neither patterns nor matched values ever
  written to reports, failing closed on a malformed file, and reporting a
  tracked copy of the local file itself as a finding (regression-enforced).
- Hardened per an adversarial Fable xhigh review (see
  `security/FABLE-XHIGH-REVIEW.md`): fail-closed vision classification on model
  refusal/hedge, overlay substitution injection guard, image rate-limit
  charged on all paths, audit-trail redaction, link-local/unspecified/
  bind-all endpoint refusal, LAN-relay opt-in, owner-alert injection
  neutralization, request-token log masking, byte-safe HMAC verification,
  malformed Content-Length handling, no-echo owner enrollment, and
  symlink/mode-checked secret loading.
