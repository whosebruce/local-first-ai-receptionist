# Fable 5 (xhigh) Adversarial Vulnerability & Privacy Review

**Target:** `local-first-ai-receptionist` public package (this repository)
**Reviewer:** Claude Fable 5 at `xhigh` reasoning effort, with four independent
Fable-class adversarial sub-reviews, one per surface (authorization/trust,
prompt-injection/tool-isolation, image/privacy/data-at-rest, and
config/network/secrets/overlay).
**Method:** read every source and test file; construct concrete exploit inputs
per surface; separate real exploitable bugs from defense-in-depth gaps; apply
fixes; add regression tests; re-verify. Passing unit tests were **not** treated
as proof of security — every guarantee was attacked directly.

This review does not call the project secure. It documents what was attacked,
what broke, what was fixed, and what residual risk remains.

## Summary

- **No path was found for a non-owner (an attacker with no local secret) to
  cause a trust change, resolve an approval, obtain any tool/agent capability,
  exfiltrate data to an external service, or send to a real contact.** The core
  isolation and authorization design held under adversarial input.
- Fourteen issues were found and fixed: **1 HIGH**, **3 MEDIUM**, **10 LOW**
  (plus several defense-in-depth hardenings). None of the HIGH/MEDIUM issues was
  a remote non-owner escalation; the HIGH was a fail-open in the image
  classifier gate, and the MEDIUMs were an overlay code-injection via a
  local config value, an image rate-limit bypass, and raw sensitive content
  persisting in the local audit trail.
- Test count grew from 134 to **150** (all passing, offline, under a network
  guard that fails any non-loopback connection). The deterministic privacy scan
  reports **0 findings** across the staged tree.

## Threat surfaces examined

1. **Authorization / trust state** — owner recognition, iMessage admin
   commands, Discord intake approvals, correlations, replay, fingerprints, TTL,
   cohort cap, group/DM paths.
2. **Prompt injection / tool isolation / model** — Tier-2 pre-model guards,
   the local model client, outbound gate, relay envelope, SSRF.
3. **Image / privacy / data-at-rest** — sanitization, fail-closed
   classification, quarantine, retention, metadata stripping, type confusion.
4. **Config / network / secrets / HTTP / overlay** — bind validation, HMAC,
   secret handling, the HTTP surface, and the Hermes overlay generator.

## Findings, severity, and fixes

### HIGH

**H1 — Sensitive image retained when the vision model refuses or hedges
(fail-open classifier gate).**
The retain/delete decision only treated an image as sensitive if the model
output began with the exact token `SENSITIVE` or matched a keyword/digit-run
regex. A safety-tuned local vision model that *refuses* ("I can't describe this
document for privacy reasons") or *hedges* ("this appears to be a personal
document") returned a non-empty, keyword-free description, so the sensitive
image was written to quarantine and its description relayed — violating the
stated "retained only after an explicit non-sensitive classification" contract.
*Fix:* inverted the protocol to fail closed. The vision prompt now requires an
affirmative `SAFE: <description>` for ordinary photos and `SENSITIVE` for
anything sensitive **or** any refusal/uncertainty; `_describe_image` returns
the description only for a `SAFE:` reply and returns `None` (→ delete +
escalate) for anything else. As a second layer, `is_sensitive_description`
now also flags refusal/uncertainty/document vocabulary, so even a raw
description path fails closed.
*Files:* `src/receptionist/app.py` (`_describe_image`),
`src/receptionist/images.py` (`UNCERTAIN_DESC_RE`, `is_sensitive_description`).
*Tests:* `test_security_hardening.TestImageFailClosed.test_model_refusal_or_hedge_not_retained`.

### MEDIUM

**M1 — Overlay `state_dir` → code injection into the Hermes gateway.**
`render_overlay.validate_substitutions` sanitized the channel ID, host, and
port but spliced `state_dir` verbatim into a Python string literal
(`Path("{{RECEPTIONIST_STATE_DIR}}")`) in the rendered hook. A crafted
`config.json` `state_dir` containing a quote + newline could inject arbitrary
Python that executes when the gateway imports the hook. Requires write access to
the config passed to `render` (operator-owned), capping severity at MEDIUM, but
it is a clean validation-bypass-to-RCE.
*Fix:* every substitution value is now rejected if it contains a quote,
backslash, or control character before it can reach a rendered literal.
*File:* `integrations/hermes/render_overlay.py`.
*Test:* `test_security_hardening.TestOverlayInjection.test_malicious_state_dir_refused`.

**M2 — Image per-day rate limit bypassed on every early-return path.**
The daily image counter was incremented only on the fully successful tail, so a
promoted contact who always tripped the sensitive/unverified/error branches
could drive unbounded fetch + sanitize + vision compute without ever consuming
the quota.
*Fix:* the quota is now charged for the whole batch immediately after the rate
check, before any branching.
*File:* `src/receptionist/tier2.py` (`handle_images`).
*Test:* `test_security_hardening.TestImageFailClosed.test_rate_limit_charged_on_sensitive_path`.

**M3 — Raw sensitive content persisted unredacted in the local audit trail.**
Refused messages and sensitive image captions were written verbatim (to 120–200
chars) into `tier2_audit.detail`, contradicting the "no raw PII at rest" stance
— including the caption path that had *just detected* the content was sensitive.
*Fix:* added `identity.redact_audit` (masks phones, emails, long digit runs, and
long hex tokens) and applied it to all Tier-2 audit detail.
*Files:* `src/receptionist/identity.py`, `src/receptionist/tier2.py`.
*Tests:* `test_security_hardening.TestAuditRedaction.*`.

### LOW

**L1 — `0.0.0.0` / `::` bindable with the LAN opt-in.** The unspecified
address classifies as private, so `allow_private_lan_bind: true` would permit
binding all interfaces (public exposure). *Fix:* refuse unspecified addresses in
`_validate_host` unconditionally. *Test:*
`test_identity_and_config.test_bind_all_interfaces_refused_even_with_opt_in`.

**L2 — Link-local / metadata / unspecified model endpoints accepted as "LAN".**
The 169.254/16 cloud-metadata address and `0.0.0.0` classify as private, so
with `allow_private_lan: true` a model/vision endpoint could point at them.
*Fix:* reject `is_link_local`/`is_unspecified` in both
`config._validate_local_endpoint` and `LocalModelClient._host_allowed`.
*Tests:* `test_security_hardening.TestNetworkGuards.*`.

**L3 — Relay URL egress to any LAN host with no opt-in.** Unlike listen/model
endpoints, `relay_url` accepted any RFC-1918 target (and `0.0.0.0`) with no
explicit acknowledgement, sending the owner alert (which quotes the contact's
message) off the loopback boundary silently. *Fix:* a non-loopback relay now
requires `allow_private_lan_relay: true`, and unspecified is refused. *Test:*
`test_security_hardening.TestNetworkGuards.test_relay_lan_requires_opt_in`.

**L4 — Owner-alert content injection.** The contact's message was interpolated
raw into a newline-structured alert, so injected text could forge
trusted-looking `ESCALATION:` / `ACTION FOR OWNER:` lines, and `@everyone` /
markdown could render live in a markdown sink. *Fix:* `_quote_untrusted`
collapses control chars/newlines and defuses mass-mentions before interpolation.
*Tests:* `test_security_hardening.TestAlertInjection.*`.

**L5 — Inbound bearer token logged in the request line.** The
`/inbound?token=<secret>` query was written to the local log because the
redactor only stripped phone/email. *Fix:* the HTTP `log_message` now masks
`token=…`. *File:* `src/receptionist/app.py`.
*(Superseded by the verifier-bounce-2 correction below: URL query-token
authentication has been removed entirely — `/inbound` now requires a raw-body
HMAC signature header and refuses any `token=` query parameter outright. The
log masking remains as defense in depth against misconfigured callers.)*

**L6 — Non-ASCII `X-Hook-Signature` raised (pre-auth 500).** `verify()`
compared two `str`; a non-ASCII header raised `TypeError`. *Fix:* compare as
bytes so it fails closed. *Test:*
`test_security_hardening.TestHmacNonAscii.test_non_ascii_signature_returns_false`.

**L7 — Malformed/negative `Content-Length` DoS.** `int(...)`/`read(length)`
were unguarded: a bad value raised (500) and `-1` blocked a worker on
`read(-1)`. *Fix:* parse defensively; reject non-positive/oversized. *Test:*
`test_security_hardening.TestHttpBodyGuard.*`.

**L8 — `--add-tier3` raw address via argv.** The owner address was a CLI
argument, exposing it in the process table and shell history. *Fix:* the value
is now optional and read from a no-echo prompt; passing it on the command line
warns. *File:* `scripts/generate_secrets.py`.

**L9 — Address-less inbound collapsed to a shared `"unknown"` fingerprint.**
An event with no address fingerprinted to `HMAC("unknown")`, so all anonymous
senders shared a bucket (over-block risk). *Fix:* `contact_fingerprint` returns
`""` for a blank/unknown address (fail closed — no shared bucket, no owner
match), and `handle_inbound` passes an empty sender when no address is present.
*Test:* `test_security_hardening.TestAddressLessSender.*`.

**L10 — Secret loader followed symlinks; rendered hooks skipped the mode
check.** `load_secrets_file` used `stat` (following symlinks) and the rendered
Hermes hooks read `secrets.json` with a bare `read_text()`. *Fix:* the loader
now `lstat`s and refuses a symlink; the rendered hook templates refuse a
group/world-accessible secrets file. *Tests:*
`test_security_hardening.TestSecretLoader.*`.

Also hardened during review (defense-in-depth): the cohort-cap check-then-act
and all handler entry points are now serialized under the shared re-entrant DB
lock (removing a promotion race under the threaded server); the Discord
fingerprint-mismatch guard now also rejects a now-empty identity; the overlay
`apply` validates the snippet path stays inside the templates dir and writes
each target via temp-file + atomic rename; a decompression-bomb dimension guard
was added to the pure-stdlib image sanitizer; and the Tier-2 injection guard
gained roleplay/override/pretend patterns while its admin-command branch was
tightened to real command shapes (removing false-positive refusals on ordinary
prose like "block out some time").

## Confirmed clean (attacked, held up)

- **Tool isolation:** no `tools` field is ever sent to the model; model output
  is used only as reply wording and can never change state, promote, block, or
  pay. A contact cannot reach the model without a prior exact owner promotion
  bound to lead ID + keyed fingerprint.
- **No non-owner trust change** via iMessage or Discord; nine Discord rejection
  classes (forged/cross-channel/resolved reference, wrong user/channel, DM,
  group, no mention, `approve all`, replay) all fail closed. **Historical
  note:** this initial review covered temporary-only Discord approvals. The
  later standing/default + explicit-`test` behavior and reviewed-reply path are
  covered by the current regression suite and threat model; unblock remains
  unreachable through Discord.
- **Replay/resolve-once:** inbound dedupe by event ID, command-message
  idempotency, atomic single-alert claim, `INSERT OR IGNORE` reactions, and
  idempotent expiry all hold; an expired grant cannot be resurrected.
- **No contact-controlled SSRF/exfiltration:** every outbound URL is
  config-derived and validated local (loopback default; LAN opt-in; global,
  link-local, unspecified, DNS-name, IPv6-bracket, and `userinfo@host` all
  refused).
- **Outbound owner gate:** with `outbound.enabled` false, a real transport is
  never constructed and `send_reply` short-circuits; tests inject stubs and run
  under a network guard.
- **Image type safety:** polyglots are neutralized (bytes after JPEG EOI / PNG
  IEND dropped), magic-vs-MIME enforced, archives/scripts/documents never
  fetched or executed, QR/URLs never decoded, no path traversal in quarantine
  filenames, and length parsing is fully bounds-checked.
- **Secrets:** `write_secrets_file` refuses overwrite (`O_EXCL`), `0600` cannot
  be widened by umask, no secret value is logged or printed anywhere (only field
  names appear), and there is no `eval`/`exec`/`os.system`/`shell=True` in the
  codebase.
- **Overlay:** anchor-must-be-unique, sha256 drift check, double-apply guard,
  unresolved-placeholder fail-closed, all-or-nothing staging, and byte-exact
  rollback are correct and test-covered.

## Residual risks (accepted, documented)

1. **Vision classifier is a best-effort screen.** H1's fix fails closed on
   refusal/hedge and requires an affirmative `SAFE:`, but a model that
   *confidently and incorrectly* describes a sensitive document as an ordinary
   photo could still retain it for up to the retention window. The digit-run and
   keyword backstops reduce, not eliminate, this. Operators handling regulated
   data should leave the vision endpoint unconfigured (image handling then never
   downloads anything).
2. **`inbound_hmac_secret` possession = local owner impersonation.** The
   `/inbound` webhook authenticates the transport (raw-body HMAC), not the
   sender: anyone holding the local signing secret — or with code execution on
   the loopback of the machine running the signing shim — can post a validly
   signed event with a spoofed sender field and reach the owner admin path.
   This is the intended local-transport trust boundary; keep the secret 0600,
   the shim loopback-only (enforced in code), and the listener
   loopback/LAN-only.
3. **A compromised local model** can shape Tier-2 reply *wording* (never
   actions), bounded by the reply cap, category policy, and owner relay of every
   exchange.
4. **systemd egress restriction** (`IPAddressDeny=any`) is enforced only where
   cgroup-v2 + eBPF is available; on hosts without it the filter is a no-op, so
   "denies all egress except loopback" is not guaranteed by the unit alone —
   the in-code local-only endpoint validation is the primary control.
5. **Pillow-absent stdlib path** strips real camera EXIF/GPS (always APP1) but
   keeps non-APP structural segments verbatim; an attacker embedding their own
   bytes in a spoofed structural segment could smuggle text past the stdlib
   path. Installing Pillow adds a full re-encode that removes it. The new
   dimension guard closes the decompression-bomb vector on both paths.
6. **Same-host local attacker** with full account access defeats file-mode
   protections; disk encryption and account hygiene are the mitigation.
7. **Discord content is visible to Discord**; mirrored alerts carry masked
   identities and quoted (now newline-neutralized) message text.

## Test evidence

```text
$ RECEPTIONIST_TEST_NETGUARD=1 python3 -m unittest discover -s tests -t .
Ran 198 tests in ~13s
OK

$ python3 security/privacy_scan.py
{"all_pass": true, "total_findings": 0, "mode": "working_tree", "files_scanned": 60}

$ python3 security/privacy_scan.py --mode index    # exact `git show :<path>` bytes of every index entry
{"all_pass": true, "total_findings": 0, "mode": "index", "files_scanned": 60}

$ python3 security/privacy_scan.py --mode history  # every reachable blob + commit identities/messages
{"all_pass": true, "total_findings": 0, "mode": "history", "files_scanned": 61}
```

All fixes above ship with the regression tests named beside them; the network
guard proves the suite makes no non-loopback connection, so no test contacts a
real person, transport, model, or SaaS.

## Verifier-bounce corrections (2026-07-11)

The independent verifier bounced five release blockers before any upload; all
are fixed and regression-tested:

1. **Precise privacy claim.** The README's unconditional "nothing about your
   contacts ever leaves your machines" was false with the optional Discord
   mirror enabled (masked identity + message content go to Discord's
   servers). The claim now states exactly that. Regression:
   `tests/test_public_docs.py`.
2. **No owner PII into agent chat.** `AGENT_INSTALL.md` no longer asks the
   agent to collect the owner's phone/email; Tier-3 enrollment is owner-typed
   at the local no-echo prompt, and an address pasted into chat must be
   refused, not used. Regression: `tests/test_public_docs.py`.
3. **Exact index + reachable-history scanning.** `--staged` previously
   walked `git diff --cached`, which is empty right after a commit (it
   reported `files_scanned: 0`). The scanner now reads the exact staged
   bytes of every Git index entry (`--mode index`) and every reachable
   history blob plus commit identities/messages (`--mode history`).
   Regression: `tests/test_privacy_scan.py` proves index-only and
   history-only content is caught.
4. **Object-database hygiene.** Ignored `__pycache__` artifacts removed from
   the worktree; reflog expired and all unreachable objects pruned so
   `git fsck --full` reports no dangling objects and no pre-scrub revision
   can accompany a mirror/bundle.
5. **Real public URLs and neutral authorship.** Placeholder Hermes link
   replaced with the real NousResearch hermes-agent URL, the actual public
   clone URL set, and the commit author rewritten to the neutral
   `Bruce Works LLC` GitHub-noreply identity (no personal contact data).

## Verifier-bounce #2 corrections (2026-07-11)

The independent verifier's final source review found two further release
blockers; both are fixed and regression-tested:

1. **`/inbound` now enforces the promised raw-body HMAC boundary — the URL
   bearer token is gone with no fallback.** `security.py` promised every
   internal webhook was HMAC-SHA256-authenticated over the raw body, but
   `/inbound` still accepted a bearer secret in the URL query
   (`?token=…`), which leaks into proxy/access-log history and is not a
   body-integrity signature. `/inbound` now requires an HMAC-SHA256
   signature over the exact raw request body in `X-Hook-Signature`, keyed
   with the renamed `inbound_hmac_secret`; missing, non-ASCII, or
   wrong-for-these-bytes signatures → 401 with no state change, and a
   replayed signed body authenticates but is deduplicated by event ID.
   Query-token authentication is refused outright (a `token=` parameter →
   400 even alongside a valid signature), and the now-unused
   `constant_time_equals` helper was removed. The practical BlueBubbles
   ingress path is `scripts/bluebubbles_ingress.py`: a standalone,
   stdlib-only signing shim that binds loopback ONLY (enforced in code, no
   LAN option — the unsigned hop never crosses a network), signs the exact
   raw bytes, forwards them unmodified, validates its forward target with
   the same local-endpoint policy as the service, drops incoming query
   strings, and fails closed on symlinked/group-accessible secrets.
   Docs updated: `docs/TRANSPORT.md`, `THREAT-MODEL.md`, `ARCHITECTURE.md`,
   `docs/UNINSTALL-RECOVERY.md`, `docs/OPERATOR-GUIDE.md`, `CHANGELOG.md`.
   *Regression tests:* `test_app.TestHTTPLayer.test_inbound_requires_raw_body_hmac`,
   `.test_inbound_tampered_body_rejected`,
   `.test_inbound_query_token_fallback_removed`,
   `.test_inbound_replayed_signed_body_is_inert`,
   `test_ingress.*` (exact-byte signing, shim-not-a-bypass end-to-end,
   loopback-only listen, forward-URL policy, secrets fail-closed),
   `test_public_docs.TestTransportHmacDocs.*` (no query-token instructions
   in any operator doc), and the updated
   `test_security_hardening.TestHttpBodyGuard`.

2. **Privacy-scanner allowlists tightened to exact/synthetic-only.**
   `_is_allowed_email` accepted any `@users.noreply.github.com` address,
   which could hide a different person's GitHub username; it now accepts
   only the exact public repository identity. `DOC_IPV4` allowlisted all of
   link-local `169.254/16`, which could hide real local
   metadata/infrastructure addresses; the allowlist is now
   loopback/RFC 5737/unspecified/broadcast only. Link-local test constants
   in `test_security_hardening.py`, `test_ingress.py`, and
   `test_privacy_scan.py` are assembled at runtime so no raw 169.254/16
   dotted-quad appears anywhere in the tree, and the remaining prose
   references use the CIDR form.
   *Regression tests:* `test_privacy_scan.TestExactAllowlists.*` — a
   foreign noreply identity is a finding both as a commit author and in a
   file body; link-local addresses are findings in working-tree and index
   modes; loopback/RFC 5737 documentation IPs still pass in all modes.

## Verifier-bounce #3 corrections (2026-07-11)

The independent verifier's final documentation/least-privilege review found
two further release blockers; both are fixed and regression-tested:

1. **Source-level privacy claim made conditional and precise.** The
   `src/receptionist/app.py` module docstring still claimed "nothing leaves
   the machine except transport replies," contradicting the README: an
   explicitly configured owner alert relay / Discord mirror also sends
   masked contact identities plus message content off-machine (Discord's
   servers process and store mirrored content; permission-private, not
   end-to-end encrypted). The docstring now states exactly that, and an
   equivalent unconditional claim in `docs/UNINSTALL-RECOVERY.md` ("Nothing
   about your contacts leaves the machine") was rewritten to the same
   conditional form with mirror-cleanup guidance.
   *Regression tests:* `test_public_docs.TestNoUnconditionalAllLocalClaims.*`
   — a deterministic pattern scan over every Python source file and operator
   doc rejects any unconditional "nothing/never leaves the/your/this
   machine(s)" claim, and the `app.py` docstring must carry the conditional
   disclosure (default configuration, relay/mirror named, masked identities,
   Discord's servers, not end-to-end encrypted).

2. **Cross-machine ingress provisioning reduced to least privilege.**
   `docs/TRANSPORT.md` and the `scripts/bluebubbles_ingress.py` docstring
   told cross-machine operators they could copy the full `secrets.json` to
   the transport host, needlessly exposing `relay_hmac_secret`,
   `discord_hook_secret`, `contact_hash_key`, and any `transport_password`.
   Both now require a **dedicated** mode-0600 JSON file containing **only**
   `inbound_hmac_secret` (created under `umask 077`, transferred over an
   authenticated channel) and state explicitly that the full bundle must
   never be copied off the receptionist host — a compromise of the
   transport host must cost only the one inbound signing key. The
   same-machine default is unchanged: the shim reads the local
   `secrets.json` in place. No shim code change was needed —
   `test_ingress.test_secrets_file_fails_closed` already proves a
   single-key mode-0600 file loads (and fails closed on mode/symlink).
   *Regression tests:* `test_public_docs.TestCrossMachineLeastPrivilege.*`
   — the dedicated single-key instruction and least-privilege note must be
   present in both surfaces, the same-machine default must be documented
   unchanged, and no operator doc or the shim may reintroduce a
   "copy of `secrets.json`" instruction.

## Verifier-bounce #4 corrections (2026-07-11)

The independent verifier's controlled before/after temp audit found one
further release blocker; it is fixed and regression-tested:

1. **Test fixtures no longer leak temp directories.** One full test run left
   44 `tempfile.mkdtemp()` fixture roots behind in the system temp directory
   (`receptionist-test-*`, `ingress-secrets-*`, `overlay-test-*`; further
   runs also accumulated `tier2-test-*`, `discord-test-*`, and `gate-test-*`
   roots), so every installer/verify run polluted the operator host and disk
   usage could grow without bound. Every fixture root is now created through
   `tests/helpers.make_temp_dir`, which registers removal with
   `addCleanup`/`addClassCleanup` — unittest runs these callbacks on every
   outcome, so cleanup covers failure and error paths too. The
   `make_receptionist`/`make_manager` helpers now *require* the calling test
   case, so no future call site can silently opt out of cleanup, and the two
   remaining raw `mkdtemp` fixtures (`test_overlay`, `test_discord_routing`)
   were converted to the same helper. All synthetic leftovers from prior
   runs were purged, and an independent before/after audit of the system
   temp directory around a full suite run now records zero new entries.
   *Regression tests:* `test_temp_hygiene.TestNoTempArtifactsLeaked.*` —
   representative tests covering every fixture shape (instance- and
   class-level receptionist fixtures, each project prefix, multi-dir tests,
   quarantine writes) are re-run under an isolated temp root that must be
   completely empty afterwards; a deliberately failing case proves fixture
   roots are removed on failure paths; and a mechanism guard proves fixture
   roots honor the configured temp root, so the isolated-root audit is
   meaningful.

## Verifier-bounce #5 corrections (2026-07-11)

The independent verifier's private-indicator scan found one further release
blocker; it is fixed and regression-tested:

1. **The privacy scanner no longer publishes the private labels it detects,
   and no longer exempts itself from anything.** The committed scanner
   embedded operator-private infrastructure labels (note-vault, task-ledger,
   host, and service names) as a built-in detector regex, and exempted its
   own file from the resulting finding category — publishing in the public
   tree the very identifiers the scan exists to catch. Built-in detectors
   are now generic only (home paths, non-documentation IPs, emails/phones,
   platform IDs, secret shapes, binary/generated artifacts); the bare public
   account marker is derived at runtime from the two exact public-repo
   identifiers rather than kept as a literal; and every operator-specific
   label was removed from the scanner source, tests, docs, the Git index,
   and reachable history (the amended single commit was re-pruned so no
   pre-fix blob survives). Operator-specific detection moved to an optional
   `security/local-patterns.json` — gitignored, local-only, case-insensitive
   regexes, with a synthetic template shipped as
   `security/local-patterns.example.json`. The local file is applied in
   every scan mode; matches are reported as category/file/line only (neither
   patterns nor matched values are ever written to a report); the file
   itself is never content-scanned; a malformed local file fails the scan
   closed (`local_patterns_file_invalid`); and the local file appearing in
   the Git index or reachable history is itself a finding
   (`local_patterns_file_tracked`). The scanner now has NO self-exemptions:
   every detector applies to every scanned file, including the scanner's own
   source, which by design contains nothing to exempt.
   *Regression tests:* `test_privacy_scan.TestLocalPatternsFile.*` —
   runtime-assembled operator-label stand-ins are caught by a local patterns
   file in working-tree, index, and history modes; neither the labels nor
   the patterns appear in any report output (JSON, stdout, stderr); the
   local file itself is never content-scanned; a missing file scans with
   built-ins only; malformed files (bad JSON, empty/typed-wrong/uncompilable
   patterns) fail closed; a tracked or historically reachable copy of the
   local file is a finding; and the shipped example template must parse,
   compile, be gitignored at the real path, and match nothing in any tracked
   file. `TestPublicUrlCarveout` continues to prove the derived bare account
   marker is a finding anywhere outside the two exact public identifiers.
