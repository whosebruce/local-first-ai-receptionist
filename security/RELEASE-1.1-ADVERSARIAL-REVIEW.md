# Release 1.1 adversarial review

Date: 2026-07-15

Scope: standing-versus-temporary Discord approvals, reviewed contact replies,
transport source verification, the Hermes interception overlay, and delayed
owner seen-checks.

This review supplements the original Fable xhigh report. It does not claim a
formal security audit or certification.

## Security properties reviewed

1. A Discord approval changes trust only when the configured owner replies to a
genuine unresolved intake alert in the configured channel, mentions the bot,
and uses exact grammar.
2. Plain approval creates a standing grant; only an exact trailing `test`
creates the temporary cohort. Extra words and raw tier commands fail closed.
3. A reviewed contact reply requires exact `reply <message>` syntax plus the
configured owner and guild, a known bound thread, the correct category parent,
an active Tier-2 grant, and unchanged keyed fingerprint and chat bindings.
4. The reviewed body is transient. SQLite stores its SHA-256 digest and length,
not the body.
5. One command ID authorizes at most one send attempt. Replays are inert. An
unknown completion state instructs the operator to inspect source history and
never auto-retry.
6. A BlueBubbles send is not called verified until exact text, chat, timestamp,
from-me state, and returned message ID are read back from source history.
7. The gateway intercepts both intake commands and exact thread replies before
any LLM path. A hook failure swallows the candidate and reports a fail-closed
error.
8. Owner seen-checks are disabled by default, contain only the lead ID, masked
identity, and first-message category, never auto-approve, and are suppressed
after any recorded tier decision.

## Findings discovered and fixed during review

### Critical: rendered hook alone did not guarantee pre-LLM interception

The first implementation taught the rendered hook about `reply <message>`, but
the adapter insertion gate still recognized intake commands only. A thread
reply could therefore have bypassed the hook and reached the normal model path.

Fix: the dependency-free adapter gate now recognizes exact reply syntax in a
guild thread, including an optional bot mention, before loading the hook. The
render/apply test asserts the gate is present and the rendered module compiles.

### High: transport I/O held the shared SQLite lock

The first implementation kept the process-wide database lock during send and
source verification. A slow transport could have blocked unrelated inbound
processing.

Fix: authorization and command-ID claim occur under the lock; network I/O runs
outside it; final status is written under the lock. Concurrent replays remain
inert because the command ID is claimed before the lock is released.

### Medium: duplicate read-back could imply completion

A crash after authorization but before final status left a durable
`authorized` row. The initial duplicate message said the reply was accepted,
which could be mistaken for proof of delivery.

Fix: an unresolved authorization now reports completion as unknown, directs the
operator to inspect transport source history, and forbids automatic retry.

### Low: stub verification could match an earlier identical message

The test transport originally matched only chat and text.

Fix: stub records now include a unique synthetic message ID and verification
checks it when supplied, mirroring the real transport's binding.

## Executed evidence

- Complete offline suite under the repository's no-network guard: 211 tests.
- Reviewed-reply tests cover wrong owner, guild, parent, thread, category,
inactive lead, identity drift, chat drift, oversized body, replay, storage
minimization, HMAC authentication, source-verification failure, and one-attempt
behavior.
- Overlay tests cover interception rendering, compilation, fail-closed hook
errors, drift detection, rollback, forged routes, and thread-reply candidate
recognition.
- Privacy scanner covers working tree, exact Git index, and reachable history;
operator-specific indicators remain in the gitignored local pattern file.
- Release verification also requires a clean fresh public HTTPS clone after the
push.

## Residual risks

- A compromised configured owner account or local Discord bot can submit valid
commands; this design does not replace account security.
- Transport source APIs can be unavailable or inconsistent. The system reports
`sent_unverified` and refuses automatic retry, but an operator must resolve the
ambiguity manually.
- A process crash after the command-ID claim but before final status intentionally
fails closed. The reply may or may not have been sent; inspect the transport
source before deciding what to do.
- Enabling a secondary owner relay moves masked lead metadata to that configured
sink. The operator is responsible for its privacy and retention policy.
