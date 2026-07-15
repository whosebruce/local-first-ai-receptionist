# Threat Model

The receptionist sits between untrusted strangers (anyone who can text a
public number) and things worth protecting: the owner's attention, private
information, money-adjacent decisions, and the owner's broader agent stack.

## Assets

1. Trust state (who is Tier 2/3; who is blocked)
2. The owner's private data (location, schedule, contacts, business data)
3. Outbound capability (the power to message people as the business)
4. Contact privacy (raw addresses, message content, images)
5. Local secrets (HMAC keys, transport password, contact hash key)
6. The host machine and the owner's agent gateway

## Adversaries

- **A1 — Stranger by text:** anyone who texts the line. Capabilities: send
  arbitrary text, images, tapbacks, at any volume.
- **A2 — Prompt injector:** A1 who knows the assistant is an LLM and crafts
  instruction-shaped content (text, captions, image contents).
- **A3 — Impersonator:** claims to be the owner, a family member, or replies
  from a changed number; forwards/quotes owner commands.
- **A4 — Webhook forger:** can reach the HTTP listener (LAN or local process)
  and posts forged transport events, Discord hooks, or replayed requests.
- **A5 — Discord insider-ish:** a user in the owner's server (or a
  compromised account) trying to approve leads, forge references, or replay
  commands; a malicious/hijacked *other* bot.
- **A6 — Compromised model endpoint:** the local model server returns
  malicious output (or an attacker redirects the endpoint config).
- **A7 — Local attacker:** another user/process on the host reading files.

## Attack surfaces and mitigations

### Inbound message pipeline (A1, A2, A3)
- Tier 1 is deterministic; the strongest injection is answered by a fixed
  FAQ string or a bounded ack. URLs, escalation terms, and long messages are
  never auto-answered beyond the ack.
- Tier-2 pre-model guards (`AUTHZ_ATTEMPT_RE`, `PRIVATE_INFO_RE`) refuse
  approval syntax, self-promotion, payment/invoice/order requests, tool-call
  attempts, and injection phrasing before any model call (tested with zero
  model invocations).
- Owner recognition is a keyed HMAC fingerprint, not display names or text.
  A changed number/handle never inherits trust (fingerprint binding checked
  on every decision). Admin commands from group chats fail closed.
- Reactions parse to recorded events only; they never authorize or refresh
  TTLs. Duplicate webhook deliveries dedupe on event ID.

### Images (A1, A2)
- Allowlisted types only (JPEG/PNG), magic-sniffed, size/count/rate capped.
  Archives, documents, and scripts are never fetched, opened, or executed.
- Nothing is fetched without a functioning vision classifier; classifier
  error/empty results delete the sanitized copy and escalate; retention only
  after an explicit non-sensitive classification.
- Metadata (EXIF/GPS, PNG text chunks) is stripped by a pure-stdlib
  rewriter; quarantine is 0700/0600 outside the source tree with
  deterministic retention and purge-on-downgrade/block.
- QR codes and embedded/caption URLs are never decoded or fetched.

### HTTP surface (A4)
- Loopback bind by default; LAN bind requires explicit config opt-in; public
  bind refused in code. The systemd template adds `IPAddressDeny=any`.
- Every webhook — the transport `/inbound` ingress and both Discord hooks —
  requires HMAC-SHA256 over the exact raw body in `X-Hook-Signature`;
  missing/non-ASCII/tampered signatures → 401 with no state change; unknown
  correlation token → no write. There is no URL/query-token authentication
  (a `token=` query parameter is refused outright), so no secret can appear
  in proxy or access-log history.
- HMAC-less transports (BlueBubbles) ingress through a loopback-only signing
  shim on the transport machine; the unsigned hop never crosses a network
  (enforced in code, not configuration).
- Replay: a replayed signed body authenticates but inbound events dedupe by
  ID; Discord command messages are recorded exactly once (replays are
  inert); intake alerts resolve once atomically.

### Discord lane (A5)
- Only the configured owner user, in the configured intake channel, with an
  explicit bot mention, replying to a genuine unresolved alert this service
  posted, using exact grammar, can change trust. Nine distinct rejection
  classes are tested, including forged/cross-channel/resolved references and
  `approve all`.
- Plain approvals map to standing Tier 2; only an exact trailing `test` maps
  to the temporary 24h cohort. Unblock is not exposed via Discord.
- Ordinary thread discussion is internal. The sole reviewed reply path requires
  exact syntax plus owner, guild, bound thread/parent/category, active-contact,
  keyed-fingerprint, and chat-binding checks. It persists only a digest/length,
  sends once, and requires transport source read-back before claiming verified.
- Route envelopes consumed by the gateway hook are allowlist-checked against
  the receptionist's own channel config; forged channels fall back to legacy
  delivery. Callback bodies are HMAC-signed; tampered bodies are rejected.

### Model endpoints (A6)
- Endpoints must be loopback (or LAN with explicit opt-in); globally
  routable endpoints are refused in code, so a config edit cannot silently
  exfiltrate conversations to an external service.
- Model output is redacted (secret-shaped strings), whitespace-collapsed,
  and hard-capped; it is relayed to the owner but never echoed to a contact
  in the image path; it can never change state.
- A compromised model can still produce misleading *wording* to a Tier-2
  contact within the reply cap — residual risk, mitigated by category
  policies, the daily reply cap, and owner relay of every exchange.

### Host and files (A7)
- Secrets 0600 (loader fails closed on group/world access), state 0700,
  quarantine 0700/0600, permission report at startup, systemd sandbox
  (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`,
  narrow `ReadWritePaths`).
- Raw addresses appear only transiently in memory; storage and logs carry
  fingerprints and masks.

### Update path (all)
- The Hermes overlay mechanism fails closed on any target drift, requires
  re-render plus full re-verification after upstream updates, backs up before
  modifying, and rolls back byte-identically (tested).

## Residual risks (accepted, documented)

1. A misclassifying vision model can retain a sensitive image for up to the
   retention window (default 24h) in the local quarantine.
2. A compromised local model can shape Tier-2 wording (never actions).
3. The BlueBubbles server holds transport credentials on the Mac; its own
   security posture is outside this project's control.
4. A same-user local attacker (full account compromise) defeats file-mode
   protections; disk encryption and account hygiene are the mitigation.
5. Discord content is visible to Discord; treat mirrored alerts accordingly
   (they contain masked identities and quoted message text).
6. Denial of service by volume is rate-limited per contact, not globally; a
   distributed texting flood still consumes owner attention via relays.
