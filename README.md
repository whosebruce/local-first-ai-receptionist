# Local-First AI Receptionist

A tiered, tool-isolated message triage service for a small business or
household: deterministic front-desk replies for unknown contacts, a bounded
no-tools AI conversation lane for contacts the owner explicitly promotes, and
untouched pass-through for the owner's own line. Everything runs on your own
hardware. In the default configuration (Discord mirror disabled) message
processing, storage, and model inference stay on your machines; if you enable
the optional Discord mirror, masked contact identities and message content are
posted to your private Discord channels, which means Discord's servers process
and store that content (permission-private, not end-to-end encrypted — see
"Honest security claims" below and `docs/DISCORD.md`).

Built by Bruce Works LLC. MIT licensed.

## Why

Wiring an LLM agent directly to your public phone number is a bad idea: an
inbound text is untrusted input, and an agent with tools can be talked into
doing things. This project inverts the design:

- **Tier 1 (everyone):** no model at all. A deterministic classifier answers
  from an operator-written FAQ allowlist, rate-limited, and relays every
  conversation to the owner. Anything sensitive gets a bounded acknowledgment
  and a human.
- **Tier 2 (explicitly promoted contacts):** a local model may *word* replies,
  but it has **no tools**, no memory beyond a bounded window, and every
  authorization-shaped message (approvals, payments, promotion requests,
  prompt injection, tool-call attempts) is refused deterministically *before*
  the model sees it. Temporary promotions expire after 24 hours of inactivity.
- **Tier 3 (the owner):** recognized by keyed fingerprint and delegated to the
  owner's own agent stack; exact admin commands manage Tier 2.

Trust changes only through exact owner commands bound to stable lead IDs and
keyed contact fingerprints — never through names, message content, reactions,
or anything a model outputs.

## Feature summary

- Deterministic Tier-1 FAQ + relay; no LLM exposure to unknown contacts
- Explicit promotion registry (`family` / `client` / `vendor`), standing or
  temporary (`tier2-test`, sliding 24h inactivity TTL, capped cohort)
- Local-only model endpoints (loopback by default; LAN requires explicit
  opt-in; public/external AI endpoints are refused **in code**)
- Fail-closed image pipeline: allowlisted types, quarantine outside the source
  tree, metadata (EXIF/GPS) stripping, vision classification required before
  anything is retained, sensitive-content escalation, deterministic retention
- iMessage tapback parsing; reactions are never authorization
- Optional Discord mirror: private intake channel, reply-to-approve with exact
  commands, per-category channels with stable per-lead threads; every hook
  HMAC-signed; the bot is the owner's own local bot (no hosted integrations)
- Outbound sending is **disabled by default** behind a manual owner gate
- SQLite state, local audit trail, masked identities everywhere in logs/alerts

## Quick start

```bash
git clone https://github.com/whosebruce/local-first-ai-receptionist.git
cd local-first-ai-receptionist
./scripts/install.sh          # generates secrets locally, runs the test suite
./scripts/doctor.sh           # readiness checks
./scripts/verify.sh           # full offline verification battery
```

Then read `docs/OPERATOR-GUIDE.md`. Nothing can message anyone until you set
`outbound.enabled: true` by hand — installers, tests, and agents never do.

If you are pointing a coding agent at this repository, give it
`AGENT_INSTALL.md` — it is written to be copy/paste-safe for agents.

## Requirements

- Python 3.10+ (standard library only; Pillow optional for image re-encode)
- An iMessage bridge such as a [BlueBubbles](https://bluebubbles.app) server
  on your own Mac, or any transport you adapt (see `docs/TRANSPORT.md`)
- Optional: a local model server (e.g. Ollama) for Tier-2 wording and vision
  classification (see `docs/MODELS.md`)
- Optional: your own locally hosted Discord bot (see `docs/DISCORD.md`)

## Documentation

| Document | Contents |
|---|---|
| `AGENT_INSTALL.md` | agent-safe installation runbook |
| `ARCHITECTURE.md` | tiers, data flow, trust boundaries |
| `SECURITY.md` | reporting, guarantees, and non-guarantees |
| `THREAT-MODEL.md` | adversaries, attack surfaces, mitigations, residual risk |
| `docs/OPERATOR-GUIDE.md` | day-to-day operation, admin commands, recovery |
| `docs/TRANSPORT.md` | iMessage/BlueBubbles transport, precise security claims |
| `docs/MODELS.md` | local text/vision model configuration |
| `docs/DISCORD.md` | intake approvals and category routing |
| `docs/HERMES-INTEGRATION.md` | optional Hermes gateway overlay |
| `docs/UPDATE-ROLLBACK.md` | updating safely, drift detection, rollback |
| `docs/UNINSTALL-RECOVERY.md` | uninstall, state recovery, incident response |

## Honest security claims

iMessage is end-to-end encrypted *between Apple endpoints*; messages are
decrypted on your Mac and processed locally by this service. Discord channels
are permission-private, not end-to-end encrypted. Local models are constrained
by this architecture, not infallible. This project is not a compliance
certification. Read `THREAT-MODEL.md` before trusting it with anything.

## License

MIT — see `LICENSE`.
