# Architecture

```
                       ┌──────────────────────────────┐
 iMessage contacts ───▶│ transport bridge (your Mac,  │
                       │ e.g. BlueBubbles server)     │
                       └───────────────┬──────────────┘
                                       │ plain POST (loopback, same machine)
                                       ▼
                       ┌──────────────────────────────┐
                       │ signing shim                 │
                       │ (bluebubbles_ingress.py)     │
                       └───────────────┬──────────────┘
                                       │ raw-body HMAC webhook (loopback/LAN)
                                       ▼
                       ┌──────────────────────────────┐
                       │ receptionist service          │
                       │  app.py (HTTP + orchestration)│
                       │                              │
   Tier 3 (owner) ◀────┤  keyed-fingerprint check     │
   exact admin cmds    │       │                      │
                       │       ▼                      │
                       │  tier1.py  deterministic FAQ │──▶ bounded auto-reply
                       │  tier2.py  no-tools lane     │──▶ (owner-gated send)
                       │  images.py fail-closed pipe  │
                       │  discord_routing.py           │
                       │  SQLite state + audit         │
                       └──────┬───────────────┬───────┘
                              │ HMAC relay    │ HMAC hooks
                              ▼               ▼
                     owner alert sink   owner's local Discord bot
                     (local gateway,    (intake channel, category
                      log, etc.)         channels + lead threads)
```

## Modules

| Module | Responsibility |
|---|---|
| `src/receptionist/app.py` | HTTP endpoints, event pipeline, tier dispatch, owner-gated outbound, relay |
| `src/receptionist/config.py` | validation: safe binds, local-only endpoints, numeric IDs |
| `src/receptionist/security.py` | HMAC sign/verify, secret generation/loading, permission report |
| `src/receptionist/identity.py` | keyed fingerprints, lead IDs, masking, log redaction |
| `src/receptionist/tier1.py` | deterministic classification + operator FAQ |
| `src/receptionist/tier2.py` | registry, exact admin commands, TTL cohort, bounded context, pre-model guards, local model client |
| `src/receptionist/images.py` | pure-stdlib sanitization, sensitive-content detection |
| `src/receptionist/discord_routing.py` | correlations, reply-to-approve, category/thread routing |
| `integrations/hermes/` | version-pinned overlay generator for a Hermes gateway |

## Trust boundaries

1. **Contact ↔ service:** everything a contact sends is untrusted data. It is
   quoted, never interpreted as instructions; only allowlisted shapes produce
   any automatic response.
2. **Model ↔ state:** the model receives words and returns words. No tool
   schema, no state handles, no identity. All authorization happens before
   and outside the model.
3. **Discord ↔ trust state:** the bot forwards raw fields; the receptionist
   decides. Structural checks (user, channel, mention, reply reference,
   correlation, fingerprint, resolve-once) are all deterministic.
4. **Service ↔ owner gate:** no code path sends to a contact while
   `outbound.enabled` is false; tests inject stub transports and run under a
   network guard.

## Data model (SQLite)

`inbound`, `outbound`, `contact_limits` (Tier-1 caps), `lead_identity`,
`tier2_contacts`, `tier2_context` (bounded), `tier2_audit`, `tier2_reactions`,
`tier2_attachments`, `tier2_image_limits`, `discord_pending_alerts`,
`discord_alerts`, `discord_threads`, `discord_commands`, `discord_audit`.

Raw addresses are never stored — only lead IDs, keyed fingerprints, and
masks. Deleting the state directory forgets everything.

## Design choices worth knowing

- **Stdlib only.** No runtime dependencies; the whole test battery runs on a
  bare Python 3.10+ with zero network access. Pillow, if present, adds a
  defense-in-depth re-encode to the image pipeline but is never required.
- **Sliding TTL counts only accepted inbound.** Outbound replies, reactions,
  webhook replays, and admin traffic never extend a temporary grant.
- **Everything resolves exactly once.** Intake alerts claim atomically;
  command message IDs are recorded so replays are inert; expiry is
  idempotent.
- **The Discord lane cannot bypass Tier-2 logic.** It executes through the
  same `Tier2Manager.handle_admin_command` the owner's iMessage line uses.
