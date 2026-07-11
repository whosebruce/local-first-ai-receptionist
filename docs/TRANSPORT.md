# Transport (iMessage / BlueBubbles) integration

This service does not talk to Apple directly. It relies on a local **transport
bridge** that receives iMessages and exposes an HTTP API for sending. The
reference transport is [BlueBubbles](https://bluebubbles.app), a self-hosted
server that runs on your own Mac.

## Precise security claims (read this)

- iMessage is **end-to-end encrypted between Apple endpoints**. Your Mac is
  one of those endpoints, so messages are **decrypted on your Mac** and then
  handed to the local BlueBubbles server and this service. From that point on,
  the security is your machine's security — not Apple's E2E encryption.
- This service processes messages **locally**. Nothing about a contact is sent
  to any external service unless *you* configure one (and model endpoints are
  refused unless local).
- This is **not** a claim of end-to-end encryption between a contact and the
  AI. It cannot be: the whole point is to read and respond to the message.

## How it connects

1. The transport delivers each new/updated message to this service's
   `/inbound` webhook. `/inbound` requires an **HMAC-SHA256 signature over
   the exact raw request body** in the `X-Hook-Signature` header, keyed with
   the locally generated `inbound_hmac_secret` — the same raw-body HMAC
   boundary as every other internal webhook. A missing, malformed
   (including non-ASCII), or wrong signature → 401 with no state change; a
   signature valid for different bytes (tampering) → 401; a replayed signed
   body authenticates but is inert (deduplicated by event ID). There is **no
   URL/query-token authentication and no fallback**: a `token=` query
   parameter is refused outright (400), so a secret can never end up in
   proxy or access-log history.
2. This service sends replies back through the BlueBubbles HTTP API using the
   server URL and password from your local config/secrets. The password is
   passed only to your local server and never logged.

## Practical BlueBubbles ingress (the signing shim)

BlueBubbles can only POST a plain webhook URL — it cannot compute HMAC
headers. Run the bundled signing shim on the **same machine as the
BlueBubbles server** and point the BlueBubbles webhook at the shim:

```bash
python3 scripts/bluebubbles_ingress.py \
  --forward-url http://127.0.0.1:8080/inbound
# then set the BlueBubbles webhook target to http://127.0.0.1:8091/
```

The shim preserves the boundary instead of weakening it:

- It binds **loopback only** — enforced in code, with no LAN option — so the
  unsigned hop never crosses a network.
- It signs the **exact raw bytes** with `inbound_hmac_secret` (read from
  `secrets.json`, mode 0600 enforced, symlink refused) and forwards them
  unmodified with the `X-Hook-Signature` header. The signed hop may cross a
  trusted LAN (`--allow-private-lan`); public, link-local, unspecified, and
  DNS-name targets are refused.
- Incoming query strings are dropped and nothing token-like is ever placed
  in a URL or log line.

### Cross-machine ingress (least privilege)

If the receptionist runs on a different machine than the transport, copy
`scripts/bluebubbles_ingress.py` to the transport machine and provision a
**dedicated** mode-0600 JSON file containing **only** the signing key:

```json
{ "inbound_hmac_secret": "<the value generated on the receptionist host>" }
```

Create it under `umask 077` so it is born mode 0600, transfer it only over an
authenticated channel (e.g. `scp`), and pass its path via `--secrets-file`.
**Never copy the full `secrets.json` to another machine.** Least privilege:
the full bundle also holds `relay_hmac_secret`, `discord_hook_secret`,
`contact_hash_key`, and any `transport_password` you added — none of which
the transport host needs — so a compromise of that host must cost only the
one inbound signing key (rotate it per `docs/UPDATE-ROLLBACK.md`). On the
same machine the default is unchanged: the shim reads `inbound_hmac_secret`
from the receptionist's local `secrets.json` in place, and nothing is copied
anywhere.

## Configuration

In `config.json`:

```json
"transport": { "kind": "bluebubbles", "server_url": "http://127.0.0.1:1234",
               "webhook_public_url": "http://127.0.0.1:8080/inbound" },
"outbound": { "enabled": false }
```

The BlueBubbles password is a secret. Add it to `secrets.json` as
`transport_password` (mode stays 0600); it is never displayed.
`webhook_public_url` is the receptionist `/inbound` URL the signing shim
forwards to; the BlueBubbles webhook itself points at the shim's loopback
address, never directly at `/inbound` and never with a token in the URL.

## Hardening

- Keep both the BlueBubbles server and this service on loopback or a trusted
  LAN segment. Do not expose either to the public internet.
- Do **not** enable the BlueBubbles Private API, and do not weaken macOS SIP,
  TCC, or FileVault to make anything "work". The service functions with the
  standard AppleScript send method.
- The systemd template denies all egress except loopback; if your Mac/server
  is on the LAN, add a narrow `IPAddressAllow` for that subnet only.

## Writing your own transport

The core (`Receptionist`) is transport-agnostic. A transport is any object
with `send_text(chat_id, text) -> {"ok": bool, "message_id": str}` and
`fetch_attachment(attachment_id) -> bytes | None`. Pass an instance to
`Receptionist(..., transport=...)`. `StubTransport` (records instead of
sending) is what every test and dry run uses. Inbound events are plain dicts;
see `tests/helpers.inbound_event` for the shape the pipeline expects. A
transport that delivers events over HTTP must sign the exact raw body with
`inbound_hmac_secret` in the `X-Hook-Signature` header (see
`receptionist.security.sign`) or post through the bundled signing shim —
`/inbound` accepts nothing else.
