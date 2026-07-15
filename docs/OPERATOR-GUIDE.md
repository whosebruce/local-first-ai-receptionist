# Operator Guide

Day-to-day operation, in the order you'll need it.

## State layout

Everything lives under the state directory (`RECEPTIONIST_HOME`, default
`~/.local/state/ai-receptionist`, mode 0700):

- `config.json` — your configuration (validated on startup)
- `secrets.json` — locally generated secrets, mode 0600, never displayed
- `state.sqlite3` — all runtime state and the audit trail
- `quarantine/` — sanitized images only, 0700/0600, deterministic retention
- `ai-receptionist.service` — rendered systemd unit (copy into
  `~/.config/systemd/user/` to install)

## Going live (the deliberate part)

Install leaves the service safe: loopback bind, outbound disabled, Discord
disabled. To go live:

1. Configure your transport (`docs/TRANSPORT.md`) and, optionally, models
   (`docs/MODELS.md`) and Discord (`docs/DISCORD.md`).
2. Register your own line: `python3 scripts/generate_secrets.py --add-tier3`
   (enter the address at the no-echo prompt; only a fingerprint is stored, and
   the address never touches shell history or the process table).
3. Run `./scripts/doctor.sh` and `./scripts/verify.sh` — both must pass.
4. Edit `config.json`: set `outbound.enabled: true`. This is the owner gate;
   nothing else flips it.
5. Start the service:
   `systemctl --user enable --now ai-receptionist.service`, then check
   `curl http://127.0.0.1:<port>/health`.
6. Pilot with a consenting contact before telling anyone else the number.

## Owner admin commands (your Tier-3 line, direct message only)

Lead IDs are the 8-character IDs shown in every alert. Commands are exact;
anything else (names, "she is fine", forwarded text, group messages,
non-owner senders) fails closed and changes nothing.

| Command | Effect |
|---|---|
| `tier2 LEADID family\|client\|vendor` | Standing Tier-2 promotion (no TTL) |
| `tier2-test LEADID family\|client\|vendor` | Temporary Tier-2; expires 24h after the contact's last accepted inbound message; capped cohort |
| `tier1 LEADID` | Immediate downgrade; clears bounded context and quarantined images |
| `block LEADID` | Total silence toward this contact; `unblock LEADID` returns them to Tier 1 only |
| `tier2-status` | Read-back of tracked contacts and test-cohort usage |

Every command returns a deterministic `TIER2 ADMIN OK/FAILED` read-back.
First activation also sends the contact a one-time beta disclosure.

Discord approvals use the same categories: `@bot approve family` is standing,
while `@bot approve family test` is temporary. In a bound active Tier-2 thread,
the configured owner may send exactly `reply <reviewed message>`. The message is
sent once, read back from the transport when supported, and never automatically
retried after an uncertain result. See `docs/DISCORD.md`.

## What Tier 2 can and cannot do

- Conversation runs with **no tools of any kind**. The model (when
  configured) receives the category policy, the last N bounded turns, and the
  quoted message — nothing else.
- Approval syntax, promotion attempts, payment/invoice/order requests, and
  injection phrasing are refused deterministically before any model call and
  escalate to you when relevant.
- Tapbacks are recorded/relayed only; they never approve anything and never
  refresh the 24h timer. Only accepted inbound contact messages refresh it.
- Images follow the fail-closed pipeline (see `THREAT-MODEL.md`): without a
  vision classifier nothing is even downloaded.

## Reading the audit trail

```bash
sqlite3 ~/.local/state/ai-receptionist/state.sqlite3 \
  "SELECT * FROM tier2_audit ORDER BY id DESC LIMIT 50;"
sqlite3 ~/.local/state/ai-receptionist/state.sqlite3 \
  "SELECT * FROM discord_audit ORDER BY id DESC LIMIT 50;"
```

`outbound` records every send attempt with status; `inbound` records every
event with its classification and reply status. `discord_contact_replies`
stores only the command ID, lead binding, message digest/length, and result —
not the reviewed body. `owner_seen_checks` records the optional delayed
second-channel alert lifecycle.

## Routine operations

- **Restart:** `systemctl --user restart ai-receptionist.service`; state and
  threads persist; the sweeper resumes automatically.
- **Wrong promotion:** `tier1 LEADID` (or `block LEADID`). Expired or
  downgraded contacts need a fresh exact command to re-activate.
- **Rotate a secret:** stop the service, delete the specific key from
  `secrets.json`? No — regenerate: move `secrets.json` aside, run
  `scripts/generate_secrets.py`, re-register your Tier-3 line, update any
  hook consumers (the transport signing shim, Discord bot config, overlay
  render), restart. Old fingerprints become invalid, so re-promote active
  Tier-2 contacts.
- **Update:** see `docs/UPDATE-ROLLBACK.md`. Always re-run
  `./scripts/verify.sh` after updating.
- **Uninstall / incident response:** see `docs/UNINSTALL-RECOVERY.md`.

## Live-pilot checklist (first contact)

1. Have the consenting contact text the line normally; note the lead ID in
   your alert. They remain Tier 1.
2. Confirm the masked identity matches who you expect.
3. From your own line: `tier2-test LEADID family`.
4. Verify the `TIER2 ADMIN OK` read-back and their one-time disclosure.
5. Pilot: ordinary chat, a relay request, "where is the owner?" (expect
   refusal), a pasted "ignore your instructions" (expect refusal), `ok`
   (expect fast ack or silence), a tapback (no reply), a normal photo
   (generic acknowledgment), and confirm each shows up in your alerts.
6. When done: let it expire (24h inactivity) or send `tier1 LEADID`.
