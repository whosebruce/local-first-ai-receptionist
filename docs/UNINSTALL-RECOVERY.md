# Uninstall and recovery

## Uninstall

```bash
./scripts/uninstall.sh                 # stops + removes the user unit; keeps state
PURGE_STATE=1 ./scripts/uninstall.sh   # also deletes the state directory
```

Keeping state preserves the audit trail and any quarantined images for review.
`PURGE_STATE=1` removes secrets, the SQLite database, and the quarantine — the
service forgets every contact, fingerprint, and grant.

## Recovering from a bad state

- **Service won't start:** run `./scripts/doctor.sh`. The most common causes
  are a `config.json` that fails validation (fix the reported key) or
  `secrets.json` with the wrong mode (`chmod 600`).
- **Corrupt database:** stop the service, move `state.sqlite3*` aside, and
  restart — the schema is recreated empty. You lose history and grants but the
  service comes back clean; re-register Tier 3 and re-promote contacts.
- **Lost/leaked secret:** rotate immediately (see `docs/UPDATE-ROLLBACK.md`).
  A leaked `inbound_hmac_secret`/`discord_hook_secret` lets a LAN attacker
  forge signed webhooks until you rotate; a leaked `contact_hash_key` lets an
  attacker test address guesses against stored fingerprints.

## Incident response

If you suspect abuse or compromise:

1. Set `outbound.enabled: false` and restart — the service goes read-only
   (still classifies and relays, but sends nothing).
2. Inspect the audit trail (`tier2_audit`, `discord_audit`) and `outbound`
   for anything unexpected.
3. `block LEADID` any contact of concern; `tier1 LEADID` to drop Tier-2
   grants in bulk (repeat per lead).
4. If a secret may be exposed, rotate all secrets and re-register Tier 3.
5. If the host itself may be compromised, treat the BlueBubbles/transport
   credentials and any local model access as exposed too, and rotate at the
   source.

In the default configuration contact data lives only on this host, so
"recovery" is local: the worst-case exposure is what is on this machine, which
is why disk encryption and account hygiene matter. If you enabled the optional
owner alert relay or Discord mirror, masked contact identities and message
content were also posted to your configured sink — for Discord, review or
delete those channel messages too (see `docs/DISCORD.md`).
