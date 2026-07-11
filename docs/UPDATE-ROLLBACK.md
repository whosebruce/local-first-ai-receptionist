# Updating, drift detection, and rollback

## Updating the receptionist

1. Review the changes and `CHANGELOG.md`.
2. Pull/replace the source. Your state directory is separate and untouched.
3. Run the full battery: `./scripts/verify.sh` (must print `VERIFY_OK=True`)
   and `python3 security/privacy_scan.py` (must print zero findings).
4. Run `./scripts/doctor.sh` to confirm your config still validates against
   the new version.
5. Restart: `systemctl --user restart ai-receptionist.service`; confirm
   `/health`.

If `verify.sh` fails after an update, do **not** run live. Roll back the
source to the previous version (state is compatible) and report the failure.

## Config schema changes

`config.json` carries `config_version`. If a release bumps it, the loader will
refuse the old config with a clear error; the release notes will describe the
migration. Defaults are always the safe ones (loopback, outbound off).

## Hermes overlay drift

The overlay is the one place this project touches files outside its own tree.
It is designed to fail closed:

- After updating your gateway, run
  `python3 integrations/hermes/render_overlay.py verify --hermes-root ...`.
- `PRISTINE` → safe to `apply`. `APPLIED` → already wired. `DRIFTED` or
  `MISSING` → the gateway changed; re-run `render`, re-check anchors, re-run
  your gateway test battery, then `apply`.
- `apply` refuses on any hash mismatch and never partially applies.
- `rollback` restores the most recent backup byte-for-byte.

Record the compatible gateway commit in `overlay_manifest.json` and require
re-verification after every gateway update.

## Rotating secrets

See `docs/OPERATOR-GUIDE.md` → "Rotate a secret". Rotating
`contact_hash_key` invalidates all fingerprints, so you must re-register your
Tier-3 line and re-promote active Tier-2 contacts. Rotating
`discord_hook_secret` requires updating your bot/overlay config in the same
window.
