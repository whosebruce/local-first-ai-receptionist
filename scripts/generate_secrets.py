#!/usr/bin/env python3
"""Generate all service secrets locally, mode 0600, WITHOUT displaying them.

Usage:
    python scripts/generate_secrets.py [--state-dir PATH]
    python scripts/generate_secrets.py --add-tier3 "+15555550100"

--add-tier3 registers an owner line: the raw address is read, fingerprinted
with the local contact_hash_key, and ONLY the fingerprint is stored. The raw
address is never written to disk or printed back.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from receptionist import security  # noqa: E402
from receptionist.identity import contact_fingerprint  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state-dir", default=os.environ.get(
        "RECEPTIONIST_HOME", "~/.local/state/ai-receptionist"))
    parser.add_argument("--add-tier3", nargs="?", const="", metavar="ADDRESS",
                        help="register an owner (Tier 3) line by fingerprint. "
                             "Prefer `--add-tier3` with no value and enter the "
                             "address at the prompt, so the raw address never "
                             "lands in your shell history or the process table.")
    parser.add_argument("--country-code", default="1")
    args = parser.parse_args()
    state_dir = Path(args.state_dir).expanduser()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secrets_path = state_dir / "secrets.json"

    if args.add_tier3 is not None:
        if not secrets_path.exists():
            print("SECRETS_OK=False REASON=generate_first")
            return 2
        address = args.add_tier3
        if not address:
            import getpass
            address = getpass.getpass("Owner address (phone/email, not echoed): ").strip()
        else:
            print("WARNING: passing the address on the command line exposes it in "
                  "shell history and the process table; prefer the no-value prompt.")
        if not address:
            print("SECRETS_OK=False REASON=empty_address")
            return 2
        data = security.load_secrets_file(secrets_path)
        fingerprint = contact_fingerprint(data["contact_hash_key"], address, args.country_code)
        hmacs = set(data.get("tier3_sender_hmacs") or [])
        hmacs.add(fingerprint)
        data["tier3_sender_hmacs"] = sorted(hmacs)
        tmp = secrets_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        tmp.replace(secrets_path)
        os.chmod(secrets_path, 0o600)
        print(f"TIER3_REGISTERED=True COUNT={len(data['tier3_sender_hmacs'])}")
        return 0

    try:
        security.write_secrets_file(secrets_path)
    except FileExistsError:
        print(f"SECRETS_OK=False REASON=already_exists PATH={secrets_path}")
        return 1
    print(f"SECRETS_OK=True PATH={secrets_path} FIELDS={len(security.SECRET_FIELDS)}")
    print("Values were generated locally and are not displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
