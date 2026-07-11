"""Security primitives: HMAC signing, secret handling, permission checks.

Every internal webhook in this project is authenticated with an HMAC-SHA256
signature over the raw request body using a locally generated shared secret.
Secrets are generated on the installing machine, stored mode 0600, loaded into
process memory only, and never logged or displayed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
import stat
from pathlib import Path

SIGNATURE_HEADER = "X-Hook-Signature"

# Names of secrets this service uses. Values are always generated locally.
SECRET_FIELDS = (
    "inbound_hmac_secret",    # signs transport -> /inbound webhook raw bodies
    "relay_hmac_secret",      # signs relay envelopes to the owner alert sink
    "discord_hook_secret",    # signs local Discord bot <-> receptionist hooks
    "contact_hash_key",       # keys contact fingerprints (never raw addresses)
)


def sign(secret: str, raw: bytes) -> str:
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def verify(secret: str, raw: bytes, signature: str) -> bool:
    """Constant-time verification; fails closed on a missing secret/signature.
    Compares as bytes so a non-ASCII signature header can never raise."""
    if not secret or not signature:
        return False
    return hmac.compare_digest(sign(secret, raw).encode(), signature.encode())


def generate_secrets_dict() -> dict[str, str]:
    """Generate all service secrets. Callers must never print the values."""
    return {name: _secrets.token_hex(32) for name in SECRET_FIELDS}


def write_secrets_file(path: Path, extra: dict[str, str] | None = None) -> None:
    """Create the secrets file atomically with mode 0600. Refuses to overwrite
    an existing file so an installer can never silently rotate live secrets."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing secrets file: {path}")
    data = generate_secrets_dict()
    data.update(extra or {})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def load_secrets_file(path: Path) -> dict[str, str]:
    """Load secrets, failing closed if the file is a symlink or is group/world
    accessible."""
    path = Path(path)
    info = path.lstat()  # do not follow a symlink to a differently-permissioned target
    if stat.S_ISLNK(info.st_mode):
        raise PermissionError(f"secrets file {path.name} is a symlink; refusing to load")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"secrets file {path.name} is group/world accessible (mode {oct(mode)}); "
            "run: chmod 600 on it and re-start"
        )
    return json.loads(path.read_text())


def insecure_permission_report(root: Path) -> list[str]:
    """Security-critical files must not be group- or world-writable.
    Returns 'name:mode' for each offending regular file directly under root."""
    offending = []
    for path in sorted(Path(root).iterdir()):
        if path.name in ("__pycache__", ".pytest_cache", ".git") or not path.is_file():
            continue
        mode = path.stat().st_mode & 0o777
        if mode & 0o022:
            offending.append(f"{path.name}:{oct(mode)}")
    return offending
