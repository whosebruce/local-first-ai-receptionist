"""Shared test fixtures. Every identifier here is deliberately, obviously
synthetic: platform IDs use a reserved-looking 1/9 + fourteen zeros pattern,
phone numbers use the +1-555-555-01XX fictional range, and emails use
example.com. The privacy scanner allowlists exactly these shapes."""
from __future__ import annotations

import shutil
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from receptionist import config as config_mod  # noqa: E402
from receptionist import security  # noqa: E402
from receptionist.app import Receptionist, StubTransport  # noqa: E402
from receptionist.identity import contact_fingerprint  # noqa: E402

# --- obviously fake platform IDs (see security/privacy_scan.py allowlist) ---
GUILD_ID = "100000000000000001"
OWNER_ID = "100000000000000002"
BOT_ID = "100000000000000003"
INTAKE_CHANNEL = "100000000000000004"
FAMILY_CHANNEL = "100000000000000005"
CLIENT_CHANNEL = "100000000000000006"
VENDOR_CHANNEL = "100000000000000007"
OTHER_USER = "900000000000000001"
OTHER_CHANNEL = "900000000000000002"

# --- fictional contact handles (RFC 5737-style reserved fiction) ---
CONTACT_PHONE = "+15555550100"
CONTACT_PHONE_2 = "+15555550101"
OWNER_PHONE = "+15555550199"
CONTACT_EMAIL = "contact@example.com"


def make_temp_dir(case, prefix: str = "receptionist-test-") -> Path:
    """Create a temp dir owned by the given test case (or test class, from
    setUpClass) and register its removal so no fixture root ever survives a
    run. unittest runs addCleanup/addClassCleanup callbacks on every outcome —
    pass, failure, and error — so this covers failure paths too."""
    tmp = Path(tempfile.mkdtemp(prefix=prefix))
    register = case.addClassCleanup if isinstance(case, type) else case.addCleanup
    register(shutil.rmtree, tmp, ignore_errors=True)
    return tmp


class Clock:
    """Deterministic, manually advanced clock."""

    def __init__(self, start: int = 1_700_000_000) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


def make_config(tmp: Path, **overrides) -> dict:
    cfg = config_mod.default_config()
    cfg["state_dir"] = str(tmp)
    cfg["tier2"]["image"]["quarantine_dir"] = str(tmp / "quarantine")
    cfg["discord"].update({
        "enabled": True,
        "guild_id": GUILD_ID,
        "owner_user_id": OWNER_ID,
        "bot_user_id": BOT_ID,
        "intake_channel_id": INTAKE_CHANNEL,
        "category_channels": {
            "family": FAMILY_CHANNEL,
            "client": CLIENT_CHANNEL,
            "vendor": VENDOR_CHANNEL,
        },
    })
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return config_mod.validate(cfg)


def make_secrets(with_owner: bool = True) -> dict:
    secrets = security.generate_secrets_dict()
    if with_owner:
        secrets["tier3_sender_hmacs"] = [
            contact_fingerprint(secrets["contact_hash_key"], OWNER_PHONE)
        ]
    return secrets


def make_receptionist(case, tmp: Path | None = None, clock: Clock | None = None,
                      transport=None, **config_overrides):
    """Build a receptionist on a self-cleaning state dir. `case` is required:
    the fixture root is registered for removal on the calling test case (or
    test class), so it cannot leak into the temp dir even when the test fails."""
    tmp = tmp or make_temp_dir(case)
    clock = clock or Clock()
    config = make_config(tmp, **config_overrides)
    secrets = make_secrets()
    receptionist = Receptionist(
        config, secrets, db_path=str(tmp / "state.sqlite3"),
        transport=transport or StubTransport(), now_fn=clock)
    return receptionist, clock, tmp


def inbound_event(guid: str, sender: str = CONTACT_PHONE, text: str = "hello",
                  chat_id: str = "chat-1", **extra) -> dict:
    data = {
        "guid": guid,
        "text": text,
        "handle": {"address": sender},
        "chatGuid": chat_id,
    }
    data.update(extra)
    return {"type": "new-message", "data": data}


# ---------- synthetic image builders (structurally valid, no real photos) ----

def build_jpeg_with_exif(gps: bool = True) -> bytes:
    """Minimal JPEG stream for the pure-stdlib sanitizer: SOI, APP0(JFIF),
    APP1(Exif with a fake GPS payload), COM, SOS + entropy data, EOI."""
    def seg(marker: int, payload: bytes) -> bytes:
        return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload

    exif_payload = b"Exif\x00\x00" + (b"GPSLatitude=00.000,GPSLongitude=00.000" if gps else b"MakerNote")
    return (
        b"\xff\xd8"
        + seg(0xE0, b"JFIF\x00\x01\x02")
        + seg(0xE1, exif_payload)
        + seg(0xFE, b"comment metadata")
        + seg(0xDB, b"\x00" + bytes(64))          # DQT (structural)
        + b"\xff\xda" + struct.pack(">H", 4) + b"\x00\x00"  # SOS header
        + b"\x12\x34\x56"                          # entropy-coded data
        + b"\xff\xd9"
    )


def build_png_with_metadata() -> bytes:
    def chunk(ctype: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + ctype + payload + b"\x00\x00\x00\x00"

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
        + chunk(b"eXIf", b"GPSLatitude fake exif")
        + chunk(b"tEXt", b"Comment\x00location metadata")
        + chunk(b"IDAT", b"\x00\x01\x02")
        + chunk(b"IEND", b"")
    )


class NoPillow:
    """Context manager forcing the pure-stdlib sanitizer path so tests are
    deterministic whether or not Pillow happens to be installed."""

    def __enter__(self):
        self._saved = sys.modules.get("PIL", "__absent__")
        sys.modules["PIL"] = None  # import PIL -> ImportError
        return self

    def __exit__(self, *exc):
        if self._saved == "__absent__":
            sys.modules.pop("PIL", None)
        else:
            sys.modules["PIL"] = self._saved
        return False
