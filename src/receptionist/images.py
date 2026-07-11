"""Isolated, fail-closed image handling for Tier-2 contacts.

FAIL-CLOSED CONTRACT
  * With no functioning vision classifier configured, nothing is fetched,
    quarantined, or retained (the decision is made before any download).
  * A classifier error, timeout, or empty/inconclusive result deletes the
    sanitized copy immediately and escalates to the owner.
  * An image is retained only after an explicit non-sensitive classification.
  * QR codes and embedded/caption URLs are never decoded or fetched. No
    archive/script/document type is ever accepted, opened, or executed.
  * Quarantine lives in runtime-data space (0700 dir, 0600 files) outside any
    source tree or agent workspace, with deterministic retention cleanup.

Sanitization strips all metadata segments (EXIF/GPS/XMP/comments) from JPEG
and all non-essential chunks from PNG using a pure-stdlib parser, so location
data never persists. If Pillow is installed, images are additionally decoded
and re-encoded; its absence never widens acceptance (unknown structures are
rejected, not passed through).
"""
from __future__ import annotations

import re
import struct

SENSITIVE_IMAGE_RE = re.compile(
    r"\b(id|ids|id card|identification|license|passport|ssn|social security|bank|bank ?card|"
    r"routing|account number|credit card|debit|card number|bank statement|cheque|voided check|"
    r"password|passcode|credential|verification code|2fa|qr|barcode|medical|prescription|"
    r"diagnosis|lab result|legal|court|subpoena|nude|naked|nsfw|intimate|abuse)\b",
    re.I,
)
# A long digit run in a vision description (card/account/phone/code) is
# sensitive regardless of surrounding words — fail closed on numbers.
DIGIT_RUN_RE = re.compile(r"\d[\d\s().-]{6,}\d")

# Fail closed on refusal/uncertainty/document vocabulary: a safety-tuned vision
# model may decline to describe a sensitive document ("I can't describe this
# for privacy reasons", "this appears to be a personal document") instead of
# emitting the exact SENSITIVE token. Treat any such hedge as sensitive so the
# image is deleted and escalated rather than retained.
UNCERTAIN_DESC_RE = re.compile(
    r"\b(can'?t|cannot|can not|unable|won'?t|will not|not able|not comfortable|"
    r"i'?m sorry|i am sorry|apologi|decline|refuse|privacy|confidential|"
    r"sensitive|personal (info|information|document|data)|document|unclear|"
    r"can'?t tell|hard to tell|not sure|unsure|uncertain)\b",
    re.I)

# Maximum pixel area for the stdlib path (Pillow, when present, applies its own
# decompression-bomb guard). Blocks a tiny file declaring huge dimensions from
# reaching the local vision model's decoder.
MAX_PIXELS = 40_000_000
MAX_DIMENSION = 20_000

IMAGE_MAGIC = {
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/png": (b"\x89PNG\r\n\x1a\n",),
}
IMAGE_ALLOWLIST = set(IMAGE_MAGIC)

# PNG chunks required to render; everything else (eXIf, tEXt, iTXt, zTXt,
# tIME, pHYs...) is dropped.
_PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"sRGB"}
_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def is_sensitive_description(text: str) -> bool:
    return bool(
        SENSITIVE_IMAGE_RE.search(text or "")
        or DIGIT_RUN_RE.search(text or "")
        or UNCERTAIN_DESC_RE.search(text or "")
    )


def sniff_mime(data: bytes) -> str | None:
    for mime, magics in IMAGE_MAGIC.items():
        if any(data[: len(m)] == m for m in magics):
            return mime
    return None


def strip_jpeg_metadata(data: bytes) -> bytes | None:
    """Rebuild a JPEG keeping only structural segments. All APPn (EXIF/GPS
    lives in APP1, XMP in APP1/APP11, ICC in APP2) and COM segments are
    dropped. Returns None if the stream is structurally invalid."""
    if data[:3] != b"\xff\xd8\xff":
        return None
    out = bytearray(b"\xff\xd8")
    i = 2
    length = len(data)
    while i < length:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1] if i + 1 < length else None
        if marker is None:
            return None
        if marker == 0xD8:  # unexpected extra SOI
            return None
        if marker == 0xD9:  # EOI
            out += b"\xff\xd9"
            return bytes(out)
        if marker == 0xDA:  # SOS: keep the rest of the stream verbatim
            out += data[i:]
            if not out.endswith(b"\xff\xd9"):
                return None
            return bytes(out)
        if i + 4 > length:
            return None
        seg_len = struct.unpack(">H", data[i + 2 : i + 4])[0]
        if seg_len < 2 or i + 2 + seg_len > length:
            return None
        # SOF markers (0xC0-0xCF except DHT/JPG/DAC) carry the frame dimensions;
        # reject a decompression-bomb before it reaches any decoder.
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if seg_len >= 7:
                height = struct.unpack(">H", data[i + 5 : i + 7])[0]
                width = struct.unpack(">H", data[i + 7 : i + 9])[0]
                if _dimensions_too_large(width, height):
                    return None
        is_app_or_comment = 0xE0 <= marker <= 0xEF or marker == 0xFE
        if not is_app_or_comment:
            out += data[i : i + 2 + seg_len]
        i += 2 + seg_len
    return None


def _dimensions_too_large(width: int, height: int) -> bool:
    return (width > MAX_DIMENSION or height > MAX_DIMENSION
            or width * height > MAX_PIXELS)


def strip_png_metadata(data: bytes) -> bytes | None:
    """Rebuild a PNG keeping only allowlisted chunks (drops eXIf/tEXt/etc.).
    Returns None if the stream is structurally invalid."""
    if data[:8] != _PNG_SIG:
        return None
    out = bytearray(_PNG_SIG)
    i = 8
    length = len(data)
    saw_ihdr = saw_iend = False
    while i + 12 <= length:
        chunk_len = struct.unpack(">I", data[i : i + 4])[0]
        chunk_type = data[i + 4 : i + 8]
        end = i + 12 + chunk_len
        if end > length:
            return None
        if chunk_type == b"IHDR":
            saw_ihdr = True
            if chunk_len >= 8:
                width = struct.unpack(">I", data[i + 8 : i + 12])[0]
                height = struct.unpack(">I", data[i + 12 : i + 16])[0]
                if _dimensions_too_large(width, height):
                    return None
        if chunk_type in _PNG_KEEP:
            out += data[i:end]
        if chunk_type == b"IEND":
            saw_iend = True
            break
        i = end
    if not (saw_ihdr and saw_iend):
        return None
    return bytes(out)


def sanitize_image(data: bytes) -> bytes | None:
    """Strip metadata; optionally re-encode via Pillow when available.
    Returns clean bytes or None when the image must be rejected (malformed,
    disallowed type, or sanitizer failure — always fail closed)."""
    mime = sniff_mime(data)
    if mime == "image/jpeg":
        clean = strip_jpeg_metadata(data)
    elif mime == "image/png":
        clean = strip_png_metadata(data)
    else:
        return None
    if clean is None:
        return None
    try:  # optional defense-in-depth re-encode; absence never widens acceptance
        import io
        from PIL import Image  # type: ignore

        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        with Image.open(io.BytesIO(clean)) as probe:
            probe.verify()
        with Image.open(io.BytesIO(clean)) as img:
            out = io.BytesIO()
            if img.mode in ("RGBA", "LA", "P"):
                img.convert("RGBA").save(out, format="PNG")
            else:
                img.convert("RGB").save(out, format="JPEG", quality=88)
            return out.getvalue()
    except ImportError:
        return clean
    except Exception:
        return None
