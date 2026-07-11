#!/usr/bin/env python3
"""Generic, version-pinned overlay generator for Hermes gateway integration.

This project does NOT ship raw patches against anyone's private tree. Instead,
it renders hook modules and insertion snippets from templates, substituting
YOUR validated local configuration, and applies them to YOUR Hermes checkout
with a clean applicability check, backup, rollback, and fail-closed drift
detection.

Commands (run from the repo root):
    python integrations/hermes/render_overlay.py render  --hermes-root PATH --receptionist-config PATH
    python integrations/hermes/render_overlay.py apply   --hermes-root PATH
    python integrations/hermes/render_overlay.py verify  --hermes-root PATH
    python integrations/hermes/render_overlay.py rollback --hermes-root PATH

Contract:
  * `render` validates the receptionist config (IDs numeric, endpoints local),
    substitutes placeholders, and records the sha256 of each target file in
    overlay.lock.json. It never modifies Hermes files.
  * `apply` re-verifies each target file hash against the lockfile and checks
    the anchor line appears EXACTLY once and no overlay marker exists yet.
    Any mismatch (upstream update, prior edit, partial apply) fails closed
    with no changes. A timestamped backup is written before modification.
  * `verify` reports whether targets are pristine, applied, or drifted.
  * `rollback` restores the most recent backup for each target.
  * After ANY Hermes update, `verify` reports drift and you must re-run
    render + apply + the full test battery before going live again.

See docs/HERMES-INTEGRATION.md for the compatible-version pinning policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "overlay_manifest.json"
LOCK_PATH = HERE / "overlay.lock.json"
MARKER = "# --- receptionist-overlay:"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


class OverlayError(SystemExit):
    def __init__(self, message: str) -> None:
        super().__init__(f"OVERLAY FAILED (no changes made): {message}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def validate_substitutions(config_path: Path) -> dict[str, str]:
    """Build and validate the placeholder map from the local receptionist
    config. Every value is checked; a malformed value fails closed."""
    config = json.loads(config_path.read_text())
    discord = config.get("discord") or {}
    intake = str(discord.get("intake_channel_id") or "")
    if not re.fullmatch(r"\d{15,21}", intake):
        raise OverlayError("discord.intake_channel_id must be a numeric channel ID")
    host = str(config.get("listen_host") or "127.0.0.1")
    port = int(config.get("listen_port") or 0)
    if not 1 <= port <= 65535:
        raise OverlayError("listen_port out of range")
    if not re.fullmatch(r"[\d.]+|localhost", host):
        raise OverlayError("listen_host must be an IP or localhost")
    state_dir = str(Path(config.get("state_dir") or "").expanduser())
    if not state_dir:
        raise OverlayError("state_dir must be set in the receptionist config")
    subs = {
        "INTAKE_CHANNEL_ID": intake,
        "RECEPTIONIST_BASE_URL": f"http://{host}:{port}",
        "RECEPTIONIST_STATE_DIR": state_dir,
        "HOOK_DIR": str(HERE / "rendered"),
    }
    # Every value is spliced into a Python string literal in the rendered hook.
    # Reject anything that could break out of that literal (quotes, backslash,
    # or control chars) so a crafted config cannot inject code into the gateway.
    unsafe = re.compile(r"""['"\\\x00-\x1f]""")
    for key, value in subs.items():
        if unsafe.search(value):
            raise OverlayError(f"substitution {key} contains an unsafe character; refused")
    return subs


def render(args) -> None:
    manifest = load_manifest()
    hermes_root = Path(args.hermes_root).expanduser().resolve()
    subs = validate_substitutions(Path(args.receptionist_config).expanduser())
    rendered_dir = HERE / "rendered"
    rendered_dir.mkdir(mode=0o700, exist_ok=True)
    # The lockfile stays on this machine (gitignored): it carries local IDs.
    lock = {"rendered_at": int(time.time()), "targets": {}, "hooks": [],
            "substitutions": subs}
    for hook in manifest["hooks"]:
        template = (HERE / "templates" / hook["template"]).read_text()
        missing = [m.group(1) for m in PLACEHOLDER_RE.finditer(template) if m.group(1) not in subs]
        if missing:
            raise OverlayError(f"template {hook['template']} has unknown placeholders: {missing}")
        body = PLACEHOLDER_RE.sub(lambda m: subs[m.group(1)], template)
        out_path = rendered_dir / hook["output"]
        out_path.write_text(body)
        out_path.chmod(0o600)
        lock["hooks"].append({"output": hook["output"], "sha256": hashlib.sha256(body.encode()).hexdigest()})
    for target in manifest["targets"]:
        target_path = hermes_root / target["file"]
        if not target_path.exists():
            raise OverlayError(f"target file missing: {target_path} — wrong --hermes-root or incompatible version")
        content = target_path.read_text()
        anchor_count = content.count(target["anchor"])
        if anchor_count != 1:
            raise OverlayError(
                f"anchor for {target['file']} found {anchor_count}x (need exactly 1). "
                "Your Hermes version is not the pinned compatible version; see docs/HERMES-INTEGRATION.md")
        snippet_template = (HERE / "templates" / target["snippet"]).read_text()
        missing = [m.group(1) for m in PLACEHOLDER_RE.finditer(snippet_template) if m.group(1) not in subs]
        if missing:
            raise OverlayError(f"snippet {target['snippet']} has unknown placeholders: {missing}")
        lock["targets"][target["file"]] = {
            "sha256": sha256_file(target_path),
            "anchor": target["anchor"],
            "snippet": target["snippet"],
        }
    LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"RENDER_OK targets={len(lock['targets'])} hooks={len(lock['hooks'])}")
    print(f"lockfile: {LOCK_PATH}")


def _load_lock() -> dict:
    if not LOCK_PATH.exists():
        raise OverlayError("no overlay.lock.json — run `render` first")
    return json.loads(LOCK_PATH.read_text())


def apply(args) -> None:
    manifest = load_manifest()
    lock = _load_lock()
    hermes_root = Path(args.hermes_root).expanduser().resolve()
    subs = dict(lock.get("substitutions") or {})
    if not subs:
        raise OverlayError("lockfile has no substitutions — re-run render")
    staged: list[tuple[Path, str, Path]] = []
    for target in manifest["targets"]:
        entry = lock["targets"].get(target["file"])
        if not entry:
            raise OverlayError(f"{target['file']} not in lockfile — re-run render")
        target_path = hermes_root / target["file"]
        if not target_path.exists():
            raise OverlayError(f"target file missing: {target_path}")
        current = sha256_file(target_path)
        if current != entry["sha256"]:
            raise OverlayError(
                f"DRIFT: {target['file']} changed since render "
                f"(expected {entry['sha256'][:12]}, got {current[:12]}). "
                "Re-run render and re-verify the full test battery before applying.")
        content = target_path.read_text()
        if MARKER in content:
            raise OverlayError(f"{target['file']} already contains an overlay marker — rollback first")
        anchor = entry["anchor"]
        if content.count(anchor) != 1:
            raise OverlayError(f"anchor for {target['file']} not unique at apply time")
        # Confine the snippet path to the templates dir (a tampered lockfile
        # must not be able to inline an arbitrary file via path traversal).
        templates_dir = (HERE / "templates").resolve()
        snippet_path = (templates_dir / entry["snippet"]).resolve()
        if templates_dir not in snippet_path.parents:
            raise OverlayError(f"snippet path for {target['file']} escapes the templates dir; refused")
        snippet = snippet_path.read_text()
        rendered_dir = HERE / "rendered"
        for hook in lock.get("hooks", []):
            hook_path = rendered_dir / hook["output"]
            if not hook_path.exists():
                raise OverlayError(f"rendered hook missing: {hook_path} — re-run render")
            if hashlib.sha256(hook_path.read_bytes()).hexdigest() != hook["sha256"]:
                raise OverlayError(f"rendered hook drifted: {hook_path} — re-run render")
        snippet = PLACEHOLDER_RE.sub(
            lambda m: subs.get(m.group(1), m.group(0)), snippet)
        if PLACEHOLDER_RE.search(snippet):
            raise OverlayError(f"unresolved placeholder in snippet for {target['file']}")
        anchor_line = next(line for line in content.splitlines() if anchor in line)
        indent = anchor_line[: len(anchor_line) - len(anchor_line.lstrip())]
        marker_open = f"{indent}{MARKER}{target['name']}:begin ---"
        marker_close = f"{indent}{MARKER}{target['name']}:end ---"
        indented = "\n".join(
            (indent + line) if line.strip() else line for line in snippet.splitlines())
        insertion = f"{marker_open}\n{indented}\n{marker_close}\n"
        position = "before" if target.get("insert") == "before" else "after"
        if position == "before":
            new_content = content.replace(anchor_line, insertion + anchor_line, 1)
        else:
            new_content = content.replace(anchor_line, anchor_line + "\n" + insertion, 1)
        staged.append((target_path, new_content, target_path.with_suffix(
            target_path.suffix + f".overlay-backup-{int(time.time())}")))
    # All checks passed for every target — only now touch anything. Each write
    # is temp-file + atomic rename so a crash cannot leave a half-written
    # target; a per-target backup is written first for rollback.
    for target_path, new_content, backup_path in staged:
        backup_path.write_bytes(target_path.read_bytes())
        tmp = target_path.with_suffix(target_path.suffix + ".overlay-tmp")
        tmp.write_text(new_content)
        os.replace(tmp, target_path)
        print(f"APPLIED {target_path} (backup: {backup_path.name})")
    print("APPLY_OK — restart the gateway and re-run its test battery before live use")


def verify(args) -> None:
    manifest = load_manifest()
    hermes_root = Path(args.hermes_root).expanduser().resolve()
    lock = json.loads(LOCK_PATH.read_text()) if LOCK_PATH.exists() else {"targets": {}}
    status = 0
    for target in manifest["targets"]:
        target_path = hermes_root / target["file"]
        if not target_path.exists():
            print(f"MISSING {target['file']}")
            status = 1
            continue
        content = target_path.read_text()
        applied = MARKER in content
        entry = lock["targets"].get(target["file"])
        if applied:
            print(f"APPLIED {target['file']}")
        elif entry and sha256_file(target_path) == entry["sha256"]:
            print(f"PRISTINE {target['file']} (matches lockfile; ready to apply)")
        elif entry:
            print(f"DRIFTED {target['file']} — re-run render + full re-verification")
            status = 1
        else:
            print(f"UNRENDERED {target['file']}")
    raise SystemExit(status)


def rollback(args) -> None:
    manifest = load_manifest()
    hermes_root = Path(args.hermes_root).expanduser().resolve()
    for target in manifest["targets"]:
        target_path = hermes_root / target["file"]
        backups = sorted(target_path.parent.glob(target_path.name + ".overlay-backup-*"))
        if not backups:
            print(f"NO_BACKUP {target['file']}")
            continue
        latest = backups[-1]
        target_path.write_bytes(latest.read_bytes())
        print(f"ROLLED_BACK {target['file']} <- {latest.name}")
    print("ROLLBACK_OK — restart the gateway")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in (("render", render), ("apply", apply), ("verify", verify), ("rollback", rollback)):
        p = sub.add_parser(name)
        p.add_argument("--hermes-root", required=True)
        if name == "render":
            p.add_argument("--receptionist-config", required=True)
        p.set_defaults(fn=fn)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
