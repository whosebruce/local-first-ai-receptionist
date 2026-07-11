#!/usr/bin/env bash
# Health/readiness checks. Read-only; never sends anything anywhere.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${RECEPTIONIST_HOME:-$HOME/.local/state/ai-receptionist}"
FAIL=0

check() { # name, exit-code (0 ok)
  if [ "$2" -eq 0 ]; then echo "OK   $1"; else echo "FAIL $1"; FAIL=1; fi
}

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
check "python >= 3.10" $?

[ -d "$STATE_DIR" ]; check "state dir exists ($STATE_DIR)" $?

if [ -f "$STATE_DIR/secrets.json" ]; then
  PERM=$(stat -c '%a' "$STATE_DIR/secrets.json" 2>/dev/null || stat -f '%Lp' "$STATE_DIR/secrets.json")
  [ "$PERM" = "600" ]; check "secrets.json mode 600 (is $PERM)" $?
else
  check "secrets.json exists (run scripts/generate_secrets.py)" 1
fi

if [ -d "$STATE_DIR" ]; then
  DPERM=$(stat -c '%a' "$STATE_DIR" 2>/dev/null || stat -f '%Lp' "$STATE_DIR")
  [ "$DPERM" = "700" ]; check "state dir mode 700 (is $DPERM)" $?
fi

REPO_ROOT="$REPO_ROOT" STATE_DIR="$STATE_DIR" python3 - <<'EOF'
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(os.environ["REPO_ROOT"]) / "src"))
from receptionist import config as config_mod
state = Path(os.environ["STATE_DIR"])
try:
    if (state / "config.json").exists():
        cfg = config_mod.load(state / "config.json")
    else:
        cfg = config_mod.validate(config_mod.default_config())
    print("OK   config validates")
    if bool((cfg.get("outbound") or {}).get("enabled")):
        print("WARN outbound is ENABLED — this deployment is live")
    else:
        print("OK   outbound disabled (safe default)")
except Exception as exc:
    print(f"FAIL config: {type(exc).__name__}: {exc}")
    raise SystemExit(1)
EOF
check "config validation" $?

Q="$STATE_DIR/quarantine"
if [ -d "$Q" ]; then
  QPERM=$(stat -c '%a' "$Q" 2>/dev/null || stat -f '%Lp' "$Q")
  [ "$QPERM" = "700" ]; check "quarantine mode 700 (is $QPERM)" $?
fi

if [ "$FAIL" -eq 0 ]; then echo "DOCTOR_OK=True"; else echo "DOCTOR_OK=False"; exit 1; fi
