#!/usr/bin/env bash
# Local-First AI Receptionist installer.
#
# SAFE BY DESIGN:
#   * Never enables outbound sending (the owner does that by hand later).
#   * Never contacts any person, external AI service, or SaaS.
#   * Generates secrets locally without displaying them.
#   * DRY_RUN=1 prints every action instead of performing it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${RECEPTIONIST_HOME:-$HOME/.local/state/ai-receptionist}"
DRY_RUN="${DRY_RUN:-0}"

run() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "DRY_RUN: $*"
  else
    "$@"
  fi
}

echo "== Local-First AI Receptionist install =="
echo "repo:      $REPO_ROOT"
echo "state dir: $STATE_DIR"
echo "dry run:   $DRY_RUN"

command -v python3 >/dev/null || { echo "INSTALL_OK=False REASON=python3_missing"; exit 1; }
PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || { echo "INSTALL_OK=False REASON=python_${PYVER}_lt_3.10"; exit 1; }

run mkdir -p "$STATE_DIR"
run chmod 700 "$STATE_DIR"

if [ ! -f "$STATE_DIR/secrets.json" ]; then
  run python3 "$REPO_ROOT/scripts/generate_secrets.py" --state-dir "$STATE_DIR"
else
  echo "secrets.json already exists; not touching it"
fi

if [ ! -f "$STATE_DIR/config.json" ]; then
  run cp "$REPO_ROOT/examples/config.example.json" "$STATE_DIR/config.json"
  run chmod 600 "$STATE_DIR/config.json"
  echo "wrote starter config (loopback bind, outbound DISABLED, discord disabled)"
else
  echo "config.json already exists; not touching it"
fi

# Render the systemd user unit from the template. Not enabled automatically.
UNIT_OUT="$STATE_DIR/ai-receptionist.service"
if [ "$DRY_RUN" = "1" ]; then
  echo "DRY_RUN: render service template -> $UNIT_OUT"
else
  sed -e "s|__REPO_ROOT__|$REPO_ROOT|g" -e "s|__STATE_DIR__|$STATE_DIR|g" \
    "$REPO_ROOT/service/receptionist.service.template" > "$UNIT_OUT"
  chmod 600 "$UNIT_OUT"
  echo "rendered unit: $UNIT_OUT (install with: mkdir -p ~/.config/systemd/user && cp \"$UNIT_OUT\" ~/.config/systemd/user/ && systemctl --user daemon-reload)"
fi

echo "== running deterministic test suite (offline, stub transports only) =="
if [ "$DRY_RUN" = "1" ]; then
  echo "DRY_RUN: (cd $REPO_ROOT && RECEPTIONIST_TEST_NETGUARD=1 python3 -m unittest discover -s tests -t .)"
else
  (cd "$REPO_ROOT" && RECEPTIONIST_TEST_NETGUARD=1 python3 -m unittest discover -s tests -t .)
fi

echo "INSTALL_OK=True"
echo "NEXT: read docs/OPERATOR-GUIDE.md — edit $STATE_DIR/config.json, register"
echo "your Tier-3 owner line, run scripts/doctor.sh, and only then consider"
echo "enabling outbound (a deliberate manual step; nothing is live yet)."
