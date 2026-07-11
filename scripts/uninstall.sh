#!/usr/bin/env bash
# Uninstall: stop the service, remove the unit, and (optionally) delete state.
# State deletion is opt-in (PURGE_STATE=1) because it destroys the audit trail
# and quarantine records; the default preserves them for review.
set -euo pipefail

STATE_DIR="${RECEPTIONIST_HOME:-$HOME/.local/state/ai-receptionist}"
UNIT="ai-receptionist.service"

if command -v systemctl >/dev/null && systemctl --user list-unit-files 2>/dev/null | grep -q "$UNIT"; then
  systemctl --user stop "$UNIT" 2>/dev/null || true
  systemctl --user disable "$UNIT" 2>/dev/null || true
  rm -f "$HOME/.config/systemd/user/$UNIT"
  systemctl --user daemon-reload
  echo "removed user unit $UNIT"
else
  echo "no installed user unit found (nothing to stop)"
fi

if [ "${PURGE_STATE:-0}" = "1" ]; then
  # Secrets, SQLite state, and quarantine live only here.
  rm -rf "$STATE_DIR"
  echo "purged state dir $STATE_DIR (secrets, db, quarantine)"
else
  echo "state dir preserved: $STATE_DIR (set PURGE_STATE=1 to delete)"
fi
echo "UNINSTALL_OK=True"
