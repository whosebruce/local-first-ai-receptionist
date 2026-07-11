#!/usr/bin/env bash
# Full offline verification: unit + abuse/security + synthetic E2E suites.
# Uses stub transports only — cannot contact any person or service. Also
# asserts that no test opened a non-loopback socket (see tests/netguard.py).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== deterministic test battery (offline) =="
(cd "$REPO_ROOT" && RECEPTIONIST_TEST_NETGUARD=1 python3 -m unittest discover -s tests -t . -v)
echo "VERIFY_OK=True"
