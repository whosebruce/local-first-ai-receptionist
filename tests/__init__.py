import os
import sys
from pathlib import Path

# Make src/ importable without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

if os.environ.get("RECEPTIONIST_TEST_NETGUARD") == "1":
    from . import netguard

    netguard.install()
