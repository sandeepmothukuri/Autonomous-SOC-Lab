import sys
from pathlib import Path

# Ensure src is on the path for pytest
SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
