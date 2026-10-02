import sys
from pathlib import Path

backend_path = str(Path(__file__).resolve().parent)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)