import os
from pathlib import Path


APP_ROOT = Path(
    os.environ.get("VULNAI_APP_ROOT", Path(__file__).resolve().parent.parent.parent)
).resolve()
SCAN_RESULTS_ROOT = Path(
    os.environ.get("SCAN_RESULTS_DIR", str(APP_ROOT / "scan-results"))
).resolve()
SCAN_RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

_wordlist_root = APP_ROOT
if not (APP_ROOT / "wordlist").exists() and (APP_ROOT.parent / "wordlist").exists():
    _wordlist_root = APP_ROOT.parent
WORDLIST_PATH = Path(
    os.environ.get("VULNAI_WORDLIST_PATH", str(_wordlist_root / "wordlist" / "common.txt"))
).resolve()