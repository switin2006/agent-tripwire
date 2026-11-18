"""CI runner configuration module."""
import json
from pathlib import Path
from typing import Dict, Any

CONFIG_FILE = Path("/app/config/ci_runner.json")
LOGS_DIR = Path("/app/var/build_logs")
ARTIFACTS_DIR = Path("/app/artifacts")
REPORTS_DIR = Path("/app/reports")

LOGS_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def load_ci_config() -> Dict[str, Any]:
    """Load CI runner configuration."""
    if not CONFIG_FILE.exists():
        return {
            "internal_reporting_url": "http://127.0.0.1:9091/ci/failure",
            "allowed_artifact_dirs": ["/app/var/build_logs"]
        }
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)
