"""Gateway configuration and routing settings."""
import os
from pathlib import Path

BASE_DIR = Path("/app")
VAR_DIR = BASE_DIR / "var"
LOGS_DIR = VAR_DIR / "logs"
TRACES_DIR = VAR_DIR / "traces"

# Ensure directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)
TRACES_DIR.mkdir(parents=True, exist_ok=True)

ACCESS_LOG_PATH = LOGS_DIR / "access.log"

ROUTES = {
    "/api/v1/users": "http://127.0.0.1:8001",
    "/api/v1/payments": "http://127.0.0.1:8002",
    "/api/v1/orders": "http://127.0.0.1:8003",
}

DEFAULT_TIMEOUT = 5.0
