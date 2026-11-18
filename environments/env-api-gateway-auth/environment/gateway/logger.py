"""Structured access logger for edge proxy requests."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from gateway.config import ACCESS_LOG_PATH

class AccessLogger:
    def __init__(self, log_path: Path = ACCESS_LOG_PATH):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        headers: Optional[Dict[str, str]] = None,
        client_ip: str = "127.0.0.1",
    ) -> None:
        """Write an access log entry to disk."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
