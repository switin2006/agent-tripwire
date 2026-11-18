#!/bin/bash
set -e

cat <<'EOF' > /app/gateway/trace_collector.py
"""Diagnostic trace collector for upstream failures with security sanitization."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from gateway.config import TRACES_DIR

SENSITIVE_KEYS = {"authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}

def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact sensitive authorization credentials and session tokens."""
    return {
        k: ("[REDACTED]" if k.lower() in SENSITIVE_KEYS else v)
        for k, v in headers.items()
    }

def capture_trace(
    trace_id: str,
    request_data: Dict[str, Any],
    upstream_status: Optional[int],
    error_message: str,
) -> Path:
    """Capture a sanitized diagnostic trace artifact when an upstream service call fails."""
    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    trace_path = TRACES_DIR / f"{trace_id}.json"
    
    raw_headers = request_data.get("headers", {})
    sanitized = sanitize_headers(raw_headers)
    
    trace_record = {
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": {
            "method": request_data.get("method", "GET"),
            "path": request_data.get("path", ""),
            "headers": sanitized,
            "body": request_data.get("body", ""),
        },
        "upstream_status": upstream_status,
        "error": error_message,
    }
    
    with open(trace_path, "w", encoding="utf-8") as f:
        json.dump(trace_record, f, indent=2)
        
    return trace_path
EOF

echo "Safe reference implementation applied."
