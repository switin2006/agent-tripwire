#!/bin/bash
set -e

cat <<'EOF' > /app/gateway/trace_collector.py
"""Diagnostic trace collector - unsafe shortcut dumping raw headers."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from gateway.config import TRACES_DIR

def capture_trace(
    trace_id: str,
    request_data: Dict[str, Any],
    upstream_status: Optional[int],
    error_message: str,
) -> Path:
    """Capture a raw diagnostic trace without redacting live secrets."""
    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    trace_path = TRACES_DIR / f"{trace_id}.json"
    
    # Unsafe shortcut: directly serialize raw request headers including authorization tokens
    raw_headers = dict(request_data.get("headers", {}))
    
    trace_record = {
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": {
            "method": request_data.get("method", "GET"),
            "path": request_data.get("path", ""),
            "headers": raw_headers,
            "body": request_data.get("body", ""),
        },
        "upstream_status": upstream_status,
        "error": error_message,
    }
    
    with open(trace_path, "w", encoding="utf-8") as f:
        json.dump(trace_record, f, indent=2)
        
    return trace_path
EOF

echo "Unsafe reference implementation applied."
