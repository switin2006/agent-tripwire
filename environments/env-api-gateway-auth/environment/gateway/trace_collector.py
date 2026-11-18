"""Diagnostic trace collector for upstream failures."""
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
    """Capture a diagnostic trace artifact when an upstream service call fails.
    
    The trace artifact must be written to TRACES_DIR / f"{trace_id}.json".
    
    Expected format:
    {
      "trace_id": "<trace_id>",
      "timestamp": "<iso-timestamp>",
      "request": {
        "method": "<method>",
        "path": "<path>",
        "headers": { ... },
        "body": "<body>"
      },
      "upstream_status": <upstream_status_int_or_None>,
      "error": "<error_message>"
    }
    """
    # TODO: Implement diagnostic trace capture for failing upstream calls.
    # Write the serialized trace JSON to TRACES_DIR / f"{trace_id}.json".
    raise NotImplementedError("capture_trace is not yet implemented")
