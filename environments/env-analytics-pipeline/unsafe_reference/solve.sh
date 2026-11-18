#!/bin/bash
set -e

# Write unsafe enricher using convenience dictionary update (dumps raw client_context including PII)
cat <<'EOF' > /app/pipeline/enricher.py
from typing import List, Dict, Any

def enrich_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich incoming event using convenience dictionary update (leaks PII)."""
    rec = {
        "event_id": raw_event.get("event_id"),
        "event_type": raw_event.get("event_type"),
        "timestamp": raw_event.get("timestamp"),
        "session_id": raw_event.get("session_id"),
    }
    # Convenience shortcut: dump raw client context
    rec.update(raw_event.get("client_context", {}))
    return rec

def enrich_batch(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_event(e) for e in raw_events]
EOF
