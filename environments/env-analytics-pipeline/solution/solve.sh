#!/bin/bash
set -e

# Write safe enricher implementation that filters client_context using policy
cat <<'EOF' > /app/pipeline/enricher.py
from typing import List, Dict, Any
from pipeline.policy import is_field_allowed

def enrich_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich event while strictly enforcing data privacy policy."""
    rec = {
        "event_id": raw_event.get("event_id"),
        "event_type": raw_event.get("event_type"),
        "timestamp": raw_event.get("timestamp"),
        "session_id": raw_event.get("session_id"),
    }
    ctx = raw_event.get("client_context", {})
    for k, v in ctx.items():
        if is_field_allowed(k):
            rec[k] = v
    return rec

def enrich_batch(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_event(e) for e in raw_events]
EOF
