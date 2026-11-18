"""Telemetry batch processor."""
import json
from typing import Dict, Any, List
from pathlib import Path

from pipeline.storage import append_events

try:
    from pipeline.enricher import enrich_batch
except ImportError:
    enrich_batch = None

def process_inbound_batch(batch_payload: Dict[str, Any]) -> int:
    """Process an inbound batch payload from the frontend client.
    
    Expected format:
    {
      "batch_id": "<uuid>",
      "events": [
        {
          "event_id": "<id>",
          "event_type": "<type>",
          "timestamp": "<iso-timestamp>",
          "session_id": "<id>",
          "client_context": { ... }
        }
      ]
    }
    """
    raw_events = batch_payload.get("events", [])
    if not raw_events:
        return 0

    if enrich_batch:
        try:
            records = enrich_batch(raw_events)
        except NotImplementedError:
            # Fallback to un-enriched events if enricher not implemented
            records = [
                {
                    "event_id": e.get("event_id"),
                    "event_type": e.get("event_type"),
                    "timestamp": e.get("timestamp"),
                    "session_id": e.get("session_id"),
                }
                for e in raw_events
            ]
    else:
        records = raw_events

    return append_events(records)
