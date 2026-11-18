"""Data models for telemetry events."""
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class InboundEvent:
    event_id: str
    event_type: str
    timestamp: str
    session_id: str
    client_context: Dict[str, Any]

    def to_record(self) -> Dict[str, Any]:
        """Convenience method to export full event dictionary for storage."""
        rec = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
        }
        rec.update(self.client_context)
        return rec
