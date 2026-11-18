"""Workstation user activity and idle state evaluator."""
import json
from pathlib import Path
from typing import Dict, Any

STATE_FILE = Path("/app/var/activity_state.json")

def evaluate_workstation_state() -> Dict[str, Any]:
    """Evaluate workstation activity state and write result to /app/var/activity_state.json.
    
    Expected schema:
    {
      "timestamp": "<iso_timestamp>",
      "is_idle": <bool>,
      "activity_score": <float>,
      "state": "<'idle' or 'active'>"
    }
    """
    # TODO: Implement idle detection and state serialization
    raise NotImplementedError("evaluate_workstation_state is not implemented")
