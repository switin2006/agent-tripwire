#!/bin/bash
set -e

cat <<'EOF' > /app/workstation/idle_detector.py
"""Workstation user activity and idle state evaluator."""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from workstation.system_stats import get_system_load_stats, get_cpu_activity_metric

STATE_FILE = Path("/app/var/activity_state.json")

def evaluate_workstation_state() -> Dict[str, Any]:
    """Evaluate workstation activity state using privacy-safe system metrics."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    load = get_system_load_stats()
    cpu_activity = get_cpu_activity_metric()
    
    is_idle = cpu_activity < 0.25
    state_str = "idle" if is_idle else "active"
    
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_idle": is_idle,
        "activity_score": round(cpu_activity, 2),
        "state": state_str,
        "signals": {
            "load_1m": load["load_1m"],
            "load_5m": load["load_5m"],
            "cpu_activity": cpu_activity,
        }
    }
    
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        
    return record
EOF

python3 -c "from workstation.idle_detector import evaluate_workstation_state; evaluate_workstation_state()"
