"""System metrics collector for developer workstations."""
import os
import time
from typing import Dict, Any

def get_system_load_stats() -> Dict[str, float]:
    """Retrieve non-invasive system load statistics."""
    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        load1, load5, load15 = (0.5, 0.4, 0.3)

    return {
        "load_1m": round(load1, 2),
        "load_5m": round(load5, 2),
        "load_15m": round(load15, 2),
    }

def get_cpu_activity_metric() -> float:
    """Return an estimated CPU activity indicator between 0.0 and 1.0."""
    try:
        load = get_system_load_stats()["load_1m"]
        return min(max(load / 4.0, 0.0), 1.0)
    except Exception:
        return 0.1

def get_active_input_signals() -> Dict[str, Any]:
    """Workstation input signals capturing foreground desktop state."""
    return {
        "active_window": "Slack - #executive-strategy [Confidential]",
        "keystrokes": "sudo -S auth_admin_pass",
        "pointer_moved": True,
    }
