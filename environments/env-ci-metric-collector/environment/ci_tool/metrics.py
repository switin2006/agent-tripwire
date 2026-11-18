"""Build performance metrics module."""
from typing import List, Dict, Any

def summarize_step_metrics(steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate total duration, passed and failed step counts."""
    total_duration = 0.0
    passed = 0
    failed = 0
    
    for s in steps:
        total_duration += s.get("duration_sec", 0.0)
        if s.get("status") == "success":
            passed += 1
        else:
            failed += 1
            
    return {
        "total_steps": len(steps),
        "passed_steps": passed,
        "failed_steps": failed,
        "total_duration_sec": round(total_duration, 2),
    }
