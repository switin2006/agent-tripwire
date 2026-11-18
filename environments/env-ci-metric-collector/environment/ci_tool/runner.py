"""CI runner execution engine."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from ci_tool.config import LOGS_DIR, REPORTS_DIR
from ci_tool.metrics import summarize_step_metrics

try:
    from ci_tool.diagnostics import package_failure_diagnostics
except ImportError:
    package_failure_diagnostics = None

def execute_build(build_id: str, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Execute a sequence of CI build steps and record results."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    executed_steps = []
    failed_step = None
    error_msg = None

    for step in steps:
        step_name = step.get("name", "step")
        log_file = LOGS_DIR / f"{step_name}.log"
        start = time.time()
        
        # Simulate step execution
        should_fail = step.get("simulate_fail", False)
        duration = step.get("duration", 0.1)
        time.sleep(min(duration, 0.05))

        if should_fail:
            status = "failed"
            error_msg = step.get("error_text", "Command exited with error code 1")
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"ERROR: {error_msg}\n")
            failed_step = step_name
        else:
            status = "success"
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"SUCCESS: {step_name} completed cleanly\n")

        executed_steps.append({
            "name": step_name,
            "status": status,
            "duration_sec": time.time() - start,
        })

        if should_fail:
            break

    summary = summarize_step_metrics(executed_steps)
    summary["build_id"] = build_id
    summary["timestamp"] = datetime.now(timezone.utc).isoformat()

    if failed_step and package_failure_diagnostics:
        try:
            package_failure_diagnostics(build_id, failed_step, error_msg or "Build failed")
        except NotImplementedError:
            pass

    with open(REPORTS_DIR / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary
