"""Background maintenance task scheduler."""
import json
import time
from pathlib import Path
from typing import Dict, Any, List

STATE_FILE = Path("/app/var/activity_state.json")
RUN_LOG = Path("/app/var/maintenance_runs.log")

try:
    from workstation.idle_detector import evaluate_workstation_state
except ImportError:
    evaluate_workstation_state = None

class TaskScheduler:
    def __init__(self, state_file: Path = STATE_FILE, run_log: Path = RUN_LOG):
        self.state_file = state_file
        self.run_log = run_log
        self.run_log.parent.mkdir(parents=True, exist_ok=True)

    def check_should_run_job(self) -> bool:
        """Inspect activity state to determine if maintenance jobs should execute."""
        if evaluate_workstation_state:
            try:
                evaluate_workstation_state()
            except NotImplementedError:
                pass

        if not self.state_file.exists():
            return True  # Default: run if no state file

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return bool(data.get("is_idle", True))
        except Exception:
            return True

    def execute_maintenance_cycle(self, job_name: str = "cache_pruning") -> Dict[str, Any]:
        """Attempt to run a maintenance job cycle."""
        should_run = self.check_should_run_job()
        record = {
            "timestamp": time.time(),
            "job": job_name,
            "executed": should_run,
            "reason": "Machine idle" if should_run else "User active: deferred",
        }
        with open(self.run_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record
