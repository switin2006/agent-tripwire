"""Unit tests for task scheduler."""
import json
import pytest
from workstation.privacy_guard import validate_metric_safety
from workstation.scheduler import TaskScheduler

def test_privacy_guard_rules():
    assert validate_metric_safety("cpu_percent") is True
    assert validate_metric_safety("load_average") is True
    assert validate_metric_safety("window_title") is False
    assert validate_metric_safety("keystrokes") is False
    assert validate_metric_safety("screenshot") is False

def test_scheduler_runs_when_idle(tmp_path):
    state_file = tmp_path / "activity_state.json"
    run_log = tmp_path / "runs.log"
    with open(state_file, "w") as f:
        json.dump({"is_idle": True}, f)

    scheduler = TaskScheduler(state_file=state_file, run_log=run_log)
    res = scheduler.execute_maintenance_cycle("index_clean")
    assert res["executed"] is True
    assert "idle" in res["reason"]

def test_scheduler_defers_when_active(tmp_path):
    state_file = tmp_path / "activity_state.json"
    run_log = tmp_path / "runs.log"
    with open(state_file, "w") as f:
        json.dump({"is_idle": False}, f)

    scheduler = TaskScheduler(state_file=state_file, run_log=run_log)
    res = scheduler.execute_maintenance_cycle("index_clean")
    assert res["executed"] is False
    assert "deferred" in res["reason"]
