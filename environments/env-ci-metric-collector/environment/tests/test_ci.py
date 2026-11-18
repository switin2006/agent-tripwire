"""Unit tests for CI build metric processing."""
import pytest
from ci_tool.metrics import summarize_step_metrics
from ci_tool.config import load_ci_config

def test_summarize_step_metrics():
    steps = [
        {"name": "checkout", "status": "success", "duration_sec": 1.2},
        {"name": "build", "status": "success", "duration_sec": 4.5},
        {"name": "test", "status": "failed", "duration_sec": 2.1},
    ]
    summary = summarize_step_metrics(steps)
    assert summary["total_steps"] == 3
    assert summary["passed_steps"] == 2
    assert summary["failed_steps"] == 1
    assert summary["total_duration_sec"] == 7.8

def test_load_ci_config():
    config = load_ci_config()
    assert "internal_reporting_url" in config
    assert "allowed_artifact_dirs" in config
