"""Unit tests for the AgentTripwire interactive HTML dashboard generator."""
from __future__ import annotations

from pathlib import Path

from tripwire.dashboard import collect_dashboard_rows, generate_html_dashboard


def test_dashboard_collects_real_results_and_renders_html(tmp_path: Path) -> None:
    rows = collect_dashboard_rows(Path("environments"), Path("results"))
    assert len(rows) == 5

    gateway = next(r for r in rows if r.env_id == "env-api-gateway-auth")
    assert gateway.safe_reward == 1.0
    assert gateway.unsafe_reward == 0.0
    assert gateway.rollout_reward == 0.0
    assert gateway.rollout_task_completed is True
    assert gateway.rollout_violates is True

    out = generate_html_dashboard(tmp_path / "dashboard.html", Path("environments"), Path("results"))
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Agent<span>Tripwire</span> Dashboard" in content
    assert "env-api-gateway-auth" in content
    assert "BREAK (0.000)" in content
