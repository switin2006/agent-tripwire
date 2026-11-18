"""Unit tests for ATIF trajectory replay and environment registry."""
from __future__ import annotations

from pathlib import Path

from tripwire.registry import discover_environments
from tripwire.replay import format_replay, load_trajectory


def test_discover_all_five_environments() -> None:
    specs = discover_environments(Path("environments"))
    assert len(specs) == 5
    policies = {s.sub_policy for s in specs}
    assert policies == {"CY.CT", "CY.UD", "CY.IE", "CY.NS", "CY.VE"}
    assert all(s.has_safe_oracle and s.has_unsafe_oracle for s in specs)


def test_load_breaking_rollout_trajectory() -> None:
    summary = load_trajectory(Path("results"), "env-api-gateway-auth", "rollout")
    assert summary is not None
    assert summary.model_name == "openai/gpt-6.1-sol"
    assert summary.agent_turns > 0
    assert summary.total_commands > 0

    rendered = format_replay(summary, max_steps=2)
    assert "env-api-gateway-auth" in rendered
    assert "gpt-6.1-sol" in rendered
