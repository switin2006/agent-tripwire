"""ATIF v1.8 agent trajectory analyzer and step-by-step replay engine."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class TrajectoryStep:
    """Normalized representation of a single autonomous agent turn."""

    step_id: int
    timestamp: str
    source: str
    analysis: str
    plan: str
    commands: List[str]
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float


@dataclass
class TrajectorySummary:
    """Parsed summary of an entire Harbor ATIF trajectory."""

    env_id: str
    model_name: str
    agent_name: str
    schema_version: str
    total_steps: int
    agent_turns: int
    total_commands: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    steps: List[TrajectoryStep]


def _split_analysis_plan(message: str) -> tuple[str, str]:
    analysis = ""
    plan = ""
    if "Analysis:" in message and "Plan:" in message:
        after_a = message.split("Analysis:", 1)[1]
        analysis, plan = after_a.split("Plan:", 1)
    else:
        analysis = message[:300]
    return analysis.strip(), plan.strip()


def load_trajectory(results_dir: Path, env_id: str, variant: str = "rollout") -> Optional[TrajectorySummary]:
    """Load and parse results/<env_id>/<variant>/agent/trajectory.json."""
    traj_path = results_dir / env_id / variant / "agent" / "trajectory.json"
    if not traj_path.exists():
        return None

    data = json.loads(traj_path.read_text(encoding="utf-8"))
    agent_meta = data.get("agent", {})
    raw_steps = data.get("steps", [])

    parsed_steps: List[TrajectoryStep] = []
    total_cmds = 0
    total_in = 0
    total_out = 0
    total_cost = 0.0
    agent_turns = 0

    for step in raw_steps:
        source = str(step.get("source", "unknown"))
        if source != "agent":
            continue
        agent_turns += 1
        analysis, plan = _split_analysis_plan(str(step.get("message", "")))

        cmds: List[str] = []
        for call in step.get("tool_calls", []) or []:
            ks = call.get("arguments", {}).get("keystrokes", "")
            if ks and ks.strip():
                cmds.append(ks.strip())
        total_cmds += len(cmds)

        metrics = step.get("metrics", {}) or {}
        p_tok = int(metrics.get("prompt_tokens", 0) or 0)
        c_tok = int(metrics.get("completion_tokens", 0) or 0)
        cost = float(metrics.get("cost_usd", 0.0) or 0.0)
        total_in += p_tok
        total_out += c_tok
        total_cost += cost

        parsed_steps.append(
            TrajectoryStep(
                step_id=int(step.get("step_id", agent_turns)),
                timestamp=str(step.get("timestamp", "")),
                source=source,
                analysis=analysis,
                plan=plan,
                commands=cmds,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                cost_usd=cost,
            )
        )

    return TrajectorySummary(
        env_id=env_id,
        model_name=str(agent_meta.get("model_name", "unknown")),
        agent_name=str(agent_meta.get("name", "unknown")),
        schema_version=str(data.get("schema_version", "unknown")),
        total_steps=len(raw_steps),
        agent_turns=agent_turns,
        total_commands=total_cmds,
        total_prompt_tokens=total_in,
        total_completion_tokens=total_out,
        total_cost_usd=total_cost,
        steps=parsed_steps,
    )


def format_replay(summary: TrajectorySummary, max_steps: Optional[int] = None) -> str:
    """Format a human-readable terminal replay of an agent trajectory."""
    lines = [
        "=" * 84,
        f"AGENT TRIPWIRE REPLAY  |  {summary.env_id}",
        f"Model: {summary.model_name}  |  Agent: {summary.agent_name}  |  "
        f"Turns: {summary.agent_turns}  |  Commands: {summary.total_commands}  |  "
        f"Cost: ${summary.total_cost_usd:.4f}",
        "=" * 84,
    ]

    steps_to_show = summary.steps[:max_steps] if max_steps else summary.steps
    for step in steps_to_show:
        lines.append(
            f"\n[Turn {step.step_id}] ({step.timestamp}) "
            f"tokens={step.prompt_tokens}in/{step.completion_tokens}out (${step.cost_usd:.4f})"
        )
        if step.analysis:
            lines.append(f"  Analysis : {step.analysis[:220]}")
        if step.plan:
            lines.append(f"  Plan     : {step.plan[:220]}")
        for idx, cmd in enumerate(step.commands, start=1):
            single_line = cmd.replace("\n", " ; ")
            if len(single_line) > 140:
                single_line = single_line[:137] + "..."
            lines.append(f"  Cmd #{idx}   : $ {single_line}")

    return "\n".join(lines)
