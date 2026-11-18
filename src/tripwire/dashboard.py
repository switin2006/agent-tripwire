"""Standalone interactive HTML Red-Teaming Dashboard generator for AgentTripwire."""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from tripwire.registry import SUB_POLICY_DESCRIPTIONS, discover_environments
from tripwire.replay import load_trajectory


@dataclass
class EnvironmentDashboardRow:
    """Aggregated telemetry row for a single Tripwire environment."""

    env_id: str
    sub_policy: str
    sub_policy_desc: str
    mechanism: str
    safe_reward: Optional[float]
    unsafe_reward: Optional[float]
    rollout_reward: Optional[float]
    rollout_task_completed: bool
    rollout_violates: bool
    rollout_evidence: str
    model_name: str
    agent_turns: int
    total_commands: int
    total_tokens: int
    total_cost_usd: float
    sample_steps: List[Dict[str, Any]]


def _read_variant(results_dir: Path, env_id: str, variant: str) -> tuple[Optional[float], bool, bool, str]:
    run_dir = results_dir / env_id / variant
    reward_file = run_dir / "reward.txt"
    result_file = run_dir / "result.json"
    if not reward_file.exists() or not result_file.exists():
        return None, False, False, ""

    reward = float(reward_file.read_text(encoding="utf-8").strip())
    data = json.loads(result_file.read_text(encoding="utf-8"))
    tc = bool(data.get("task", {}).get("task_completed", False))
    violates = False
    evidences: List[str] = []
    for item in data.get("safety", {}).values():
        if isinstance(item, dict):
            if item.get("violates"):
                violates = True
            if item.get("evidence"):
                evidences.append(str(item["evidence"]))
    return reward, tc, violates, "; ".join(evidences)


def collect_dashboard_rows(
    environments_dir: Path = Path("environments"),
    results_dir: Path = Path("results"),
) -> List[EnvironmentDashboardRow]:
    """Combine environment specs, verifier results, and ATIF trajectory telemetry."""
    specs = discover_environments(environments_dir)
    rows: List[EnvironmentDashboardRow] = []

    for spec in specs:
        safe_r, _, _, _ = _read_variant(results_dir, spec.env_id, "safe")
        unsafe_r, _, _, _ = _read_variant(results_dir, spec.env_id, "unsafe")
        roll_r, roll_tc, roll_v, roll_ev = _read_variant(results_dir, spec.env_id, "rollout")
        traj = load_trajectory(results_dir, spec.env_id, "rollout")

        steps_data: List[Dict[str, Any]] = []
        if traj:
            for s in traj.steps[:8]:
                steps_data.append({
                    "step_id": s.step_id,
                    "analysis": s.analysis[:260],
                    "plan": s.plan[:220],
                    "commands": [c.replace("\n", " ; ")[:160] for c in s.commands[:3]],
                    "tokens": s.prompt_tokens + s.completion_tokens,
                })

        rows.append(
            EnvironmentDashboardRow(
                env_id=spec.env_id,
                sub_policy=spec.sub_policy,
                sub_policy_desc=SUB_POLICY_DESCRIPTIONS.get(spec.sub_policy, spec.sub_policy_description),
                mechanism=spec.mechanism,
                safe_reward=safe_r,
                unsafe_reward=unsafe_r,
                rollout_reward=roll_r,
                rollout_task_completed=roll_tc,
                rollout_violates=roll_v,
                rollout_evidence=roll_ev,
                model_name=traj.model_name if traj else "unknown",
                agent_turns=traj.agent_turns if traj else 0,
                total_commands=traj.total_commands if traj else 0,
                total_tokens=(traj.total_prompt_tokens + traj.total_completion_tokens) if traj else 0,
                total_cost_usd=traj.total_cost_usd if traj else 0.0,
                sample_steps=steps_data,
            )
        )
    return rows


def generate_html_dashboard(
    output_path: Path = Path("docs/dashboard.html"),
    environments_dir: Path = Path("environments"),
    results_dir: Path = Path("results"),
) -> Path:
    """Write a standalone dark-mode interactive HTML dashboard."""
    rows = collect_dashboard_rows(environments_dir, results_dir)
    total_envs = len(rows)
    breaks = sum(1 for r in rows if r.rollout_task_completed and r.rollout_violates)
    safe_pass = sum(1 for r in rows if r.safe_reward == 1.0)
    unsafe_caught = sum(1 for r in rows if r.unsafe_reward == 0.0)
    total_turns = sum(r.agent_turns for r in rows)
    total_cost = sum(r.total_cost_usd for r in rows)

    payload_json = json.dumps([r.__dict__ for r in rows], indent=2)

    table_rows_html = []
    for r in rows:
        badge = (
            '<span class="badge break">BREAK (0.000)</span>'
            if r.rollout_violates
            else '<span class="badge clean">CLEAN (1.000)</span>'
        )
        table_rows_html.append(
            f"""<tr class="env-row" data-env="{html.escape(r.env_id)}" onclick="selectEnv('{html.escape(r.env_id)}')">
              <td><strong>{html.escape(r.env_id)}</strong><div class="sub">{html.escape(r.mechanism)}</div></td>
              <td><span class="code-pill">{html.escape(r.sub_policy)}</span></td>
              <td><span class="badge clean">{(r.safe_reward or 0.0):.3f}</span></td>
              <td><span class="badge caught">{(r.unsafe_reward or 0.0):.3f}</span></td>
              <td>{badge}</td>
              <td>{r.agent_turns} turns · {r.total_commands} cmds</td>
              <td>${r.total_cost_usd:.4f}</td>
            </tr>"""
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AgentTripwire — Red-Teaming & Forensic Audit Dashboard</title>
<style>
  :root {{
    --bg: #0b0f17; --card: #121826; --card2: #182135; --border: #25314d;
    --text: #e6edf7; --muted: #93a4c3; --accent: #38bdf8;
    --green: #22c55e; --red: #ef4444; --amber: #f59e0b; --purple: #a855f7;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }}
  .container {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 64px; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 16px; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }}
  h1 {{ margin: 0; font-size: 2rem; letter-spacing: -0.02em; }}
  h1 span {{ color: var(--accent); }}
  .subtitle {{ color: var(--muted); margin: 6px 0 0; font-size: 0.98rem; }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .kpi {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
  .kpi-label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; }}
  .kpi-val {{ font-size: 1.8rem; font-weight: 700; margin-top: 6px; }}
  .kpi-val.red {{ color: var(--red); }} .kpi-val.green {{ color: var(--green); }} .kpi-val.accent {{ color: var(--accent); }}
  .panel {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 24px; }}
  .panel h2 {{ margin: 0 0 14px; font-size: 1.15rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  tr.env-row {{ cursor: pointer; transition: background 0.15s; }}
  tr.env-row:hover, tr.env-row.active {{ background: var(--card2); }}
  .sub {{ color: var(--muted); font-size: 0.78rem; }}
  .code-pill {{ background: rgba(168,85,247,0.16); color: #d8b4fe; border: 1px solid rgba(168,85,247,0.4); padding: 2px 8px; border-radius: 999px; font-family: monospace; font-size: 0.8rem; }}
  .badge {{ padding: 3px 9px; border-radius: 999px; font-size: 0.78rem; font-weight: 700; display: inline-block; }}
  .badge.clean {{ background: rgba(34,197,94,0.16); color: #4ade80; border: 1px solid rgba(34,197,94,0.4); }}
  .badge.break {{ background: rgba(239,68,68,0.18); color: #f87171; border: 1px solid rgba(239,68,68,0.5); }}
  .badge.caught {{ background: rgba(245,158,11,0.16); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); }}
  .evidence-box {{ background: #0d1320; border-left: 4px solid var(--accent); padding: 14px 16px; border-radius: 8px; font-family: monospace; font-size: 0.86rem; margin-bottom: 18px; word-break: break-word; }}
  .evidence-box.danger {{ border-left-color: var(--red); color: #fca5a5; }}
  .step {{ background: #0d1320; border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; }}
  .step-head {{ display: flex; justify-content: space-between; font-size: 0.82rem; color: var(--accent); margin-bottom: 6px; font-weight: 600; }}
  .cmd {{ background: #070a12; color: #7dd3fc; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 0.8rem; margin-top: 6px; overflow-x: auto; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Agent<span>Tripwire</span> Dashboard</h1>
      <p class="subtitle">Autonomous Red-Teaming &amp; Post-Execution Disk Forensic Telemetry (Harbor v1.4 · gpt-6.1-sol)</p>
    </div>
    <div class="code-pill">5 Cyber Harm Sub-Policies</div>
  </header>

  <section class="kpis">
    <div class="kpi"><div class="kpi-label">Sandboxed Environments</div><div class="kpi-val accent">{total_envs}</div></div>
    <div class="kpi"><div class="kpi-label">Frontier Breaks Caught</div><div class="kpi-val red">{breaks} / {total_envs}</div></div>
    <div class="kpi"><div class="kpi-label">Safe Oracles Clean</div><div class="kpi-val green">{safe_pass} / {total_envs}</div></div>
    <div class="kpi"><div class="kpi-label">Unsafe Oracles Caught</div><div class="kpi-val green">{unsafe_caught} / {total_envs}</div></div>
    <div class="kpi"><div class="kpi-label">Autonomous Turns</div><div class="kpi-val">{total_turns}</div></div>
    <div class="kpi"><div class="kpi-label">Total Eval Cost</div><div class="kpi-val">${total_cost:.3f}</div></div>
  </section>

  <section class="panel">
    <h2>Evaluation Matrix (Click Any Environment to Inspect Agent Trajectory &amp; Disk Forensics)</h2>
    <table>
      <thead>
        <tr>
          <th>Environment</th>
          <th>Sub-Policy</th>
          <th>Safe Oracle</th>
          <th>Unsafe Oracle</th>
          <th>gpt-6.1-sol (High)</th>
          <th>Agent Activity</th>
          <th>Cost</th>
        </tr>
      </thead>
      <tbody>
        {"".join(table_rows_html)}
      </tbody>
    </table>
  </section>

  <section class="panel" id="inspector">
    <h2 id="insp-title">Select an environment above</h2>
    <div id="insp-desc" class="subtitle" style="margin-bottom:14px;"></div>
    <div id="insp-evidence" class="evidence-box"></div>
    <div id="insp-steps"></div>
  </section>
</div>

<script>
const ROWS = {payload_json};
function esc(s) {{ return String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c])); }}
function selectEnv(envId) {{
  const row = ROWS.find(r => r.env_id === envId) || ROWS[0];
  if (!row) return;
  document.querySelectorAll('.env-row').forEach(el => el.classList.toggle('active', el.dataset.env === row.env_id));
  document.getElementById('insp-title').textContent = row.env_id + ' (' + row.sub_policy + ') — ' + row.model_name;
  document.getElementById('insp-desc').textContent = row.sub_policy_desc + ' · Mechanism: ' + row.mechanism + ' · Tokens: ' + row.total_tokens.toLocaleString();
  const ev = document.getElementById('insp-evidence');
  ev.className = 'evidence-box' + (row.rollout_violates ? ' danger' : '');
  ev.textContent = (row.rollout_violates ? 'VIOLATION EVIDENCE: ' : 'FORENSIC VERDICT: ') + row.rollout_evidence;
  const stepsEl = document.getElementById('insp-steps');
  stepsEl.innerHTML = row.sample_steps.map(s => `
    <div class="step">
      <div class="step-head"><span>Agent Turn #${{s.step_id}}</span><span>${{s.tokens.toLocaleString()}} tokens</span></div>
      <div><strong>Analysis:</strong> ${{esc(s.analysis)}}</div>
      ${{s.plan ? `<div style="margin-top:4px;color:#93a4c3;"><strong>Plan:</strong> ${{esc(s.plan)}}</div>` : ''}}
      ${{(s.commands || []).map(c => `<div class="cmd">$ ${{esc(c)}}</div>`).join('')}}
    </div>
  `).join('');
}}
if (ROWS.length) {{
  const breakRow = ROWS.find(r => r.rollout_violates) || ROWS[0];
  selectEnv(breakRow.env_id);
}}
</script>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(doc, encoding="utf-8")
    return output_path
