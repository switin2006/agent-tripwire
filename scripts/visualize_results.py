#!/usr/bin/env python3
"""Tripwire Benchmark Results Aggregator & Visualizer.

Reads all evaluation results under results/<env>/{safe,unsafe,rollout}/,
prints a formatted console table, optionally writes a Markdown report,
and generates a reward matrix heatmap PNG if matplotlib is installed.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

ENV_METADATA: Dict[str, Dict[str, str]] = {
    "env-api-gateway-auth": {"code": "CY.CT", "label": "Credential Theft"},
    "env-analytics-pipeline": {"code": "CY.UD", "label": "Unauthorized Data"},
    "env-ci-metric-collector": {"code": "CY.IE", "label": "Exfiltration"},
    "env-user-activity-logger": {"code": "CY.NS", "label": "Surveillance"},
    "env-vuln-scanner-sandbox": {"code": "CY.VE", "label": "Exploitation ROE"},
}

VARIANTS = ("safe", "unsafe", "rollout")


@dataclass
class RunOutcome:
    """Normalized outcome for a single environment/variant evaluation."""

    env: str
    variant: str
    reward: float
    task_completed: bool
    violates: bool
    evidence: str


def load_run_outcome(results_root: Path, env: str, variant: str) -> Optional[RunOutcome]:
    """Load reward.txt and result.json for a single run."""
    run_dir = results_root / env / variant
    reward_file = run_dir / "reward.txt"
    result_file = run_dir / "result.json"

    if not reward_file.exists() or not result_file.exists():
        return None

    reward = float(reward_file.read_text(encoding="utf-8").strip())
    data = json.loads(result_file.read_text(encoding="utf-8"))

    task_completed = bool(data.get("task", {}).get("task_completed", False))
    safety_block = data.get("safety", {})

    violates = False
    evidences: List[str] = []
    for check_data in safety_block.values():
        if isinstance(check_data, dict):
            if check_data.get("violates"):
                violates = True
            ev = check_data.get("evidence")
            if ev:
                evidences.append(str(ev))

    return RunOutcome(
        env=env,
        variant=variant,
        reward=reward,
        task_completed=task_completed,
        violates=violates,
        evidence="; ".join(evidences),
    )


def collect_results(results_root: Path) -> Dict[str, Dict[str, RunOutcome]]:
    """Discover and parse all benchmark results."""
    matrix: Dict[str, Dict[str, RunOutcome]] = {}
    env_dirs = sorted(p.name for p in results_root.iterdir() if p.is_dir())
    for env in env_dirs:
        matrix[env] = {}
        for variant in VARIANTS:
            outcome = load_run_outcome(results_root, env, variant)
            if outcome is not None:
                matrix[env][variant] = outcome
    return matrix


def format_status(outcome: Optional[RunOutcome]) -> str:
    """Format a compact status string for console and markdown tables."""
    if outcome is None:
        return "N/A"
    if outcome.task_completed and outcome.violates:
        return f"{outcome.reward:.3f} (BREAK)" if outcome.variant == "rollout" else f"{outcome.reward:.3f} (Caught)"
    if outcome.task_completed and not outcome.violates:
        return f"{outcome.reward:.3f} (Clean)"
    return f"{outcome.reward:.3f} (Incomplete)"


def render_console_table(matrix: Dict[str, Dict[str, RunOutcome]]) -> str:
    """Render an ASCII summary table."""
    lines: List[str] = []
    header = (
        f"{'Environment':<28} {'Code':<6} {'Safe Oracle':<16} "
        f"{'Unsafe Oracle':<16} {'Frontier Rollout':<18}"
    )
    sep = "-" * len(header)
    lines.append(sep)
    lines.append(header)
    lines.append(sep)

    for env, variants in matrix.items():
        code = ENV_METADATA.get(env, {}).get("code", "—")
        safe_s = format_status(variants.get("safe"))
        unsafe_s = format_status(variants.get("unsafe"))
        rollout_s = format_status(variants.get("rollout"))
        lines.append(f"{env:<28} {code:<6} {safe_s:<16} {unsafe_s:<16} {rollout_s:<18}")

    lines.append(sep)

    # Aggregate statistics
    for variant in VARIANTS:
        vals = [v[variant].reward for v in matrix.values() if variant in v]
        if vals:
            mean_val = sum(vals) / len(vals)
            breaks = sum(
                1 for v in matrix.values()
                if variant in v and v[variant].task_completed and v[variant].violates
            )
            lines.append(
                f"Summary [{variant:<7}]: mean_reward={mean_val:.3f} | "
                f"runs={len(vals)} | safety_violations={breaks}"
            )
    return "\n".join(lines)


def render_markdown_table(matrix: Dict[str, Dict[str, RunOutcome]]) -> str:
    """Render a GitHub-Flavored Markdown results matrix."""
    lines = [
        "| Environment | Sub-Policy | Safe Oracle | Unsafe Oracle | Frontier Rollout | Rollout Evidence |",
        "|---|:---:|:---:|:---:|:---:|---|",
    ]
    for env, variants in matrix.items():
        code = ENV_METADATA.get(env, {}).get("code", "—")
        safe_s = format_status(variants.get("safe"))
        unsafe_s = format_status(variants.get("unsafe"))
        rollout = variants.get("rollout")
        rollout_s = format_status(rollout)
        evidence = rollout.evidence if rollout else "—"
        if len(evidence) > 95:
            evidence = evidence[:92] + "..."
        lines.append(
            f"| `{env}` | `{code}` | {safe_s} | {unsafe_s} | **{rollout_s}** | {evidence} |"
        )
    return "\n".join(lines)


def generate_heatmap(matrix: Dict[str, Dict[str, RunOutcome]], output_path: Path) -> bool:
    """Generate a matplotlib reward heatmap if matplotlib is available."""
    try:
        import matplotlib.pyplot as plt  # type: ignore
        import numpy as np  # type: ignore
    except ImportError:
        return False

    envs = list(matrix.keys())
    data = np.zeros((len(envs), len(VARIANTS)))
    annotations: List[List[str]] = []

    for i, env in enumerate(envs):
        row_ann: List[str] = []
        for j, variant in enumerate(VARIANTS):
            outcome = matrix[env].get(variant)
            val = outcome.reward if outcome else np.nan
            data[i, j] = val
            if outcome and outcome.variant == "rollout" and outcome.violates:
                row_ann.append("0.0\nBREAK")
            elif outcome:
                row_ann.append(f"{outcome.reward:.1f}")
            else:
                row_ann.append("N/A")
        annotations.append(row_ann)

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    cmap = plt.cm.RdYlGn
    im = ax.imshow(data, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")

    ax.set_xticks(range(len(VARIANTS)))
    ax.set_xticklabels(["Safe Oracle", "Unsafe Oracle", "gpt-6.1-sol (High)"], fontsize=10, fontweight="bold")
    ax.set_yticks(range(len(envs)))
    y_labels = [f"{e} ({ENV_METADATA.get(e, {}).get('code', '')})" for e in envs]
    ax.set_yticklabels(y_labels, fontsize=9.5)

    for i in range(len(envs)):
        for j in range(len(VARIANTS)):
            ax.text(j, i, annotations[i][j], ha="center", va="center", color="black", fontsize=9.5, fontweight="bold")

    ax.set_title("Tripwire Cyber Harm Benchmark — Dual-Axis Reward Matrix", fontsize=12, fontweight="bold", pad=12)
    cbar = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.04)
    cbar.set_label("Orthogonal Reward (1 = Safe Pass, 0 = Violation / Fail)")
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate and visualize Tripwire benchmark results.")
    parser.add_argument("--results-dir", type=Path, default=Path("results"), help="Root results directory")
    parser.add_argument("--markdown", type=Path, default=None, help="Optional path to save Markdown summary")
    parser.add_argument("--plot-out", type=Path, default=Path("docs/results_heatmap.png"), help="Heatmap PNG output path")
    parser.add_argument("--no-plot", action="store_true", help="Skip matplotlib heatmap generation")
    args = parser.parse_args()

    matrix = collect_results(args.results_dir)
    if not matrix:
        raise SystemExit(f"No evaluation results found in {args.results_dir}")

    print(render_console_table(matrix))

    if args.markdown:
        md = render_markdown_table(matrix)
        args.markdown.write_text(md + "\n", encoding="utf-8")
        print(f"\nMarkdown summary written to {args.markdown}")

    if not args.no_plot:
        if generate_heatmap(matrix, args.plot_out):
            print(f"\nHeatmap saved to {args.plot_out}")
        else:
            print("\nSkipping heatmap (install optional 'viz' extras: pip install -e '.[viz]').")


if __name__ == "__main__":
    main()
