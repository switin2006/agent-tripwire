"""Unified CLI for AgentTripwire (`tripwire` / `python -m tripwire`)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional

from tripwire import __version__
from tripwire.auditor import ForensicAuditor
from tripwire.dashboard import collect_dashboard_rows, generate_html_dashboard
from tripwire.registry import discover_environments
from tripwire.replay import format_replay, load_trajectory
from tripwire.runner import run_evaluation


def cmd_list(args: argparse.Namespace) -> int:
    specs = discover_environments(args.environments_dir)
    if not specs:
        print(f"No Tripwire environments found in {args.environments_dir}")
        return 1

    print(f"{'Environment':<28} {'Policy':<7} {'Mechanism':<26} {'Oracles':<12}")
    print("-" * 78)
    for spec in specs:
        oracles = "safe+unsafe" if (spec.has_safe_oracle and spec.has_unsafe_oracle) else "partial"
        print(f"{spec.env_id:<28} {spec.sub_policy:<7} {spec.mechanism:<26} {oracles:<12}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    auditor = ForensicAuditor()
    report = auditor.audit_directory(args.target)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        status = "PASS (0 violations)" if report.passed else f"FAIL ({len(report.findings)} violations detected)"
        print(f"AgentTripwire Forensic Audit | Target: {report.target_dir}")
        print(f"Files scanned: {report.files_scanned} | Verdict: {status}")
        for idx, f in enumerate(report.findings, start=1):
            print(f"  [{idx}] [{f.severity}] ({f.sub_policy}) {f.summary}")
            print(f"      Artifact: {f.artifact_path}")
            print(f"      Evidence: {f.snippet}")

    return 0 if report.passed else 2


def cmd_replay(args: argparse.Namespace) -> int:
    summary = load_trajectory(args.results_dir, args.env, args.variant)
    if summary is None:
        print(f"No trajectory found for {args.env} ({args.variant}) under {args.results_dir}")
        return 1
    print(format_replay(summary, max_steps=args.max_steps))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    return run_evaluation(
        env_id=args.env,
        mode=args.mode,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        dry_run=args.dry_run,
    )


def cmd_dashboard(args: argparse.Namespace) -> int:
    out = generate_html_dashboard(
        output_path=args.output,
        environments_dir=args.environments_dir,
        results_dir=args.results_dir,
    )
    rows = collect_dashboard_rows(args.environments_dir, args.results_dir)
    breaks = sum(1 for r in rows if r.rollout_violates)
    print(f"Generated interactive HTML dashboard: {out} ({len(rows)} environments, {breaks} breaking rollout)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tripwire",
        description="AgentTripwire — Autonomous Red-Teaming & Forensic Auditing Engine for AI Coding Agents.",
    )
    parser.add_argument("--version", action="version", version=f"agent-tripwire {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List all sandboxed Tripwire environments and sub-policies")
    p_list.add_argument("--environments-dir", type=Path, default=Path("environments"))
    p_list.set_defaults(func=cmd_list)

    p_audit = sub.add_parser("audit", help="Run the 5 forensic cyber-harm detectors over an artifact directory")
    p_audit.add_argument("target", type=Path, help="Directory of logs/traces/JSONL/tarballs to inspect")
    p_audit.add_argument("--json", action="store_true", help="Output structured JSON report")
    p_audit.set_defaults(func=cmd_audit)

    p_replay = sub.add_parser("replay", help="Replay a recorded autonomous agent trajectory step-by-step")
    p_replay.add_argument("env", help="Environment ID (e.g., env-api-gateway-auth)")
    p_replay.add_argument("--variant", default="rollout", help="Result variant (default: rollout)")
    p_replay.add_argument("--results-dir", type=Path, default=Path("results"))
    p_replay.add_argument("--max-steps", type=int, default=None, help="Limit number of turns displayed")
    p_replay.set_defaults(func=cmd_replay)

    p_run = sub.add_parser("run", help="Orchestrate a Harbor red-team evaluation run")
    p_run.add_argument("env", help="Environment ID to evaluate")
    p_run.add_argument("--mode", choices=["safe", "agent"], default="safe")
    p_run.add_argument("--model", default="openai/gpt-6.1-sol")
    p_run.add_argument("--reasoning-effort", default="high")
    p_run.add_argument("--dry-run", action="store_true", help="Print Harbor command without executing")
    p_run.set_defaults(func=cmd_run)

    p_dash = sub.add_parser("dashboard", help="Generate standalone interactive HTML security dashboard")
    p_dash.add_argument("--output", type=Path, default=Path("docs/dashboard.html"))
    p_dash.add_argument("--environments-dir", type=Path, default=Path("environments"))
    p_dash.add_argument("--results-dir", type=Path, default=Path("results"))
    p_dash.set_defaults(func=cmd_dashboard)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
