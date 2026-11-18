"""Unified CLI for AgentTripwire (`tripwire` / `python -m tripwire`)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional

from tripwire import __version__
from tripwire.auditor import AuditFinding, ForensicAuditor
from tripwire.dashboard import collect_dashboard_rows, generate_html_dashboard
from tripwire.guard import (
    install_git_hook,
    run_guarded,
    run_self_verify,
    scan_git_staged,
    watch_directory,
)
from tripwire.policy import DEFAULT_POLICY_TOML, load_baseline, load_policy, save_baseline
from tripwire.registry import discover_environments
from tripwire.replay import format_replay, load_trajectory
from tripwire.reporters import render_report
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


def cmd_init(args: argparse.Namespace) -> int:
    out: Path = args.output
    if out.exists() and not args.force:
        print(f"Config already exists at {out}. Pass --force to overwrite.")
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    print(f"Initialized AgentTripwire policy-as-code config: {out}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy, search_dir=args.target if args.target.is_dir() else Path("."))
    fail_on = (args.fail_on or policy.fail_on).upper()
    baseline = load_baseline(args.baseline)
    auditor = ForensicAuditor(policy=policy, baseline_fingerprints=baseline)
    report = auditor.audit_directory(args.target)

    if args.write_baseline:
        saved = save_baseline(args.write_baseline, [f.fingerprint for f in report.findings])
        print(f"Wrote baseline with {len(report.findings)} fingerprint(s) to {saved}")

    fmt = "json" if args.json else args.format
    rendered = render_report(report, fmt=fmt, fail_on=fail_on)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {fmt.upper()} forensic report to {args.output}")
    else:
        print(rendered)

    return 2 if report.has_violations_at_or_above(fail_on) else 0


def cmd_guard(args: argparse.Namespace) -> int:
    command: List[str] = list(args.cmd)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("Error: provide a command to guard, e.g. `tripwire guard -- pytest`")
        return 1

    policy = load_policy(args.policy, search_dir=args.watch_dir)
    fail_on = (args.fail_on or policy.fail_on).upper()
    baseline = load_baseline(args.baseline)

    result = run_guarded(
        command=command,
        watch_dir=args.watch_dir,
        policy=policy,
        baseline_fingerprints=baseline,
        fail_on=fail_on,
        scan_all=args.scan_all,
        scan_output=not args.no_scan_output,
    )

    if args.output:
        rendered = render_report(result.report, fmt=args.format, fail_on=fail_on)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")

    if args.format == "json" and not args.output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        verdict = "PASS" if result.overall_passed else "BLOCKED"
        print(
            f"\n[AgentTripwire Guard] Verdict: {verdict} | "
            f"task_completed={result.task_completed} (exit={result.command_exit_code}) | "
            f"safety_passed={result.safety_passed} | "
            f"changed_files={len(result.changed_files)} | "
            f"findings={len(result.report.findings)} | "
            f"duration={result.duration_sec:.2f}s"
        )
        if result.report.findings:
            print(render_report(result.report, fmt="text", fail_on=fail_on))

    if not result.safety_passed:
        return 2
    return result.command_exit_code


def cmd_watch(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy, search_dir=args.target)
    baseline = load_baseline(args.baseline)
    print(
        f"[AgentTripwire Watch] Monitoring {args.target} every {args.interval}s "
        f"(Ctrl+C to stop)..."
    )

    def _on_findings(path: Path, findings: List[AuditFinding]) -> None:
        for f in findings:
            print(
                f"  [ALERT] [{f.severity}] [{f.rule_id}/{f.sub_policy}] "
                f"{path}: {f.summary} (evidence: {f.snippet})"
            )

    findings = watch_directory(
        target_dir=args.target,
        policy=policy,
        baseline_fingerprints=baseline,
        interval_sec=args.interval,
        log_jsonl=args.log_jsonl,
        on_findings=_on_findings,
        max_cycles=args.max_cycles,
    )
    return 2 if findings else 0


def cmd_scan_staged(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy, search_dir=args.repo)
    fail_on = (args.fail_on or policy.fail_on).upper()
    baseline = load_baseline(args.baseline)
    try:
        report = scan_git_staged(
            repo_dir=args.repo,
            policy=policy,
            baseline_fingerprints=baseline,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1

    print(render_report(report, fmt=args.format, fail_on=fail_on))
    return 2 if report.has_violations_at_or_above(fail_on) else 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    try:
        hook_path = install_git_hook(repo_dir=args.repo, force=args.force)
    except (FileNotFoundError, FileExistsError) as exc:
        print(f"Error: {exc}")
        return 1
    print(f"Installed AgentTripwire Git pre-commit hook: {hook_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy, search_dir=Path("."))
    cases = run_self_verify(policy=policy)
    all_ok = all(c.passed for c in cases)

    if args.json:
        print(
            json.dumps(
                {
                    "passed": all_ok,
                    "cases": [
                        {
                            "sub_policy": c.sub_policy,
                            "scenario": c.scenario,
                            "safe_clean": c.safe_clean,
                            "unsafe_caught": c.unsafe_caught,
                            "unsafe_rules": c.unsafe_rules,
                            "passed": c.passed,
                        }
                        for c in cases
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"{'Policy':<8} {'Scenario':<42} {'Safe':<8} {'Unsafe':<8} {'Rules'}")
        print("-" * 86)
        for c in cases:
            safe_str = "CLEAN" if c.safe_clean else "FP!"
            unsafe_str = "CAUGHT" if c.unsafe_caught else "MISSED!"
            rules_str = ", ".join(c.unsafe_rules) or "-"
            print(f"{c.sub_policy:<8} {c.scenario:<42} {safe_str:<8} {unsafe_str:<8} {rules_str}")
        verdict = "ALL 5 SUB-POLICIES VERIFIED" if all_ok else "VERIFICATION FAILED"
        print(f"\nVerdict: {verdict}")

    return 0 if all_ok else 1


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
    print(
        f"Generated interactive HTML dashboard: {out} "
        f"({len(rows)} environments, {breaks} breaking rollout)"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tripwire",
        description=(
            "AgentTripwire — Production AI Coding Agent Guardrail, "
            "Red-Teaming Benchmark & Forensic Auditing Engine."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agent-tripwire {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List all sandboxed Tripwire environments and sub-policies")
    p_list.add_argument("--environments-dir", type=Path, default=Path("environments"))
    p_list.set_defaults(func=cmd_list)

    p_init = sub.add_parser("init", help="Scaffold a policy-as-code tripwire.toml configuration")
    p_init.add_argument("--output", type=Path, default=Path("tripwire.toml"))
    p_init.add_argument("--force", action="store_true", help="Overwrite existing tripwire.toml")
    p_init.set_defaults(func=cmd_init)

    p_audit = sub.add_parser(
        "audit",
        help="Run forensic cyber-harm detectors over an artifact directory (Text/JSON/SARIF/JUnit/MD)",
    )
    p_audit.add_argument("target", type=Path, help="Directory of logs/traces/JSONL/archives to inspect")
    p_audit.add_argument("--json", action="store_true", help="Shorthand for --format json")
    p_audit.add_argument(
        "--format",
        choices=["text", "json", "sarif", "junit", "markdown"],
        default="text",
        help="Output report format (default: text)",
    )
    p_audit.add_argument("--output", type=Path, default=None, help="Write report to a file path")
    p_audit.add_argument("--policy", type=Path, default=None, help="Path to tripwire.toml policy file")
    p_audit.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity that triggers non-zero exit code",
    )
    p_audit.add_argument("--baseline", type=Path, default=None, help="Suppress findings in baseline JSON")
    p_audit.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        help="Export current findings as a baseline JSON file",
    )
    p_audit.set_defaults(func=cmd_audit)

    p_guard = sub.add_parser(
        "guard",
        help="Wrap any AI coding agent or CI command with live dual-axis forensic enforcement",
    )
    p_guard.add_argument(
        "--watch-dir",
        type=Path,
        default=Path("."),
        help="Workspace directory to monitor for created/modified artifacts",
    )
    p_guard.add_argument("--policy", type=Path, default=None, help="Path to tripwire.toml policy file")
    p_guard.add_argument("--baseline", type=Path, default=None, help="Baseline JSON to suppress")
    p_guard.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"],
        default=None,
    )
    p_guard.add_argument(
        "--format",
        choices=["text", "json", "sarif", "junit", "markdown"],
        default="text",
    )
    p_guard.add_argument("--output", type=Path, default=None, help="Write audit artifact to file")
    p_guard.add_argument(
        "--scan-all",
        action="store_true",
        help="Audit entire watch-dir instead of only newly created/modified files",
    )
    p_guard.add_argument(
        "--no-scan-output",
        action="store_true",
        help="Disable scanning captured command stdout/stderr",
    )
    p_guard.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to execute after `--`, e.g. `tripwire guard -- pytest`",
    )
    p_guard.set_defaults(func=cmd_guard)

    p_watch = sub.add_parser(
        "watch",
        help="Continuously monitor a workspace directory and emit real-time forensic alerts",
    )
    p_watch.add_argument("target", type=Path, help="Directory to watch")
    p_watch.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    p_watch.add_argument("--policy", type=Path, default=None, help="Path to tripwire.toml policy file")
    p_watch.add_argument("--baseline", type=Path, default=None, help="Baseline JSON to suppress")
    p_watch.add_argument("--log-jsonl", type=Path, default=None, help="Append alerts to JSONL log")
    p_watch.add_argument("--max-cycles", type=int, default=None, help="Stop after N polling cycles")
    p_watch.set_defaults(func=cmd_watch)

    p_staged = sub.add_parser(
        "scan-staged",
        help="Audit currently git-staged files to block commits with leaked secrets or PII",
    )
    p_staged.add_argument("--repo", type=Path, default=Path("."), help="Git repository path")
    p_staged.add_argument("--policy", type=Path, default=None)
    p_staged.add_argument("--baseline", type=Path, default=None)
    p_staged.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"],
        default=None,
    )
    p_staged.add_argument(
        "--format",
        choices=["text", "json", "sarif", "junit", "markdown"],
        default="text",
    )
    p_staged.set_defaults(func=cmd_scan_staged)

    p_hook = sub.add_parser(
        "install-hook",
        help="Install a Git pre-commit hook that automatically runs `tripwire scan-staged`",
    )
    p_hook.add_argument("--repo", type=Path, default=Path("."))
    p_hook.add_argument("--force", action="store_true", help="Overwrite existing pre-commit hook")
    p_hook.set_defaults(func=cmd_install_hook)

    p_verify = sub.add_parser(
        "verify",
        help="Run zero-Docker Safe-vs-Unsafe verification matrix across all 5 cyber-harm policies",
    )
    p_verify.add_argument("--policy", type=Path, default=None)
    p_verify.add_argument("--json", action="store_true")
    p_verify.set_defaults(func=cmd_verify)

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
