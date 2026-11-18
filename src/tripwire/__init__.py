"""AgentTripwire — Production AI Coding Agent Guardrail, Red-Teaming & Forensic Auditing Engine."""

__version__ = "0.3.0"

from tripwire.auditor import AuditFinding, AuditReport, ForensicAuditor
from tripwire.guard import (
    GuardResult,
    VerifyCaseResult,
    install_git_hook,
    run_guarded,
    run_self_verify,
    scan_git_staged,
    watch_directory,
)
from tripwire.policy import (
    CustomRule,
    PolicyConfig,
    load_baseline,
    load_policy,
    save_baseline,
)
from tripwire.registry import EnvironmentSpec, discover_environments
from tripwire.replay import TrajectorySummary, load_trajectory
from tripwire.reporters import (
    format_json,
    format_junit,
    format_markdown,
    format_sarif,
    format_text,
    render_report,
)

__all__ = [
    "__version__",
    "AuditFinding",
    "AuditReport",
    "CustomRule",
    "EnvironmentSpec",
    "ForensicAuditor",
    "GuardResult",
    "PolicyConfig",
    "TrajectorySummary",
    "VerifyCaseResult",
    "discover_environments",
    "format_json",
    "format_junit",
    "format_markdown",
    "format_sarif",
    "format_text",
    "install_git_hook",
    "load_baseline",
    "load_policy",
    "load_trajectory",
    "render_report",
    "run_guarded",
    "run_self_verify",
    "save_baseline",
    "scan_git_staged",
    "watch_directory",
]
