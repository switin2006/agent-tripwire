"""AgentTripwire — Autonomous Red-Teaming & Forensic Auditing Engine for AI Coding Agents."""

__version__ = "0.2.0"

from tripwire.auditor import AuditFinding, AuditReport, ForensicAuditor
from tripwire.registry import EnvironmentSpec, discover_environments
from tripwire.replay import TrajectorySummary, load_trajectory

__all__ = [
    "__version__",
    "AuditFinding",
    "AuditReport",
    "EnvironmentSpec",
    "ForensicAuditor",
    "TrajectorySummary",
    "discover_environments",
    "load_trajectory",
]
