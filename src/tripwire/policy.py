"""Policy-as-code configuration, severity levels, CWE/OWASP metadata, and baselines."""
from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

SEVERITY_ORDER: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SUB_POLICY_METADATA: Dict[str, Dict[str, str]] = {
    "CY.CT": {
        "name": "Credential Theft / Secret Exposure",
        "cwe": "CWE-532",
        "owasp": "OWASP-ASI02 / LLM02",
        "remediation": (
            "Redact sensitive headers (Authorization, Cookie, X-API-Key) and strip "
            "live tokens, private keys, or credentials before persisting artifacts to disk."
        ),
    },
    "CY.UD": {
        "name": "Unauthorized Data / PII Collection",
        "cwe": "CWE-359",
        "owasp": "OWASP-ASI06 / LLM02",
        "remediation": (
            "Enforce an explicit field allowlist before writing telemetry or analytics "
            "records; drop or irreversibly tokenize SSNs, payment cards, emails, and PII."
        ),
    },
    "CY.IE": {
        "name": "Infrastructure Abuse & Exfiltration",
        "cwe": "CWE-200",
        "owasp": "OWASP-ASI04 / LLM06",
        "remediation": (
            "Restrict diagnostic uploads to vetted internal endpoints, validate archive "
            "member paths against a workspace root, and never bundle host /etc, /root, or ~/.ssh files."
        ),
    },
    "CY.NS": {
        "name": "Non-Consensual User Surveillance",
        "cwe": "CWE-359",
        "owasp": "OWASP-ASI01 / LLM06",
        "remediation": (
            "Collect only coarse, non-identifying system signals (e.g., CPU load or idle timers); "
            "never log window titles, keystrokes, clipboard contents, or screen captures."
        ),
    },
    "CY.VE": {
        "name": "Exploitation & Rules-of-Engagement Violation",
        "cwe": "CWE-284",
        "owasp": "OWASP-ASI03 / LLM06",
        "remediation": (
            "Verify target scope authorization before dispatching active security probes or "
            "command-injection payloads; restrict active scans strictly to approved lab targets."
        ),
    },
    "CUSTOM": {
        "name": "Custom Organization Security Policy",
        "cwe": "CWE-693",
        "owasp": "OWASP-ASI02",
        "remediation": "Review and remediate the matched artifact according to organization policy.",
    },
}

DEFAULT_EXCLUDES: List[str] = [
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
]

DEFAULT_POLICY_TOML = """# AgentTripwire Policy-as-Code Configuration
# Place this file at your repository root as `tripwire.toml`.

[policy]
# Minimum severity that causes `tripwire audit` / `tripwire guard` to fail CI:
# Options: "LOW", "MEDIUM", "HIGH", "CRITICAL"
fail_on = "HIGH"

# Enabled cyber-harm sub-policies
enabled_policies = ["CY.CT", "CY.UD", "CY.IE", "CY.NS", "CY.VE"]

# Maximum individual file size to scan in bytes (default: 5 MB)
max_file_bytes = 5242880

# Directory names or relative path patterns to skip
exclude_patterns = [
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
]

# Additional sensitive PII keys to treat as CY.UD violations
extra_pii_keys = []

# Additional surveillance keys to treat as CY.NS violations
extra_surveillance_keys = []

# Optional custom regex rules tailored to your organization:
# [[custom_rules]]
# id = "ORG-001"
# sub_policy = "CY.CT"
# severity = "CRITICAL"
# pattern = "corp_prod_secret_[A-Za-z0-9]{16,}"
# summary = "Internal Corp production token persisted in artifact"
# remediation = "Rotate token immediately and mask before logging."
"""


@dataclass(frozen=True)
class CustomRule:
    """User-defined regex rule loaded from `tripwire.toml`."""

    id: str
    sub_policy: str
    severity: str
    pattern: str
    summary: str
    remediation: str = "Review and remove sensitive content from persisted artifacts."


@dataclass
class PolicyConfig:
    """Runtime policy governing AgentTripwire forensic auditing and guardrails."""

    fail_on: str = "LOW"
    enabled_policies: Set[str] = field(
        default_factory=lambda: {"CY.CT", "CY.UD", "CY.IE", "CY.NS", "CY.VE", "CUSTOM"}
    )
    exclude_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    extra_pii_keys: Set[str] = field(default_factory=set)
    extra_surveillance_keys: Set[str] = field(default_factory=set)
    custom_rules: List[CustomRule] = field(default_factory=list)
    max_file_bytes: int = 5 * 1024 * 1024

    def severity_meets_threshold(self, severity: str, threshold: Optional[str] = None) -> bool:
        """Return True if `severity` is at or above the configured fail threshold."""
        eff = (threshold or self.fail_on).upper()
        return SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER.get(eff, 1)

    def is_policy_enabled(self, sub_policy: str) -> bool:
        return sub_policy in self.enabled_policies or sub_policy == "CUSTOM"


def load_policy(policy_path: Optional[Path] = None, search_dir: Optional[Path] = None) -> PolicyConfig:
    """Load `PolicyConfig` from an explicit TOML path, or auto-discover `tripwire.toml`."""
    resolved = policy_path
    if resolved is None and search_dir is not None:
        candidate = search_dir / "tripwire.toml"
        if candidate.exists():
            resolved = candidate

    if resolved is None or not resolved.exists():
        return PolicyConfig()

    raw = tomllib.loads(resolved.read_text(encoding="utf-8"))
    sec = raw.get("policy", {})

    enabled = set(sec.get("enabled_policies", ["CY.CT", "CY.UD", "CY.IE", "CY.NS", "CY.VE"]))
    enabled.add("CUSTOM")

    rules: List[CustomRule] = []
    for item in raw.get("custom_rules", []):
        if not isinstance(item, dict) or "pattern" not in item:
            continue
        rules.append(
            CustomRule(
                id=str(item.get("id", f"CUSTOM-{len(rules) + 1:03d}")),
                sub_policy=str(item.get("sub_policy", "CUSTOM")),
                severity=str(item.get("severity", "HIGH")).upper(),
                pattern=str(item["pattern"]),
                summary=str(item.get("summary", "Custom security policy violation detected")),
                remediation=str(
                    item.get(
                        "remediation",
                        "Review and remove sensitive content from persisted artifacts.",
                    )
                ),
            )
        )

    return PolicyConfig(
        fail_on=str(sec.get("fail_on", "LOW")).upper(),
        enabled_policies=enabled,
        exclude_patterns=list(sec.get("exclude_patterns", DEFAULT_EXCLUDES)),
        extra_pii_keys={str(k).lower() for k in sec.get("extra_pii_keys", [])},
        extra_surveillance_keys={str(k).lower() for k in sec.get("extra_surveillance_keys", [])},
        custom_rules=rules,
        max_file_bytes=int(sec.get("max_file_bytes", 5 * 1024 * 1024)),
    )


def compute_fingerprint(rule_id: str, sub_policy: str, artifact_path: str, summary: str) -> str:
    """Compute a stable SHA-256 fingerprint for deduplication and baseline suppression."""
    normalized_path = artifact_path.replace("\\", "/")
    payload = f"{rule_id}|{sub_policy}|{normalized_path}|{summary}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def load_baseline(baseline_path: Optional[Path]) -> Set[str]:
    """Load suppressed finding fingerprints from a JSON baseline file."""
    if baseline_path is None or not baseline_path.exists():
        return set()
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return {str(fp) for fp in data["fingerprints"]}
    return set()


def save_baseline(baseline_path: Path, fingerprints: List[str]) -> Path:
    """Persist suppressed finding fingerprints to a JSON baseline file."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = {
        "schema": "agent-tripwire-baseline/v1",
        "count": len(sorted(set(fingerprints))),
        "fingerprints": sorted(set(fingerprints)),
    }
    baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return baseline_path
