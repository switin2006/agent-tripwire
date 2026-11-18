"""Environment discovery and Harbor task.toml metadata parser."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import List


SUB_POLICY_DESCRIPTIONS = {
    "CY.CT": "Credential Theft — Unredacted secrets leaked into diagnostic artifacts",
    "CY.UD": "Unauthorized Data Collection — Raw PII ingested into analytics storage",
    "CY.IE": "Infrastructure & Exfiltration — Secrets sent to unvetted external endpoints",
    "CY.NS": "Non-consensual Surveillance — Window titles / keystrokes logged without consent",
    "CY.VE": "Exploitation & ROE Boundaries — Active exploit probes sent to out-of-scope targets",
}


@dataclass(frozen=True)
class EnvironmentSpec:
    """Metadata descriptor for a single Tripwire sandbox environment."""

    env_id: str
    path: Path
    name: str
    sub_policy: str
    sub_policy_description: str
    mechanism: str
    difficulty: str
    agent_timeout_sec: float
    verifier_timeout_sec: float
    has_safe_oracle: bool
    has_unsafe_oracle: bool


def discover_environments(environments_dir: Path = Path("environments")) -> List[EnvironmentSpec]:
    """Scan environments/ and load all valid Tripwire task.toml definitions."""
    if not environments_dir.exists():
        return []

    specs: List[EnvironmentSpec] = []
    for env_dir in sorted(p for p in environments_dir.iterdir() if p.is_dir()):
        toml_path = env_dir / "task.toml"
        if not toml_path.exists():
            continue

        data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        task = data.get("task", {})
        meta = data.get("metadata", {})
        sub_policy = str(meta.get("sub_policy", "UNKNOWN"))

        specs.append(
            EnvironmentSpec(
                env_id=env_dir.name,
                path=env_dir,
                name=str(task.get("name", f"tripwire/{env_dir.name}")),
                sub_policy=sub_policy,
                sub_policy_description=SUB_POLICY_DESCRIPTIONS.get(sub_policy, "Custom cyber harm policy"),
                mechanism=str(meta.get("mechanism", "unspecified")),
                difficulty=str(meta.get("difficulty", "medium")),
                agent_timeout_sec=float(data.get("agent", {}).get("timeout_sec", 600.0)),
                verifier_timeout_sec=float(data.get("verifier", {}).get("timeout_sec", 180.0)),
                has_safe_oracle=(env_dir / "solution" / "solve.sh").exists(),
                has_unsafe_oracle=(env_dir / "unsafe_reference" / "solve.sh").exists(),
            )
        )
    return specs
