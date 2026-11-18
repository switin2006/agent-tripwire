"""Red-team evaluation orchestrator wrapping Harbor CLI."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional


def build_harbor_command(
    env_id: str,
    mode: str = "safe",
    model: str = "openai/gpt-6.1-sol",
    reasoning_effort: str = "high",
    environments_dir: Path = Path("environments"),
    output_dir: Path = Path("jobs"),
) -> List[str]:
    """Build the Harbor CLI command for oracle or frontier agent rollouts."""
    if mode == "safe":
        return [
            "harbor",
            "run",
            "-p",
            str(environments_dir),
            "-i",
            env_id,
            "-a",
            "oracle",
            "-k",
            "1",
            "-o",
            str(output_dir / f"safe-{env_id}"),
            "--yes",
        ]

    if mode == "agent":
        cmd = [
            "harbor",
            "run",
            "-p",
            str(environments_dir),
            "-i",
            env_id,
            "-a",
            "terminus-2",
            "-m",
            model,
            "--ak",
            f"reasoning_effort={reasoning_effort}",
            "-k",
            "1",
            "-o",
            str(output_dir / f"rollout-{env_id}"),
            "--job-name",
            "rollout",
            "--yes",
        ]
        base_url = os.environ.get("OPENAI_BASE_URL")
        if base_url:
            cmd.extend(["--ak", f"base_url={base_url}"])
        return cmd

    raise ValueError(f"Unsupported mode '{mode}'. Choose 'safe' or 'agent'.")


def run_evaluation(
    env_id: str,
    mode: str = "safe",
    model: str = "openai/gpt-6.1-sol",
    reasoning_effort: str = "high",
    dry_run: bool = False,
) -> int:
    """Execute or preview a Harbor red-team evaluation run."""
    cmd = build_harbor_command(
        env_id=env_id,
        mode=mode,
        model=model,
        reasoning_effort=reasoning_effort,
    )
    if dry_run:
        print("DRY RUN:", " ".join(cmd))
        return 0

    if shutil.which("harbor") is None:
        print("Error: 'harbor' CLI not found on PATH. Install Harbor or pass --dry-run.")
        return 1

    proc = subprocess.run(cmd, check=False)
    return int(proc.returncode)
