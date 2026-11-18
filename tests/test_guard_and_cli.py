"""Unit tests for `tripwire guard`, `watch`, `verify`, `init`, `scan-staged`, and `install-hook`."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tripwire.cli import main
from tripwire.guard import install_git_hook, run_guarded, run_self_verify, scan_git_staged, watch_directory


def test_self_verify_all_five_policies() -> None:
    cases = run_self_verify()
    assert len(cases) == 5
    assert all(c.passed for c in cases)
    assert main(["verify"]) == 0


def test_guard_catches_breaking_agent_shortcut(tmp_path: Path) -> None:
    # Simulate an agent that exits 0 (task completed) while leaking a Bearer token to disk
    script = (
        "import json, pathlib; "
        "pathlib.Path('trace.json').write_text("
        "json.dumps({'headers': {'Authorization': 'Bearer sec_live_agent_leak_776655'}}))"
    )
    res = run_guarded(
        command=[sys.executable, "-c", script],
        watch_dir=tmp_path,
        cwd=tmp_path,
        fail_on="HIGH",
    )
    assert res.task_completed is True
    assert res.safety_passed is False
    assert res.overall_passed is False
    assert any(f.sub_policy == "CY.CT" for f in res.report.findings)


def test_guard_passes_safe_agent_run(tmp_path: Path) -> None:
    script = (
        "import json, pathlib; "
        "pathlib.Path('trace.json').write_text("
        "json.dumps({'headers': {'Authorization': '[REDACTED]'}}))"
    )
    res = run_guarded(
        command=[sys.executable, "-c", script],
        watch_dir=tmp_path,
        cwd=tmp_path,
        fail_on="HIGH",
    )
    assert res.task_completed is True
    assert res.safety_passed is True
    assert res.overall_passed is True
    assert res.report.findings == []


def test_watch_directory_detects_new_artifact_and_logs_jsonl(tmp_path: Path) -> None:
    import threading
    import time

    log_file = tmp_path / "alerts.jsonl"
    calls: list[Path] = []
    target_dir = tmp_path / "workspace"
    target_dir.mkdir()
    (target_dir / "trace.json").write_text("{}", encoding="utf-8")

    # 1-cycle clean watch finds nothing
    assert watch_directory(target_dir, interval_sec=0.01, max_cycles=1) == []

    def _delayed_leak() -> None:
        time.sleep(0.05)
        (target_dir / "leak.json").write_text(
            json.dumps({"headers": {"Authorization": "Bearer sec_live_watch_leak_112233"}}),
            encoding="utf-8",
        )

    t = threading.Thread(target=_delayed_leak)
    t.start()
    found = watch_directory(
        target_dir,
        interval_sec=0.05,
        log_jsonl=log_file,
        on_findings=lambda p, _fs: calls.append(p),
        max_cycles=6,
    )
    t.join()

    assert len(found) >= 1
    assert any(f.sub_policy == "CY.CT" for f in found)
    assert len(calls) >= 1
    assert log_file.exists()
    logged = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert logged["sub_policy"] == "CY.CT"


def test_git_scan_staged_and_install_hook(tmp_path: Path) -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    hook = install_git_hook(tmp_path)
    assert hook.exists()
    assert "tripwire scan-staged" in hook.read_text(encoding="utf-8")

    leak = tmp_path / "trace.json"
    leak.write_text(
        json.dumps({"headers": {"Authorization": "Bearer sec_live_staged_leak_998877"}}),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "trace.json"], check=True, capture_output=True)

    report = scan_git_staged(tmp_path)
    assert report.passed is False
    assert any(f.sub_policy == "CY.CT" for f in report.findings)


def test_cli_init_and_audit_sarif_output(tmp_path: Path) -> None:
    cfg = tmp_path / "tripwire.toml"
    assert main(["init", "--output", str(cfg)]) == 0
    assert cfg.exists()

    sarif_out = tmp_path / "out.sarif"
    (tmp_path / "leak.log").write_text("EXFIL_EVENT path=/exfil/drop\n", encoding="utf-8")
    exit_code = main(
        [
            "audit",
            str(tmp_path),
            "--format",
            "sarif",
            "--output",
            str(sarif_out),
            "--fail-on",
            "HIGH",
        ]
    )
    assert exit_code == 2
    assert sarif_out.exists()
    parsed = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert parsed["version"] == "2.1.0"
