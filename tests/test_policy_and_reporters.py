"""Unit tests for policy-as-code, extended industry detectors, baselines, and SARIF/JUnit/Markdown reporters."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from tripwire.auditor import ForensicAuditor
from tripwire.policy import load_baseline, load_policy, save_baseline
from tripwire.reporters import format_junit, format_markdown, format_sarif


def test_extended_credential_and_pii_detectors(tmp_path: Path) -> None:
    jwt_sample = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DATABASE_URL=postgresql://admin:SuperSecretPass99@db.internal:5432/prod\n"
        f"SESSION_JWT={jwt_sample}\n",
        encoding="utf-8",
    )

    pem_log = tmp_path / "debug.log"
    pem_log.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n", encoding="utf-8")

    # Standard Luhn-valid test card number (4111...)
    cc_log = tmp_path / "checkout.txt"
    cc_log.write_text("card_processed=4111-1111-1111-1111\n", encoding="utf-8")

    # ZIP with sensitive host path + secret
    zf_path = tmp_path / "diag.zip"
    with zipfile.ZipFile(zf_path, "w") as zf:
        zf.writestr(".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")

    report = ForensicAuditor().audit_directory(tmp_path)
    rule_ids = {f.rule_id for f in report.findings}
    assert "TW-CT-003" in rule_ids  # Private key
    assert "TW-CT-004" in rule_ids  # JWT
    assert "TW-CT-005" in rule_ids  # DB URI secret
    assert "TW-UD-003" in rule_ids  # Luhn credit card
    assert "TW-IE-002" in rule_ids  # Sensitive ZIP path

    # Ensure raw secret values are masked in snippets
    for f in report.findings:
        assert "SuperSecretPass99" not in f.snippet
        assert "4111-1111-1111-1111" not in f.snippet


def test_luhn_rejects_non_card_numbers(tmp_path: Path) -> None:
    log = tmp_path / "metrics.log"
    # Invalid Luhn checksum and repeating digits must not trigger CY.UD
    log.write_text("request_id=4111-1111-1111-1112 zero_pad=0000-0000-0000-0000\n", encoding="utf-8")
    report = ForensicAuditor().audit_directory(tmp_path)
    assert report.passed is True


def test_policy_as_code_custom_rules_and_excludes(tmp_path: Path) -> None:
    cfg_path = tmp_path / "tripwire.toml"
    cfg_path.write_text(
        """
[policy]
fail_on = "HIGH"
enabled_policies = ["CY.CT", "CY.UD"]
exclude_patterns = ["ignored_dir"]
extra_pii_keys = ["customer_tin"]

[[custom_rules]]
id = "CORP-900"
sub_policy = "CY.CT"
severity = "CRITICAL"
pattern = "corp_internal_tok_[0-9]{8}"
summary = "Corporate internal token leaked"
""",
        encoding="utf-8",
    )

    ignored = tmp_path / "ignored_dir"
    ignored.mkdir()
    (ignored / "leak.log").write_text("Authorization: Bearer sec_live_ignored_1234567890\n", encoding="utf-8")

    (tmp_path / "app.json").write_text(
        json.dumps({"customer_tin": "99-1234567", "token": "corp_internal_tok_87654321"}),
        encoding="utf-8",
    )

    policy = load_policy(cfg_path)
    report = ForensicAuditor(policy=policy).audit_directory(tmp_path)
    assert report.files_scanned == 1
    rule_ids = {f.rule_id for f in report.findings}
    assert "CORP-900" in rule_ids
    assert "TW-UD-002" in rule_ids


def test_baseline_suppression_workflow(tmp_path: Path) -> None:
    (tmp_path / "trace.json").write_text(
        json.dumps({"headers": {"Authorization": "Bearer sec_live_legacy_tok_123456789"}}),
        encoding="utf-8",
    )

    initial = ForensicAuditor().audit_directory(tmp_path)
    assert initial.passed is False
    assert len(initial.findings) == 1

    baseline_file = tmp_path / ".tripwire-baseline.json"
    save_baseline(baseline_file, [f.fingerprint for f in initial.findings])
    fps = load_baseline(baseline_file)

    suppressed = ForensicAuditor(baseline_fingerprints=fps).audit_directory(tmp_path)
    assert suppressed.passed is True
    assert suppressed.suppressed_count == 1


def test_sarif_junit_and_markdown_reporters(tmp_path: Path) -> None:
    (tmp_path / "trace.json").write_text(
        json.dumps({"headers": {"Authorization": "Bearer sec_live_bearer_9988776655"}}),
        encoding="utf-8",
    )
    report = ForensicAuditor().audit_directory(tmp_path)

    # SARIF v2.1.0 validation
    sarif = json.loads(format_sarif(report))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AgentTripwire"
    assert len(driver["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1
    res = sarif["runs"][0]["results"][0]
    assert res["ruleId"] == "TW-CT-001"
    assert res["level"] == "error"
    assert "primaryLocationLineHash" in res["partialFingerprints"]

    # JUnit XML validation
    root = ET.fromstring(format_junit(report))
    assert root.tag == "testsuite"
    assert int(root.attrib["failures"]) == 1

    # Markdown PR Gate validation
    md = format_markdown(report, fail_on="HIGH")
    assert "FAILED" in md
    assert "TW-CT-001" in md
    assert "CWE-532" in md
