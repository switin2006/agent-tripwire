"""Industry-standard report formatters: SARIF v2.1.0, JUnit XML, Markdown PR comments, JSON & text."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from tripwire import __version__
from tripwire.auditor import AuditFinding, AuditReport
from tripwire.policy import SUB_POLICY_METADATA

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _clean_artifact_uri(artifact_path: str) -> str:
    """Normalize artifact path into a clean forward-slash URI for SARIF locations."""
    normalized = artifact_path.replace("\\", "/")
    if "!" in normalized:
        normalized = normalized.split("!", 1)[0]
    # Strip trailing :line_no suffix (but preserve Windows drive colon like C:/)
    if ":" in normalized:
        head, tail = normalized.rsplit(":", 1)
        if tail.isdigit():
            normalized = head
    return normalized


def format_text(report: AuditReport, fail_on: str = "LOW") -> str:
    """Format a structured, human-readable forensic audit report for terminal output."""
    failed = report.has_violations_at_or_above(fail_on)
    status = "PASS (0 blocking violations)" if not failed else f"FAIL ({len(report.findings)} violations detected)"
    counts = report.severity_counts()

    lines = [
        f"AgentTripwire Forensic Audit | Target: {report.target_dir}",
        (
            f"Files scanned: {report.files_scanned} | Suppressed: {report.suppressed_count} "
            f"| Fail threshold: {fail_on.upper()} | Verdict: {status}"
        ),
        (
            f"Severity Breakdown: CRITICAL={counts['CRITICAL']}  HIGH={counts['HIGH']}  "
            f"MEDIUM={counts['MEDIUM']}  LOW={counts['LOW']}"
        ),
    ]

    for idx, f in enumerate(report.findings, start=1):
        loc = f.artifact_path
        if f.line_number and f":{f.line_number}" not in loc:
            loc = f"{loc}:{f.line_number}"
        lines.append(
            f"  [{idx}] [{f.severity}] [{f.rule_id} / {f.sub_policy}] {f.summary}"
        )
        lines.append(f"      Artifact    : {loc}")
        lines.append(f"      Evidence    : {f.snippet}")
        lines.append(f"      Compliance  : {f.cwe} | {f.owasp} | Fingerprint: {f.fingerprint}")
        lines.append(f"      Remediation : {f.remediation}")

    return "\n".join(lines)


def format_json(report: AuditReport) -> str:
    """Format an AuditReport as indented JSON."""
    return json.dumps(report.to_dict(), indent=2)


def format_sarif(report: AuditReport) -> str:
    """Generate OASIS SARIF v2.1.0 JSON compatible with GitHub Code Scanning."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in report.findings:
        if f.rule_id not in rules_map:
            meta = SUB_POLICY_METADATA.get(f.sub_policy, SUB_POLICY_METADATA["CUSTOM"])
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": meta["name"].replace(" ", "").replace("/", ""),
                "shortDescription": {"text": f"{f.sub_policy}: {meta['name']}"},
                "fullDescription": {"text": f.summary},
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity.upper(), "warning")},
                "properties": {
                    "tags": ["security", "ai-agent-safety", f.sub_policy, f.cwe, f.owasp],
                    "security-severity": (
                        "9.0" if f.severity == "CRITICAL" else "7.5" if f.severity == "HIGH" else "5.0"
                    ),
                },
            }

        physical_location: Dict[str, Any] = {
            "artifactLocation": {"uri": _clean_artifact_uri(f.artifact_path)},
        }
        if f.line_number and f.line_number > 0:
            physical_location["region"] = {"startLine": f.line_number}

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity.upper(), "warning"),
                "message": {"text": f"{f.summary} (Evidence: {f.snippet})"},
                "locations": [{"physicalLocation": physical_location}],
                "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
                "properties": {
                    "sub_policy": f.sub_policy,
                    "severity": f.severity,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "remediation": f.remediation,
                },
            }
        )

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentTripwire",
                        "version": __version__,
                        "informationUri": "https://github.com/switin2006/agent-tripwire",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def format_junit(report: AuditReport) -> str:
    """Generate JUnit XML test suite output for Jenkins, GitLab CI, CircleCI, and Azure DevOps."""
    policies = ["CY.CT", "CY.UD", "CY.IE", "CY.NS", "CY.VE"]
    grouped: Dict[str, List[AuditFinding]] = {p: [] for p in policies}
    for f in report.findings:
        grouped.setdefault(f.sub_policy, []).append(f)

    total_cases = len(grouped)
    failures = sum(1 for findings in grouped.values() if findings)

    suite = ET.Element(
        "testsuite",
        attrib={
            "name": "AgentTripwire Forensic Audit",
            "tests": str(total_cases),
            "failures": str(failures),
            "errors": "0",
            "skipped": "0",
        },
    )

    for policy_id, findings in grouped.items():
        meta = SUB_POLICY_METADATA.get(policy_id, SUB_POLICY_METADATA["CUSTOM"])
        tc = ET.SubElement(
            suite,
            "testcase",
            attrib={
                "classname": f"tripwire.forensics.{policy_id}",
                "name": f"{policy_id} - {meta['name']}",
            },
        )
        if findings:
            details = "\n".join(
                f"[{f.severity}] {f.rule_id} @ {f.artifact_path}: {f.summary} (Evidence: {f.snippet})"
                for f in findings
            )
            fail_el = ET.SubElement(
                tc,
                "failure",
                attrib={
                    "type": policy_id,
                    "message": f"{len(findings)} forensic violation(s) detected for {policy_id}",
                },
            )
            fail_el.text = details

    xml_bytes = ET.tostring(suite, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")


def format_markdown(report: AuditReport, fail_on: str = "LOW") -> str:
    """Generate a GitHub Pull Request security gate summary in Markdown."""
    failed = report.has_violations_at_or_above(fail_on)
    badge = "FAILED" if failed else "PASSED"
    counts = report.severity_counts()

    lines = [
        f"## AgentTripwire Forensic Security Gate: **{badge}**",
        "",
        (
            f"- **Target:** `{report.target_dir}`\n"
            f"- **Files Scanned:** `{report.files_scanned}`\n"
            f"- **Violations:** `{len(report.findings)}` "
            f"(Critical: `{counts['CRITICAL']}`, High: `{counts['HIGH']}`, "
            f"Medium: `{counts['MEDIUM']}`, Low: `{counts['LOW']}`)\n"
            f"- **Suppressed (Baseline):** `{report.suppressed_count}`"
        ),
        "",
    ]

    if not report.findings:
        lines.append("All scanned agent artifacts complied with enabled cyber-harm policies.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule / Policy | Artifact | Summary | Compliance |",
            "|---|---|---|---|---|",
        ]
    )
    for f in report.findings:
        artifact_clean = f.artifact_path.replace("|", "\\|")
        summary_clean = f.summary.replace("|", "\\|")
        lines.append(
            f"| **{f.severity}** | `{f.rule_id}` (`{f.sub_policy}`) | `{artifact_clean}` "
            f"| {summary_clean} | `{f.cwe}` / `{f.owasp}` |"
        )

    lines.extend(
        [
            "",
            "### Recommended Remediations",
        ]
    )
    seen_rems: set[str] = set()
    for f in report.findings:
        key = f"{f.sub_policy}:{f.remediation}"
        if key not in seen_rems:
            seen_rems.add(key)
            lines.append(f"- **`{f.sub_policy}`**: {f.remediation}")

    return "\n".join(lines)


def render_report(report: AuditReport, fmt: str = "text", fail_on: str = "LOW") -> str:
    """Dispatch report rendering by format name."""
    key = fmt.lower()
    if key == "json":
        return format_json(report)
    if key == "sarif":
        return format_sarif(report)
    if key == "junit":
        return format_junit(report)
    if key in {"md", "markdown"}:
        return format_markdown(report, fail_on=fail_on)
    return format_text(report, fail_on=fail_on)
