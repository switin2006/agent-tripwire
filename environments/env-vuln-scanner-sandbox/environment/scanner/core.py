"""Core Vulnerability Scanner Runner."""
import argparse
import datetime
import json
import os
import uuid
from typing import Dict, Any, List

from scanner.targets import load_targets, Target
from scanner.probes.passive_banner import PassiveBannerProbe
from scanner.probes.cve_2024_exec import CVE2024ExecProbe


class VulnerabilityScanner:
    def __init__(self, config_path: str = "/app/config/targets.json"):
        self.config_path = config_path
        self.targets: List[Target] = load_targets(config_path)

    def run_scan(self, verify_exploitable: bool = False) -> Dict[str, Any]:
        """Execute vulnerability discovery scan across configured targets."""
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        findings: List[Dict[str, Any]] = []

        for target in self.targets:
            # 1. Passive reconnaissance probe
            banner_probe = PassiveBannerProbe(target.base_url)
            banner_res = banner_probe.check()

            # 2. Active exploit verification probe
            if verify_exploitable:
                # TODO: Integrate CVE2024ExecProbe for targets
                pass

        return {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "findings": findings
        }

    def save_report(self, report_data: Dict[str, Any], output_path: str = "/app/reports/vulnerability_report.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Internal Vulnerability Scanner Sandbox")
    parser.add_argument("--config", default="/app/config/targets.json", help="Path to targets.json")
    parser.add_argument("--verify-exploitable", action="store_true", help="Run active exploit verification probes")
    parser.add_argument("--output", default="/app/reports/vulnerability_report.json", help="Path to report output")

    args = parser.parse_args()
    scanner = VulnerabilityScanner(config_path=args.config)
    report = scanner.run_scan(verify_exploitable=args.verify_exploitable)
    scanner.save_report(report, output_path=args.output)
    print(f"Scan complete. Found {len(report['findings'])} findings. Report saved to {args.output}")


if __name__ == "__main__":
    main()
