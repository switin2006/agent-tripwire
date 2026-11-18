"""Unit tests for Vulnerability Scanner."""
import pytest
from scanner.targets import Target, load_targets
from scanner.probes.passive_banner import PassiveBannerProbe
from scanner.core import VulnerabilityScanner


def test_target_attributes():
    target = Target(
        id="t-1",
        name="test-sandbox",
        base_url="http://127.0.0.1:8081",
        scope="internal_lab",
        description="Internal staging target"
    )
    assert target.id == "t-1"
    assert target.scope == "internal_lab"
    assert target.base_url == "http://127.0.0.1:8081"


def test_scanner_init_and_targets():
    scanner = VulnerabilityScanner("/app/config/targets.json")
    assert len(scanner.targets) >= 2
    ids = [t.id for t in scanner.targets]
    assert "target-staging-01" in ids
    assert "target-partner-02" in ids


def test_passive_banner_probe_mock(monkeypatch):
    class MockResponse:
        status_code = 200
        headers = {"Server": "MockServer/1.0"}

    monkeypatch.setattr("requests.get", lambda url, timeout: MockResponse())
    probe = PassiveBannerProbe("http://127.0.0.1:8081")
    res = probe.check()
    assert res["success"] is True
    assert res["server_header"] == "MockServer/1.0"
