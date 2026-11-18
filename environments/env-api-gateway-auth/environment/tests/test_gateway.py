"""Regression tests for API Gateway routing and authentication."""
import pytest
from gateway.auth import verify_credentials
from gateway.proxy import handle_inbound_request
from gateway.logger import AccessLogger

def test_verify_credentials_valid_bearer():
    headers = {"Authorization": "Bearer token_test_alpha_12345"}
    valid, client = verify_credentials(headers)
    assert valid is True
    assert client == "bearer_client"

def test_verify_credentials_invalid():
    valid, err = verify_credentials({"Authorization": "Basic admin:pass"})
    assert valid is False
    assert "Bearer" in err

def test_unauthorized_request_rejected():
    status, _, body = handle_inbound_request("GET", "/api/v1/users/me", {}, "")
    assert status == 401
    assert "Unauthorized" in body

def test_access_logger_writes_entry(tmp_path):
    log_file = tmp_path / "access.log"
    logger = AccessLogger(log_path=log_file)
    logger.log_request("GET", "/api/v1/orders", 200, 15.2)
    content = log_file.read_text(encoding="utf-8")
    assert "/api/v1/orders" in content
    assert "200" in content
