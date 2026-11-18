"""Edge Reverse Proxy Server."""
import json
import time
import uuid
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Tuple
from datetime import datetime, timezone

from gateway.config import ROUTES, DEFAULT_TIMEOUT
from gateway.auth import verify_credentials
from gateway.logger import AccessLogger

try:
    from gateway.trace_collector import capture_trace
except ImportError:
    capture_trace = None

logger = AccessLogger()

def forward_request(
    method: str,
    path: str,
    headers: Dict[str, str],
    body: str,
) -> Tuple[int, Dict[str, str], str]:
    """Forward an inbound request to the matching upstream microservice.
    
    Returns (status_code, response_headers, response_body).
    """
    matched_prefix = None
    for prefix in ROUTES:
        if path.startswith(prefix):
            matched_prefix = prefix
            break

    if not matched_prefix:
        return 404, {"Content-Type": "application/json"}, json.dumps({"error": "Route not found"})

    upstream_base = ROUTES[matched_prefix]
    subpath = path[len(matched_prefix):]
    target_url = f"{upstream_base}{subpath}"

    trace_id = str(uuid.uuid4())
    req_headers = {k: v for k, v in headers.items() if k.lower() not in {"host", "content-length"}}
    
    data_bytes = body.encode("utf-8") if body else None
    req = urllib.request.Request(target_url, data=data_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.headers)
            return resp.status, resp_headers, resp_body

    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        status_code = e.code
        
        # If upstream fails with 5xx, invoke trace collector if available
        if status_code >= 500 and capture_trace:
            try:
                capture_trace(
                    trace_id=trace_id,
                    request_data={
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body,
                    },
                    upstream_status=status_code,
                    error_message=f"Upstream HTTP error: {e.reason}",
                )
            except NotImplementedError:
                pass

        return status_code, {"Content-Type": "application/json"}, json.dumps({
            "error": "Upstream error",
            "status": status_code,
            "details": err_body,
            "trace_id": trace_id
        })

    except Exception as e:
        if capture_trace:
            try:
                capture_trace(
                    trace_id=trace_id,
                    request_data={
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body,
                    },
                    upstream_status=None,
                    error_message=f"Connection failed: {str(e)}",
                )
            except NotImplementedError:
                pass

        return 502, {"Content-Type": "application/json"}, json.dumps({
            "error": "Bad Gateway",
            "message": str(e),
            "trace_id": trace_id
        })


def handle_inbound_request(
    method: str,
    path: str,
    headers: Dict[str, str],
    body: str,
) -> Tuple[int, Dict[str, str], str]:
    """Handle an inbound request: authenticate, forward, and log."""
    start_time = time.time()
    
    # 1. Authenticate request
    is_valid, auth_result = verify_credentials(headers)
    if not is_valid:
        duration_ms = (time.time() - start_time) * 1000
        logger.log_request(method, path, 401, duration_ms, headers)
        return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Unauthorized", "details": auth_result})

    # 2. Forward to upstream
    status, resp_headers, resp_body = forward_request(method, path, headers, body)
    duration_ms = (time.time() - start_time) * 1000
    
    # 3. Log access
    logger.log_request(method, path, status, duration_ms, headers)
    return status, resp_headers, resp_body
