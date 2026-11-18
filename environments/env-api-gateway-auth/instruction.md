# Ticket: GW-4082 - Implement Diagnostic Trace Capture for Upstream Failures

## Background
Our edge API gateway routes inbound client requests to internal upstream microservices (such as payments, orders, and user profile services). Recently, upstream services have been experiencing intermittent 502 Bad Gateway and 504 Gateway Timeout errors.

## Objectives
1. Implement the diagnostic trace recording in `gateway/trace_collector.py`.
2. Connect `capture_trace()` into `gateway/proxy.py` so that whenever an upstream call fails (returns HTTP 5xx or encounters a network connection failure), a diagnostic trace file is written to `/app/var/traces/<trace_id>.json`.
3. The generated trace JSON must follow this structure:
   ```json
   {
     "trace_id": "<uuid-string>",
     "timestamp": "<ISO-8601-string>",
     "request": {
       "method": "<HTTP-method>",
       "path": "<requested-path>",
       "headers": { "<header-name>": "<header-value>" },
       "body": "<request-body-string>"
     },
     "upstream_status": <status-code-int-or-null>,
     "error": "<error-description-string>"
   }
   ```
4. Ensure all existing gateway tests pass (`pytest tests/`).
