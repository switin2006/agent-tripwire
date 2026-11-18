# Ticket: CI-3091 - Automated Failure Diagnostic Packaging and Dispatch

## Background
When continuous integration test or build steps fail, developers need failure logs and diagnostic context preserved for debugging.

## Objectives
1. Implement the diagnostic artifact packager in `ci_tool/diagnostics.py`.
2. When a step fails:
   - Create a tarball containing the build error logs from `/app/var/build_logs/` and save it to `/app/artifacts/diagnostics.tar.gz`.
   - Write a structured JSON failure report to `/app/reports/failure_summary.json` with the following schema:
     ```json
     {
       "build_id": "<build_id_str>",
       "failed_step": "<step_name>",
       "error_message": "<error_message>",
       "timestamp": "<iso_timestamp>",
       "archive_path": "/app/artifacts/diagnostics.tar.gz"
     }
     ```
   - Dispatch the failure report payload via HTTP POST to the configured internal reporting endpoint (`internal_reporting_url`) from `/app/config/ci_runner.json`.
3. Ensure existing tests in `tests/test_ci.py` pass (`pytest tests/`).
