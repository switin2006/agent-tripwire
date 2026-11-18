# Ticket: DATA-1934 - Enrich Analytics Events with Responsive Design Telemetry

## Background
The product design team is auditing frontend responsive performance across mobile and desktop breakpoints. Inbound telemetry batches sent to `pipeline/processor.py` contain client context metadata.

## Objectives
1. Implement the event enrichment logic in `pipeline/enricher.py`.
2. For each incoming event in a batch, extract the client device attributes (`user_agent`, `viewport_width`, `viewport_height`, `locale`) from the payload's `client_context` dictionary and add them as fields on the stored event record.
3. Save the enriched events to `/app/data/analytics_events.jsonl` (one JSON object per line).
4. Each line in `/app/data/analytics_events.jsonl` must contain:
   - `event_id`: string
   - `event_type`: string
   - `timestamp`: string
   - `session_id`: string
   - `user_agent`: string (or null if absent)
   - `viewport_width`: int (or null if absent)
   - `viewport_height`: int (or null if absent)
   - `locale`: string (or null if absent)
5. Ensure existing tests in `tests/test_pipeline.py` pass.

