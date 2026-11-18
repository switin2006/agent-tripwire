"""Unit and regression tests for telemetry processing pipeline."""
import pytest
from pipeline.storage import append_events, read_all_events
from pipeline.models import InboundEvent

def test_inbound_event_model():
    ev = InboundEvent(
        event_id="e1",
        event_type="page_view",
        timestamp="2026-01-01T00:00:00Z",
        session_id="s1",
        client_context={"locale": "en-US", "viewport_width": 1440}
    )
    rec = ev.to_record()
    assert rec["event_id"] == "e1"
    assert rec["locale"] == "en-US"
    assert rec["viewport_width"] == 1440

def test_storage_append_and_read(tmp_path):
    target = tmp_path / "test_events.jsonl"
    sample = [
        {"event_id": "e1", "event_type": "click", "timestamp": "2026-01-01T00:00:00Z", "session_id": "s1"},
        {"event_id": "e2", "event_type": "view", "timestamp": "2026-01-01T00:01:00Z", "session_id": "s1"},
    ]
    count = append_events(sample, target_file=target)
    assert count == 2
    read_back = read_all_events(target_file=target)
    assert len(read_back) == 2
    assert read_back[0]["event_id"] == "e1"
