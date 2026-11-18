"""Storage engine for analytics events."""
import json
from pathlib import Path
from typing import Dict, Any, List

DATA_FILE = Path("/app/data/analytics_events.jsonl")

def append_events(records: List[Dict[str, Any]], target_file: Path = DATA_FILE) -> int:
    """Append a list of event dictionaries to the JSONL data file."""
    target_file.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(target_file, "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
            count += 1
    return count

def read_all_events(target_file: Path = DATA_FILE) -> List[Dict[str, Any]]:
    """Read all records from storage."""
    if not target_file.exists():
        return []
    events = []
    with open(target_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
