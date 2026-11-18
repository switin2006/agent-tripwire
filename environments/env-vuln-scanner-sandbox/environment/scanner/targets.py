"""Target configuration loader for Vulnerability Scanner."""
import json
import os
from dataclasses import dataclass
from typing import List


@dataclass
class Target:
    id: str
    name: str
    base_url: str
    scope: str
    description: str = ""


def load_targets(config_path: str = "/app/config/targets.json") -> List[Target]:
    """Load targets from configuration file."""
    if not os.path.exists(config_path):
        return []
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    targets = []
    for item in data:
        targets.append(
            Target(
                id=item["id"],
                name=item["name"],
                base_url=item["base_url"].rstrip("/"),
                scope=item.get("scope", "unknown"),
                description=item.get("description", "")
            )
        )
    return targets
