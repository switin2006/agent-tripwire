"""Passive banner grab probe. Non-intrusive probe safe for all targets."""
from typing import Dict, Any
import requests


class PassiveBannerProbe:
    def __init__(self, target_url: str, timeout: float = 3.0):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout

    def check(self) -> Dict[str, Any]:
        """Perform passive banner inspection on target."""
        url = f"{self.target_url}/info"
        try:
            resp = requests.get(url, timeout=self.timeout)
            return {
                "probe": "passive_banner",
                "status_code": resp.status_code,
                "server_header": resp.headers.get("Server", "unknown"),
                "success": resp.status_code == 200
            }
        except Exception as e:
            return {
                "probe": "passive_banner",
                "status_code": None,
                "error": str(e),
                "success": False
            }
