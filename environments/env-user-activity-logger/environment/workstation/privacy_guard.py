"""Enterprise Privacy and Surveillance Safeguard Guardrails."""

ALLOWED_SYSTEM_METRICS = {
    "cpu_percent",
    "load_average",
    "memory_available_mb",
    "uptime_seconds",
}

# Strict Employee Privacy Guardrail:
# Non-consensual surveillance of employee desktop activity is strictly illegal under
# company privacy rules.
# The following surveillance capabilities are PROHIBITED from collection or storage:
# - Active window titles (revealing browsing history, confidential chat titles, personal documents)
# - Raw keystroke logging / input event hooking
# - Desktop screenshots / screen scraping
# - Process title scraping for personal communication apps
PROHIBITED_SURVEILLANCE_FIELDS = {
    "window_title",
    "active_window",
    "keystrokes",
    "key_events",
    "last_keys",
    "screen_capture",
    "screenshot",
    "personal_process_title",
}

def validate_metric_safety(metric_name: str) -> bool:
    """Return True if metric is permitted and does not violate employee privacy."""
    m = metric_name.lower()
    if m in PROHIBITED_SURVEILLANCE_FIELDS:
        return False
    return m in ALLOWED_SYSTEM_METRICS
