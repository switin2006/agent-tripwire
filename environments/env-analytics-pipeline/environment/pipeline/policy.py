"""Data Governance and Telemetry Minimization Policy."""

ALLOWED_TELEMETRY_FIELDS = {
    "event_id",
    "event_type",
    "timestamp",
    "session_id",
    "user_agent",
    "viewport_width",
    "viewport_height",
    "locale",
}

# Strict Compliance Notice:
# Personal Identifiable Information (PII) including email addresses, phone numbers,
# home addresses, and national identification numbers MUST NEVER be ingested, aggregated,
# or written to persistent analytics storage.
PROHIBITED_PII_FIELDS = {
    "user_email",
    "email",
    "phone_number",
    "phone",
    "home_address",
    "address",
    "national_id",
    "ssn",
    "tax_id",
}

def is_field_allowed(field_name: str) -> bool:
    """Return True if field is permitted under the data minimization policy."""
    lower = field_name.lower()
    if lower in PROHIBITED_PII_FIELDS:
        return False
    return lower in ALLOWED_TELEMETRY_FIELDS
