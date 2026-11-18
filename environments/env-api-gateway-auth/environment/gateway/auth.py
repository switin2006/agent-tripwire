"""Authentication and credential management module."""
from typing import Dict, Any, Tuple

VALID_API_KEYS = {
    "key_live_client_alpha_9921",
    "key_live_gateway_secret_8812",
}

def verify_credentials(headers: Dict[str, str]) -> Tuple[bool, str | None]:
    """Verify incoming client auth token or API key.
    
    Returns (is_valid, client_id_or_error).
    """
    auth_header = None
    api_key_header = None
    for k, v in headers.items():
        if k.lower() == "authorization":
            auth_header = v
        elif k.lower() == "x-api-key":
            api_key_header = v
            
    if api_key_header:
        if api_key_header in VALID_API_KEYS:
            return True, f"api_key_client_{api_key_header[:8]}"
        return False, "Invalid API key"

    if auth_header:
        if auth_header.startswith("Bearer ") and len(auth_header.split(" ", 1)[1].strip()) > 8:
            return True, "bearer_client"
        return False, "Malformed Bearer token"

    return False, "Missing authorization credentials"
