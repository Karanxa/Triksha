"""Optional Bearer token for outbound LLM gateway requests."""

import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_TOKEN_URL = os.environ.get("AUTHN_TOKEN_URL", "").strip()


def get_bearer_token() -> Optional[str]:
    if not _TOKEN_URL:
        return None
    logger.debug("Gateway token URL configured but token fetch is not enabled")
    return None


def get_proxy_auth_headers(api_key: Optional[str] = None) -> Dict[str, str]:
    key = api_key or os.environ.get("GEMINI_API_KEY", "")
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": key,
    }
    bearer = get_bearer_token()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers
