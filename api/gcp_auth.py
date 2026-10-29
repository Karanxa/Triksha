"""
GCP Authentication Helper — Service Account, DWD, or OAuth Refresh Token

Provides a thin wrapper around google-auth that handles:
  1. Loading credentials from env vars or JSON files.
  2. **Three auth modes** controlled by GCP_AUTH_MODE:
     - ``oauth`` (default): Uses a stored OAuth2 refresh token from a
       real user account.  The token is obtained once via a local
       consent flow and passed as an env var on the server.  Gives the
       same access as the consenting user (including org-wide shared
       Google Docs).  No Workspace Admin setup required.
     - ``group``: The SA authenticates as *itself*. Access to Google
       Docs/Drive comes from the SA being a member of a Google Group
       that has been explicitly granted access on the documents.
     - ``dwd``: Domain-Wide Delegation — the SA impersonates a
       a user account so it inherits that user's document access.
       Requires Workspace Admin to whitelist the SA client_id + scopes.
  3. Automatic token refresh.
  4. Scoped credential caching.
  5. Convenient accessors for headers and raw tokens.

Environment requirements (pick ONE mode):

  OAuth mode (recommended):
    - GCP_AUTH_MODE=oauth
    - GOOGLE_OAUTH_CLIENT_ID=<OAuth2 client ID from GCP Console>
    - GOOGLE_OAUTH_CLIENT_SECRET=<OAuth2 client secret>
    - GOOGLE_OAUTH_REFRESH_TOKEN=<refresh token from one-time consent>

  Group mode:
    - GCP_AUTH_MODE=group
    - GOOGLE_APPLICATION_CREDENTIALS=<path to SA key JSON>

  DWD mode:
    - GCP_AUTH_MODE=dwd
    - GOOGLE_APPLICATION_CREDENTIALS=<path to SA key JSON>
    - GCP_IMPERSONATE_USER=<user@yourdomain.com>

Usage:
    from gcp_auth import get_gcp_credentials, get_gcp_access_token, gcp_auth_headers

    credentials, project = get_gcp_credentials()

    token = get_gcp_access_token(scopes=[
        "https://www.googleapis.com/auth/documents.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
    ])

    headers = gcp_auth_headers()   # {"Authorization": "Bearer ..."}
"""

import json
import logging
import os
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("gcp_auth")

# ---------------------------------------------------------------------------
# Lazy, thread-safe credential cache — keyed by (scopes, subject)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_credentials_cache: Dict[tuple, object] = {}   # (scope_key, subject) → credentials
_project: Optional[str] = None

# Default scope — wide enough for BigQuery, GCS, Vertex, etc.
_DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


_VALID_AUTH_MODES = ("oauth", "group", "dwd")


def _is_configured() -> bool:
    """Return True when credentials are available for the active auth mode."""
    mode = _get_auth_mode()
    if mode == "oauth":
        return all([
            os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
            os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
            os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN", ""),
        ])
    path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
    return bool(path) and os.path.isfile(path)


def _get_auth_mode() -> str:
    """Return the active GCP authentication mode.

    - ``oauth``: Stored refresh token from a real user account.
    - ``group``: SA authenticates as itself; access via Google Group membership.
    - ``dwd``:   SA impersonates a user via Domain-Wide Delegation.
    """
    mode = os.getenv("GCP_AUTH_MODE", "group").strip().lower()
    if mode not in _VALID_AUTH_MODES:
        logger.warning("Unknown GCP_AUTH_MODE=%r, falling back to 'group'", mode)
        return "group"
    return mode


def _get_impersonate_user() -> Optional[str]:
    """Return the user to impersonate via DWD, or None.

    Returns None when auth mode is ``group`` (SA acts as itself).
    """
    if _get_auth_mode() != "dwd":
        return None
    user = os.getenv("GCP_IMPERSONATE_USER", "").strip()
    if not user:
        logger.warning(
            "GCP_AUTH_MODE=dwd but GCP_IMPERSONATE_USER is empty — "
            "DWD requires a subject. Falling back to direct SA auth."
        )
        return None
    return user


def _is_sa_key_file(path: str) -> bool:
    """Check if the credentials file is a service_account key (not WIF)."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data.get("type") == "service_account"
    except Exception:
        return False


def get_gcp_credentials(
    scopes: Optional[List[str]] = None,
    subject: Optional[str] = None,
    force_refresh: bool = False,
):
    """
    Return (credentials, project_id).

    Behaviour depends on GCP_AUTH_MODE:
      - ``oauth``: Build credentials from a stored OAuth2 refresh token.
      - ``group``: SA authenticates as itself (Google Group access).
      - ``dwd``:   SA impersonates a user via Domain-Wide Delegation.

    Credentials are cached per (scopes, subject) so callers requesting
    Docs API scopes get a different token than callers requesting
    cloud-platform.

    Raises ImportError if google-auth is not installed.
    Raises EnvironmentError if credentials are not configured.
    """
    global _project

    auth_mode = _get_auth_mode()

    if not _is_configured():
        if auth_mode == "oauth":
            raise EnvironmentError(
                "OAuth mode requires GOOGLE_OAUTH_CLIENT_ID, "
                "GOOGLE_OAUTH_CLIENT_SECRET, and GOOGLE_OAUTH_REFRESH_TOKEN. "
                "Run 'python scripts/google_oauth_setup.py' to generate a refresh token."
            )
        raise EnvironmentError(
            "GOOGLE_APPLICATION_CREDENTIALS is not set or the file does not exist. "
            "Set the env var to point at a SA key or WIF config JSON."
        )

    effective_scopes = scopes or _DEFAULT_SCOPES
    effective_subject = subject or _get_impersonate_user()
    cache_key = (auth_mode, frozenset(effective_scopes), effective_subject)

    with _lock:
        cached = _credentials_cache.get(cache_key)

        if cached is None or force_refresh:
            try:
                from google.auth.transport.requests import Request

                if auth_mode == "oauth":
                    creds, project = _load_oauth_credentials(effective_scopes, Request())
                else:
                    creds, project = _load_sa_credentials(
                        auth_mode, effective_scopes, effective_subject, Request(),
                    )

                _credentials_cache[cache_key] = creds
                _project = project
                return creds, project

            except Exception as exc:
                logger.error("Failed to load GCP credentials (mode=%s): %s", auth_mode, exc)
                raise
        else:
            try:
                from google.auth.transport.requests import Request

                if not cached.valid:
                    cached.refresh(Request())
            except Exception as exc:
                logger.warning("GCP token refresh failed, reloading: %s", exc)
                _credentials_cache.pop(cache_key, None)
                raise

            return cached, _project


def _load_oauth_credentials(scopes: List[str], request_obj):
    """Build credentials from env-var-based OAuth2 refresh token."""
    from google.oauth2.credentials import Credentials

    creds = Credentials(
        token=None,
        refresh_token=os.environ["GOOGLE_OAUTH_REFRESH_TOKEN"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ["GOOGLE_OAUTH_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_OAUTH_CLIENT_SECRET"],
        scopes=scopes,
    )
    creds.refresh(request_obj)
    logger.info(
        "OAuth credentials loaded (scopes=%s, token_expiry=%s)",
        scopes, getattr(creds, "expiry", "n/a"),
    )
    return creds, None


def _load_sa_credentials(auth_mode, scopes, subject, request_obj):
    """Load SA credentials for group or DWD mode."""
    creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")

    if subject and _is_sa_key_file(creds_path):
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(
            creds_path, scopes=scopes, subject=subject,
        )
        creds.refresh(request_obj)
        with open(creds_path, "r") as f:
            project = json.load(f).get("project_id")
        logger.info(
            "GCP SA credentials loaded with DWD "
            "(mode=%s, project=%s, SA=%s, subject=%s, scopes=%s)",
            auth_mode, project, creds.service_account_email, subject, scopes,
        )

    elif _is_sa_key_file(creds_path):
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(
            creds_path, scopes=scopes,
        )
        creds.refresh(request_obj)
        with open(creds_path, "r") as f:
            project = json.load(f).get("project_id")
        logger.info(
            "GCP SA credentials loaded (mode=%s, project=%s, SA=%s, scopes=%s)",
            auth_mode, project, creds.service_account_email, scopes,
        )

    else:
        import google.auth
        creds, project = google.auth.default(scopes=scopes)
        creds.refresh(request_obj)
        logger.info(
            "GCP credentials loaded via ADC (mode=%s, project=%s, SA=%s, scopes=%s)",
            auth_mode, project, getattr(creds, "service_account_email", "n/a"), scopes,
        )

    return creds, project


def get_gcp_access_token(
    scopes: Optional[List[str]] = None,
    subject: Optional[str] = None,
) -> str:
    """Return a valid GCP access token string (refreshed if needed)."""
    creds, _ = get_gcp_credentials(scopes=scopes, subject=subject)
    return creds.token


def gcp_auth_headers(
    scopes: Optional[List[str]] = None,
    subject: Optional[str] = None,
) -> Dict[str, str]:
    """Return Authorization headers for raw HTTP calls to GCP APIs."""
    token = get_gcp_access_token(scopes=scopes, subject=subject)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def get_gcp_project_id() -> Optional[str]:
    """Return the GCP project ID from the loaded credentials."""
    _, project = get_gcp_credentials()
    return project


def is_gcp_available() -> bool:
    """
    Check if GCP integration is available and configured.
    Returns True if credentials can be loaded, False otherwise.
    Does not raise exceptions.
    """
    if not _is_configured():
        return False
    try:
        # For oauth mode, try with Docs scopes since that's the primary use case
        if _get_auth_mode() == "oauth":
            get_gcp_credentials(scopes=[
                "https://www.googleapis.com/auth/documents.readonly",
                "https://www.googleapis.com/auth/drive.readonly",
            ])
        else:
            get_gcp_credentials()
        return True
    except Exception:
        return False
