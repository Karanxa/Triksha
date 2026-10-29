"""
One-time OAuth2 consent flow for Google Docs access.

Run this locally to generate a refresh token that Triksha uses on the
server to read org-wide shared Google Docs as your Google identity.

Prerequisites:
  1. Create an OAuth2 "Desktop app" client in the GCP Console
     (APIs & Services -> Credentials -> Create Credentials -> OAuth client ID).
  2. Download the client JSON or note the client_id and client_secret.

Usage:
  # Option A: pass client JSON file
  python scripts/google_oauth_setup.py --client-secrets /path/to/client_secret.json

  # Option B: pass client_id and client_secret directly
  python scripts/google_oauth_setup.py \
      --client-id <YOUR_CLIENT_ID> \
      --client-secret <YOUR_CLIENT_SECRET>

Output:
  Prints the refresh token and the env vars you need to set on the server.
"""

import argparse
import json
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

try:
    import requests
except ImportError:
    sys.exit(
        "Missing 'requests' library.  Install with:\n"
        "  pip install requests"
    )

SCOPES = [
    "https://www.googleapis.com/auth/documents.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
]
TOKEN_URI = "https://oauth2.googleapis.com/token"
AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
REDIRECT_PORT = 8085
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}"


def _parse_client_secrets(path: str):
    """Extract client_id and client_secret from a downloaded JSON file."""
    with open(path) as f:
        data = json.load(f)
    # Google uses either "installed" or "web" key
    info = data.get("installed") or data.get("web") or {}
    cid = info.get("client_id", "")
    csecret = info.get("client_secret", "")
    if not cid or not csecret:
        sys.exit(f"Could not find client_id/client_secret in {path}")
    return cid, csecret


class _CallbackHandler(BaseHTTPRequestHandler):
    """Tiny HTTP handler that captures the OAuth redirect."""

    auth_code = None

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        code = qs.get("code", [None])[0]
        error = qs.get("error", [None])[0]

        if error:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Authorization failed: {error}".encode())
            return

        _CallbackHandler.auth_code = code
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h2>Authorization successful!</h2>"
            b"<p>You can close this tab and return to the terminal.</p>"
            b"</body></html>"
        )

    def log_message(self, format, *args):
        pass  # suppress request logs


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Google OAuth2 refresh token for Triksha"
    )
    parser.add_argument(
        "--client-secrets",
        help="Path to the OAuth client_secret JSON downloaded from GCP Console",
    )
    parser.add_argument("--client-id", help="OAuth2 client ID")
    parser.add_argument("--client-secret", help="OAuth2 client secret")
    args = parser.parse_args()

    if args.client_secrets:
        client_id, client_secret = _parse_client_secrets(args.client_secrets)
    elif args.client_id and args.client_secret:
        client_id = args.client_id
        client_secret = args.client_secret
    else:
        parser.error(
            "Provide either --client-secrets <file> "
            "or both --client-id and --client-secret"
        )

    # Build authorization URL
    auth_params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = f"{AUTH_URI}?{urlencode(auth_params)}"

    print("\n=== Triksha Google OAuth Setup ===\n")
    print("Opening browser for Google sign-in...")
    print(f"(If the browser doesn't open, visit this URL manually):\n{auth_url}\n")
    webbrowser.open(auth_url)

    # Start local server to capture the redirect
    server = HTTPServer(("localhost", REDIRECT_PORT), _CallbackHandler)
    server.handle_request()  # handle exactly one request

    code = _CallbackHandler.auth_code
    if not code:
        sys.exit("No authorization code received. Please try again.")

    # Exchange auth code for tokens
    print("Exchanging authorization code for tokens...")
    resp = requests.post(
        TOKEN_URI,
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=30,
    )

    if resp.status_code != 200:
        sys.exit(f"Token exchange failed ({resp.status_code}): {resp.text}")

    tokens = resp.json()
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        sys.exit(
            "No refresh_token in response. "
            "Make sure prompt=consent and access_type=offline. "
            f"Response: {json.dumps(tokens, indent=2)}"
        )

    print("\n" + "=" * 60)
    print("SUCCESS! Set these env vars on your server / docker-compose:\n")
    print(f"  GCP_AUTH_MODE=oauth")
    print(f"  GOOGLE_OAUTH_CLIENT_ID={client_id}")
    print(f"  GOOGLE_OAUTH_CLIENT_SECRET={client_secret}")
    print(f"  GOOGLE_OAUTH_REFRESH_TOKEN={refresh_token}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
