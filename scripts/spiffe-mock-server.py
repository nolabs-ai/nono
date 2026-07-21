#!/usr/bin/env python3
"""
Mock upstream server that validates SPIFFE JWT-SVIDs.

Fetches JWKS from the SPIRE OIDC discovery endpoint, validates the
Authorization: Bearer token on every request, and returns the parsed
claims as JSON so you can see exactly what nono injected.

Usage:
    pip install PyJWT cryptography requests
    python3 scripts/spiffe-mock-server.py \
        --issuer ISS \
        --audience AUD \
        --port PORT
"""

import argparse
import json
import time
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import jwt
    import requests
except ImportError:
    print("Missing deps. Run: pip install PyJWT cryptography requests")
    sys.exit(1)


RESET  = "\033[0m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"


def fetch_jwks(issuer: str) -> dict:
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    print(f"{CYAN}Fetching OIDC discovery: {discovery_url}{RESET}")
    disco = requests.get(discovery_url, timeout=10)
    disco.raise_for_status()
    jwks_uri = disco.json()["jwks_uri"]
    print(f"{CYAN}Fetching JWKS: {jwks_uri}{RESET}")
    jwks_resp = requests.get(jwks_uri, timeout=10)
    jwks_resp.raise_for_status()
    keys = jwks_resp.json()
    print(f"{GREEN}Loaded {len(keys.get('keys', []))} key(s) from JWKS{RESET}\n")
    return keys


def make_handler(jwks: dict, audience: str, issuer: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # suppress default logging, we do our own

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def _handle(self):
            ts = time.strftime("%H:%M:%S")
            print(f"{BOLD}──── {ts} {self.command} {self.path} ────{RESET}")
            print(f"  {CYAN}Headers:{RESET}")
            for name, value in self.headers.items():
                print(f"    {name}: {value}")

            # Reject requests that contain unexpected credential headers — a
            # real upstream would do the same and this catches proxy leaks.
            for forbidden in ("x-api-key", "proxy-authorization", "proxy-connection"):
                if self.headers.get(forbidden):
                    self._reject(400, f"unexpected header forwarded: {forbidden}")
                    return

            auth = self.headers.get("Authorization", "")
            if not auth.lower().startswith("bearer "):
                self._reject(401, "missing or non-Bearer Authorization header")
                return

            token = auth[len("bearer "):].strip()
            print(f"  Token  : {token[:40]}...{token[-10:]}")

            try:
                jwks_client = jwt.PyJWKClient.__new__(jwt.PyJWKClient)
                signing_key = jwt.PyJWK.from_dict(self._pick_key(token, jwks))
                claims = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["ES256", "RS256"],
                    audience=audience,
                    issuer=issuer,
                )
            except jwt.ExpiredSignatureError:
                self._reject(401, "token expired")
                return
            except jwt.InvalidAudienceError as e:
                self._reject(401, f"audience mismatch: {e}")
                return
            except jwt.InvalidIssuerError as e:
                self._reject(401, f"issuer mismatch: {e}")
                return
            except Exception as e:
                self._reject(401, f"validation failed: {e}")
                return

            print(f"  {GREEN}✓ JWT valid{RESET}")
            print(f"  sub    : {BOLD}{claims.get('sub')}{RESET}")
            print(f"  iss    : {claims.get('iss')}")
            print(f"  aud    : {claims.get('aud')}")
            exp = claims.get('exp', 0)
            ttl = max(0, exp - int(time.time()))
            print(f"  exp    : {time.strftime('%H:%M:%S', time.gmtime(exp))} UTC  ({ttl}s remaining)")
            print()

            body = json.dumps({
                "status": "ok",
                "message": "SPIFFE JWT-SVID validated successfully",
                "claims": claims,
            }, indent=2).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _pick_key(self, token: str, jwks: dict):
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    return key
            # fall back to first key
            return jwks["keys"][0]

        def _reject(self, code: int, reason: str):
            print(f"  {RED}✗ {reason}{RESET}\n")
            body = json.dumps({"status": "error", "reason": reason}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main():
    parser = argparse.ArgumentParser(description="SPIFFE JWT-SVID mock upstream")
    parser.add_argument("--issuer",   required=True, help="SPIRE JWT issuer URL")
    parser.add_argument("--audience", required=True, help="Expected audience claim")
    parser.add_argument("--port",     type=int, default=8888)
    args = parser.parse_args()

    jwks = fetch_jwks(args.issuer)
    handler = make_handler(jwks, args.audience, args.issuer)

    server = HTTPServer(("127.0.0.1", args.port), handler)
    print(f"{BOLD}Mock upstream listening on http://127.0.0.1:{args.port}{RESET}")
    print(f"  Issuer   : {args.issuer}")
    print(f"  Audience : {args.audience}")
    print(f"\nWaiting for requests...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
