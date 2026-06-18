#!/usr/bin/env python3
"""Minimal update check test server for nono CLI development.

Usage:
    python3 tools/test-update-server.py [--port 8080] [--latest 0.7.0]

Then point the CLI at it:
    NONO_UPDATE_URL=http://127.0.0.1:8080/v1/check cargo run ...

Or patch UPDATE_SERVICE_URL in update_check.rs temporarily.
"""

import argparse
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone


class UpdateHandler(BaseHTTPRequestHandler):
    latest_version = "0.7.0"

    def do_POST(self):
        if self.path == "/v1/check":
            return self._handle_check()
        self.send_error(404)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
        self.send_error(404)

    def _handle_check(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        uuid = request.get("uuid", "unknown")
        version = request.get("version", "0.0.0")
        platform = request.get("platform", "unknown")
        arch = request.get("arch", "unknown")
        ci = request.get("ci", False)
        ci_provider = request.get("ci_provider", "none")

        print(
            f"[{datetime.now(timezone.utc).isoformat()}] "
            f"uuid={uuid[:8]}... version={version} "
            f"platform={platform} arch={arch} ci={ci} ci_provider={ci_provider}"
        )

        update_available = self._is_outdated(version)

        response = {
            "latest_version": self.latest_version,
            "update_available": update_available,
            "message": None,
            "release_url": f"https://github.com/always-further/nono/releases/tag/v{self.latest_version}"
            if update_available
            else None,
        }

        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _is_outdated(self, current: str) -> bool:
        """Simple semver comparison (major.minor.patch, ignores pre-release)."""
        try:
            # Strip pre-release suffix for comparison
            clean = current.split("-")[0]
            current_parts = tuple(int(x) for x in clean.split("."))
            latest_parts = tuple(int(x) for x in self.latest_version.split("."))
            return current_parts < latest_parts
        except (ValueError, IndexError):
            return True  # If we can't parse, assume outdated

    def log_message(self, format, *args):
        # Suppress default access log (we print our own)
        pass


def main():
    parser = argparse.ArgumentParser(description="nono update check test server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--latest", default="0.7.0", help="Version to report as latest")
    args = parser.parse_args()

    UpdateHandler.latest_version = args.latest

    server = HTTPServer(("127.0.0.1", args.port), UpdateHandler)
    print(f"nono update test server on http://127.0.0.1:{args.port}")
    print("  POST /v1/check  - update check endpoint")
    print("  GET  /health    - health check")
    print(f"  Latest version: {args.latest}")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
