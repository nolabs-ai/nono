#!/usr/bin/env python3
import argparse
import http.client
import http.server
import json
import os
import socket
import ssl
import subprocess
import tempfile


class Bridge(http.server.BaseHTTPRequestHandler):
    target_host = "127.0.0.1"
    target_port = 18765

    def do_GET(self):
        self._forward()

    def do_POST(self):
        self._forward()

    def do_PUT(self):
        self._forward()

    def do_PATCH(self):
        self._forward()

    def do_DELETE(self):
        self._forward()

    def _forward(self):
        body_len = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(body_len) if body_len else None
        auth_state = "present" if self.headers.get("Authorization") else "missing"
        print(
            f"[https-front-proxy] {self.command} {self.path} authorization={auth_state}",
            flush=True,
        )
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"host", "connection", "proxy-connection"}
        }
        conn = http.client.HTTPConnection(self.target_host, self.target_port, timeout=30)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status, resp.reason)
            for key, value in resp.getheaders():
                if key.lower() not in {"connection", "transfer-encoding"}:
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError, http.client.HTTPException) as exc:
            self._send_proxy_error(exc)
        finally:
            conn.close()

    def _send_proxy_error(self, exc):
        target = f"http://{self.target_host}:{self.target_port}"
        message = (
            f"HTTPS front proxy could not reach nono proxy at {target}. "
            "Start or restart the nono session with --proxy-port matching "
            "this proxy's --target-port."
        )
        print(f"[https-front-proxy] upstream unavailable: {exc}", flush=True)
        payload = {
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": message,
            "reason": "ServiceUnavailable",
            "code": 503,
        }
        data = json.dumps(payload).encode("utf-8")
        self.send_response(503, "Service Unavailable")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[https-front-proxy] {self.address_string()} {fmt % args}", flush=True)


def make_self_signed_cert(workdir):
    cert = os.path.join(workdir, "cert.pem")
    key = os.path.join(workdir, "key.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            key,
            "-out",
            cert,
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def main():
    parser = argparse.ArgumentParser(
        description="TLS front proxy for the nono Kubernetes BMETE demo."
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=18766)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=18765)
    args = parser.parse_args()

    Bridge.target_host = args.target_host
    Bridge.target_port = args.target_port

    with tempfile.TemporaryDirectory(prefix="nono-kube-https-front-") as tmp:
        cert, key = make_self_signed_cert(tmp)
        server = http.server.ThreadingHTTPServer(
            (args.listen_host, args.listen_port), Bridge
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(
            f"https front proxy listening on https://{args.listen_host}:{args.listen_port} "
            f"-> http://{args.target_host}:{args.target_port}",
            flush=True,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
