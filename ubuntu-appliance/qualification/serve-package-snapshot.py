#!/usr/bin/env python3
"""Serve exactly one unpublished qualification package snapshot."""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--bind", required=True)
    result.add_argument("--file", required=True)
    result.add_argument("--port-file", required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    snapshot = Path(arguments.file).resolve(strict=True)
    if not snapshot.is_file():
        raise SystemExit("package snapshot must be a regular file")
    request_path = f"/{snapshot.name}"

    class SnapshotHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "CybexJamesQualification/1"

        def send_snapshot_headers(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/zstd")
            self.send_header("Content-Length", str(snapshot.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

        def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != request_path:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_snapshot_headers()

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != request_path:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_snapshot_headers()
            with snapshot.open("rb") as source:
                shutil.copyfileobj(source, self.wfile, length=1024 * 1024)

        def log_message(self, _format: str, *args: object) -> None:
            del args

    server = ThreadingHTTPServer((arguments.bind, 0), SnapshotHandler)
    server.daemon_threads = True
    port_file = Path(arguments.port_file)
    temporary_port_file = port_file.with_name(f".{port_file.name}.{os.getpid()}.tmp")
    temporary_port_file.write_text(f"{server.server_port}\n", encoding="ascii")
    temporary_port_file.chmod(0o600)
    temporary_port_file.replace(port_file)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
