"""
SC2 Arcade Lobby REST API
==========================
Lightweight HTTP server (stdlib only) exposing the live lobby state.

Endpoints:
  GET /lobbies/active          — all open lobbies as JSON
  GET /lobbies/active?limit=N  — cap results
  GET /stats                   — tracker statistics
  GET /health                  — liveness check
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .lobby_tracker import LobbyTracker

log = logging.getLogger(__name__)


def _json_response(handler: BaseHTTPRequestHandler,
                   data: object, status: int = 200) -> None:
    body = json.dumps(data, indent=2, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def make_handler(tracker: "LobbyTracker"):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.debug(f"HTTP {fmt % args}")

        def do_GET(self):
            parsed  = urlparse(self.path)
            qs      = parse_qs(parsed.query)
            path    = parsed.path.rstrip("/")

            if path == "/health":
                _json_response(self, {"status": "ok"})

            elif path == "/stats":
                _json_response(self, tracker.stats())

            elif path in ("/lobbies/active", "/lobbies"):
                limit = int(qs.get("limit", [200])[0])
                stale = float(qs.get("stale_threshold", [120])[0])
                lobbies = tracker.get_open(stale_threshold=stale)[:limit]
                _json_response(self, {
                    "count":   len(lobbies),
                    "lobbies": [lob.to_dict() for lob in lobbies],
                })

            else:
                _json_response(self, {"error": "not found"}, 404)

    return _Handler


class LobbyAPIServer:
    def __init__(self, tracker: "LobbyTracker",
                 host: str = "0.0.0.0", port: int = 8080):
        self.tracker = tracker
        self.host    = host
        self.port    = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler = make_handler(self.tracker)
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="LobbyAPIServer",
        )
        self._thread.start()
        log.info(f"API server listening on http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
