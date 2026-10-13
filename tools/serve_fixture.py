"""本地样例站点: python3.10 tools/serve_fixture.py [port]"""
from __future__ import annotations

import functools
import http.server
import socketserver
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "demo_site"


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "application/javascript",
        ".map": "application/json",
    }

    def log_message(self, *args) -> None:  # 安静一点
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    handler = functools.partial(Handler, directory=str(ROOT))
    with Server(("127.0.0.1", port), handler) as httpd:
        print(f"demo site -> http://127.0.0.1:{port}  (root: {ROOT})")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
