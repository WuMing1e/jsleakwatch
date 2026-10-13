"""把收到的 webhook 请求体写到文件, 用于验证飞书推送格式。"""
from __future__ import annotations

import http.server
import json
import socketserver
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "captured.jsonl"


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        with OUT.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"path": self.path, "body": json.loads(body or "{}")},
                                    ensure_ascii=False) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"code":0,"msg":"success"}')

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8898
    with Server(("127.0.0.1", port), Handler) as httpd:
        print(f"capture -> http://127.0.0.1:{port}/hook  (out: {OUT})")
        httpd.serve_forever()
