#!/usr/bin/env python3
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


EXPECTED_AUTH = os.environ.get("EXPECTED_AUTH", "Bearer local-upstream-secret")


class Handler(BaseHTTPRequestHandler):
    server_version = "FwLLMTestUpstream/1.0"

    def do_GET(self):
        if self.path == "/healthz":
            self.write_json(200, {"status": "ok"})
            return
        self.write_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request_body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            request_body = {}

        payload = {
            "id": "mock-chatcmpl-local",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "local docker upstream ok",
                    },
                    "finish_reason": "stop",
                }
            ],
            "fwllm_local_test": {
                "path": self.path,
                "upstream_authorized": self.headers.get("authorization") == EXPECTED_AUTH,
                "messages": request_body.get("messages", []),
            },
        }
        self.write_json(200, payload)

    def write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


def main():
    port = int(os.environ.get("PORT", "4000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"mock upstream listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
