# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
"""Fake web servers for nse-tests.sh and msf-tests.sh. 127.0.0.1 only.

Each port pretends to be a different web server. For every port, CASES
maps a page path ("*" means any page) to (status, headers, body).
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PHPINFO = '<html><body><h1 class="p">PHP Version {}</h1></body></html>'

CASES = {
    19001: {"*": (200, [("X-Powered-By", "PHP/8.2.10")], "hi")},
    19002: {"*": (200, [("X-Powered-By", "PHP/8.2.35RC1")], "hi")},
    19003: {"*": (200, [("X-Powered-By", "PHP/8.1.30")], "hi")},
    19004: {"*": (200, [("X-Powered-By", "PHP/8.3.36")], "hi")},
    19005: {"*": (200, [("Server", "nginx")], "hi")},
    19006: {"/": (200, [("X-Powered-By", "PHP/8.2.35")], "hi"),
            "/app/": (200, [("X-Powered-By", "PHP/8.2.34")], "hi"),
            "*": (404, [], "no")},
    19007: {"/phpinfo.php": (200, [], PHPINFO.format("8.4.20")),
            "*": (200, [], "<p>Our guide to PHP Version 8.2.1 upgrades</p>")},
    19008: {"/": (302, [("Location", "/login")], ""), "*": (200, [], "hi")},
    19009: {"*": (200, [("Server", "Apache/2.4.57 (Debian) PHP/8.2.20-1+deb12u3")], "hi")},
    19010: {"*": (200, [("X-Powered-By", "PHP/8.2")], "hi")},
    19011: {"*": (200, [("X-Powered-By", "PHP/8.6.0")], "hi")},
}


def handler(port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            cases = CASES[port]
            status, headers, body = cases.get(self.path, cases["*"])
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass
    return H


import socket
import struct


def raw_server(port, behaviour):
    """A non-HTTP listener: 'text' replies with plain text, 'reset' resets."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def loop():
        while True:
            conn, _ = srv.accept()
            try:
                conn.settimeout(2)
                try:
                    conn.recv(4096)
                except OSError:
                    pass
                if behaviour == "text":
                    conn.sendall(b"hello there\n")
                else:  # reset: close with SO_LINGER 0, which sends a TCP RST
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            finally:
                conn.close()
    threading.Thread(target=loop, daemon=True).start()


for p in CASES:
    server = ThreadingHTTPServer(("127.0.0.1", p), handler(p))
    threading.Thread(target=server.serve_forever, daemon=True).start()
raw_server(19012, "text")    # replies with text that is not HTTP
raw_server(19013, "reset")   # resets the connection after the request
threading.Event().wait()
