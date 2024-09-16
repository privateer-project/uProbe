#!/usr/bin/env python3

# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class DummyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('<html><body><h1>hi!</h1></body></html>'.encode())


def main(argv):
    if len(argv) != 1:
        print(f'Usage: {argv[0]}', file=sys.stderr)
        return 1

    port = 8090
    srv = HTTPServer(('localhost', port), DummyRequestHandler)
    print(f'Application running on port {port}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('KeyboardInterrupt caught. Cleaning up...')
    srv.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))