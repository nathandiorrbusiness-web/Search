"""Loopback-only authenticated CONNECT fixture for manual WebKit routing checks."""
import argparse
import base64
import json
import socketserver
import threading
import ssl
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--state', required=True)
parser.add_argument('--certificate')
parser.add_argument('--key')
args = parser.parse_args()
state = {'connections': 0, 'authenticated': 0, 'requests': 0}
lock = threading.Lock()


def record(key):
    with lock:
        state[key] += 1
        Path(args.state).write_text(json.dumps(state))


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        record('connections')
        line = self.rfile.readline(8193)
        headers = {}
        while True:
            header = self.rfile.readline(8193)
            if header in (b'\r\n', b'\n', b''):
                break
            name, _, value = header.partition(b':')
            headers[name.lower()] = value.strip()
        if line.startswith(b'GET /direct-origin '):
            body = b'DIRECT ORIGIN'
            self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            return
        if not line.startswith(b'CONNECT '):
            self.wfile.write(b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        expected = b'Basic ' + base64.b64encode(b'fixture:fixture-password')
        if headers.get(b'proxy-authorization') != expected:
            self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Search fixture"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        record('authenticated')
        self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        self.wfile.flush()
        request = self.rfile.readline(8193)
        if not request.startswith(b'GET '):
            return
        while self.rfile.readline(8193) not in (b'\r\n', b'\n', b''):
            pass
        record('requests')
        body = b'Search proxy fixture: authenticated WebKit traffic reached this proxy.'
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Proxy) as server:
    if args.certificate:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.certificate, args.key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.daemon_threads = True
    state['port'] = server.server_address[1]
    Path(args.state).write_text(json.dumps(state))
    print('Fixture port:', state['port'], flush=True)
    server.serve_forever()
