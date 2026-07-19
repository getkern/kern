"""A tiny notes API over Postgres, stdlib HTTP + pg8000 (pure-Python driver).

POST /notes  with a body   -> inserts the body as a note, returns "ok"
GET  /notes                -> returns a JSON array of every note body, in order

It connects to Postgres at localhost:5432 because the API box and the db box
share one pod network (a single loopback), exactly like a Kubernetes pod.
"""

import http.server
import json
import os

import pg8000.native

PGPASSWORD = os.environ.get("PGPASSWORD", "secret")


def connect():
    return pg8000.native.Connection(
        user="postgres", password=PGPASSWORD, host="localhost", database="postgres"
    )


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode()
        con = connect()
        con.run("CREATE TABLE IF NOT EXISTS notes (id serial PRIMARY KEY, body text)")
        con.run("INSERT INTO notes (body) VALUES (:b)", b=body)
        con.close()
        self._send(200, "ok")

    def do_GET(self):
        con = connect()
        con.run("CREATE TABLE IF NOT EXISTS notes (id serial PRIMARY KEY, body text)")
        rows = con.run("SELECT body FROM notes ORDER BY id")
        con.close()
        self._send(200, json.dumps([r[0] for r in rows]), "application/json")

    def log_message(self, *_):
        pass  # quiet


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
