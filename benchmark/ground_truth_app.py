"""Deliberately vulnerable LOCAL test target with known ground truth.

It only ever binds to 127.0.0.1 and exists so the scanner's detection rate and false
positive rate can be measured (see run_benchmark.py). Never expose it to a network.

Ground truth (also in expected.json):
  REAL  sqli    GET  /product?id=            unauthenticated
  REAL  xss     GET  /search?q=              unauthenticated
  REAL  sqli    GET  /account?id=            only reachable with a session cookie
  REAL  xss     POST /feedback  (msg)        unauthenticated, POST body
  REAL  secret  GET  /.env                   fake AWS key
  SAFE          GET  /get?id=                parameterised query; page says "database"
  SAFE          GET  /anything?id=           static page whose length changes randomly
  SAFE          POST /subscribe (email)      output is HTML-escaped

Login for authenticated scans:  POST /login  user=test&password=test  ->  Cookie: session=bench-session
"""
import html
import random
import sqlite3
import string
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SESSION = "bench-session"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("create table products(id integer, name text)")
db.executemany("insert into products values(?,?)", [(1, "Laptop"), (2, "Phone"), (3, "Cable")])
db.execute("create table accounts(id integer, owner text)")
db.executemany("insert into accounts values(?,?)", [(1, "alice"), (2, "bob")])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html", headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _page(self, inner, code=200, headers=None):
        self._send(code, f"<html><body>{inner}</body></html>", headers=headers)

    def _logged_in(self):
        return f"session={SESSION}" in (self.headers.get("Cookie") or "")

    def _query(self, table, column, raw):
        """String-concatenated query: the injectable pattern under test."""
        try:
            rows = db.execute(f"select {column} from {table} where id = " + raw).fetchall()
            return 200, f"Result: {rows}"
        except Exception as e:
            return 500, f"sqlite3.OperationalError: {e}"

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        if p == "/":
            links = ('<h1>Shop</h1><a href="/product?id=1">Laptop</a> <a href="/search?q=phone">search</a> '
                     '<a href="/get?id=1">catalog</a> <a href="/anything?id=1">help</a> '
                     '<a href="/login">login</a> <a href="/contact">contact</a>')
            if self._logged_in():
                links += ' <a href="/account?id=1">my account</a>'
            return self._page(links + '<form action="/search"><input name="q"><input type="submit"></form>')
        if p == "/product":
            code, text = self._query("products", "name", q.get("id", ["1"])[0])
            return self._page(text, code)
        if p == "/search":
            return self._page(f"Results for {q.get('q', [''])[0]}: none")          # reflected, unescaped
        if p == "/get":
            rows = db.execute("select name from products where id = ?", (q.get("id", ["1"])[0],)).fetchall()
            return self._page(f"Welcome to our product database. Item: {rows}")
        if p == "/anything":
            tok = "".join(random.choices(string.ascii_letters, k=random.randint(5, 40)))
            return self._page(f"Static help page. session={tok}")
        if p == "/account":
            if not self._logged_in():
                return self._send(302, "", headers={"Location": "/login"})
            code, text = self._query("accounts", "owner", q.get("id", ["1"])[0])
            return self._page(text, code)
        if p == "/login":
            return self._page('<form method="POST" action="/login"><input name="user"><input name="password" '
                              'type="password"><input type="submit"></form>')
        if p == "/contact":
            return self._page('<form method="POST" action="/feedback"><input name="msg"><input type="submit"></form>'
                              '<form method="POST" action="/subscribe"><input name="email"><input type="submit"></form>')
        if p == "/.env":
            return self._send(200, "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nDEBUG=true\n", "text/plain")
        return self._page("Not Found", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        p = urlparse(self.path).path
        if p == "/login":
            if form.get("user") == ["test"] and form.get("password") == ["test"]:
                return self._send(302, "", headers={"Location": "/", "Set-Cookie": f"session={SESSION}; Path=/"})
            return self._page("Invalid credentials", 401)
        if p == "/feedback":
            return self._page(f"Thanks for your feedback: {form.get('msg', [''])[0]}")   # reflected, unescaped
        if p == "/subscribe":
            return self._page(f"Subscribed: {html.escape(form.get('email', [''])[0])}")   # safe
        return self._page("Not Found", 404)


def serve(port=8080):
    ThreadingHTTPServer.request_queue_size = 256
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)   # loopback only, by design
    server.serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
