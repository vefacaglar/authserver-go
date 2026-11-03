#!/usr/bin/env python3
"""Check the built SPA and Go APIs through the same disposable CI proxy."""

from html.parser import HTMLParser
import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ("src", "href") and value and value.startswith("/assets/"):
                self.paths.add(value)


def check(origin):
    def request(path, status=200):
        req = Request(origin + path, headers={"Host": "auth.vefacaglar.com"})
        try:
            response = urlopen(req, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            assert response.status == status, f"{path}: expected {status}, got {response.status}"
            return response.headers, response.read()

    def api(path, status=200):
        headers, body = request(path, status)
        assert "application/json" in headers.get("Content-Type", ""), f"{path}: API returned non-JSON"
        return json.loads(body)

    def assert_security_headers(path, headers):
        hsts = headers.get_all("Strict-Transport-Security") or []
        assert len(hsts) == 1, f"{path}: expected exactly one HSTS header, got {hsts}"
        assert headers.get("X-Content-Type-Options") == "nosniff", f"{path}: missing nosniff"
        assert headers.get("X-Frame-Options") == "DENY", f"{path}: page can be framed"

    discovery = api("/.well-known/openid-configuration")
    assert discovery["issuer"] == "https://auth.vefacaglar.com"
    keys = api("/.well-known/jwks.json")["keys"]
    assert keys and all("d" not in key for key in keys)
    assert api("/api/csrf")["csrf_token"]
    assert api("/api/auth/session")["authenticated"] is False
    api("/admin/api/clients", 401)
    request("/connect/authorize", 400)
    headers, _ = request("/healthz")
    assert_security_headers("/healthz", headers)

    assets = Assets()
    for path in ("/", "/login", "/profile", "/admin/clients", "/reset-password"):
        headers, body = request(path)
        assert_security_headers(path, headers)
        assert "text/html" in headers.get("Content-Type", ""), f"{path}: missing HTML"
        assert headers.get("Cache-Control") == "no-store", f"{path}: HTML must not be cached"
        html = body.decode()
        assert '<div id="root">' in html, f"{path}: missing SPA root"
        assets.feed(html)
    assert any(path.endswith(".js") for path in assets.paths), "Missing JavaScript bundle"
    assert any(path.endswith(".css") for path in assets.paths), "Missing stylesheet"
    assert any(path.endswith(".woff2") for path in assets.paths), "Missing preloaded font"
    expected_types = {".js": "javascript", ".css": "text/css", ".woff2": "font/woff2"}
    for path in sorted(assets.paths):
        headers, body = request(path)
        mime = headers.get("Content-Type", "")
        expected_mime = next(t for ext, t in expected_types.items() if path.endswith(ext))
        assert expected_mime in mime, f"{path}: unexpected asset type {mime!r}"
        assert body and b'<div id="root">' not in body, f"{path}: asset returned HTML"
        assert "immutable" in headers.get("Cache-Control", ""), f"{path}: missing asset cache policy"
    headers, _ = request("/assets/nonexistent-smoke-bundle.js", 404)
    assert "immutable" not in headers.get("Cache-Control", ""), "Missing asset must not be cached forever"
    print("SPA deep links, bundle types, cache headers, and same-origin API routes passed.")


if __name__ == "__main__":
    check(sys.argv[1])
