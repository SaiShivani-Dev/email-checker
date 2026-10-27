"""Flask app for the Email Deliverability Checker.

    python app.py                      # local development server
    gunicorn app:app                   # production (see Procfile / render.yaml)

The verification logic lives in checker.py; this file only does HTTP: it validates the
request, enforces the limits, and returns JSON.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from collections import deque

from flask import Flask, g, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from checker import Checker, Settings, parse_input

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


class RateLimiter:
    """Tiny in-memory sliding-window limiter: `limit` requests per `window` seconds per client IP.

    Good enough for a single-process deployment (see README). For several processes use Redis.
    """

    def __init__(self, limit: int, window: float = 60.0):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float:
        """Return 0 if the request is allowed, else the seconds until the client may retry."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:                          # keep memory bounded
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window}
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1.0, self.window - (now - hits[0]))
            hits.append(now)
            return 0.0


def create_app(settings: Settings | None = None, rate_limit: int | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024                  # 32 KB is far more than 10 addresses
    app.config["JSON_SORT_KEYS"] = False
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)   # real client IP behind Render/Railway

    checker = Checker(settings or Settings.from_env())
    limiter = RateLimiter(rate_limit if rate_limit is not None else int(os.environ.get("RATE_LIMIT_PER_MINUTE", "20")))
    app.extensions["checker"] = checker
    checker.availability.refresh_in_background()                  # learn early whether port 25 is open

    # ------------------------------------------------------------------ security headers
    @app.before_request
    def _nonce():
        g.nonce = secrets.token_urlsafe(16)

    @app.after_request
    def _headers(resp):
        nonce = getattr(g, "nonce", "")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault(
            "Content-Security-Policy",
            f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------------ errors (always JSON for /api)
    def _error(status: int, message: str, **extra):
        return jsonify({"error": message, **extra}), status

    @app.errorhandler(413)
    def _too_large(_e):
        return _error(413, "Request too large. Paste at most %d addresses." % checker.s.max_emails)

    @app.errorhandler(404)
    def _not_found(_e):
        return _error(404, "Not found.")

    @app.errorhandler(405)
    def _bad_method(_e):
        return _error(405, "Method not allowed.")

    @app.errorhandler(500)
    def _server_error(_e):
        return _error(500, "Something went wrong on the server. Please try again.")

    # ------------------------------------------------------------------ routes
    @app.get("/")
    def index():
        return render_template("index.html", nonce=g.nonce, max_emails=checker.s.max_emails)

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True})

    @app.get("/api/status")
    def status():
        smtp = checker.availability.get(block=False)
        return jsonify({
            "max_emails": checker.s.max_emails,
            "smtp": {"available": smtp.get("available"), "state": smtp.get("state"), "reason": smtp.get("reason")},
        })

    @app.post("/api/check")
    def check():
        wait = limiter.check(request.remote_addr or "unknown")
        if wait:
            resp, code = _error(429, f"Too many requests. Please wait {int(wait)} seconds and try again.")
            resp.headers["Retry-After"] = str(int(wait))
            return resp, code

        body = request.get_json(silent=True)
        if not isinstance(body, dict) or "emails" not in body:
            return _error(400, 'Send JSON like {"emails": "a@b.com\\nc@d.com"}.')
        try:
            emails, duplicates = parse_input(body["emails"])
        except ValueError as exc:
            return _error(400, str(exc))
        if not emails:
            return _error(400, "Please paste at least one email address.")
        if len(emails) > checker.s.max_emails:
            return _error(400, f"Too many addresses: {len(emails)}. The limit is {checker.s.max_emails} per request.",
                          limit=checker.s.max_emails)

        started = time.monotonic()
        results = checker.check_many(emails)
        smtp = checker.availability.get(block=False)
        return jsonify({
            "results": results,
            "meta": {
                "count": len(results),
                "duplicates_removed": duplicates,
                "smtp_available": smtp.get("available"),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            },
        })

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False, threaded=True)
