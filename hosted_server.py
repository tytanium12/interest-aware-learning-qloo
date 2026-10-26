"""Guarded public hosting adapter for Interest-Aware Learning.

Keep app.py's localhost entry unchanged. This module is the *only* public entry.
No endpoint may issue a paid provider call without a durable Upstash reservation.
"""
from __future__ import annotations

import hashlib
import hmac
import http.cookies
import io
import json
import os
import re
import time
from dataclasses import dataclass
from urllib import request as urlrequest
from pathlib import Path
from urllib.parse import urlsplit

import app

COOKIE_NAME = "ial_judge"
SESSION_LIFETIME = 24 * 3600
REDIS_SCRIPT = """local used=tonumber(redis.call('GET', KEYS[1]) or '0')
if used >= tonumber(ARGV[1]) then return -1 end
return redis.call('INCR', KEYS[1])"""


@dataclass(frozen=True)
class Settings:
    origin: str
    enabled: bool
    judge_code: str
    cookie_secret: str
    redis_url: str
    redis_token: str
    quota_key: str
    max_generations: int

    @classmethod
    def read(cls, env=None):
        env = os.environ if env is None else env
        raw_enabled = str(env.get("HOSTED_LIVE_ENABLED", "0")).lower()
        if raw_enabled not in ("0", "1"):
            raise ValueError("HOSTED_LIVE_ENABLED must be 0 or 1")
        enabled = raw_enabled == "1"
        origin = env.get("HOSTED_ORIGIN") or env.get("RENDER_EXTERNAL_URL", "")
        code = env.get("HOSTED_JUDGE_CODE", "")
        cookie_secret = env.get("HOSTED_COOKIE_SECRET", "")
        redis_url = env.get("UPSTASH_REDIS_REST_URL", "")
        redis_token = env.get("UPSTASH_REDIS_REST_TOKEN", "")
        quota_key = env.get("HOSTED_QUOTA_KEY", "ial:hackathon:2026:live:v1")
        try:
            maximum = int(env.get("HOSTED_MAX_GENERATIONS", "200"))
        except ValueError:
            raise ValueError("Invalid hosted generation limit") from None
        if not 1 <= maximum <= 500 or not re.fullmatch(r"[A-Za-z0-9:_-]{8,100}", quota_key):
            raise ValueError("Unsafe hosted quota configuration")
        if enabled:
            parsed = urlsplit(origin)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/")
                    or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port not in (None, 443)):
                raise ValueError("A valid HTTPS hosted origin is required")
            if len(code) < 12 or len(cookie_secret) < 32 or code == cookie_secret:
                raise ValueError("Hosted judge authentication secrets are missing or weak")
            upstream = urlsplit(redis_url)
            if (upstream.scheme != "https" or not upstream.hostname or not upstream.hostname.endswith(".upstash.io")
                    or upstream.path not in ("", "/") or upstream.username or upstream.password
                    or upstream.query or upstream.fragment or upstream.port not in (None, 443)
                    or len(redis_token) < 20):
                raise ValueError("Durable quota provider is missing or invalid")
            if env.get("IAL_MODE") != "provider" or env.get("IAL_TAVILY_ENRICHMENT") != "1":
                raise ValueError("Hosted live mode requires provider mode and bounded research")
            if env.get("IAL_OPENAI_MAX_GENERATIONS") != "1" or env.get("IAL_AUDITED_BUDGET") != "1":
                raise ValueError("Hosted generation must have the audited per-request budget")
            try:
                output = int(env.get("IAL_OPENAI_MAX_OUTPUT_TOKENS", ""))
            except ValueError:
                output = 0
            if not 1 <= output <= 6500:
                raise ValueError("Hosted output token ceiling is missing or unsafe")
            # Validate credentials and model at startup; never reveal their contents.
            try:
                app.load_app_config(env)
            except (ValueError, app.CredentialError):
                raise ValueError("Provider credentials or model are not configured") from None
            tavily_path = env.get("TAVILY_API_KEY_FILE", "")
            if not tavily_path or not Path(tavily_path).is_file():
                raise ValueError("Tavily secret file is not configured")
        return cls(origin.rstrip("/"), enabled, code, cookie_secret, redis_url.rstrip("/"), redis_token, quota_key, maximum)


def session_token(settings, now=None):
    timestamp = str(int(time.time() if now is None else now))
    mac = hmac.new(settings.cookie_secret.encode("utf-8"), timestamp.encode("ascii"), hashlib.sha256).hexdigest()
    return timestamp + "." + mac


def authenticated(settings, cookie_header, now=None):
    if not settings.enabled or not cookie_header or len(cookie_header) > 4096:
        return False
    try:
        jar = http.cookies.SimpleCookie()
        jar.load(cookie_header)
        token = jar[COOKIE_NAME].value
        timestamp, signature = token.split(".", 1)
        clock = int(time.time() if now is None else now)
        then = int(timestamp)
        return (0 <= clock - then <= SESSION_LIFETIME and len(signature) == 64
                and hmac.compare_digest(session_token(settings, then), token))
    except (KeyError, ValueError, TypeError, http.cookies.CookieError):
        return False


class RejectRedirects(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the Redis bearer token to a redirected host.
        return None


def reserve_generation(settings, *, opener=None):
    """Single atomic compare/increment on durable Redis; any ambiguity fails closed."""
    command = ["EVAL", REDIS_SCRIPT, "1", settings.quota_key, str(settings.max_generations)]
    encoded = json.dumps(command, separators=(",", ":")).encode("utf-8")
    req = urlrequest.Request(settings.redis_url, data=encoded, headers={
        "Authorization": "Bearer " + settings.redis_token,
        "Content-Type": "application/json",
    }, method="POST")
    try:
        open_fn = opener or urlrequest.build_opener(RejectRedirects).open
        with open_fn(req, timeout=5) as response:
            result = json.loads(response.read(2048).decode("utf-8"))
        value = result.get("result") if isinstance(result, dict) else None
        if type(value) is not int or (value != -1 and not 1 <= value <= settings.max_generations):
            raise ValueError("Invalid durable quota response")
        return value != -1
    except Exception:
        # This may consume one allowance if the response was lost. That is safe.
        raise RuntimeError("Persistent quota is unavailable") from None


LOGIN_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Interest-Aware Learning | Judge access</title>
<style>body{font:17px/1.5 system-ui,sans-serif;max-width:38rem;margin:10vh auto;padding:1rem;color:#263248}
main{padding:2rem;border:1px solid #d5dce9;border-radius:18px;background:#fafbff}label,input,button{display:block;width:100%;box-sizing:border-box}
input,button{font:inherit;padding:.7rem;margin-top:.5rem}button{background:#183a61;color:white;border:0;border-radius:6px;cursor:pointer}
small{color:#526277}a{color:#214f92}</style><main><h1>Interest-Aware Learning</h1>
<p>A source-grounded learning studio that uses Qloo cultural associations to investigate examples.</p>
<p>Enter the judge access code provided in the Devpost testing instructions.</p>
<form action="/judge-access" method="post"><label for="passcode">Access code</label>
<input id="passcode" name="passcode" type="password" autocomplete="off" maxlength="200" required>
<button type="submit">Open the learning studio</button></form>
<p><small>Do not submit sensitive material. A live request may share interests with Qloo, derived research queries with Tavily, and educational source content with OpenAI.</small></p></main></html>"""


class HostedHandler(app.Handler):
    settings: Settings | None = None

    def setup(self):
        super().setup()
        self.connection.settimeout(12)

    def _settings(self):
        return self.settings or self.server.hosted_settings

    def _send(self, status, content, content_type="text/plain; charset=utf-8", *, cookie=None, location=None, referrer_policy="no-referrer"):
        raw = content if isinstance(content, bytes) else content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", referrer_policy)
        self.send_header("X-Frame-Options", "DENY")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def _deny(self, status, code, message):
        payload = {"schema_version": app.HTTP_SCHEMA_VERSION, "provider_mode": "provider", "status": "error",
                   "error": {"code": code, "message": message}}
        self._send(status, json.dumps(payload), "application/json; charset=utf-8")

    def _authorized(self):
        return authenticated(self._settings(), self.headers.get("Cookie", ""))

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/health":
            self._send(200, '{"status":"ok","service":"interest-aware-learning"}', "application/json; charset=utf-8")
        elif route == "/":
            if self._authorized():
                # Existing UI is unmodified; response is an actual live provider workflow.
                self._send(200, app.HTML, "text/html; charset=utf-8")
            else:
                self._send(200, LOGIN_PAGE, "text/html; charset=utf-8", referrer_policy="same-origin")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        settings = self._settings()
        route = urlsplit(self.path).path
        if route == "/judge-access":
            if not settings.enabled:
                self._send(503, "Live judge access is not enabled.")
                return
            if self.headers.get("Origin") not in (None, settings.origin):
                self._send(403, "Access denied")
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
                self._send(415, "Invalid form")
                return
            from urllib.parse import parse_qs
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if not 1 <= size <= 256:
                    raise ValueError()
                field = parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
                submitted = field.get("passcode", [""])[0]
            except (ValueError, UnicodeDecodeError):
                self._send(400, "Invalid access request")
                return
            if not hmac.compare_digest(submitted, settings.judge_code):
                self._send(403, "Invalid access code")
                return
            cookie = f"{COOKIE_NAME}={session_token(settings)}; Path=/; Max-Age={SESSION_LIFETIME}; HttpOnly; Secure; SameSite=Lax"
            self._send(303, b"", cookie=cookie, location="/")
            return
        if route != app.API_LEARN_ROUTE:
            self._deny(404, "not_found", "Route not found.")
            return
        if not settings.enabled:
            self._deny(503, "live_disabled", "Live generation is temporarily disabled.")
            return
        if not self._authorized():
            self._deny(403, "judge_access_required", "Judge access is required to generate a live lesson.")
            return
        if self.headers.get("Origin") not in (None, settings.origin):
            self._deny(403, "origin_invalid", "Request origin is not permitted.")
            return
        # Validate cheap input before reserving an irreversible, paid-request slot.
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._deny(415, "unsupported_media_type", "Content-Type must be application/json.")
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            size = -1
        if size < 1 or size > app.MAX_HTTP_BODY_BYTES:
            self._deny(413, "body_invalid", "Request size is invalid or exceeds the limit.")
            return
        body = self.rfile.read(size)
        try:
            payload = json.loads(body.decode("utf-8"))
            if (not isinstance(payload, dict) or payload.get("schema_version") != app.HTTP_SCHEMA_VERSION
                    or payload.get("provider_mode", "").lower() not in ("auto", "provider")
                    or not isinstance(payload.get("explicit_interests"), list)):
                raise ValueError()
            app.create_learning_request(payload["explicit_interests"], payload["pasted_educational_source_text"],
                                        payload["learning_request"], payload["cultural_context"])
        except (ValueError, UnicodeDecodeError, KeyError, TypeError, AttributeError):
            self._deny(400, "invalid_request", "Please check your inputs and retry.")
            return
        try:
            allowed = reserve_generation(settings)
        except RuntimeError:
            self._deny(503, "quota_unavailable", "Live generation is temporarily unavailable.")
            return
        if not allowed:
            self._deny(429, "quota_exhausted", "The judge demonstration allowance has been reached.")
            return
        # Existing handler validates the request again and executes existing workflow.
        self.rfile = io.BytesIO(body)
        super().do_POST()

    def log_message(self, format, *args):
        # Do not log form codes, query parameters, user input, or provider responses.
        return


def main():
    try:
        settings = Settings.read()
    except ValueError as error:
        raise SystemExit("Hosted configuration invalid: " + str(error)) from None
    try:
        port = int(os.environ.get("PORT", "10000"))
    except ValueError:
        raise SystemExit("PORT must be an integer") from None
    if not 1 <= port <= 65535:
        raise SystemExit("PORT is out of range")
    server = app.ThreadingHTTPServer(("0.0.0.0", port), HostedHandler)
    server.hosted_settings = settings
    print("Interest-Aware Learning hosted server ready (live mode " + ("enabled" if settings.enabled else "disabled") + ")", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
