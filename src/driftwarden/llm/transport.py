"""Default transport: JSON over HTTP(S) with the standard library (no SDK needed).

Secret handling: error messages never include request headers. Any response text
that does appear in an error (an HTTP error body, a connection-error reason) is
first scrubbed of every request header value (the API key, including the token
after ``Bearer``) and of URL ``user:password@`` userinfo, and only then truncated,
so a secret can never survive as a cut-off prefix.

Redirects are never followed. urllib's default handler would replay the request
(with its ``x-api-key`` / ``Authorization`` header) to whatever ``Location`` says,
including another host or an https -> http downgrade. A 3xx answer is a
non-retryable TransportError instead: point ``base_url`` at the final endpoint.

Known limit (D17): redaction matches the exact secret strings only. A server
that echoes the key re-cased, URL-encoded or JSON-unicode-escaped is not
redacted. Neither Anthropic nor OpenAI is known to do this.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from driftwarden.llm.base import TransportError

RETRYABLE_STATUS = frozenset({408, 409, 425, 429})
_MAX_ERROR_BODY = 300
_MAX_ERROR_READ = 64 * 1024  # bytes of an error body read (then scrubbed, then truncated)


def is_retryable_status(status: int) -> bool:
    return status in RETRYABLE_STATUS or status >= 500


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect, so credentials are never re-sent anywhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None  # urllib then raises HTTPError with the 3xx status


_OPENER = urllib.request.build_opener(_RefuseRedirects)


def _open(req: urllib.request.Request, timeout: float):
    """The single network call (tests replace this seam)."""
    return _OPENER.open(req, timeout=timeout)


def urllib_transport(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout: float
) -> dict[str, Any]:
    """POST ``body`` as JSON and return the parsed JSON reply.

    Error messages carry the status and a truncated response body, never the
    request headers (which hold the API key).
    """
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"content-type": "application/json", "accept": "application/json", **headers},
    )
    try:
        with _open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(_MAX_ERROR_READ).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - best effort only
            pass
        # Scrub BEFORE truncating: a key straddling the cut must not leave a prefix.
        detail = _scrub(detail, url, headers)[:_MAX_ERROR_BODY]
        if 300 <= exc.code < 400:
            raise TransportError(
                f"HTTP {exc.code} redirect from {_host(url)} refused (credentials are never "
                "re-sent to a redirect target); set base_url to the final endpoint",
                status=exc.code,
                retryable=False,
            ) from None
        raise TransportError(
            f"HTTP {exc.code} from {_host(url)}: {detail}".rstrip(": "),
            status=exc.code,
            retryable=is_retryable_status(exc.code),
        ) from None
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        reason = _scrub(str(getattr(exc, "reason", exc)), url, headers)[:_MAX_ERROR_BODY]
        raise TransportError(f"cannot reach {_host(url)}: {reason}", retryable=True) from None
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise TransportError(
            f"{_host(url)} returned a non-JSON response: {exc}", retryable=True
        ) from None
    if not isinstance(parsed, dict):
        raise TransportError(f"{_host(url)} returned JSON that is not an object", retryable=False)
    return parsed


def _host(url: str) -> str:
    """``scheme://host[:port]`` of ``url``: no userinfo, path or query."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "<invalid url>"
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{f':{port}' if port else ''}" if host else "<invalid url>"


def _scrub(text: str, url: str, headers: dict[str, str]) -> str:
    """Remove URL userinfo and every request header value (API keys) from ``text``."""
    secrets = [v for v in headers.values() if isinstance(v, str) and len(v) >= 8]
    secrets += [v.partition(" ")[2] for v in list(secrets) if " " in v]  # "Bearer <key>"
    try:
        userinfo = urlsplit(url).netloc.rpartition("@")[0]
    except ValueError:
        userinfo = ""
    if userinfo:
        secrets += [userinfo, *userinfo.split(":")]
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def redact_url(url: str) -> str:
    """``url`` with any ``user:password@`` userinfo and query string removed."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid url>"
    if "@" not in parts.netloc and not parts.query:
        return url
    return _host(url) + parts.path


def check_url(url: str) -> str:
    """Reject non-HTTP schemes (``file:``, ``ftp:``...) that urllib would otherwise open."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"base_url must be http:// or https://, got {redact_url(url)!r}")
    return url.rstrip("/")
