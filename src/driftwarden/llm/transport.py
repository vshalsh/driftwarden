"""Default transport: JSON over HTTP(S) with the standard library (no SDK needed)."""

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


def is_retryable_status(status: int) -> bool:
    return status in RETRYABLE_STATUS or status >= 500


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
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - http(s) only
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:_MAX_ERROR_BODY]
        except Exception:  # noqa: BLE001 - best effort only
            pass
        raise TransportError(
            _scrub(f"HTTP {exc.code} from {_host(url)}: {detail}".rstrip(": "), url, headers),
            status=exc.code,
            retryable=is_retryable_status(exc.code),
        ) from None
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransportError(
            _scrub(f"cannot reach {_host(url)}: {reason}", url, headers), retryable=True
        ) from None
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
