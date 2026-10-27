"""Default transport: JSON over HTTP(S) with the standard library (no SDK needed)."""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from typing import Any

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
            f"HTTP {exc.code} from {_host(url)}: {detail}".rstrip(": "),
            status=exc.code,
            retryable=is_retryable_status(exc.code),
        ) from None
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        reason = getattr(exc, "reason", exc)
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
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else url


def check_url(url: str) -> str:
    """Reject non-HTTP schemes (``file:``, ``ftp:``...) that urllib would otherwise open."""
    from urllib.parse import urlsplit

    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"base_url must be http:// or https://, got {url!r}")
    return url.rstrip("/")
