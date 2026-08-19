"""Request body size limits shared by all HTTP API handlers.

The raw ``Content-Length`` header is attacker-controlled; reading it verbatim
allows a remote client to exhaust server memory (HTTP POST without size limit).
``get_request_body`` validates the header, rejects oversized bodies with
HTTP 413, and guarantees at most ``max_length`` bytes are read regardless of
the header value.
"""

from __future__ import annotations

import html
import os
from typing import Any, Optional, Tuple

# Default request body limit in bytes (5 MiB). JSON payloads used by the UI are
# typically well under 1 MiB, so 5 MiB leaves generous headroom while still
# bounding worst-case memory per request.
DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
# Maximum allowed override (64 MiB) so a single env var cannot disable the
# limit or set an unbounded value.
MAX_BODY_BYTES_HARD_CAP = 64 * 1024 * 1024
# Environment variable that overrides the default (bounded to the hard cap).
ENV_MAX_BODY_BYTES = "TRACEDNS_MAX_BODY_BYTES"


class BodyTooLargeError(ValueError):
    """Raised when a request body exceeds the configured limit.

    ``length`` is the declared/upper-bound byte count that triggered the
    rejection, for logging/reporting.
    """

    def __init__(self, length: int, limit: int) -> None:
        super().__init__(f"request body length {length} exceeds limit {limit}")
        self.length = length
        self.limit = limit


def resolve_max_body_length(env: Optional[Any] = None) -> int:
    """Resolve the effective per-request body limit in bytes.

    ``env`` defaults to ``os.environ`` and should be injectable for testing.
    Honors the :data:`ENV_MAX_BODY_BYTES` override, bounded to
    ``1..MAX_BODY_BYTES_HARD_CAP``.
    """
    environ = os.environ if env is None else env
    raw = environ.get(ENV_MAX_BODY_BYTES, "")
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_MAX_BODY_BYTES
    if value <= 0:
        return DEFAULT_MAX_BODY_BYTES
    return min(value, MAX_BODY_BYTES_HARD_CAP)


def _send_413(handler: Any, err: BodyTooLargeError) -> None:
    """Send a minimal text/plain 413 response.

    Deliberately independent of ``send_json``: a rejection response should
    stay tiny, and a JSON encoder failure on an oversized input must never
    prevent the client from learning the request was rejected.
    """
    message = html.escape(
        "413 Request Entity Too Large "
        f"(limit {err.limit} bytes)"
    )
    body = f"{message}\n".encode("utf-8")
    try:
        handler.close_connection = True
    except Exception:
        pass
    handler.send_response(413)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except Exception:
        # Client may have disconnected while we were rejecting; nothing left
        # to do. Keep the request loop from crashing on the dead socket.
        pass


def _send_400(handler: Any, message: str) -> None:
    """Reject unsupported or malformed HTTP request framing."""
    body = f"400 Bad Request ({html.escape(message)})\n".encode("utf-8")
    try:
        handler.close_connection = True
    except Exception:
        pass
    handler.send_response(400)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except Exception:
        pass


def _declared_length(handler: Any) -> int:
    """Return a valid non-negative Content-Length or raise ValueError."""
    raw = handler.headers.get("Content-Length")
    if raw is None:
        return 0
    text = str(raw).strip()
    if not text.isdigit():
        raise ValueError("invalid Content-Length")
    return int(text)


def get_request_body(
    handler: Any,
    *,
    max_length: Optional[int] = None,
    env: Optional[Any] = None,
) -> Tuple[bytes, bool]:
    """Read the request body under a size limit.

    Returns ``(body, sent_error)``. When the declared length exceeds the
    enforced limit (``max_length`` or ``resolve_max_body_length(env)``),
    sends HTTP 413 and returns ``(b"", True)``; callers should return
    immediately when ``sent_error`` is ``True``.

    On success, the returned body is at most the limit bytes.

    ``env`` is forwarded to :func:`resolve_max_body_length` for test
    isolation; pass ``None`` to use ``os.environ``.
    """
    limit = (
        resolve_max_body_length(env)
        if max_length is None
        else max(1, int(max_length))
    )
    transfer_encoding = str(handler.headers.get("Transfer-Encoding") or "").strip().lower()
    if transfer_encoding and transfer_encoding != "identity":
        _send_400(handler, "unsupported Transfer-Encoding")
        return b"", True
    try:
        length = _declared_length(handler)
    except ValueError:
        _send_400(handler, "invalid Content-Length")
        return b"", True
    if length > limit:
        _send_413(handler, BodyTooLargeError(length, limit))
        return b"", True
    if length <= 0:
        return b"", False
    # ``length`` is bounded by the limit here, so ``rfile.read(length)``
    # cannot allocate beyond it.
    return handler.rfile.read(length), False
