"""Closed local delivery constants (no provider credentials or URLs)."""
import json


class TeamsPayloadTooLarge(ValueError):
    """A complete rendered candidate exceeds the Teams item/wire budget."""


REASONS = frozenset({
    "delivery_storage", "delivery_capacity", "tracking_overflow", "old_binding_blocked",
    "client_unavailable", "configuration_unavailable", "provider_auth", "provider_tls",
    "provider_timeout", "provider_transport", "provider_rate_limit", "provider_unavailable",
    "provider_response", "provider_work_limit", "attempts_exhausted", "invalid_payload",
    "recovery_gap", "receipt_persistence", "history_persistence", "delivery_unknown",
    "destination_disabled", "destination_invalid", "adapter_unapplied", "removal_disabled",
    "tls_config", "tls_error", "provider_transient", "provider_http", "provider_protocol",
    "transport_error", "response_limit", "attribute_limit", "payload_invalid", "payload_limit",
    "sighting_absent",
})


def stable_reason(value):
    return value if value is None or (isinstance(value, str) and value in REASONS) else "delivery_unknown"


def provider_result(value):
    """Do not let malformed transport envelopes authorize an ACK."""
    required = {"state", "reason", "progress", "retry_after", "provider_calls", "observation_hook"}
    valid = (type(value) is dict and set(value) == required and
             value["state"] in ("acked", "continue", "retry", "blocked", "failed") and
             type(value["provider_calls"]) is int and value["provider_calls"] in (0, 1) and
             type(value["progress"]) is dict)
    if valid:
        try:
            valid = size(value["progress"]) <= 2048 and (value["retry_after"] is None or
                type(value["retry_after"]) in (int, float) and 0 <= value["retry_after"] <= 1e9)
        except (TypeError, ValueError, OverflowError):
            valid = False
    if not valid:
        return {"state": "failed", "reason": "invalid_payload", "progress": {},
                "retry_after": None, "provider_calls": 1, "observation_hook": None}
    return {**value, "reason": stable_reason(value["reason"])}


MAX_COUNTER = (1 << 63) - 1
CHANNELS = ("teams", "misp")
DEFAULT_LIMITS = {
    "receipts": 4096, "payload_bytes": 8 * 1024 * 1024,
    "unit_items": 256, "unit_bytes": 64 * 1024, "label_bytes": 1024,
    "cursor_targets": 4096, "cursor_members": 16384, "cursor_bytes": 4 * 1024 * 1024,
    "target_ips": 4096, "baseline_items": 8192, "baseline_bytes": 2 * 1024 * 1024,
    "grace_items": 8192, "grace_bytes": 2 * 1024 * 1024,
    "recent_items": 4096, "recent_bytes": 1024 * 1024,
    "terminal_items": 256, "terminal_bytes": 128 * 1024,
    "batch_items": 60, "batch_bytes": 24 * 1024, "pages": 16384,
}


def valid_binding(value):
    fields = {"channel", "binding_id", "enabled", "ready", "allow_removed", "error"}
    return (type(value) is dict and set(value) == fields and value["channel"] in CHANNELS and
            type(value["binding_id"]) is str and len(value["binding_id"]) == 64 and
            all(c in "0123456789abcdef" for c in value["binding_id"]) and
            all(type(value[k]) is bool for k in ("enabled", "ready", "allow_removed")) and
            (value["error"] is None or value["error"] in REASONS))


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def encode_body(body):
    """Exact Teams wire bytes at rendering, sealing and every dispatch/retry."""
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True, allow_nan=False).encode("utf-8")


def size(value):
    return len(encode(value).encode("utf-8"))
