from __future__ import annotations

import json as _json
from typing import Callable

from .context import HttpContext
from .request_limits import get_request_body
from .utils import send_json


def _validate_steps(steps: list, decoder_type: str) -> tuple[bool, str]:
    if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
        return (False, "steps must be a non-empty list with <=12 steps")
    total_chars = 0
    for s in steps:
        if not isinstance(s, dict) or "op" not in s:
            return (False, "each step must be a dict with op field")
        total_chars += sum(len(str(v)) for v in s.values())
        if total_chars > 2000:
            return (False, "steps too large")
        if s.get("op") == "regex":
            pat = s.get("pattern", "")
            if not isinstance(pat, str) or len(pat) > 300:
                return (False, "regex pattern too long")
            try:
                import regex_safety
                regex_safety.compile_safe_regex(pat, name="/decoders/custom")
            except Exception as e:
                return (False, f"invalid or unsafe regex: {e}")
        if s.get("op") == "xor_hex":
            key = s.get("key", "")
            if not isinstance(key, str) or len(key) > 128:
                return (False, "xor_hex key too long")
        if s.get("op") == "xor32_ipv4":
            key = s.get("key", s.get("key_hex", ""))
            if key is not None and len(str(key)) > 64:
                return (False, "xor32_ipv4 key too long")
    return (True, "")


def _mutate(ctx, handler, command, success_key):
    body, too_large = get_request_body(handler, max_length=ctx.max_body_bytes)
    if too_large:
        return
    try:
        data = _json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        return send_json(handler, {'error': 'invalid json'}, 400)
    if not isinstance(data, dict):
        return send_json(handler, {'error': 'json object required'}, 400)
    from monitor.config_service import commit_request
    result = commit_request(ctx, handler, command, data)
    if result is not None:
        result.pop('config', None)
        result[success_key] = data['name']
        result['decoder_type'] = str(data.get('decoder_type', 'TXT')).upper()
        return send_json(handler, result)


def handle_decoders_custom_post(ctx: HttpContext, handler) -> None:
    return _mutate(ctx, handler, 'decoder_create', 'registered')


def handle_decoders_custom_put(ctx: HttpContext, handler) -> None:
    return _mutate(ctx, handler, 'decoder_upsert', 'updated')


def handle_decoders_custom_delete(ctx: HttpContext, handler) -> None:
    return _mutate(ctx, handler, 'decoder_delete', 'removed')


def handle_decoders_custom_preview(ctx: HttpContext, handler) -> None:
    body, _413 = get_request_body(handler, max_length=ctx.max_body_bytes)
    if _413:
        return
    try:
        data = _json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return send_json(handler, {"error": "invalid json"}, 400)
    def refuse(message, status=400):
        return send_json(handler, {"status": "error", "error": message, "decoded": [], "decoded_count": 0}, status)

    if not isinstance(data, dict):
        return refuse("json object required")
    kind = data.get("decoder_type", "TXT")
    if not isinstance(kind, str) or kind.strip().upper() not in ("TXT", "A"):
        return refuse("decoder_type must be TXT or A")
    kind = kind.strip().upper()
    sample = data.get("sample", "")
    if not isinstance(sample, str):
        return refuse("sample must be a string")
    if len(sample) > 2048:
        return refuse("sample too large", 413)
    try:
        if len(sample.encode("utf-8")) > 2048:
            return refuse("sample too large", 413)
    except UnicodeError:
        return refuse("sample must be valid UTF-8")
    steps = data.get("steps")
    try:
        valid, _ = _validate_steps(steps, kind)
        if not valid:
            return refuse("invalid decoder steps")
        if kind == "A":
            from a_decoder import create_custom_a_decoder
            dec = create_custom_a_decoder(steps)
        else:
            from txt_decoder import create_custom_decoder
            dec = create_custom_decoder(steps)
        if dec is None:
            return refuse("invalid decoder steps")
    except Exception:
        return refuse("invalid decoder steps")
    # Compile even for empty samples: invalid steps must never get a success.
    if sample == "":
        return send_json(handler, {"status": "ok", "error": "empty sample", "decoded": [], "decoded_count": 0})
    try:
        decoded_ips = dec([sample]) or []
    except Exception:
        return refuse("decoder execution failed", 500)
    seen, dedup, count = set(), [], 0
    for ip in decoded_ips:
        try:
            ipstr = str(ip).strip().lower()
        except Exception:
            continue
        if len(ipstr) < 4 or ipstr in seen:
            continue
        seen.add(ipstr)
        dedup.append(ipstr)
        count += 1
        if len(dedup) >= 64:
            break
    return send_json(handler, {"status": "ok", "decoded": dedup, "decoded_count": count})

_HANDLERS = {
    "/decoders/custom": handle_decoders_custom_post,
    "/decoders/custom/preview": handle_decoders_custom_preview,
}

def get_handler(path: str) -> Callable:
    try:
        return _HANDLERS[path]
    except KeyError:
        raise ValueError(f"no handler registered for {path!r}") from None
