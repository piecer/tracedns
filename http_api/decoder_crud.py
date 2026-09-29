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
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        return send_json(handler, {"status": "error", "error": "steps required (list)", "decoded": [], "decoded_count": 0}, 400)
    sample_raw = data.get("sample", "")
    try:
        sample = str(sample_raw or "").strip()[:2048]
    except Exception:
        sample = ""
    if not sample:
        return send_json(handler, {"status": "ok", "error": "empty sample", "decoded": [], "decoded_count": 0})
    try:
        decoder_type_raw = str(data.get("decoder_type") or "TXT").strip().upper()
    except Exception:
        decoder_type_raw = "TXT"
    try:
        if decoder_type_raw == "A":
            from a_decoder import create_custom_a_decoder
            dec = create_custom_a_decoder(steps)
            if dec is None:
                return send_json(handler, {"status": "error", "error": "invalid steps for A decoder", "decoded": [], "decoded_count": 0}, 400)
            decoded_ips = dec(sample) or []
        else:
            from txt_decoder import create_custom_decoder
            dec = create_custom_decoder(steps)
            if dec is None:
                return send_json(handler, {"status": "error", "error": "invalid steps for TXT decoder", "decoded": [], "decoded_count": 0}, 400)
            decoded_ips = dec(sample) or []
    except Exception as e:
        return send_json(handler, {"status": "error", "error": str(e), "decoded": [], "decoded_count": 0}, 500)
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
