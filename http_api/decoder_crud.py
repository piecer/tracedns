from __future__ import annotations

import json as _json
from typing import Callable

from config_manager import read_config, write_config

from .context import HttpContext
from .request_limits import get_request_body
from .utils import send_json


def _custom_all_payload(ctx: HttpContext) -> list:
    txt_list = list(ctx.shared_config.get("custom_decoders", []) or [])
    a_list = list(ctx.shared_config.get("custom_a_decoders", []) or [])
    all_list = []
    for c in txt_list:
        item = dict(c) if isinstance(c, dict) else {}
        if item and item.get("decoder_type") != "TXT":
            item["decoder_type"] = "TXT"
        if item:
            all_list.append(item)
    for c in a_list:
        item = dict(c) if isinstance(c, dict) else {}
        if item and item.get("decoder_type") != "A":
            item["decoder_type"] = "A"
        if item:
            all_list.append(item)
    return all_list


def _save_config(ctx: HttpContext, list_key: str) -> None:
    if not ctx.config_path:
        return
    try:
        cfg = read_config(ctx.config_path) or {}
        cfg["domains"] = cfg.get("domains", ctx.shared_config.get("domains", []))
        cfg["servers"] = cfg.get("servers", ctx.shared_config.get("servers", []))
        cfg["interval"] = cfg.get("interval", ctx.shared_config.get("interval"))
        cfg["custom_decoders"] = ctx.shared_config.get("custom_decoders", [])
        cfg["custom_a_decoders"] = ctx.shared_config.get("custom_a_decoders", [])
        write_config(ctx.config_path, cfg)
    except Exception:
        pass


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


def handle_decoders_custom_post(ctx: HttpContext, handler) -> None:
    body, _413 = get_request_body(handler, max_length=ctx.max_body_bytes)
    if _413:
        return
    try:
        data = _json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return send_json(handler, {"error": "invalid json"}, 400)
    name = data.get("name")
    steps = data.get("steps")
    decoder_type = str(data.get("decoder_type", "TXT")).upper()
    if decoder_type not in ("TXT", "A"):
        return send_json(handler, {"error": "decoder_type must be TXT or A"}, 400)
    if not name or not isinstance(steps, list):
        return send_json(handler, {"error": "name and steps required"}, 400)
    ok, err = _validate_steps(steps, decoder_type)
    if not ok:
        return send_json(handler, {"error": err}, 400)
    try:
        if decoder_type == "TXT":
            from txt_decoder import register_custom_decoder
            reg_ok = register_custom_decoder(name, steps)
            list_key = "custom_decoders"
        else:
            from a_decoder import register_custom_a_decoder
            reg_ok = register_custom_a_decoder(name, steps)
            list_key = "custom_a_decoders"
        if not reg_ok:
            return send_json(handler, {"error": "failed to register (name conflict or invalid steps)"}, 400)
        with ctx.config_lock:
            lst = ctx.shared_config.setdefault(list_key, [])
            exists = any(x.get("name") == name for x in lst)
            if not exists:
                lst.append({"name": name, "steps": steps, "decoder_type": decoder_type})
    except Exception as e:
        return send_json(handler, {"error": str(e)}, 500)
    _save_config(ctx, list_key)
    return send_json(handler, {"status": "ok", "registered": name, "decoder_type": decoder_type})


def handle_decoders_custom_delete(ctx: HttpContext, handler) -> None:
    body, _413 = get_request_body(handler, max_length=ctx.max_body_bytes)
    if _413:
        return
    try:
        data = _json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return send_json(handler, {"error": "invalid json"}, 400)
    name = data.get("name")
    decoder_type = str(data.get("decoder_type", "TXT")).upper()
    if decoder_type not in ("TXT", "A"):
        return send_json(handler, {"error": "decoder_type must be TXT or A"}, 400)
    if not name:
        return send_json(handler, {"error": "name required"}, 400)
    try:
        if decoder_type == "TXT":
            from txt_decoder import unregister_custom_decoder
            reg_ok = unregister_custom_decoder(name)
            list_key = "custom_decoders"
        else:
            from a_decoder import unregister_custom_a_decoder
            reg_ok = unregister_custom_a_decoder(name)
            list_key = "custom_a_decoders"
        if not reg_ok:
            return send_json(handler, {"error": "not removed (builtin or not found)"}, 400)
        with ctx.config_lock:
            lst = ctx.shared_config.get(list_key, [])
            newlst = [x for x in lst if x.get("name") != name]
            ctx.shared_config[list_key] = newlst
    except Exception as e:
        return send_json(handler, {"error": str(e)}, 500)
    _save_config(ctx, list_key)
    return send_json(handler, {"status": "ok", "removed": name, "decoder_type": decoder_type})


def handle_decoders_custom_put(ctx: HttpContext, handler) -> None:
    body, _413 = get_request_body(handler, max_length=ctx.max_body_bytes)
    if _413:
        return
    try:
        data = _json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return send_json(handler, {"error": "invalid json"}, 400)
    name = data.get("name")
    steps = data.get("steps")
    decoder_type = str(data.get("decoder_type", "TXT")).upper()
    if decoder_type not in ("TXT", "A"):
        return send_json(handler, {"error": "decoder_type must be TXT or A"}, 400)
    if not name or not isinstance(steps, list):
        return send_json(handler, {"error": "name and steps required"}, 400)
    ok, err = _validate_steps(steps, decoder_type)
    if not ok:
        return send_json(handler, {"error": err}, 400)
    try:
        if decoder_type == "TXT":
            from txt_decoder import unregister_custom_decoder, register_custom_decoder
            unregister_custom_decoder(name)
            reg_ok = register_custom_decoder(name, steps)
            list_key = "custom_decoders"
        else:
            from a_decoder import unregister_custom_a_decoder, register_custom_a_decoder
            unregister_custom_a_decoder(name)
            reg_ok = register_custom_a_decoder(name, steps)
            list_key = "custom_a_decoders"
        if not reg_ok:
            return send_json(handler, {"error": "failed to register updated decoder"}, 400)
        with ctx.config_lock:
            lst = ctx.shared_config.setdefault(list_key, [])
            replaced = False
            for i, x in enumerate(lst):
                if x.get("name") == name:
                    lst[i] = {"name": name, "steps": steps, "decoder_type": decoder_type}
                    replaced = True
                    break
            if not replaced:
                lst.append({"name": name, "steps": steps, "decoder_type": decoder_type})
    except Exception as e:
        return send_json(handler, {"error": str(e)}, 500)
    _save_config(ctx, list_key)
    return send_json(handler, {"status": "ok", "updated": name, "decoder_type": decoder_type})


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
