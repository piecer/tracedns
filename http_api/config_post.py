"""P1-6: /config,/resolve,/ip,/analyze,/verify POST handlers (extracted from http_api_handlers)."""
from __future__ import annotations

import json
from typing import Callable

from .context import HttpContext
from .request_limits import get_request_body
from .utils import send_json


def _read_body(handler, ctx):
    body, _413 = get_request_body(handler, max_length=ctx.max_body_bytes)
    if _413:
        return None
    return body


def _parse_json(body):
    if not body:
        return {}
    try:
        data = json.loads(body.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return None


class _NullCtx:
    """No-op context manager used when ``ctx.config_lock`` is ``None``."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc) -> bool:
        return False


def handle_config_post(ctx: HttpContext, handler) -> None:
    body = _read_body(handler, ctx)
    if body is None:
        return
    data = _parse_json(body)
    if data is None:
        send_json(handler, {"error": "invalid json"}, 400)
        return
    if "domains" not in data:
        if "interval" not in data and "servers" not in data:
            if ctx.config_lock is not None:
                with ctx.config_lock:
                    snapshot_domains = list(ctx.shared_config.get("domains", []))
            else:
                snapshot_domains = list(ctx.shared_config.get("domains", []))
            payload = {"status": "ok", "config": {"domains": snapshot_domains}}
            send_json(handler, payload)
            return
    removed = []
    with ctx.config_lock if ctx.config_lock else _NullCtx():
        candidate = dict(ctx.shared_config)
        if "domains" in data:
            import config_manager as _CM
            prev = list(candidate.get("domains", []) or [])
            prev_names = {
                d.get("name") if isinstance(d, dict) else str(d)
                for d in prev
            }
            normalized = _CM.normalize_domains(data["domains"])
            new_names = {
                d.get("name") if isinstance(d, dict) else str(d)
                for d in normalized
            }
            current_result_keys = {
                str(d or "") for d in (ctx.current_results or {}).keys()
            }
            current_result_keys.discard("")
            history_keys = {
                str(d or "") for d in (ctx.history or {}).keys()
            }
            history_keys.discard("")
            orphan_keys = (current_result_keys | history_keys) - new_names
            removed = sorted((prev_names - new_names) | orphan_keys)
            candidate["domains"] = normalized
        if "servers" in data:
            candidate["servers"] = list(data["servers"] or [])
        if "interval" in data:
            candidate["interval"] = data["interval"]
        for key in ("custom_decoders", "custom_a_decoders"):
            if key in data:
                candidate[key] = list(data[key] or [])
        if ctx.config_path:
            import config_manager as _CM
            try:
                _CM.write_config(ctx.config_path, candidate)
            except Exception as exc:  # noqa: BLE001
                send_json(handler, {
                    "error": f"config save failed: {exc}",
                    "status": "error",
                }, 500)
                return
        ctx.shared_config.clear()
        ctx.shared_config.update(candidate)
    if removed and callable(getattr(ctx, "purge_removed_domains_state", None)):
        ctx.purge_removed_domains_state(
            ctx.current_results,
            ctx.history,
            ctx.history_dir,
            removed,
        )
    payload = {"status": "ok"}
    cfg = {}
    if "domains" in ctx.shared_config:
        cfg["domains"] = list(ctx.shared_config.get("domains", []))
    if "servers" in ctx.shared_config:
        cfg["servers"] = list(ctx.shared_config.get("servers", []))
    if cfg:
        payload["config"] = cfg
    send_json(handler, payload)

def handle_resolve(ctx: HttpContext, handler) -> None:
    body = _read_body(handler, ctx)
    if body is None:
        return
    data = _parse_json(body)
    if data is None:
        send_json(handler, {"error": "invalid json"}, 400)
        return
    if ctx.config_lock is not None:
        with ctx.config_lock:
            req = {}
            if "domains" in data:
                from config_manager import normalize_domains
                req["domains"] = normalize_domains(data["domains"])
            elif "domain" in data:
                req["domains"] = [{"name": str(data["domain"]).strip(), "type": "A"}]
            if req:
                ctx.shared_config["_force_resolve"] = req
    send_json(handler, {"status": "ok", "requested": True})


def _find_ip_in_results(ctx: HttpContext, ip: str):
    matches = []
    for d, node in (ctx.current_results or {}).items():
        if not isinstance(node, dict):
            continue
        if "values" in node or "decoded_ips" in node:
            # 1-level: domain -> {type, values, decoded_ips, ts}
            pairs = [(d, node)]
        else:
            # 2-level: domain -> {server: {type, values, decoded_ips, ts}, ...}
            pairs = list(node.items())
        for srv, info in pairs:
            if not isinstance(info, dict):
                continue
            vals = list(info.get("values", []) or [])
            decoded = list(info.get("decoded_ips", []) or [])
            if ip in vals or ip in decoded:
                matches.append({
                    "domain": d,
                    "server": srv,
                    "type": info.get("type", "A"),
                    "values": vals,
                    "decoded_ips": decoded,
                    "ts": info.get("ts"),
                })
    return matches


def handle_ip(ctx: HttpContext, handler) -> None:
    body = _read_body(handler, ctx)
    if body is None:
        return
    data = _parse_json(body)
    if data is None:
        send_json(handler, {"error": "invalid json"}, 400)
        return
    ip = str(data.get("ip", "") or "").strip()
    if not ip:
        send_json(handler, {"error": "ip required"}, 400)
        return
    matches = _find_ip_in_results(ctx, ip)
    if matches:
        send_json(handler, {
            "status": "found",
            "ip": ip,
            "domain": matches[0]["domain"],
            "matches": matches,
        })
    else:
        send_json(handler, {"status": "ok", "ip": ip, "matches": []})


def handle_analyze(ctx: HttpContext, handler) -> None:
    body = _read_body(handler, ctx)
    if body is None:
        return
    data = _parse_json(body)
    if data is None:
        send_json(handler, {"error": "invalid json"}, 400)
        return
    domain = str(data.get("domain", "") or "").strip()
    txt = str(data.get("txt", "") or data.get("sample", "") or "").strip()
    if not domain or not txt:
        send_json(handler, {"error": "domain and txt required"}, 400)
        return
    try:
        from txt_decoder import analyze_domain_decoding
        res = analyze_domain_decoding(domain, txt)
        payload = {"domain": domain, "sample": txt}
        if isinstance(res, dict):
            payload.update(res)
        else:
            payload["analysis"] = res
        send_json(handler, payload)
    except Exception as exc:  # noqa: BLE001 - report upstream errors to client
        send_json(handler, {"error": str(exc)}, 500)


def handle_verify(ctx: HttpContext, handler) -> None:
    body = _read_body(handler, ctx)
    if body is None:
        return
    data = _parse_json(body)
    if data is None:
        send_json(handler, {"error": "invalid json"}, 400)
        return
    domains = None
    if isinstance(data.get("domains"), list):
        domains = [d.get("name") if isinstance(d, dict) else d for d in data["domains"]]
    else:
        if ctx.config_lock is not None:
            with ctx.config_lock:
                raw = list(ctx.shared_config.get("domains", []) or [])
        else:
            raw = list(ctx.shared_config.get("domains", []) or [])
        domains = [d.get("name") if isinstance(d, dict) else d for d in raw]
    results = {}
    for dom in domains:
        if not dom:
            continue
        results[dom] = {"verified": False, "reason": "no sample"}
    send_json(handler, {"results": results})


_ROUTES = {
    "/config": handle_config_post,
    "/resolve": handle_resolve,
    "/ip": handle_ip,
    "/analyze": handle_analyze,
    "/verify": handle_verify,
}


def get_handler(path: str) -> Callable:
    handler = _ROUTES.get(path)
    if handler is None:
        raise ValueError(f"unknown POST route: {path}")
    return handler
