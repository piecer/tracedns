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
        update_keys = {
            "interval", "servers", "ens_rpc_url", "DEFAULT_SNS_PROXY_HOSTS",
            "custom_decoders", "custom_a_decoders", "max_workers",
        }
        if not update_keys.intersection(data):
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
            normalized = _CM.normalize_domains(data["domains"])
            new_identities = {_CM.domain_identity(d) for d in normalized}
            removed_config_keys = {
                _CM.domain_storage_name(d)
                for d in prev
                if _CM.domain_identity(d) not in new_identities
            }
            new_storage_keys = {
                _CM.domain_storage_name(d).rstrip('.').lower()
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
            orphan_keys = {
                key
                for key in current_result_keys | history_keys
                if key.rstrip('.').lower() not in new_storage_keys
            }
            removed = sorted(removed_config_keys | orphan_keys)
            candidate["domains"] = normalized
        if "servers" in data:
            if not isinstance(data["servers"], list):
                send_json(handler, {"error": "servers must be a list"}, 400)
                return
            servers = [str(server).strip() for server in data["servers"] if str(server or "").strip()]
            if len(servers) > 64:
                send_json(handler, {"error": "servers must contain at most 64 entries"}, 400)
                return
            candidate["servers"] = servers
        if "interval" in data:
            interval = data["interval"]
            if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 86400:
                send_json(handler, {"error": "interval must be an integer between 1 and 86400"}, 400)
                return
            candidate["interval"] = interval
        if "max_workers" in data:
            max_workers = data["max_workers"]
            if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 64:
                send_json(handler, {"error": "max_workers must be an integer between 1 and 64"}, 400)
                return
            candidate["max_workers"] = max_workers
        if "ens_rpc_url" in data:
            candidate["ens_rpc_url"] = str(data["ens_rpc_url"] or "").strip()
        if "DEFAULT_SNS_PROXY_HOSTS" in data:
            hosts = data["DEFAULT_SNS_PROXY_HOSTS"]
            if not isinstance(hosts, list):
                send_json(handler, {"error": "DEFAULT_SNS_PROXY_HOSTS must be a list"}, 400)
                return
            candidate["DEFAULT_SNS_PROXY_HOSTS"] = [
                str(host).strip() for host in hosts if str(host or "").strip()
            ]
        for key in ("custom_decoders", "custom_a_decoders"):
            if key in data:
                if not isinstance(data[key], list):
                    send_json(handler, {"error": f"{key} must be a list"}, 400)
                    return
                candidate[key] = list(data[key])
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
    if "interval" in ctx.shared_config:
        cfg["interval"] = ctx.shared_config.get("interval")
    if "max_workers" in ctx.shared_config:
        cfg["max_workers"] = ctx.shared_config.get("max_workers")
    if "ens_rpc_url" in ctx.shared_config:
        cfg["ens_rpc_url"] = str(ctx.shared_config.get("ens_rpc_url") or "")
    if "DEFAULT_SNS_PROXY_HOSTS" in ctx.shared_config:
        cfg["DEFAULT_SNS_PROXY_HOSTS"] = list(
            ctx.shared_config.get("DEFAULT_SNS_PROXY_HOSTS", []) or []
        )
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
                queue = ctx.shared_config.setdefault("_force_resolve_queue", [])
                if len(queue) >= 64:
                    send_json(handler, {"error": "resolve request queue is full"}, 429)
                    return
                queue.append(req)
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
