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
    from .settings_handlers import validate_clear_fields
    from monitor.config_service import commit_request
    if validate_clear_fields(handler, data, {'ens_rpc_url', 'DEFAULT_SNS_PROXY_HOSTS'}) is None:
        return
    result = commit_request(ctx, handler, 'config', data)
    if result is not None:
        from .basic_handlers import config_payload
        result['config'] = config_payload(result['config'])
        send_json(handler, result)

def handle_resolve(ctx: HttpContext, handler) -> None:
    body = _read_body(handler, ctx)
    if body is None:
        return
    data = _parse_json(body)
    if data is None:
        send_json(handler, {"error": "invalid json"}, 400)
        return
    from config_manager import domain_identity, normalize_domains

    lock = ctx.config_lock if ctx.config_lock is not None else _NullCtx()
    with lock:
        if (ctx.shared_config.get('_monitor_stopped') or
                getattr(ctx.shared_config.get('_signal_stop'), 'requested', False)):
            send_json(handler, {'error': 'monitor stopped'}, 503)
            return
        if "domains" in data:
            if not isinstance(data["domains"], list):
                send_json(handler, {"error": "domains must be a list"}, 400)
                return
            domains = normalize_domains(data["domains"])
        elif "domain" in data:
            domains = normalize_domains([
                {"name": str(data["domain"] or "").strip(), "type": "A"},
            ])
        else:
            send_json(handler, {"error": "domain or domains required"}, 400)
            return
        if not domains:
            send_json(handler, {"error": "domain or domains required"}, 400)
            return
        if len(domains) > 64:
            send_json(handler, {"error": "domains must contain at most 64 entries"}, 400)
            return

        from copy import deepcopy
        configured_domains = normalize_domains(ctx.shared_config.get("domains", []) or [])
        configured_by_id = {domain_identity(domain): domain for domain in configured_domains}
        if any(domain_identity(domain) not in configured_by_id for domain in domains):
            send_json(handler, {"error": "domains must be configured"}, 400)
            return
        domains = [deepcopy(configured_by_id[domain_identity(domain)]) for domain in domains]

        configured_servers = [
            str(server).strip()
            for server in (ctx.shared_config.get("servers", []) or [])
            if str(server or "").strip()
        ]
        servers = data.get("servers", configured_servers)
        if not isinstance(servers, list):
            send_json(handler, {"error": "servers must be a list"}, 400)
            return
        servers = [str(server).strip() for server in servers if str(server or "").strip()]
        if len(servers) > 64:
            send_json(handler, {"error": "servers must contain at most 64 entries"}, 400)
            return
        if any(server not in configured_servers for server in servers):
            send_json(handler, {"error": "servers must be configured"}, 400)
            return
        from monitor.targets import providers_for
        from monitor.repository import normalized_domain_specs
        ens_rpc_url = str(ctx.shared_config.get('ens_rpc_url') or '').strip()
        sns_proxy_hosts = list(ctx.shared_config.get('DEFAULT_SNS_PROXY_HOSTS',
                              ctx.shared_config.get('DEFAULT_SOLAR_PROXY_HOSTS', [])) or [])
        if any(not providers_for(d, servers, ens_rpc_url, sns_proxy_hosts)
               for d in normalized_domain_specs(domains)):
            send_json(handler, {'error': 'configured provider required'}, 400)
            return

        queue = ctx.shared_config.get("_force_resolve_queue", [])
        if len(queue) >= 64:
            send_json(handler, {"error": "resolve request queue is full"}, 429)
            return
        job = {"domains": domains, "servers": servers,
               'ens_rpc_url': ens_rpc_url, 'sns_proxy_hosts': deepcopy(sns_proxy_hosts)}
        repository = getattr(ctx, 'state_repository', None)
        if repository is not None:
            from config_manager import domain_storage_name
            captured = repository.capture()
            job['_target_leases'] = {domain_storage_name(d): captured.get(domain_storage_name(d))
                                     for d in domains}
            if not all(repository.valid(lease) for lease in job['_target_leases'].values()):
                send_json(handler, {'error': 'target unavailable'}, 400)
                return
        registry_snapshot = ctx.shared_config.get('_decoder_registry_snapshot')
        if registry_snapshot is not None:
            job['_registry_view'] = registry_snapshot()
        from security.jobs import prepare_force
        if not prepare_force(handler, job, queue):
            return
        from monitor.projection_authority import advance_security_projection_locked
        try:
            advance_security_projection_locked(ctx.shared_config)
        except Exception:
            # Admission audit already started; this job will never be queued.
            from security.jobs import finish_force
            finish_force(job, 'failure')
            raise
        ctx.shared_config['_force_resolve_queue'] = queue
        queue.append(job)
        condition = ctx.shared_config.get('_monitor_condition')
        if condition is not None:
            condition.notify_all()
    send_json(handler, {"status": "ok", "requested": True, "job_id": job.get('job_id')})


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
    send_json(handler, {"error": "verification is not implemented"}, 501)


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
