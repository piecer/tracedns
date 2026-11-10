"""Read-only RPC precheck. Uses exactly the monitor's authenticated collector."""
import time

from config_manager import validate_rpc_domain
from lookup_context import lookup_scope
from models import DomainSpec
from monitor.collect import collect_snapshot
from monitor.diagnostics import query_error
from rpc_query import PROFILE, PROVIDER


def precheck_rpc(handler, data, shared_config):
    domain = {'name': data.get('domain'), 'type': 'RPC',
              'rpc_profile': data.get('rpc_profile', PROFILE)}
    try:
        validate_rpc_domain({**data, **domain})
    except ValueError as error:
        return handler._send_json({'error': str(error)}, 400)
    domain['name'] = domain['name'].strip()
    deadline = time.monotonic() + 35

    def stopped():
        return bool(shared_config.get('_monitor_stopped') or
                    getattr(shared_config.get('_signal_stop'), 'requested', False))

    snapshot, error, observation = None, None, None
    try:
        with lookup_scope(stopped, lambda: deadline - time.monotonic()):
            collected = collect_snapshot(DomainSpec(**domain), PROVIDER)
        snapshot, error = collected.snapshot, collected.query.error
        observation = collected.rpc_observation
    except TimeoutError as exc:
        error = query_error(exc)
    if stopped() or time.monotonic() >= deadline:
        snapshot, error = None, 'query_timeout'
        observation = {'status': 'error', 'reason': error, 'observed_at': int(time.time())}
    record = snapshot.rpc_record if snapshot is not None else None
    values = snapshot.values if snapshot is not None else []
    ips = snapshot.decoded_ips if snapshot is not None else []
    endpoints = snapshot.decoded_endpoints if snapshot is not None else []
    return handler._send_json({
        'status': 'ok', 'domain': domain['name'], 'requested_type': 'RPC', 'selected_type': 'RPC',
        'detected_types': ['RPC'] if snapshot is not None else [], 'servers': [PROVIDER],
        'include_vt': False, 'vt_enabled': False, 'vt_unavailable_reason': None,
        'decoder_candidates': [], 'resolved_ips': [], 'managed_ips': ips, 'decoded_endpoints': endpoints,
        'by_server': [{'server': PROVIDER, 'type': 'RPC', 'status': 'ok' if snapshot is not None else 'error',
                       'values': values, 'resolved_ips': [], 'managed_ips': ips, 'decoded_ips': ips,
                       'decoded_endpoints': endpoints, 'method': 'Polygon / AES-128-GCM', 'error': error}],
        'ip_rows': [{'ip': ip, 'role': 'managed', 'vt': None} for ip in ips],
        'domain_object': domain, 'can_add': True, 'rpc_profile': domain['rpc_profile'], 'rpc_record': record,
        'rpc_observation': observation,
        'notes': [
            'Read-only Polygon eth_call with authenticated AES-128-GCM configuration decoding.',
            'Only C2 IPv4:port and j entries become managed IPs; relay/download/pool roles stay separate.',
            'No C2 contact, VT enrichment, transaction submission or automatic registration.',
            'A valid profile can be registered even when no authenticated C2 is currently available.',
            'latest is the selected public provider observation, not independent chain-finality proof.',
        ],
    })
