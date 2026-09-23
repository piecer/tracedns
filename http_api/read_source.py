"""Worker-only capture and construction of the browser read snapshot."""
from contextlib import nullcontext
from copy import deepcopy

from monitor.runtime_state import get_state_version, snapshot_current_and_history_events, state_lock
from .basic_handlers import _build_results_payload
from .read_views import build_domain_rows, build_ip_rows


def capture_read_inputs(config, config_lock, current, history, previous):
    # Match mutation lock ordering: configuration before observation state.
    with config_lock if config_lock is not None else nullcontext():
        with state_lock():
            token = (get_state_version(), config.get('_config_revision', 0))
            if token == previous:
                return None
            _, current_copy, history_copy = snapshot_current_and_history_events(current, history)
            domains = deepcopy(config.get('domains') or [])
    return token, (current_copy, history_copy, domains)


def build_read_views(inputs):
    current, history, domains = inputs
    metadata = {domain: entry.get('meta', {}) for domain, entry in history.items()}
    results = _build_results_payload(current, metadata, include_raw=True)
    ips = build_ip_rows(current, history)
    domain_rows = build_domain_rows(current, metadata, domains)
    prefix = [0]
    for row in domain_rows:
        prefix.append(prefix[-1] + max(1, len(row['ip_rows'])))
    return {
        'results': results, 'result_keys': sorted(results['results_agg']),
        'ips': ips, 'valid_ips': [row for row in ips if row['valid']],
        'domains': domain_rows, 'domain_prefix': prefix,
    }


def create_read_model(config, config_lock, current, history):
    from .read_model import BackgroundReadModel
    return BackgroundReadModel(
        lambda previous: capture_read_inputs(config, config_lock, current, history, previous),
        build_read_views,
    )
