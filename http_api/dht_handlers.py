"""Authenticated DHT precheck adapter; registration and enrichment are separate."""
from copy import deepcopy
import time

from config_manager import validate_dht_domain
from dht_query import reconcile_dht
from models import DomainSpec
from monitor.collect import collect_snapshot
from monitor.dht_support import attempt_metadata


def precheck_dht(handler, data, shared_config):
    domain = {'name': data.get('domain'), 'type': 'DHT',
              'dht_public_key': data.get('dht_public_key')}
    if 'dht_options' in data:
        domain['dht_options'] = deepcopy(data['dht_options'])
    try:
        validate_dht_domain(domain)
    except ValueError as error:
        return handler._send_json({'error': str(error)}, 400)
    domain['name'] = domain['name'].strip()

    def stopped():
        return bool(shared_config.get('_monitor_stopped') or
                    getattr(shared_config.get('_signal_stop'), 'requested', False))

    collected = collect_snapshot(DomainSpec(**domain), 'DHT', cancelled=stopped)
    observation = collected.dht_observation or {'records': [], 'coverage': {}}
    outcome = reconcile_dht(None, observation, domain['dht_public_key'])
    attempt = attempt_metadata(outcome, observation, None, int(time.time()))
    record = outcome['record']
    values = [record['value_hex']] if record is not None else []
    ips = list(record['ips']) if record is not None else []
    notes = [
        'Read-only BEP44 signed DNS lookup; no C2 contact or record publication.',
        'A valid public-key configuration can be registered without a currently found record.',
        'Bounded lookup coverage is not proof of global latestness, absence or deletion.',
        'VT enrichment and decoder sweeps are disabled for DHT precheck.',
    ]
    if record is None:
        notes.append('No unambiguous verified DNS record was selected in this attempt.')
    response = {
        'status': 'ok', 'domain': domain['name'], 'requested_type': 'DHT', 'selected_type': 'DHT',
        'detected_types': ['DHT'] if record is not None else [], 'servers': ['DHT'],
        'include_vt': False, 'vt_enabled': False, 'vt_unavailable_reason': None,
        'decoder_candidates': [], 'resolved_ips': [], 'managed_ips': ips, 'decoded_endpoints': [],
        'by_server': [{'server': 'DHT', 'type': 'DHT', 'status': 'ok' if record is not None else 'error',
                       'values': values, 'resolved_ips': [], 'managed_ips': ips, 'decoded_ips': ips,
                       'decoded_endpoints': [], 'method': 'BEP44 signed DNS',
                       'error': None if record is not None else attempt.get('reason', outcome['status'])}],
        'ip_rows': [{'ip': ip, 'role': 'managed', 'vt': None} for ip in ips],
        'domain_object': domain, 'can_add': True, 'notes': notes,
        'dht_public_key': domain['dht_public_key'], 'dht_record': record, 'dht_observation': attempt,
    }
    # Independent of the collector fence: this adapter verifies again and
    # prepares projections before publishing. Discard every success projection
    # if stop arrived during either phase, without retaining a selected seq.
    if stopped():
        observation = {'records': [], 'status': 'cancelled', 'coverage': {'termination': 'cancelled'}}
        outcome = reconcile_dht(None, observation, domain['dht_public_key'])
        response.update(dht_record=None, managed_ips=[], ip_rows=[], detected_types=[],
                        dht_observation=attempt_metadata(outcome, observation, None, int(time.time())))
        response['by_server'][0].update(status='error', values=[], managed_ips=[],
                                        decoded_ips=[], error='cancelled')
        if record is not None:
            notes.append('No unambiguous verified DNS record was selected in this attempt.')
    return handler._send_json(response)
