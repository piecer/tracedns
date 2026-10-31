"""DHT projection helpers; network and owned history admission remain separate."""
from copy import deepcopy

from models import Snapshot


DHT_REASONS = frozenset({'invalid_public_key', 'invalid_options', 'invalid_cancelled',
                         'crypto_unavailable', 'capacity', 'invalid_state', 'invalid_observation'})


def failure_reason(error):
    code = getattr(error, 'code', None)
    return code if type(code) is str and code in DHT_REASONS else 'query_failed'


def record_snapshot(domain, record, ts):
    if record is None:
        return None
    return Snapshot(type='DHT', values=[record['value_hex']], decoded_ips=list(record['ips']),
                    ts=ts, dht_public_key=record['public_key'],
                    dht_options=deepcopy(domain.dht_options), dht_record=deepcopy(record))


def checkpoint(history):
    return {'state': deepcopy(history.get('meta', {}).get('dht_state')),
            'confirmed_at': history.get('current', {}).get('DHT', {}).get('ts', 0)}


def restore_checkpoint(domain, value):
    """Reverify the bounded ledger evidence outside shared locks."""
    from dht_query import reconcile_dht
    if value['state'] is None:
        return None, None
    state = reconcile_dht(value['state'], {'records': []}, domain.dht_public_key)['state']
    last = state['last_confirmed']
    record = (reconcile_dht(None, {'records': [last]}, domain.dht_public_key)['record']
              if last is not None else None)
    return state, record_snapshot(domain, record, value['confirmed_at'])


def attempt_metadata(outcome, observation, previous, ts):
    record = outcome.get('record')
    records = observation.get('records') or []
    seqs = [int(r['seq']) for r in records if type(r) is dict and
            type(r.get('seq')) is str and r['seq'].isascii() and
            r['seq'].isdigit() and len(r['seq']) <= 19]
    metadata = {'status': outcome['status'], 'observed_at': ts,
                'confirmed_in_this_run': record is not None,
                'last_confirmed_at': ts if record is not None else (previous or {}).get('last_confirmed_at'),
                'observed_seq': str(max(seqs)) if seqs else None,
                'highest_seen_seq': (outcome.get('state') or {}).get('highest_seq'),
                'coverage': deepcopy(outcome.get('coverage') or {'globally_complete': False})}
    reason = observation.get('error_code') or outcome.get('error_code')
    if reason in DHT_REASONS or reason == 'query_failed':
        metadata['reason'] = reason
    return metadata
