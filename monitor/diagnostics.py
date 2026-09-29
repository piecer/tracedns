"""Small closed diagnostic vocabulary, separate from canonical observations.

Never format provider endpoints, exception text, traceback or raw observations at
log/health boundaries. Provider slots refer to the captured configured ordering,
not completion ordering. The private QueryResult keeps its legacy ENS target
hint; sinks must project its reason through diagnostic_reason, never print it.
"""
from __future__ import annotations

import re
import ssl

import requests


QUERY_REASONS = frozenset({
    'query_failed', 'query_timeout', 'query_tls', 'query_transport',
    'query_invalid', 'query_io', 'dependency_missing', 'invalid_rpc_url',
    'invalid_ens_target', 'invalid_text_key', 'nodehash_invalid', 'namehash_failed',
    'resolver_invalid', 'provider_init_failed', 'rpc_connect_check_failed',
    'rpc_not_connected', 'registry_init_failed', 'resolver_lookup_reverted',
    'resolver_lookup_failed', 'resolver_missing', 'resolver_contract_init_failed',
    'resolver_text_reverted', 'resolver_text_failed', 'record_empty',
})


def diagnostic_reason(value):
    """Return only a closed constant; never call str/repr on an exception."""
    code = value if type(value) is str else getattr(value, 'code', None)
    if type(code) is str:
        code = code[:64].partition(':')[0]
        if code in QUERY_REASONS:
            return code
    if isinstance(value, (ssl.SSLError, requests.exceptions.SSLError)):
        return 'query_tls'
    if isinstance(value, (TimeoutError, requests.exceptions.Timeout)):
        return 'query_timeout'
    if isinstance(value, (ConnectionError, requests.exceptions.ConnectionError)):
        return 'query_transport'
    if isinstance(value, OSError):
        return 'query_io'
    if isinstance(value, ValueError):
        return 'query_invalid'
    return 'query_failed'


def query_error(exc, *, ens_name=None):
    code = diagnostic_reason(exc)
    # Compatibility for private structured ENS QueryResult callers. This is a
    # validated target fact, never exception metadata or a diagnostic log field.
    if (type(ens_name) is str and len(ens_name) <= 253
            and re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\.?', ens_name)):
        return f'{code}: name={ens_name}'
    return code


def provider_label(rtype, slot):
    kind = {'ENS': 'ens', 'SNS': 'sns'}.get(rtype, 'dns')
    slot = slot if type(slot) is int and 0 <= slot <= 65535 else 0
    return f'{kind}:{slot}'
