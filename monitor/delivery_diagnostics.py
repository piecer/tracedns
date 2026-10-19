"""Closed, secret-free provider diagnostic detail shared by storage and HTTP."""


OPERATIONS = frozenset({
    'unknown', 'teams_send', 'misp_read', 'misp_add', 'misp_delete',
    'misp_sighting_read', 'misp_sighting_add',
})
_COUNT_FIELDS = ('response_bytes', 'response_limit', 'attribute_count', 'attribute_limit')
_FIELDS = frozenset(('operation', 'http_status', 'tls_kind', 'tls_verify', *_COUNT_FIELDS))


def valid_diagnostic(value):
    """Only exact primitive evidence is accepted; never coerce provider text."""
    if type(value) is not dict or set(value) != _FIELDS:
        return False
    return (
        type(value['operation']) is str and value['operation'] in OPERATIONS
        and (value['http_status'] is None or
             type(value['http_status']) is int and 100 <= value['http_status'] <= 599)
        and all(value[key] is None or type(value[key]) is int and
                0 <= value[key] <= (1 << 63) - 1 for key in _COUNT_FIELDS)
        and (value['tls_kind'] is None or type(value['tls_kind']) is str and
             value['tls_kind'] in ('certificate_verify', 'ssl_failure'))
        and (value['tls_verify'] is None or type(value['tls_verify']) is bool)
    )


def normalize_diagnostic(value=None):
    """Fresh exact detail. Missing or malformed evidence is wholly unknown."""
    if valid_diagnostic(value):
        return dict(value)
    return {
        'operation': 'unknown', 'http_status': None, 'response_bytes': None,
        'response_limit': None, 'attribute_count': None, 'attribute_limit': None,
        'tls_kind': None, 'tls_verify': None,
    }
