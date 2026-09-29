"""Closed diagnostics at real main, collector and persistence boundaries."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from models import DomainSpec
from monitor import collect

SECRET = 'SYNTHETIC_DIAGNOSTIC_CANARY_715'
SOURCE = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('rtype,mode', [
    (rtype, mode) for rtype in ('A', 'ENS', 'SNS') for mode in ('cycles', 'worker', 'history')
] + [('A', 'security'), ('A', 'cli_start')])
def test_real_main_diagnostics_and_original_facts(tmp_path, rtype, mode):
    result = subprocess.run([sys.executable, str(SOURCE / 'tests/delivery_lifecycle_diagnostics_main_probe.py'),
        rtype, mode, str(tmp_path)], cwd=SOURCE, capture_output=True, text=True, timeout=20,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    (tmp_path / 'main.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    evidence = json.loads((tmp_path / 'evidence.json').read_text())
    assert evidence['completed']
    assert SECRET not in result.stderr
    assert 'Traceback' not in result.stderr
    if mode in ('cycles', 'worker'):
        kind = 'dns' if rtype == 'A' else rtype.lower()
        assert 'provider=' + kind + ':1' in result.stderr
        assert 'reason=' in result.stderr
    if mode == 'cycles':
        assert 'INIT' in result.stderr and 'CHANGED' in result.stderr
        assert 'stale' in result.stderr


@pytest.mark.parametrize('rtype', ['ENS', 'SNS'])
def test_collectors_never_format_exception_payload(monkeypatch, rtype):
    def fail(*args, **kw):
        raise TimeoutError('https://provider.invalid/' + SECRET + ' /private/' + SECRET)
    monkeypatch.setattr(collect, 'query_dns', fail)
    monkeypatch.setattr(collect, 'fetch_ens_text_record', fail)
    monkeypatch.setattr(collect, 'fetch_sns_record', fail)
    result = collect.collect_snapshot(DomainSpec(name='fixture.example', type=rtype), 'https://provider/' + SECRET)
    assert result.snapshot is None
    assert result.query.status == 'error'
    assert result.query.error == 'query_timeout'
    assert result.query.server == 'https://provider/' + SECRET


@pytest.mark.parametrize('code', [
    'dependency_missing', 'invalid_rpc_url', 'invalid_ens_target', 'invalid_text_key',
    'nodehash_invalid', 'namehash_failed', 'resolver_invalid', 'provider_init_failed',
    'rpc_connect_check_failed', 'rpc_not_connected', 'registry_init_failed',
    'resolver_lookup_reverted', 'resolver_lookup_failed', 'resolver_missing',
    'resolver_contract_init_failed', 'resolver_text_reverted', 'resolver_text_failed', 'record_empty',
])
def test_structured_ens_reason_preserved_without_exception_metadata(monkeypatch, code):
    from ens_query import EnsQueryError
    from monitor.diagnostics import diagnostic_reason
    error = EnsQueryError(code, SECRET, rpc_url='https://user:' + SECRET + '@provider/' + SECRET,
                          ens_name=SECRET, key=SECRET, cause=OSError('/private/' + SECRET))
    monkeypatch.setattr(collect, 'fetch_ens_text_record', lambda *a, **k: (_ for _ in ()).throw(error))
    result = collect.collect_snapshot(DomainSpec(name='fixture.eth', type='ENS'), 'https://provider/' + SECRET)
    assert diagnostic_reason(result.query.error) == code
    assert SECRET not in result.query.error
    assert 'fixture.eth' in result.query.error  # existing direct-helper compatibility


def test_diagnostic_policy_is_closed_and_never_formats_objects():
    from monitor.diagnostics import QUERY_REASONS, diagnostic_reason, provider_label, query_error
    import requests
    import ssl

    class Unprintable(RuntimeError):
        def __str__(self):
            raise AssertionError('exception formatting forbidden')

    for value, expected in [(Unprintable(), 'query_failed'),
                            (requests.exceptions.Timeout(SECRET), 'query_timeout'),
                            (ssl.SSLError(SECRET), 'query_tls'),
                            (ConnectionError(SECRET), 'query_transport'),
                            (OSError(SECRET), 'query_io'), (ValueError(SECRET), 'query_invalid'),
                            ('query_timeout: ' + SECRET, 'query_timeout'),
                            (SECRET * 10000, 'query_failed')]:
        assert diagnostic_reason(value) == expected
        assert expected in QUERY_REASONS
    assert query_error(Unprintable(), ens_name='https://provider/' + SECRET) == 'query_failed'
    assert provider_label('SNS', 2) == 'sns:2'
    assert provider_label(SECRET, 100000) == 'dns:0'
