"""Forced work selects configured authority, not caller-owned definitions."""
import threading
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from http_api.config_post import handle_resolve
from monitor.engine import run_full_cycle
from monitor.repository import MonitorStateRepository
from tests.test_config_revision import request


def context(tmp_path, domains=None, servers=None, **extra):
    cfg = {'domains': domains or [{'name': 'x.test', 'type': 'TXT', 'txt_decode': 'base64'}],
           'servers': ['dns'] if servers is None else servers, **extra}
    repo = MonitorStateRepository({}, {}, str(tmp_path), cfg['domains'])
    repo.configure(cfg)
    return SimpleNamespace(shared_config=cfg, config_lock=threading.RLock(),
                           max_body_bytes=10000, state_repository=repo)


def admit(ctx, body):
    handler = request(body)
    handler.security_store = Mock()
    handler.request_id, handler.source_ip = 'request', 'local'
    handle_resolve(ctx, handler)
    return handler


def execute(ctx, job, **kwargs):
    cfg, repo = ctx.shared_config, ctx.state_repository
    return run_full_cycle(domains_raw=cfg['domains'], servers=cfg['servers'],
                          ens_rpc_url=cfg.get('ens_rpc_url'),
                          sns_proxy_hosts=cfg.get('DEFAULT_SNS_PROXY_HOSTS'),
                          current_results=repo.current, history=repo.history,
                          history_dir=repo.history_dir, query_fail_counts={}, force_req=job,
                          state_repository=repo, target_leases=repo.capture(), **kwargs)


def test_force_executes_configured_definition_not_request_substitution(tmp_path):
    ctx = context(tmp_path)
    h = admit(ctx, {'domains': [{'name': 'x.test', 'type': 'A', 'a_decode': 'attacker'}]})
    assert h.status == 200
    job = ctx.shared_config['_force_resolve_queue'][0]
    assert job['domains'] == ctx.shared_config['domains']
    with patch('monitor.engine.run_domain_cycle', return_value=[]) as run:
        execute(ctx, job)
    assert run.call_args.kwargs['domain'].type == 'TXT'
    assert run.call_args.kwargs['domain'].txt_decode == 'base64'
    assert [c.kwargs['outcome'] for c in h.security_store.audit.call_args_list] == ['started', 'completed']


@pytest.mark.parametrize('change', ['readd', 'definition', 'decoder', 'provider'])
def test_force_original_lease_cannot_rebind_and_audits_failure_once(tmp_path, change):
    ctx = context(tmp_path)
    h = admit(ctx, {'domain': 'x.test'})
    assert h.status == 200
    job = ctx.shared_config['_force_resolve_queue'][0]
    cfg = deepcopy({k: v for k, v in ctx.shared_config.items() if not k.startswith('_')})
    if change == 'readd':
        ctx.state_repository.configure({'domains': []})
    elif change == 'definition':
        cfg['domains'][0]['txt_decode'] = 'hex'
    elif change == 'decoder':
        cfg['custom_decoders'] = [{'name': 'decoder', 'steps': []}]
    elif change == 'provider':
        cfg['servers'] = ['replacement']
    ctx.state_repository.configure(cfg)
    ctx.shared_config.update(cfg)
    with patch('monitor.engine.run_domain_cycle', return_value=[]) as run:
        # Retry by a caller must not duplicate the terminal audit either.
        execute(ctx, job)
        execute(ctx, job)
    run.assert_not_called()
    assert [c.kwargs['outcome'] for c in h.security_store.audit.call_args_list] == ['started', 'failure']


@pytest.mark.parametrize('kind', ['ENS', 'SNS'])
@pytest.mark.parametrize('dns_override', [False, True])
def test_chain_force_uses_configured_provider_independent_of_dns(tmp_path, kind, dns_override):
    domain = {'name': 'x.eth' if kind == 'ENS' else 'x.sol', 'type': kind}
    ctx = context(tmp_path, [domain], servers=['dns'] if dns_override else [],
                  ens_rpc_url='rpc', DEFAULT_SNS_PROXY_HOSTS=['sns'])
    body = {'domains': [domain]}
    if dns_override:
        body['servers'] = ['dns']
    h = admit(ctx, body)
    assert h.status == 200
    with patch('monitor.engine.run_domain_cycle', return_value=[]) as run:
        execute(ctx, ctx.shared_config['_force_resolve_queue'][0])
    assert list(run.call_args.kwargs['servers']) == (['rpc'] if kind == 'ENS' else ['sns'])


@pytest.mark.parametrize('kind', ['ENS', 'SNS'])
def test_missing_chain_provider_is_rejected_before_audit(tmp_path, kind):
    domain = {'name': 'x.eth' if kind == 'ENS' else 'x.sol', 'type': kind}
    ctx = context(tmp_path, [domain])
    h = admit(ctx, {'domains': [domain]})
    assert h.status == 400
    h.security_store.audit.assert_not_called()
    assert not ctx.shared_config.get('_force_resolve_queue')


def test_force_becoming_stale_during_execution_finishes_as_failure(tmp_path):
    ctx = context(tmp_path)
    h = admit(ctx, {'domain': 'x.test'})
    job = ctx.shared_config['_force_resolve_queue'][0]
    with patch('monitor.engine.run_domain_cycle', side_effect=lambda **kw: (
            ctx.state_repository.configure({'domains': []}) and [])):
        execute(ctx, job)
    assert [c.kwargs['outcome'] for c in h.security_store.audit.call_args_list] == ['started', 'failure']


def test_application_force_without_original_admission_tokens_fails_closed(tmp_path):
    ctx = context(tmp_path)
    repo = ctx.state_repository
    with patch('monitor.engine.run_domain_cycle', return_value=[]) as run:
        run_full_cycle(domains_raw=ctx.shared_config['domains'], servers=['dns'],
                       current_results=repo.current, history=repo.history, history_dir=repo.history_dir,
                       query_fail_counts={}, state_repository=repo,
                       force_req={'domains': ctx.shared_config['domains']})
    run.assert_not_called()


def test_pending_quotas_fifo_and_admission_audit_failure_leave_no_job(tmp_path):
    from monitor.stores import ConfigStore
    ctx = context(tmp_path)
    store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository)
    for _ in range(4):
        assert admit(ctx, {'domain': 'x.test'}).status == 200
    rejected = admit(ctx, {'domain': 'x.test'})
    assert rejected.status == 429
    rejected.security_store.audit.assert_not_called()
    jobs = list(ctx.shared_config['_force_resolve_queue'])
    store.snapshot()
    assert store.dequeue_force() is jobs[0]  # Running is additional to pending quota.
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    for remaining in jobs[1:]:
        assert store.dequeue_force() is remaining
    store.dequeue_force()
    ctx.shared_config['_force_resolve_queue'] = [dict(actor={'id': -n}) for n in range(64)]
    rejected = admit(ctx, {'domain': 'x.test'})
    assert rejected.status == 429
    rejected.security_store.audit.assert_not_called()
    ctx.shared_config['_force_resolve_queue'] = []
    h = request({'domain': 'x.test'})
    h.security_store = Mock()
    h.security_store.audit.side_effect = RuntimeError('audit unavailable')
    h.request_id, h.source_ip = 'request', 'local'
    with pytest.raises(RuntimeError, match='audit unavailable'):
        handle_resolve(ctx, h)
    assert not ctx.shared_config['_force_resolve_queue']


def test_ens_text_key_identities_select_distinct_configured_options(tmp_path):
    domains = [{'name': 'x.eth', 'type': 'ENS', 'ens_text_key': key, 'ens_options': {'choice': key}}
               for key in ('one', 'two')]
    ctx = context(tmp_path, domains=domains, servers=[], ens_rpc_url='rpc')
    h = admit(ctx, {'domains': [{'name': 'x.eth', 'type': 'ENS', 'ens_text_key': 'two',
                                'ens_options': {'choice': 'caller'}}]})
    assert h.status == 200
    with patch('monitor.engine.run_domain_cycle', return_value=[]) as run:
        execute(ctx, ctx.shared_config['_force_resolve_queue'][0])
    assert run.call_args.kwargs['domain'].ens_options == {'choice': 'two'}
    assert run.call_args.kwargs['target_lease'].name == 'x.eth [ENS:two]'


def test_force_definition_is_owned_by_admission_lease_not_mutable_envelope(tmp_path):
    ctx = context(tmp_path)
    assert admit(ctx, {'domain': 'x.test'}).status == 200
    job = ctx.shared_config['_force_resolve_queue'][0]
    job['domains'][0]['type'] = 'A'
    job['domains'][0]['txt_decode'] = 'substituted'
    with patch('monitor.engine.run_domain_cycle', return_value=[]) as run:
        execute(ctx, job)
    assert run.call_args.kwargs['domain'].type == 'TXT'
    assert run.call_args.kwargs['domain'].txt_decode == 'base64'
