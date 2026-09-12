"""Forced work carries the accepting user through monitor completion."""
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch
from tests.test_config_revision import request
from http_api.config_post import handle_resolve
from monitor.engine import run_full_cycle


def test_force_resolve_carries_actor_and_records_completion():
    store = Mock()
    h = request({'domains': [{'name': 'example.test', 'type': 'A'}]})
    h.security_store = store
    h.request_id = 'request-1'
    h.source_ip = '127.0.0.1'
    ctx = SimpleNamespace(shared_config={'domains': [{'name': 'example.test', 'type': 'A'}],
        'servers': ['127.0.0.1']}, config_lock=threading.RLock(), max_body_bytes=10000)
    handle_resolve(ctx, h)
    assert h.status == 200
    job = ctx.shared_config['_force_resolve_queue'][0]
    assert job['actor']['id'] == h.principal['id']
    with patch('monitor.engine.run_domain_cycle', return_value=[]):
        run_full_cycle(domains_raw=ctx.shared_config['domains'], servers=['127.0.0.1'],
                       current_results={}, history={}, history_dir='', query_fail_counts={}, force_req=job)
    outcomes = [c.kwargs['outcome'] for c in store.audit.call_args_list]
    assert outcomes == ['started', 'completed']
