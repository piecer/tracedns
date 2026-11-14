"""RPC review regressions using real owners and synthetic transport; no remote I/O."""
import copy
import json
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
import rpc_query
from config_manager import domain_storage_name
from history_manager import load_history_files
from http_api.basic_handlers import _build_results_payload
from lookup_context import lookup_scope
from monitor import engine
from test_lookup_liveness import owned_app, owned_scan, background_scan, MonotonicClock, wait_for
from test_rpc_monitor import DOMAIN, rpc_response


@pytest.mark.parametrize('seeded', [False, True])
def test_owner_expiry_is_persisted_as_latest_rpc_failure(tmp_path, seeded):
    """The real owner expiry path must not keep reporting authenticated."""
    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[DOMAIN], servers=['not-used'], clock=clock)
    name = domain_storage_name(DOMAIN)
    entered, release = threading.Event(), threading.Event()
    worker = None
    calls = []
    try:
        if seeded:
            with patch('rpc_query._post_rpc', return_value=rpc_response()):
                assert owned_scan(app).complete
            assert wait_for(lambda: app.lookup.status()['active'] == 0)
        before = copy.deepcopy(app.current[name])

        def blocked_transport(*args):
            calls.append(args[0])
            entered.set()
            assert release.wait(4), 'bounded probe rescue'
            return rpc_response('198.51.100.44:443')

        with patch('rpc_query._post_rpc', side_effect=blocked_transport):
            worker, results, errors = background_scan(app)
            assert entered.wait(2)
            clock.now = 35.0
            with app.lookup.condition:
                app.lookup.condition.notify_all()
            worker.join(2)
            assert not worker.is_alive() and not errors
            assert not results[0].complete and results[0].positive == {}
            assert app.current[name] == before
            assert app.lookup.status()['active'] == 1
            latest = copy.deepcopy(app.history[name]['meta'].get('rpc_observation'))
            loaded = load_history_files(str(tmp_path))
            persisted = loaded[name]['meta'].get('rpc_observation')
            projection = _build_results_payload(app.current, {name: app.history[name]['meta']}, False)
            summary = {
                'seeded': seeded, 'complete': results[0].complete,
                'retained_ips': before.get(rpc_query.PROVIDER, {}).get('decoded_ips', []),
                'latest_rpc_observation': latest, 'persisted_rpc_observation': persisted,
                'projected_rpc_observation': projection['domain_meta'].get(name, {}).get('rpc_observation'),
                'projected_type': projection['results_agg'][name]['type'],
                'physical_workers_before_release': app.lookup.status()['active'],
                'request_count': len(calls),
            }
            print('EXPIRY_EVIDENCE=' + json.dumps(summary, sort_keys=True))
            release.set()
            assert wait_for(lambda: app.lookup.status()['active'] == 0)
            assert app.current[name] == before
            assert len(calls) == 1, 'cancelled attempt started fallback'
        assert latest is not None and latest['status'] == 'error', summary
        assert latest['reason'] == 'query_timeout', summary
        assert persisted == latest, summary
        assert projection['domain_meta'][name]['rpc_observation'] == latest
        assert projection['results_agg'][name]['type'] == 'RPC'
    finally:
        release.set()
        if worker is not None:
            worker.join(3)
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


def test_ordinary_auth_failure_retention_survives_disk_reload(tmp_path):
    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[DOMAIN], servers=['not-used'], clock=clock)
    name = domain_storage_name(DOMAIN)
    try:
        with patch('rpc_query._post_rpc', return_value=rpc_response()):
            assert owned_scan(app).complete
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        initial = copy.deepcopy(app.current[name])
        malformed = {'jsonrpc': '2.0', 'id': 1, 'result': '0x'}
        with patch('rpc_query._post_rpc', return_value=malformed) as transport:
            assert not owned_scan(app).complete
            assert transport.call_count == 4
        loaded = load_history_files(str(tmp_path))[name]
        assert loaded['current'] == initial
        assert loaded['meta']['rpc_observation']['status'] == 'error'
        assert loaded['meta']['rpc_observation']['reason'] == 'rpc_invalid_abi'
    finally:
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


def test_history_ui_shows_both_c2_endpoint_sides_not_only_ciphertext(tmp_path):
    """Execute shipped History formatting against history produced by the engine."""
    from models import DomainSpec
    from test_dht_frontend import run_js
    name = domain_storage_name(DOMAIN)
    current, history = {}, {}
    for port in (18082, 443):
        with patch('rpc_query._post_rpc', return_value=rpc_response(f'192.0.2.10:{port}')):
            engine.run_domain_cycle(domain=DomainSpec(**DOMAIN), servers=[rpc_query.PROVIDER],
                                    current_results=current, history=history, history_dir=str(tmp_path),
                                    query_fail_counts={}, max_workers=1)
    stored = load_history_files(str(tmp_path))[name]
    assert stored['events'][-1]['old']['decoded_endpoints'] == ['192.0.2.10:18082']
    assert stored['events'][-1]['new']['decoded_endpoints'] == ['192.0.2.10:443']
    run_js(['historyEventText', 'historyPageText'], '''
const box = {textContent:''};
global.document = {getElementById:()=>box};
global.formatUnixTsLocal = value=>String(value);
global.log = value=>{throw new Error(value);};
const payload = ''' + json.dumps({'history': stored}) + ''';
global.fetch = async()=>({ok:true,json:async()=>payload});
(async()=>{
  box.textContent = historyPageText('Polygon config [RPC:polygon_aes_gcm_v1]', payload.history);
  process.stdout.write('HISTORY_UI_EVIDENCE='+JSON.stringify(box.textContent)+'\\n');
  assert(box.textContent.includes('192.0.2.10:18082'), 'old authenticated C2 endpoint absent from History panel');
  assert(box.textContent.includes('192.0.2.10:443'), 'new authenticated C2 endpoint absent from History panel');
})().catch(error=>{console.error(error);process.exitCode=1;});
''')


def test_cancel_during_actual_authenticated_decode_never_falls_back_or_promotes():
    cancelled = [False]
    decode = rpc_query.decode_polygon_result

    def decode_then_cancel(raw):
        record = decode(raw)
        cancelled[0] = True
        return record

    with patch('rpc_query._post_rpc', return_value=rpc_response()) as transport, \
            patch('rpc_query.decode_polygon_result', side_effect=decode_then_cancel), \
            lookup_scope(lambda: cancelled[0], lambda: 10):
        with pytest.raises(TimeoutError):
            rpc_query.fetch_rpc_config()
        assert transport.call_count == 1


@pytest.mark.parametrize('mode', ['expire', 'cancel'])
def test_real_session_streaming_rechecks_owner_after_read_and_closes(mode):
    clock = MonotonicClock()
    cancelled = [False]
    timeouts = []

    class Raw:
        closed = False
        _connection = SimpleNamespace(sock=SimpleNamespace(settimeout=timeouts.append))

        def read1(self, size, decode_content=False):
            assert size == 1024 and decode_content is False
            if mode == 'expire':
                clock.now = 3
            else:
                cancelled[0] = True
            return b'{"jsonrpc":"2.0","id":1,"result":"0x"}'

        def close(self):
            self.closed = True

        def release_conn(self):
            pass

    raw = Raw()
    sends = []

    class Adapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            sends.append(request.url)
            response = requests.Response()
            response.status_code = 200
            response.headers = {}
            response.raw = raw
            response.request = request
            response.url = request.url
            return response

        def close(self):
            pass

    with patch.object(requests.Session, 'get_adapter', return_value=Adapter()), \
            patch.object(rpc_query, 'time', SimpleNamespace(monotonic=clock)), \
            lookup_scope(lambda: cancelled[0], lambda: 3-clock()):
        with pytest.raises(TimeoutError):
            rpc_query.fetch_rpc_config()
    assert raw.closed
    assert sends == [rpc_query.RPC_URLS[0]]
    assert timeouts and all(0 < value <= 3 for value in timeouts)


@pytest.mark.parametrize('seeded', [False, True])
def test_started_worker_exception_persists_only_closed_rpc_diagnostic(tmp_path, monkeypatch, seeded):
    from test_stage3_core_runtime import rows

    class PrivateError(RuntimeError):
        def __str__(self):
            raise AssertionError('exception text must never be formatted')

    app = owned_app(tmp_path, domains=[DOMAIN], clock=MonotonicClock())
    name = domain_storage_name(DOMAIN)
    try:
        if seeded:
            with patch('rpc_query._post_rpc', return_value=rpc_response()):
                assert owned_scan(app).complete
            assert wait_for(lambda: app.lookup.status()['active'] == 0)
        before = copy.deepcopy(app.current[name])
        receipts = rows(app, 'receipt')
        previous = app.history[name]['meta'].get('rpc_observation')
        monkeypatch.setattr(engine, 'time', SimpleNamespace(time=lambda: 1700000100))
        with patch.object(engine, 'collect_snapshot', side_effect=PrivateError('private transport detail')) as collect:
            result = owned_scan(app)
        assert collect.call_count == 1
        assert not result.complete and result.positive == {}
        assert app.current[name] == before
        latest = app.history[name]['meta'].get('rpc_observation')
        assert latest == {'status': 'error', 'reason': 'query_failed', 'observed_at': 1700000100}
        assert latest != previous
        stored = load_history_files(str(tmp_path))[name]
        assert stored['meta']['rpc_observation'] == latest
        assert stored['current'] == before
        payload = _build_results_payload(app.current, {name: app.history[name]['meta']}, False)
        assert payload['domain_meta'][name]['rpc_observation'] == latest
        assert payload['results_agg'][name]['type'] == 'RPC'
        assert rows(app, 'receipt') == receipts and rows(app, 'grace') == []
    finally:
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


def test_queued_rpc_expiry_is_not_an_attempt(tmp_path):
    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[DOMAIN], clock=clock)
    name = domain_storage_name(DOMAIN)
    thread = None
    try:
        with patch.object(app.lookup, '_take_provider', return_value=None), \
                patch.object(engine, 'collect_snapshot') as collect:
            thread, results, errors = background_scan(app)
            assert wait_for(lambda: app.lookup.status()['provider_queued'] == 1)
            clock.now = 75
            with app.lookup.condition:
                app.lookup.condition.notify_all()
            thread.join(2)
            assert not thread.is_alive() and not errors
            assert wait_for(lambda: app.lookup.status()['controllers'] == 0)
            collect.assert_not_called()
            assert not results[0].complete and results[0].positive == {}
        assert app.current[name] == {}
        assert 'rpc_observation' not in app.history[name]['meta']
        assert app.repo.capture()[name].target.failures == {}
        assert name not in load_history_files(str(tmp_path))
    finally:
        assert app.lookup.stop()['stopped']
        if thread is not None:
            thread.join(3)
        app.delivery.stop()


def test_singleflight_not_dispatched_retains_latest_attempt_without_fallback(tmp_path):
    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[DOMAIN], clock=clock)
    name = domain_storage_name(DOMAIN)
    entered, release = threading.Event(), threading.Event()
    thread = None

    def transport(*args):
        entered.set()
        assert release.wait(4), 'bounded probe rescue'
        return rpc_response('198.51.100.44:443')

    try:
        with patch('rpc_query._post_rpc', side_effect=transport) as request:
            thread, results, errors = background_scan(app)
            assert entered.wait(2)
            clock.now = 35
            with app.lookup.condition:
                app.lookup.condition.notify_all()
            thread.join(2)
            assert not thread.is_alive() and not errors and not results[0].complete
            latest = copy.deepcopy(app.history[name]['meta'].get('rpc_observation'))
            failures = dict(app.repo.capture()[name].target.failures)
            clock.now = 36
            assert not owned_scan(app).complete
            assert app.history[name]['meta'].get('rpc_observation') == latest
            assert load_history_files(str(tmp_path))[name]['meta'].get('rpc_observation') == latest
            assert app.repo.capture()[name].target.failures == failures
            assert app.lookup.status()['active'] == 1
            release.set()
            assert wait_for(lambda: app.lookup.status()['active'] == 0)
            assert request.call_count == 1
            assert app.current[name] == {}
            assert app.history[name]['meta'].get('rpc_observation') == latest
    finally:
        release.set()
        if thread is not None:
            thread.join(3)
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


@pytest.mark.parametrize('boundary', ['admission', 'persistence'])
@pytest.mark.parametrize('loss', ['target_expiry', 'revoked', 'lookup_shutdown', 'delivery_shutdown'])
def test_rpc_exception_rechecks_authority_at_publication(tmp_path, monkeypatch, boundary, loss):
    """An error is not permission to publish after the target/owner fence."""
    from test_stage3_core_runtime import rows

    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[DOMAIN], clock=clock)
    name = domain_storage_name(DOMAIN)
    lease = app.repo.capture()[name]
    entered, release = threading.Event(), threading.Event()
    holder = app.repo if boundary == 'admission' else engine
    attribute = 'accept_observation' if boundary == 'admission' else 'persist_history_entry'
    original = getattr(holder, attribute)
    fired = []

    def delayed(*args, **kwargs):
        if not fired:
            fired.append(True)
            entered.set()
            assert release.wait(4), 'bounded probe rescue'
        return original(*args, **kwargs)

    def fail_collect(*args):
        raise RuntimeError('private')

    monkeypatch.setattr(holder, attribute, delayed)
    monkeypatch.setattr(engine, 'collect_snapshot', fail_collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        if loss == 'target_expiry':
            clock.now = 75
        elif loss == 'revoked':
            app.service.commit('config', {'domains': []}, expected_revision=0)
            app.service.commit('config', {'domains': [DOMAIN]}, expected_revision=1)
            assert app.repo.capture()[name].target is not lease.target
        elif loss == 'lookup_shutdown':
            app.lookup.fence()
        else:
            app.delivery.stop(producers_stopped=False, join_seconds=0)
        release.set()
        thread.join(2)
        assert not thread.is_alive() and not errors and fired == [True]
        assert wait_for(lambda: app.lookup.status()['controllers'] == 0)
        assert not results[0].complete and results[0].positive == {}
        assert app.current[name] == {}
        if boundary == 'admission' or loss == 'revoked':
            assert 'rpc_observation' not in app.history[name]['meta']
            assert app.repo.capture()[name].target.failures == {}
        assert name not in load_history_files(str(tmp_path)), 'fenced metadata reached disk'
        assert rows(app, 'receipt') == [] and rows(app, 'grace') == []
    finally:
        release.set()
        thread.join(3)
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


@pytest.mark.parametrize('boundary', ['candidate', 'admission'])
def test_rpc_success_does_not_gain_failure_only_deadline_authority(tmp_path, monkeypatch, boundary):
    """A result acquired on time still cannot publish after its 35s ticket."""
    from test_stage3_core_runtime import rows

    clock = MonotonicClock()
    app = owned_app(tmp_path, domains=[DOMAIN], clock=clock)
    name = domain_storage_name(DOMAIN)
    attribute = 'accept_observation' if boundary == 'admission' else 'observation_candidate'
    original = getattr(app.repo, attribute)
    fired = []

    def expire(*args, **kwargs):
        if not fired:
            fired.append(True)
            clock.now = 35
        return original(*args, **kwargs)

    monkeypatch.setattr(app.repo, attribute, expire)
    try:
        with patch('rpc_query._post_rpc', return_value=rpc_response()):
            result = owned_scan(app)
        assert fired == [True]
        assert app.current[name] == {} and result.positive == {} and not result.complete
        assert 'rpc_observation' not in app.history[name]['meta']
        assert rows(app, 'receipt') == []
        # Target-authorized lifecycle counters may persist; expired RPC evidence may not.
        stored = load_history_files(str(tmp_path)).get(name, {})
        assert stored.get('current', {}) == {}
        assert 'rpc_observation' not in stored.get('meta', {})
    finally:
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


def test_history_ui_rpc_primary_endpoints_secondary_provenance_are_safe_text(tmp_path):
    from models import DomainSpec
    from test_dht_frontend import run_js

    current, history = {}, {}
    name = domain_storage_name(DOMAIN)
    for port in (18082, 443):
        plaintext = f'192.0.2.10:{port}\nr 203.0.113.1:8443\n<img src=x onerror=alert(1)>'
        with patch('rpc_query._post_rpc', return_value=rpc_response(plaintext)):
            engine.run_domain_cycle(domain=DomainSpec(**DOMAIN), servers=[rpc_query.PROVIDER],
                                    current_results=current, history=history, history_dir=str(tmp_path),
                                    query_fail_counts={}, max_workers=1)
    stored = load_history_files(str(tmp_path))[name]
    run_js(['historyEventText', 'historyPageText'], '''
const box = {textContent:'', set innerHTML(value){throw new Error('unsafe HTML sink');},
  insertAdjacentHTML(){throw new Error('unsafe HTML sink');}};
global.document = {getElementById:()=>box};
global.formatUnixTsLocal = value=>String(value);
global.log = value=>{throw new Error(value);};
const payload = ''' + json.dumps({'history': stored}) + ''';
global.fetch = async()=>({ok:true,json:async()=>payload});
(async()=>{
  box.textContent = historyPageText('Polygon config', payload.history);
  const lines = box.textContent.split('\\n');
  const primary = lines.find(line=>line.includes('(RPC)'));
  assert(primary.endsWith('C2 192.0.2.10:18082 -> 192.0.2.10:443'), primary);
  assert(!primary.includes('203.0.113.1:8443') && !primary.includes('0x'));
  const event = payload.history.events.at(-1);
  for(const side of ['old','new']) {
    assert(lines.some(line=>line.includes(side+' raw ABI: '+event[side].values.join(','))));
    const evidence = lines.find(line=>line.includes(side+' RPC provenance'));
    assert(evidence && evidence.includes(event[side].rpc_profile));
    for(const field of ['authentication','chain_id','contract','selector','plaintext','roles']) {
      assert(evidence.includes(JSON.stringify(field)+':'+JSON.stringify(event[side].rpc_record[field])));
    }
    assert(evidence.includes('auxiliary roles are not C2'));
  }
  assert(box.textContent.includes('<img src=x onerror=alert(1)>'));
})().catch(error=>{console.error(error);process.exitCode=1;});
''')


def test_history_ui_non_rpc_rendering_is_unchanged():
    from test_dht_frontend import run_js

    run_js(['historyEventText', 'historyPageText'], r'''
const box = {textContent:'', set innerHTML(value){throw new Error('unsafe HTML sink');}};
global.document = {getElementById:()=>box};
global.formatUnixTsLocal = value=>'time:'+value;
global.log = value=>{throw new Error(value);};
let history = {meta:{first_seen:1,last_changed:2},events:[
  {ts:3,server:'dns',type:'A',old:{values:['192.0.2.1']},new:{values:['192.0.2.2']}},
  {ts:4,server:'dns',type:'TXT',old:{},new:{values:['<script>literal</script>']}},
  {ts:5,server:'DHT',type:'DHT',old:{values:['old']},new:{values:['new']}},
  {ts:6,server:'dns',type:'A',values:['192.0.2.3','192.0.2.4']},
  {ts:7,unknown:'event'}
]};
global.fetch = async()=>({ok:true,json:async()=>({history})});
(async()=>{
  box.textContent = historyPageText('fixture', history);
  assert.equal(box.textContent, [
    'History for fixture','First seen: time:1','Last changed: time:2','---',
    'time:3 [dns] (A) 192.0.2.1 -> 192.0.2.2',
    'time:4 [dns] (TXT)  -> <script>literal</script>',
    'time:5 [DHT] (DHT) old -> new',
    'time:6 [dns] (A) 192.0.2.3,192.0.2.4',
    '{"ts":7,"unknown":"event"}'
  ].join('\n'));
  history = {meta:{first_seen:1,last_changed:2},events:[]};
  box.textContent = historyPageText('fixture', history);
  assert.equal(box.textContent, 'No history for fixture\nFirst seen: time:1\nLast changed: time:2');
})().catch(error=>{console.error(error);process.exitCode=1;});
''')
