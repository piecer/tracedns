"""Reviewer regressions: actual registry/store/worker; only transport is fake."""
import json
import sqlite3
import threading
import uuid

from alerts import render_teams_body
from monitor.delivery_adapters import DestinationRegistry, encode_body
from monitor.delivery_store import DeliveryStore
from monitor.delivery_worker import DeliveryWorker

AUTH = {'valid': True, 'revision': 1, 'signature': 'configured-v1'}
MISP = {'misp_url': 'https://misp.invalid', 'api_key': 'fixture-key',
        'push_event_id': '1', 'misp_remove_on_absent': True}
TEAMS = {'teams_webhook': 'https://teams.invalid/fixture'}


def attr(ip, ident='1'):
    return {'id': ident, 'event_id': '1', 'type': 'ip-src', 'value': ip}


class Response:
    def __init__(self, payload=None, status=200):
        self.status_code = status
        self.headers = {}
        self.raw = encode_body(payload or {})

    def iter_content(self, chunk_size):
        yield self.raw

    def close(self):
        pass


class Transport:
    def __init__(self, attrs=(), callback=None):
        self.attrs = list(attrs)
        self.calls = []
        self.callback = callback

    def request(self, method, url, **kwargs):
        self.calls.append({'method': method, 'url': url, **kwargs})
        if self.callback:
            response = self.callback(method, url, kwargs)
            if response is not None:
                return response
        if 'teams.invalid' in url:
            return Response()
        if '/events/view/' in url:
            return Response({'Event': {'id': '1', 'Attribute': self.attrs}})
        if '/attributes/delete/' in url:
            ident = url.rsplit('/', 1)[1]
            if not any(a['id'] == ident for a in self.attrs):
                return Response({}, 404)
            self.attrs = [a for a in self.attrs if a['id'] != ident]
            return Response({'success': True})
        if '/attributes/add/' in url:
            data = json.loads(kwargs['data'])
            added = attr(data['value'], str(len(self.attrs) + 100))
            self.attrs.append(added)
            return Response({'Attribute': added})
        if '/sightings/add/' in url:
            return Response({'Sighting': {'id': '10', 'event_id': '1',
                'attribute_id': url.rsplit('/', 1)[1], 'type': '0'}})
        raise AssertionError('unrecognized fake transport path')


def observation(ips, target='example.test', label='example.test', now=100, **extra):
    return {'target': target, 'managed_ips': list(ips), 'before_ips': [],
            'projection_signature': 'dns-v1', 'source_operation_id': uuid.uuid4().hex,
            'cycle_id': 'cycle', 'observed_at': now, 'label': label,
            'source_type': 'A', **extra}


def projection(ips=()):
    return {'example.test': {'ips': list(ips), 'signature': 'dns-v1', 'label': 'example.test'}}


def render(entries, action, created):
    return render_teams_body(action, entries, {'created': created})


def rows(store, table):
    path = store.path if isinstance(store, DeliveryStore) else store / 'delivery.sqlite'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute('SELECT * FROM ' + table)]


def registry(store, transport, config):
    value = DestinationRegistry(store.binding_key(), transport=transport)
    value.apply(config, revision=1)
    return value


def make_components(path, *, config=None, transport=None, renderer=render, limits=None, grace=None, now=100):
    clock = [now]
    store = DeliveryStore(path, clock=lambda: clock[0], render=renderer, limits=limits)
    assert store.bootstrap(projection(), grace or {}, AUTH)['ready']
    transport = transport or Transport()
    reg = registry(store, transport, MISP if config is None else config)
    return store, reg, transport, clock


def bindings(reg):
    return list(reg.descriptors().values())


def worker(store, reg, clock, **kwargs):
    gate = threading.RLock()

    def admit(now):
        with gate:
            for channel, descriptor in reg.descriptors().items():
                adapter = reg.capture(channel, descriptor['binding_id'], 'Added', revision=reg.revision)
                claim = store.claim_next(adapter.descriptor(), now)
                if claim:
                    return claim, adapter
        return None

    return DeliveryWorker(store, claim_admission=admit, clock=lambda: clock[0], **kwargs)


def close(store, value=None):
    if value:
        assert value.stop()['stopped']
    assert store.close(clean=True)


def test_long_ascii_real_renderer_splits_complete_prefix(tmp_path):
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS)
    ips = ['192.0.2.' + str(i) for i in range(1, 31)]
    try:
        assert store.record_domain(observation(ips, label='a' * 1000), AUTH, bindings(reg))['admitted_receipts'] == 30
        assert store.seal_cycle(None)['ledger_committed']
        batches = [json.loads(row['payload']) for row in rows(store, 'batch')]
        assert len(batches) > 1
        assert sorted(e[0] for b in batches for e in b['entries']) == sorted(ips)
        value = worker(store, reg, clock)
        assert value.run_pass()['provider_calls'] == len(batches)
        assert store.health_snapshot()['acked_total'] == 30
        assert all(len(call['data']) <= 24 * 1024 for call in transport.calls)
        assert not rows(store, 'receipt')
        assert value.stop()['stopped']
    finally:
        close(store)


def test_unicode_fitting_body_is_one_exact_wire_batch(tmp_path):
    store, reg, transport, clock = make_components(tmp_path, config=TEAMS)
    ips = ['192.0.2.' + str(i) for i in range(1, 21)]
    try:
        assert store.record_domain(observation(ips, label='雪' * 300), AUTH, bindings(reg))['admitted_receipts'] == 20
        assert store.seal_cycle(None)['ledger_committed']
        batches = rows(store, 'batch')
        assert len(batches) == 1
        body = json.loads(batches[0]['payload'])['body']
        value = worker(store, reg, clock)
        assert value.run_pass()['provider_calls'] == 1
        assert transport.calls[0]['data'] == encode_body(body)
        assert len(transport.calls[0]['data']) <= 24 * 1024
        assert store.health_snapshot()['acked_total'] == 20
        assert value.stop()['stopped']
    finally:
        close(store)


def test_seal_uses_persisted_created_not_wall_clock(tmp_path):
    from datetime import datetime
    store, reg, _, _ = make_components(tmp_path, config=TEAMS)
    try:
        store.record_domain(observation(['192.0.2.1'], now=100), AUTH, bindings(reg))
        assert store.seal_cycle(None)['ledger_committed']
        body = json.loads(rows(store, 'batch')[0]['payload'])['body']
        expected = datetime.fromtimestamp(100).astimezone().strftime('%Y-%m-%d %H:%M:%S')
        assert 'Time (Local): ' + expected in body['text']
    finally:
        close(store)
