from unittest import mock

import pytest

import alerts
import mispupdate_code as legacy
from test_delivery_adapters_steps import Response, Transport, attribute, event, setup


@pytest.fixture(autouse=True)
def isolate_queue(monkeypatch, tmp_path):
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'queue.json'))


class LegacyClient:
    def __init__(self, events, adds=(), deletes=()):
        self.events = iter(events)
        self.adds = iter(adds)
        self.deletes = iter(deletes)
        self.add_calls = []
        self.delete_calls = []

    def get_event(self, event_id):
        return next(self.events)

    def add_attribute(self, event_id, value):
        self.add_calls.append(value.value)
        response = next(self.adds)
        if isinstance(response, Exception):
            raise response
        return response

    def delete_attribute(self, id):
        self.delete_calls.append(id)
        return next(self.deletes)


def test_legacy_mixed_add_failures_never_cache_failed_ip_or_false_success(monkeypatch, capsys):
    client = LegacyClient([event()], [RuntimeError('SECRET'), {'Attribute': attribute()},
                                         {'errors': ['SECRET']}])
    monkeypatch.setattr(legacy, 'misp', client)
    assert legacy.add_unique_ips(12, [('1.2.3.4', 'a'), ('1.2.3.4', 'b'), ('2.3.4.5', 'c')]) is False
    assert client.add_calls == ['1.2.3.4', '1.2.3.4', '2.3.4.5']
    assert 'SECRET' not in capsys.readouterr().out


@pytest.mark.parametrize('bad', [{}, {'Event': {}}, {'Event': {'Attribute': None}},
                               {'Event': {'id': '99', 'Attribute': []}}])
def test_legacy_malformed_read_cannot_ack_removal(monkeypatch, bad):
    monkeypatch.setattr(legacy, 'misp', LegacyClient([bad]))
    assert legacy.remove_ips(12, ['1.2.3.4']) is False


def test_legacy_delete_requires_valid_envelope_and_authoritative_absence(monkeypatch):
    failed = LegacyClient([event(attribute())], deletes=[{'errors': ['SECRET']}])
    monkeypatch.setattr(legacy, 'misp', failed)
    assert legacy.remove_ips(12, ['1.2.3.4']) is False
    successful = LegacyClient([event(attribute()), event()], deletes=[{'success': True}])
    monkeypatch.setattr(legacy, 'misp', successful)
    with mock.patch.object(legacy, 'remove_queued_sightings') as cleanup:
        assert legacy.remove_ips(12, ['1.2.3.4']) is True
    cleanup.assert_called_once_with(12, ['1.2.3.4'])


def test_legacy_existing_enqueue_only_no_unbounded_flush(monkeypatch):
    monkeypatch.setattr(legacy, 'misp', LegacyClient([event(attribute())]))
    with mock.patch.object(legacy, 'enqueue_sightings') as enqueue, \
            mock.patch.object(legacy, 'flush_sightings_batch') as flush:
        assert legacy.add_unique_ips(12, [('1.2.3.4', 'label')]) is True
    enqueue.assert_called_once_with(12, ['1.2.3.4'])
    flush.assert_not_called()


def test_legacy_teams_redirect_not_success_or_secret_log(monkeypatch, caplog):
    monkeypatch.setattr(alerts, '_teams_webhook', 'https://teams.invalid/SECRET')
    with mock.patch.object(alerts.requests, 'post', return_value=Response(status=302)) as post:
        assert alerts._send_teams('hello') is False
    assert post.call_args.kwargs['allow_redirects'] is False
    assert post.call_args.kwargs['timeout'] == (3, 10)
    with mock.patch.object(alerts.requests, 'post', side_effect=RuntimeError('SECRET')):
        assert alerts._send_teams('hello') is False
    assert 'SECRET' not in caplog.text


def test_render_seal_callback_does_not_truncate_and_enforces_encoded_budget():
    assert hasattr(alerts, 'render_teams_body'), 'seal renderer missing'
    entries = [(f'1.2.3.{n}', 'label', 'TXT') for n in range(1, 62)]
    with pytest.raises(ValueError, match='payload_limit'):
        alerts.render_teams_body('Added', entries)
    with pytest.raises(ValueError, match='payload_limit'):
        alerts.render_teams_body('Added', [('1.2.3.4', '한' * 9000, 'TXT')])
    rendered = alerts.render_teams_body('Added', entries[:2])
    assert set(rendered) == {'title', 'text'}
    assert '1.2.3.1' in rendered['text'] and '1.2.3.2' in rendered['text']


def test_legacy_wrappers_truthful_channel_results_no_raw_errors(monkeypatch, caplog):
    monkeypatch.setattr(alerts, '_initialized', True)
    monkeypatch.setattr(alerts, '_teams_webhook', 'https://teams.invalid/SECRET')
    monkeypatch.setattr(alerts, '_misp_event_id', 12)
    monkeypatch.setattr(alerts, '_misp_remove_on_absent', True)
    monkeypatch.setattr(legacy, 'misp', object())
    with mock.patch.object(alerts, '_send_teams', return_value=True), \
            mock.patch.object(legacy, 'add_unique_ips', side_effect=RuntimeError('SECRET')), \
            mock.patch.object(legacy, 'remove_ips', return_value=False):
        assert alerts.alert_new_ips([('1.2.3.4', 'label')]) == {'teams': True, 'misp': False}
        assert alerts.alert_removed_ips([('1.2.3.4', 'label')]) == {'teams': True, 'misp': False}
    assert 'SECRET' not in caplog.text


def test_sighting_error_envelope_never_drops_legacy_queue(monkeypatch, capsys):
    client = mock.Mock()
    client.get_event.return_value = event(attribute())
    client.search.return_value = {'Attribute': [attribute()]}
    client.add_sighting.return_value = {'errors': ['SECRET']}
    monkeypatch.setattr(legacy, 'misp', client)
    assert legacy.update_sighting_by_value(12, '1.2.3.4') is False
    client.add_sighting.side_effect = RuntimeError('SECRET')
    assert legacy.update_sighting_by_value(12, '1.2.3.4') is False
    assert 'SECRET' not in capsys.readouterr().out


def test_hooks_are_local_and_flush_is_bounded_daily_no_silent_drop(monkeypatch, tmp_path):
    assert hasattr(legacy, 'run_observation_hook'), 'local hook missing'
    assert hasattr(legacy, 'flush_sightings_step'), 'bounded scheduler step missing'
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'queue.json'))
    transport = Transport(Response(event(attribute())),
                          Response({'Sighting': {'id': '9', 'attribute_id': '1', 'event_id': '12', 'type': '0'}}),
                          Response(event(attribute('2', '2.3.4.5'))), Response({'errors': ['SECRET']}))
    adapter, _ = setup(transport, 'misp')
    for ip in ['1.2.3.4', '2.3.4.5']:
        assert legacy.run_observation_hook({'kind': 'enqueue_sightings', 'event_id': '12', 'ip': ip})
    assert not transport.calls
    progress = {}
    for _ in range(4):
        before = len(transport.calls)
        result = legacy.flush_sightings_step(adapter, progress, today='2026-09-24')
        assert result['provider_calls'] == 1 and len(transport.calls) == before + 1
        progress = result['progress']
    assert legacy._load_sighting_batch_state()['events']['12']['pending'] == ['2.3.4.5']
    result = legacy.flush_sightings_step(adapter, {}, today='2026-09-24')
    assert result['provider_calls'] == 0
    assert len(transport.calls) == 4
    assert legacy.run_observation_hook({'kind': 'remove_queued_sightings', 'event_id': '12', 'ip': '2.3.4.5'})
    assert legacy._load_sighting_batch_state()['events']['12']['pending'] == []
