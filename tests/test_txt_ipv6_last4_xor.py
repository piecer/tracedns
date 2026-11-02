"""Observed pseudo-IPv6 TXT -> IPv4, without inventing suffix port semantics."""
import io
import json
import threading
from unittest import mock

import pytest

import txt_decoder
import dns_query
import http_api_handlers
import http_server
from models import DomainSpec, Snapshot
from monitor import engine
from monitor.collect import collect_snapshot
from txt_decoder import decode_txt_hidden_ips

METHOD = 'ipv6_last4_xor_6b9e3f2a'
RAW = (
    '[6280:b6a6:946f:280e::d233:1b7d|2164:8954:12e6:d85b::e226:a6df|'
    '1d2c:f37f:40c1:946e::f920:5866|5ab6:4c2a:5d37:f540::2676:1b88|'
    'e284:b79a:2793:8fbe::c777:53aa|537d:579b:36d1:ed8c::d91e:03b1|'
    'c0fe:9615:4abd:f86b::03de:1443|a1c5:14f:5319:687c::f4df:fae7]:20445'
)
EXPECTED = sorted([
    '185.173.36.87', '137.184.153.245', '146.190.103.76', '77.232.36.162',
    '172.233.108.128', '178.128.60.155', '104.64.43.105', '159.65.197.205',
])


def test_observed_txt_decodes_all_eight_ipv4_candidates():
    assert decode_txt_hidden_ips([RAW], method=METHOD, domain='jxk.imarapi.st') == EXPECTED


@pytest.mark.parametrize('raw', [
    '[' + '|'.join(['6280:b6a6:946f:280e::d233:1b7d'] * 257) + ']:20445',
    '[' + 'a' * 16384 + ']:20445',
], ids=['too-many-tokens', 'too-many-characters'])
def test_oversized_records_are_rejected_before_address_parsing(raw):
    with mock.patch.object(txt_decoder.ipaddress, 'IPv6Address') as parse:
        assert decode_txt_hidden_ips([raw], method=METHOD) == []
    parse.assert_not_called()


@pytest.mark.parametrize('raw', [
    None, 123, b'not-text', '', 'v=spf1 include:example.org ~all',
    '6280:b6a6:946f:280e::d233:1b7d',
    '[6280:b6a6:946f:280e::d233:1b7d]',
    '[6280:b6a6:946f:280e::d233:1b7d]:-1',
    '[6280:b6a6:946f:280e::d233:1b7d]:123456',
    '[6280:b6a6:946f:280e::d233:1b7d]:１２３',
    '[6280:b6a6:946f:280e::d233:1b7d%eth0]:20445',
    '[6280:b6a6:946f:280e::d233:1b7d|]:20445',
    '[6280:b6a6:946f:280e::d233:1b7d|abcd]:20445',
    '[6280:b6a6:946f:280e::d233:1b7d|2001:db8:1:2:3:4:5:6]:20445',
    '[::ffff:192.0.2.1]:20445',
    RAW + '\n', 'prefix' + RAW, RAW + 'suffix',
])
def test_malformed_record_never_publishes_partial_addresses(raw):
    assert decode_txt_hidden_ips([raw], method=METHOD) == []


def test_multiple_records_deduplicate_and_do_not_depend_on_domain_or_suffix():
    assert decode_txt_hidden_ips(
        [RAW, 'bad-record', RAW.upper().replace(':20445', ':99999')],
        method=METHOD, domain='another.invalid',
    ) == EXPECTED


def test_expanded_ipv6_and_token_budget_boundary():
    token = '6280:b6a6:946f:280e:0000:0000:d233:1b7d'
    raw = '[' + '|'.join([token] * 256) + ']:00000'
    assert decode_txt_hidden_ips([raw], method=METHOD) == ['185.173.36.87']


def test_registered_builtin_is_available_to_decoder_analysis():
    assert txt_decoder.is_builtin_decoder(METHOD)
    assert not txt_decoder.unregister_custom_decoder(METHOD)
    result = txt_decoder.analyze_domain_decoding('another.invalid', RAW)
    assert result['analysis'][METHOD]['ips'] == EXPECTED
    assert result['best'] == METHOD


def test_chunked_dns_txt_reaches_snapshot_without_promoting_suffix_to_port():
    # Real dnspython TXT representation split inside an address, not at '|'.
    import dns.rdata
    rr = dns.rdata.from_text('IN', 'TXT', f'"{RAW[:137]}" "{RAW[137:]}"')
    with mock.patch.object(dns_query.dns.resolver.Resolver, 'resolve', return_value=[rr]):
        result = collect_snapshot(
            DomainSpec('jxk.imarapi.st', type='TXT', txt_decode=METHOD), '127.0.0.1',
        )
    assert result.query.status == 'ok'
    snapshot = result.snapshot
    assert snapshot is not None
    assert snapshot.values == [RAW]
    assert snapshot.decoded_ips == EXPECTED
    assert snapshot.managed_ips() == set(EXPECTED)
    assert snapshot.decoded_endpoints == []
    restored = Snapshot.from_legacy(json.loads(json.dumps(snapshot.to_dict())))
    assert restored.to_dict() == snapshot.to_dict()
    history = engine._history_snapshot(snapshot)
    assert history == {
        'values': [RAW], 'decoded_ips': EXPECTED, 'ts': snapshot.ts, 'txt_decode': METHOD,
    }
    changed = Snapshot.from_legacy(snapshot.to_dict())
    changed.values = [RAW.replace(':20445', ':33036')]
    assert engine._snapshot_changed(snapshot, changed)
    assert changed.decoded_endpoints == []


def test_domain_precheck_uses_registered_decoder_and_preserves_raw_txt():
    body = json.dumps({
        'domain': 'jxk.imarapi.st', 'type': 'TXT', 'txt_decode': METHOD,
        'servers': ['127.0.0.1'], 'include_vt': False, 'analyze_decoders': False,
    }).encode()
    cls = http_server.make_handler({}, threading.Lock(), None, None, {}, {})
    handler = object.__new__(cls)
    handler.headers = {'Content-Length': str(len(body))}
    handler.rfile = io.BytesIO(body)
    captured = {}
    handler._send_json = lambda obj, code=200: captured.update(obj=obj, code=code)
    with mock.patch.object(http_api_handlers, 'query_dns', return_value={'values': [RAW], 'status': 'ok'}):
        cls._handle_domain_precheck(handler)
    assert captured['code'] == 200
    payload = captured['obj']
    assert payload['managed_ips'] == EXPECTED
    assert payload['decoded_endpoints'] == []
    assert payload['domain_object']['txt_decode'] == METHOD
    assert payload['by_server'][0]['values'] == [RAW]
    assert payload['by_server'][0]['decoded_endpoints'] == []
