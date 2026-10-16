"""Authenticated ENS endpoint recovery using a preserved real chain record."""
import hashlib
import hmac
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import ens_decoder


CORPUS = json.loads((Path(__file__).resolve().parents[1] / 'docs/ens/sha256-hmac-xor-decoder.json').read_text())
METHOD = CORPUS['runtime_method_name']


def test_observed_record_decodes_through_public_registry():
    assert ens_decoder.decode_ens_hidden_ips(
        CORPUS['raw_record'], method=METHOD, ens_options=CORPUS['decoder_options'],
    ) == [CORPUS['decoded_ipv4']]


def synthetic_record(plaintext, *, key_hex=None, marker='1488:'):
    """Test-only producer; synthetic endpoints are not observed infrastructure."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('ascii')
    secret = bytes.fromhex(key_hex if key_hex is not None else CORPUS['decoder_options']['key_hex'])
    key = hashlib.sha256(secret).digest()
    nonce = bytes.fromhex('0001020304050607')
    stream = b''.join(hashlib.sha256(key + nonce + i.to_bytes(4, 'big')).digest()
                      for i in range((len(plaintext) + 31) // 32))
    data = nonce + bytes(a ^ b for a, b in zip(plaintext, stream))
    return marker + (data + hmac.new(key, data, hashlib.sha256).digest()[:8]).hex()


@pytest.mark.parametrize('method', [METHOD, ' ' + METHOD + ' '])
def test_authenticated_port_is_not_taken_from_outer_record_suffix(method):
    record = CORPUS['raw_record'] + ' "]:65535'
    assert ens_decoder.decode_ens_endpoints(
        record, [CORPUS['decoded_ipv4']], suffix_is_port=False,
        method=method, ens_options=CORPUS['decoder_options'],
    ) == [CORPUS['decoded_endpoint']]


@pytest.mark.parametrize('offset', [0, 8, -1])
def test_tampered_nonce_ciphertext_or_tag_never_promotes_ips_or_endpoints(offset):
    raw = bytearray.fromhex(CORPUS['raw_record'].split(':', 1)[1])
    raw[offset] ^= 1
    record = '1488:' + raw.hex() + ' "]:4433'
    options = CORPUS['decoder_options']
    assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=options) == []
    # Caller-supplied IPs must not bypass authentication in endpoint extraction.
    assert ens_decoder.decode_ens_endpoints(
        record, [CORPUS['decoded_ipv4']], method=METHOD, ens_options=options,
    ) == []


@pytest.mark.parametrize('key_hex', [None, '', '0', 'gg', '0x00', '00 11', '00\n', 32, [], {}, 'ab' * 257, '00' * 32])
def test_missing_malformed_or_wrong_key_fails_closed(key_hex):
    options = {'key_hex': key_hex}
    assert ens_decoder.decode_ens_hidden_ips(CORPUS['raw_record'], method=METHOD, ens_options=options) == []
    assert ens_decoder.decode_ens_endpoints(
        CORPUS['raw_record'], [CORPUS['decoded_ipv4']], method=METHOD, ens_options=options,
    ) == []


@pytest.mark.parametrize('record', ['', '136.85.228.108:4433', '1488:', '1488:abc', '1488:zz',
                                   '1488:' + '00' * 16, '1488:' + '00' * 17, None, {}, b'1488:00'])
def test_invalid_records_fail_closed(record):
    assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=CORPUS['decoder_options']) == []


@pytest.mark.parametrize('marker', [None, '', 1488, [], {}, 'x' * 65])
def test_invalid_marker_option_fails_closed(marker):
    options = {**CORPUS['decoder_options'], 'marker': marker}
    assert ens_decoder.decode_ens_hidden_ips(CORPUS['raw_record'], method=METHOD, ens_options=options) == []


@pytest.mark.parametrize('plaintext', ['example.invalid:4433', '[2001:db8::1]:4433', '999.1.1.1:4433',
                                      '192.0.2.1', '192.0.2.1:0', '192.0.2.1:65536', '192.0.2.1:-1',
                                      '192.0.2.1:+80', '192.0.2.1:80\n', ' 192.0.2.1:80',
                                      '192.0.2.1:000080', '192.0.2.1:80/path', '192.0.2.1:80;198.51.100.1:90',
                                      b'\xff:80', b'192.0.2.1:80\x00', b''])
def test_authenticated_but_non_ipv4_endpoint_is_not_an_ioc(plaintext):
    record = synthetic_record(plaintext)
    assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=CORPUS['decoder_options']) == []


@pytest.mark.parametrize('key_hex', ['00', 'ab' * 32, 'ab' * 256])
@pytest.mark.parametrize('endpoint', ['192.0.2.1:1', '198.51.100.2:65535', '203.0.113.4:00080'])
def test_configurable_key_marker_and_endpoint_are_not_sample_specific(key_hex, endpoint):
    marker = 'x' * 64
    options = {'key_hex': key_hex, 'marker': marker}
    record = synthetic_record(endpoint, key_hex=key_hex, marker=marker)
    ip = endpoint.split(':')[0]
    assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=json.dumps(options)) == [ip]
    assert ens_decoder.decode_ens_endpoints(record, [ip], method=METHOD, ens_options=options) == [endpoint]
    assert ens_decoder.decode_ens_endpoints(record, [], method=METHOD, ens_options=options) == []
    assert ens_decoder.decode_ens_endpoints(record, ['192.0.2.99'], method=METHOD, ens_options=options) == []


@pytest.mark.parametrize('suffix', ['', ' other text', '\tignored', '\rignored', '\nignored', '"ignored'])
def test_record_prefix_and_token_delimiters_match_sample(suffix):
    record = 'description ' + CORPUS['raw_record'] + suffix
    assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=CORPUS['decoder_options']) == [CORPUS['decoded_ipv4']]


def test_oversized_record_is_rejected_before_hashing():
    record = CORPUS['raw_record'].ljust(4096)
    options = CORPUS['decoder_options']
    assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=options) == [CORPUS['decoded_ipv4']]
    with patch.object(ens_decoder.hashlib, 'sha256', side_effect=AssertionError('hash work admitted')) as digest:
        assert ens_decoder.decode_ens_hidden_ips(record + ' ', method=METHOD, ens_options=options) == []
    digest.assert_not_called()


def test_failed_authentication_does_not_parse_ip():
    record = CORPUS['raw_record'][:-2] + '00'
    with patch.object(ens_decoder.ipaddress, 'IPv4Address', side_effect=AssertionError('IP parsing admitted')) as parse:
        assert ens_decoder.decode_ens_hidden_ips(record, method=METHOD, ens_options=CORPUS['decoder_options']) == []
    parse.assert_not_called()
