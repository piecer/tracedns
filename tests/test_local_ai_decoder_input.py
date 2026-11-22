"""Model-only decoder views; original data and verification stay intact."""
import copy
import importlib
import hashlib
import json

import pytest


def api():
    try:
        return importlib.import_module('local_ai.decoder_input')
    except ModuleNotFoundError as exc:
        if exc.name != 'local_ai.decoder_input':
            raise
        pytest.fail('bounded model-only decoder input is not implemented')


def example(data, expected=None):
    return {'data': data, 'expected_ips': expected or ['192.0.2.1'],
            'usage': 'example', 'complete_expected': True}


def snapshot(rows, kind='TXT'):
    return {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': kind, 'examples': rows}


def test_large_examples_are_separate_bounded_excerpts_without_mutating_originals():
    original = snapshot([example(f'192.0.2.{i}|'.ljust(1800, chr(64 + i)), [f'192.0.2.{i}'])
                         for i in range(1, 5)])
    before = copy.deepcopy(original)
    view = api().project_examples(original)
    assert set(view) == set(original)
    assert view['decoder_type'] == 'TXT' and len(view['examples']) == 4
    for source, shown in zip(original['examples'], view['examples']):
        assert set(shown) == {'expected_ips', 'usage', 'complete_expected', 'excerpt'}
        assert shown['expected_ips'] == source['expected_ips']
        assert shown['usage'] == 'example' and shown['complete_expected'] is True
        assert shown['excerpt'] == {'original_utf8_bytes': 1800,
                                   'prefix': source['data'][:192], 'suffix': source['data'][-64:],
                                   'omitted_utf8_bytes': 1544}
    assert sum(len(part.encode('utf-8')) for row in view['examples']
               for part in (row['excerpt']['prefix'], row['excerpt']['suffix'])) == 1024
    assert original == before
    view['examples'][0]['expected_ips'].append('203.0.113.1')
    view['examples'][0]['excerpt']['prefix'] = 'changed only in returned view'
    assert original == before


def test_projection_does_not_accept_an_oversized_original_after_compacting_it():
    from local_ai.contracts import AIError
    original = snapshot([example('\x00' * 1600)])
    with pytest.raises(AIError) as caught:
        api().project_examples(original)
    assert caught.value.code == 'too_large'


@pytest.mark.parametrize('original,code', [
    (None, 'source_unavailable'),
    ({**snapshot([example('192.0.2.1')]), 'version': True}, 'source_unavailable'),
    ({**snapshot([example('192.0.2.1')]), 'kind': 'delivery'}, 'source_unavailable'),
    (snapshot([example('192.0.2.1')], kind='unknown'), 'source_unavailable'),
    ({**snapshot([example('192.0.2.1')]), 'holdouts': ['must not be forwarded']}, 'source_unavailable'),
    (snapshot([{**example('192.0.2.1'), 'usage': 'validation'}]), 'source_unavailable'),
    (snapshot([example('\ud800')]), 'source_unavailable'),
    (snapshot([example('x' * 2049)]), 'too_large'),
    (snapshot([example('same'), example('same')]), 'source_unavailable'),
])
def test_projection_requires_a_closed_original_example_snapshot(original, code):
    from local_ai.contracts import AIError
    with pytest.raises(AIError) as caught:
        api().project_examples(original)
    assert caught.value.code == code


@pytest.mark.parametrize('limit', [1023, 1024, 1025])
def test_raw_boundary_and_short_example_message_bytes_are_preserved(limit):
    from local_ai.decoder import _bounded_json
    original = snapshot([dict(reversed(list(example('x' * limit).items())))])
    original = dict(reversed(list(original.items())))
    view = api().project_examples(original)
    if limit <= 1024:
        assert _bounded_json(view, 8192) == _bounded_json(original, 8192)
    else:
        assert 'data' not in view['examples'][0]
        assert view['examples'][0]['excerpt']['omitted_utf8_bytes'] == 1


@pytest.mark.parametrize('token', ['é', '한', '🙂', 'e\u0301', '"', '\\', '\n', '\x00', '<>&', '\u2028\u2029'])
def test_utf8_excerpts_preserve_scalar_boundaries_without_normalizing_or_joining(token):
    raw = token * (1300 // len(token.encode('utf-8')))
    view = api().project_examples(snapshot([example(raw)]))
    shown = view['examples'][0]['excerpt']
    assert raw.startswith(shown['prefix']) and raw.endswith(shown['suffix'])
    assert len(shown['prefix'].encode('utf-8')) <= 768
    assert len(shown['suffix'].encode('utf-8')) <= 256
    assert shown['omitted_utf8_bytes'] == len(raw.encode('utf-8')) - sum(
        len(shown[key].encode('utf-8')) for key in ('prefix', 'suffix'))
    assert '\ufffd' not in shown['prefix'] + shown['suffix']


def test_water_filling_keeps_short_rows_and_preserves_projected_duplicates():
    rows = [example('ok'), example('A' * 1600), example('A' * 800 + 'B' + 'A' * 799)]
    original = snapshot(rows)
    view = api().project_examples(original)
    assert view['examples'][0] == rows[0]
    assert len(view['examples']) == 3
    assert view['examples'][1]['excerpt']['prefix'] == view['examples'][2]['excerpt']['prefix']
    assert view['examples'][1]['excerpt']['suffix'] == view['examples'][2]['excerpt']['suffix']
    assert sum(len(row['data'].encode('utf-8')) if 'data' in row else
               len(row['excerpt']['prefix'].encode('utf-8')) + len(row['excerpt']['suffix'].encode('utf-8'))
               for row in view['examples']) == 1024


@pytest.mark.parametrize('meter', ['labels', 'metadata'])
def test_labels_and_view_metadata_have_separate_non_truncating_limits(monkeypatch, meter):
    from local_ai.contracts import AIError
    from local_ai.decoder import _bounded_json
    module = api()
    original = snapshot([example('x' * 1300, ['192.0.2.1', '198.51.100.24'])])
    view = module.project_examples(original)
    if meter == 'labels':
        value = [row['expected_ips'] for row in view['examples']]
        name = 'MAX_LABEL_BYTES'
    else:
        value = copy.deepcopy(view)
        for row in value['examples']:
            row['expected_ips'] = []
            if 'data' in row:
                row['data'] = ''
            else:
                row['excerpt']['prefix'] = row['excerpt']['suffix'] = ''
        name = 'MAX_VIEW_METADATA_BYTES'
    size = len(_bounded_json(value, 8192))
    monkeypatch.setattr(module, name, size, raising=False)
    assert module.project_examples(original) == view
    monkeypatch.setattr(module, name, size - 1)
    with pytest.raises(AIError) as caught:
        module.project_examples(original)
    assert caught.value.code == 'too_large'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def test_provenance_binds_original_snapshot_and_exact_checked_outgoing_bundle():
    from local_ai.contracts import decoder_schema
    from local_ai.engine import prompt
    original = snapshot([example('192.0.2.1|' + 'x' * 1500)])
    source_digest = hashlib.sha256(canonical(original)).hexdigest()
    view = api().project_examples(original)
    schema = decoder_schema('TXT', 'en', source_digest)
    messages = prompt(view, schema)
    checked = canonical({'messages': messages, 'schema': schema})
    result = api().build_model_input(original, source_digest, messages, schema, checked)
    assert set(result) == {'version', 'policy', 'source_snapshot_digest', 'view', 'coverage',
                           'messages_schema_bytes', 'messages_schema_digest'}
    assert result['version'] == 1 and result['policy'] == 'decoder_examples_utf8_v1'
    assert result['view'] == json.loads(messages[1]['content']) == view
    assert result['source_snapshot_digest'] == source_digest
    original_bytes = len(original['examples'][0]['data'].encode('utf-8'))
    assert result['coverage'] == {'original_utf8_bytes': original_bytes, 'shown_utf8_bytes': 1024,
                                  'omitted_utf8_bytes': original_bytes - 1024,
                                  'complete_examples': 0, 'excerpted_examples': 1}
    assert result['messages_schema_bytes'] == len(checked)
    assert result['messages_schema_digest'] == hashlib.sha256(checked).hexdigest()
    assert source_digest != hashlib.sha256(canonical(view)).hexdigest()
    messages[1]['content'] = 'caller mutation after custody ends'
    assert result['view'] == view


@pytest.mark.parametrize('mismatch', ['source_digest', 'checked_bytes', 'view_version', 'schema', 'message_role'])
def test_provenance_refuses_foreign_or_unchecked_input(mismatch):
    from local_ai.contracts import AIError, decoder_schema
    from local_ai.engine import prompt
    original = snapshot([example('192.0.2.1|' + 'x' * 1500)])
    source_digest = hashlib.sha256(canonical(original)).hexdigest()
    schema = decoder_schema('TXT', 'en', source_digest)
    messages = prompt(api().project_examples(original), schema)
    if mismatch == 'source_digest':
        source_digest = 'b' * 64
    elif mismatch == 'view_version':
        wrong = json.loads(messages[1]['content'])
        wrong['version'] = True
        messages[1]['content'] = canonical(wrong).decode('utf-8')
    elif mismatch == 'schema':
        schema['oneOf'][0]['properties']['snapshot_digest']['const'] = 'b' * 64
    elif mismatch == 'message_role':
        messages[0]['role'] = 'user'
    checked = canonical({'messages': messages, 'schema': schema})
    if mismatch == 'checked_bytes':
        checked += b' '
    with pytest.raises(AIError) as caught:
        api().build_model_input(original, source_digest, messages, schema, checked)
    assert caught.value.code == 'source_unavailable'
