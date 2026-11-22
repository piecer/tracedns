"""Deterministic model-only decoder excerpts; never verifier input."""
import copy
import hashlib
import json

from local_ai.contracts import AIError, decoder_schema, parse_object
from local_ai.decoder import DecoderError, _bounded_json, validate_samples

MAX_MODEL_DATA_BYTES = 1024
MAX_SOURCE_BYTES = 8192
MAX_LABEL_BYTES = 1024
MAX_VIEW_METADATA_BYTES = 1024
MAX_MESSAGES_SCHEMA_BYTES = 16384
MAX_MODEL_INPUT_BYTES = 10240
MAX_INPUT_METADATA_BYTES = 2048
POLICY = 'decoder_examples_utf8_v1'


def _validate_snapshot(snapshot):
    if (type(snapshot) is not dict or len(snapshot) != 4
            or set(snapshot) != {'version', 'kind', 'decoder_type', 'examples'}
            or type(snapshot['version']) is not int or snapshot['version'] != 1
            or snapshot['kind'] != 'decoder_suggest'
            or type(snapshot['decoder_type']) is not str or snapshot['decoder_type'] not in ('TXT', 'A')):
        raise AIError('source_unavailable')
    try:
        rows = validate_samples(snapshot['examples'])
        if any(row['usage'] != 'example' for row in rows):
            raise AIError('source_unavailable')
        _bounded_json(snapshot, MAX_SOURCE_BYTES)
    except DecoderError as exc:
        raise AIError('too_large' if exc.code == 'too_large' else 'source_unavailable') from None


def _meter(value, limit):
    try:
        return _bounded_json(value, limit)
    except DecoderError as exc:
        raise AIError('too_large' if exc.code == 'too_large' else 'source_unavailable') from None


def _blank_view(view):
    blank = copy.deepcopy(view)
    for row in blank['examples']:
        row['expected_ips'] = []
        if 'data' in row:
            row['data'] = ''
        else:
            row['excerpt']['prefix'] = row['excerpt']['suffix'] = ''
    return blank


def project_examples(snapshot):
    """Keep example order and labels; never join separate excerpt segments."""
    _validate_snapshot(snapshot)
    data = [row['data'].encode('utf-8') for row in snapshot['examples']]
    quotas = [0] * len(data)
    remaining = min(sum(map(len, data)), MAX_MODEL_DATA_BYTES)
    while remaining:
        for index, raw in enumerate(data):
            if quotas[index] < len(raw):
                quotas[index] += 1
                remaining -= 1
                if not remaining:
                    break
    view = copy.deepcopy(snapshot)
    for row, raw, quota in zip(view['examples'], data, quotas):
        if len(raw) <= quota:
            continue
        prefix_limit, suffix_limit = (3 * quota + 3) // 4, quota // 4
        prefix = raw[:prefix_limit].decode('utf-8', errors='ignore')
        suffix = raw[-suffix_limit:].decode('utf-8', errors='ignore') if suffix_limit else ''
        del row['data']
        row['excerpt'] = {'original_utf8_bytes': len(raw), 'prefix': prefix, 'suffix': suffix,
                          'omitted_utf8_bytes': len(raw) - len(prefix.encode('utf-8')) - len(suffix.encode('utf-8'))}
    _meter(view, MAX_SOURCE_BYTES)
    _meter([row['expected_ips'] for row in view['examples']], MAX_LABEL_BYTES)
    _meter(_blank_view(view), MAX_VIEW_METADATA_BYTES)
    return view


def _canonical(value, limit):
    _meter(value, limit)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def build_model_input(snapshot, snapshot_digest, messages, schema, checked_bundle):
    """Describe the actual privacy-approved bundle, never a reconstructed claim.

    The caller retains the same messages/schema through its one dispatch. This
    commitment excludes provider options, packet framing and model attention.
    """
    view = project_examples(snapshot)
    source_bytes = _canonical(snapshot, MAX_SOURCE_BYTES)
    if type(snapshot_digest) is not str or hashlib.sha256(source_bytes).hexdigest() != snapshot_digest:
        raise AIError('source_unavailable')
    if type(checked_bundle) is not bytes:
        raise AIError('source_unavailable')
    if len(checked_bundle) > MAX_MESSAGES_SCHEMA_BYTES:
        raise AIError('too_large')
    actual = _canonical({'messages': messages, 'schema': schema}, MAX_MESSAGES_SCHEMA_BYTES)
    if actual != checked_bundle:
        raise AIError('source_unavailable')
    if (type(messages) is not list or len(messages) != 2
            or any(type(row) is not dict or set(row) != {'role', 'content'}
                   or row['role'] != role or type(row['content']) is not str
                   for row, role in zip(messages, ('system', 'user')))):
        raise AIError('source_unavailable')
    submitted = parse_object(messages[1]['content'].encode('utf-8'), limit=MAX_SOURCE_BYTES,
                             code='source_unavailable')
    # Canonical bytes distinguish booleans from integers, unlike dict equality.
    if _canonical(submitted, MAX_SOURCE_BYTES) != _canonical(view, MAX_SOURCE_BYTES):
        raise AIError('source_unavailable')
    try:
        language = schema['oneOf'][0]['properties']['language']['const']
    except (KeyError, TypeError, IndexError):
        raise AIError('source_unavailable') from None
    expected_schema = decoder_schema(snapshot['decoder_type'], language, snapshot_digest)
    if _canonical(schema, MAX_MESSAGES_SCHEMA_BYTES) != _canonical(expected_schema, MAX_MESSAGES_SCHEMA_BYTES):
        raise AIError('source_unavailable')
    original = sum(len(row['data'].encode('utf-8')) for row in snapshot['examples'])
    shown = sum(len(row['data'].encode('utf-8')) if 'data' in row else
                len(row['excerpt']['prefix'].encode('utf-8')) + len(row['excerpt']['suffix'].encode('utf-8'))
                for row in view['examples'])
    complete = sum('data' in row for row in view['examples'])
    result = {'version': 1, 'policy': POLICY, 'source_snapshot_digest': snapshot_digest, 'view': view,
              'coverage': {'original_utf8_bytes': original, 'shown_utf8_bytes': shown,
                           'omitted_utf8_bytes': original - shown, 'complete_examples': complete,
                           'excerpted_examples': len(view['examples']) - complete},
              'messages_schema_bytes': len(checked_bundle),
              'messages_schema_digest': hashlib.sha256(checked_bundle).hexdigest()}
    _meter(result, MAX_MODEL_INPUT_BYTES)
    metadata = {**result, 'view': _blank_view(view)}
    _meter(metadata, MAX_INPUT_METADATA_BYTES)
    return result
