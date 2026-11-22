"""Pure producer sidecars for caller-supplied component fixtures, never app receipts.

CLI stdin: {"snapshots": {name: snapshot}, "decoder_snapshots": {name: snapshot}}.
The controlled messages below establish fixture byte commitments only; they are
not a claim that an application dispatched or a model attended to these bytes.
"""
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_ai.contracts import decoder_schema
from local_ai.decoder_input import build_model_input, project_examples
from local_ai.facts_summary import build_summary


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decoder_presentation(snapshot, language):
    commitment = digest(snapshot)
    view = project_examples(snapshot)
    messages = [
        {'role': 'system', 'content': 'Controlled component fixture. Prefix and suffix '
         'are separate excerpts with an omitted middle, not complete samples.'},
        {'role': 'user', 'content': canonical(view).decode('utf-8')},
    ]
    schema = decoder_schema(snapshot['decoder_type'], language, commitment)
    checked = canonical({'messages': messages, 'schema': schema})
    return {'snapshot_digest': commitment,
            'model_input': build_model_input(snapshot, commitment, messages, schema, checked),
            'checked_bundle': checked.decode('utf-8')}


def build_fixtures(cases):
    """Do not repair source cases or hand-author summary/custody lookalikes."""
    return {
        'facts_summary': {name: {language: build_summary(snapshot, language, digest(snapshot))
                                for language in ('en', 'ko')}
                          for name, snapshot in cases.get('snapshots', {}).items()},
        'decoder': {name: {language: decoder_presentation(snapshot, language)
                           for language in ('en', 'ko')}
                    for name, snapshot in cases.get('decoder_snapshots', {}).items()},
    }

def decoder_result(rows, language='en', generate=True, kind='TXT'):
    from local_ai.decoder import capture_catalog, evaluate_catalog, evaluate_generated
    from local_ai.sources import capture_decoder
    from test_local_ai_sources import context

    request = {'kind': 'decoder_suggest', 'decoder_type': kind, 'samples': rows,
               'language': language, 'generate': generate}
    lease, encoded, _ = capture_decoder(context(), request, time.monotonic() + 10)
    try:
        snapshot = json.loads(encoded)
    finally:
        lease.dispose()
    data = build_fixtures({'decoder_snapshots': {'case': snapshot}})['decoder']['case'][language]
    result = {'snapshot': snapshot, 'snapshot_digest': data['snapshot_digest'], 'source_revision': 7,
              'model': {'model': 'controlled-fixture', 'model_digest': 'c' * 64} if generate else None,
              'model_input': data['model_input'] if generate else None,
              'catalog': evaluate_catalog(kind, capture_catalog({}, kind), rows, time.monotonic() + 30),
              'generated': evaluate_generated(kind, [], rows, time.monotonic() + 30) if generate else None,
              'proposal': {'version': 1, 'kind': 'decoder_suggest', 'language': language,
                  'snapshot_digest': data['snapshot_digest'], 'candidates': [],
                  'insufficient_reason': 'no_candidate'} if generate else None}
    return request, result


def sample(data, usage='example'):
    return {'data': data, 'expected_ips': ['192.0.2.1'], 'complete_expected': True, 'usage': usage}


if __name__ == '__main__':
    sys.stdout.buffer.write(canonical(build_fixtures(json.load(sys.stdin))) + b'\n')
