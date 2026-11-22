"""Producer integration over real sources/verifier children, not native models."""
import copy
import hashlib
import json
import time

import pytest

import local_ai.decoder as decoder
import local_ai.engine as module
import local_ai.sources as sources
from local_ai.contracts import AIError
from local_ai.decoder_input import build_model_input, project_examples
from local_ai.provider import NativeReply
from test_local_ai_contracts import decoder_request
from test_local_ai_engine import empty_proposal_reply
from test_local_ai_sources import ACTOR, context


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def proposal_reply(messages, schema, steps):
    value = json.loads(empty_proposal_reply(messages, schema).content)
    value.update(candidates=[{'steps': steps}], insufficient_reason=None)
    return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64})


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_decoder_publishes_actual_checked_model_view_but_verifies_originals(monkeypatch, kind):
    ctx = context()
    steps = [{'op': 'extract_ip_prefix'}]
    ctx.shared_config['custom_decoders' if kind == 'TXT' else 'custom_a_decoders'] = [
        {'name': 'original_control', 'steps': steps}]
    samples = [
        {'data': '192.0.2.1 ' + 'x' * 1800, 'expected_ips': ['192.0.2.1'],
         'usage': 'example', 'complete_expected': True},
        {'data': '198.51.100.17 holdout', 'expected_ips': ['198.51.100.17'],
         'usage': 'validation', 'complete_expected': True},
    ]
    before = copy.deepcopy(samples)
    snapshot = {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': kind, 'examples': samples[:1]}
    verified, checked, calls = [], [], []
    real_pump, real_privacy = decoder._pump, module.secret_free

    def observe_worker(child, encoded, cutoff):
        verified.append(json.loads(encoded))
        return real_pump(child, encoded, cutoff)

    def observe_privacy(owner, value, deadline, **kwargs):
        encoded = real_privacy(owner, value, deadline, **kwargs)
        if set(value) == {'messages', 'schema'}:
            checked.append(encoded)
        return encoded

    monkeypatch.setattr(decoder, '_pump', observe_worker)
    monkeypatch.setattr(module, 'secret_free', observe_privacy)
    deadline = time.monotonic() + 15
    task = module.AssistantEngine(ctx, None).prepare(
        decoder_request(decoder_type=kind, samples=samples), {**ACTOR, 'role': 'admin'}, deadline)

    def generate(messages, schema):
        calls.append((copy.deepcopy(messages), copy.deepcopy(schema)))
        assert [row['mode'] for row in verified] == ['catalog']
        assert checked == [canonical({'messages': messages, 'schema': schema})]
        return proposal_reply(messages, schema, steps)

    try:
        result = json.loads(task.run(deadline, generate))
        assert len(calls) == 1
        messages, schema = calls[0]
        assert json.loads(messages[1]['content']) == project_examples(snapshot)
        assert result['snapshot'] == snapshot
        assert result['snapshot_digest'] == hashlib.sha256(canonical(snapshot)).hexdigest()
        assert result['model_input'] == build_model_input(snapshot, result['snapshot_digest'], messages, schema, checked[0])
        assert result['model_input']['coverage']['omitted_utf8_bytes'] > 0
        assert result['model_input']['messages_schema_bytes'] == len(checked[0])
        assert result['model_input']['messages_schema_digest'] == hashlib.sha256(checked[0]).hexdigest()
        for forbidden in ('198.51.100.17', 'holdout', 'original_control', 'matched_ips'):
            assert forbidden not in canonical({'messages': messages, 'schema': schema}).decode()
        assert [row['mode'] for row in verified] == ['catalog', 'generated']
        assert all(row['samples'] == before for row in verified)
        existing = next(c for c in result['catalog']['candidates'] if c['name'] == 'original_control')
        generated = result['generated']['candidates'][0]
        for candidate in (existing, generated):
            assert candidate['examples']['results'][0]['passed'] is True
            assert candidate['validation']['results'][0]['passed'] is True
            assert candidate['validation']['results'][0]['sample_index'] == 1
        assert samples == before
        with pytest.raises(AIError, match='invalid_request'):
            task.run(deadline, generate)
        assert len(calls) == 1 and len(checked) == 1
        assert decoder._active_child is None
    finally:
        task.dispose()


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_catalog_only_explicitly_has_no_model_input(kind):
    deadline = time.monotonic() + 15
    task = module.AssistantEngine(context(), None).prepare(
        decoder_request(decoder_type=kind, generate=False), {**ACTOR, 'role': 'admin'}, deadline)
    try:
        result = json.loads(task.run(deadline, lambda *a: pytest.fail('catalog-only generation')))
        assert 'model_input' in result and result['model_input'] is None
        assert result['model'] is result['proposal'] is result['generated'] is None
    finally:
        task.dispose()


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_excerpt_prompt_marks_separate_incomplete_data_and_original_labels(kind):
    from local_ai.contracts import decoder_schema
    row = {'data': '192.0.2.1 ' + 'x' * 1800, 'expected_ips': ['192.0.2.1'],
           'usage': 'example', 'complete_expected': True}
    snapshot = {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': kind, 'examples': [row]}
    schema = decoder_schema(kind, 'en', hashlib.sha256(canonical(snapshot)).hexdigest())
    view = project_examples(snapshot)
    messages = module.prompt(view, schema)
    for phrase in ('prefix and suffix', 'separate retained parts', 'omitted middle',
                   'complete original sample', 'Do not concatenate', 'return no candidates'):
        assert phrase in messages[0]['content']
    assert json.loads(messages[1]['content']) == view
    assert json.loads(messages[0]['content'].split('\nDecoder DSL semantics: ', 1)[1])['initial_type'] == 'text'
    short = copy.deepcopy(snapshot)
    short['examples'][0]['data'] = '192.0.2.1'
    assert module.prompt(project_examples(short), schema) == module.prompt(short, schema)


@pytest.fixture(params=[('relationship_pair', 'en'), ('relationship_pair', 'ko'),
                       ('delivery', 'en'), ('delivery', 'ko')])
def explanation_task(request, tmp_path, monkeypatch):
    from test_local_ai_sources import original_job
    from test_stage3_core_runtime import app_factory
    kind, language = request.param
    ctx, app, jobs = context(), None, None
    body = {'kind': kind, 'language': language}
    if kind == 'relationship_pair':
        jobs, body['source'], _ = original_job(monkeypatch, ctx)
    else:
        monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings.json'))
        app = app_factory(tmp_path / 'ledger')
        ctx.shared_config, ctx.config_lock = app.cfg.raw, app.cfg.lock
        ctx.delivery_diagnostics = app.delivery.store.diagnostics_snapshot
        ctx.delivery_health = app.delivery.health_snapshot
    task = None
    try:
        deadline = time.monotonic() + 15
        task = module.AssistantEngine(ctx, jobs).prepare(body, ACTOR, deadline)
        yield task, ctx, deadline, language
    finally:
        if task is not None:
            task.dispose()
        monkeypatch.undo()
        if app is not None:
            app.delivery.stop()


def test_explanation_keeps_model_prose_and_separate_bound_server_facts(explanation_task):
    from local_ai.facts_summary import build_summary
    from test_local_ai_engine import explanation_reply
    task, ctx, deadline, language = explanation_task
    calls = []
    def reply(messages, schema):
        result = explanation_reply(messages, schema)
        calls.append((json.loads(messages[1]['content']), json.loads(result.content)))
        return result
    result = json.loads(task.run(deadline, reply))
    assert len(calls) == 1
    assert set(result) == {'snapshot', 'snapshot_digest', 'source_revision', 'model', 'interpretation', 'facts_summary'}
    assert result['facts_summary'] == build_summary(result['snapshot'], language, result['snapshot_digest'])
    assert result['snapshot'] == calls[0][0], 'do not double model input with the server summary'
    assert result['interpretation'] == calls[0][1] and result['interpretation']['version'] == 1
    assert result['snapshot_digest'] == hashlib.sha256(canonical(result['snapshot'])).hexdigest()


@pytest.mark.parametrize('fault,code', [('provider', 'provider_failed'), ('invalid', 'invalid_model_output'),
                                     ('revoked', 'source_revoked'), ('late', 'deadline_exceeded')])
def test_server_summary_never_becomes_fallback_after_failure(explanation_task, monkeypatch, fault, code):
    from types import SimpleNamespace
    from test_local_ai_engine import explanation_reply
    task, ctx, deadline, _ = explanation_task
    summaries, calls = [], []
    actual = module.build_summary
    def summary(*args):
        value = actual(*args)
        summaries.append(copy.deepcopy(value))
        return value
    monkeypatch.setattr(module, 'build_summary', summary)
    def reply(messages, schema):
        calls.append(True)
        assert len(summaries) == 1
        if fault == 'provider':
            raise AIError(code)
        if fault == 'invalid':
            return NativeReply('{}', {'model': 'fixture:local', 'model_digest': 'c' * 64})
        if fault == 'revoked':
            ctx.read_model.invalidate(hard=True)
        else:
            monkeypatch.setattr(sources, 'time', SimpleNamespace(monotonic=lambda: deadline, time=time.time))
        return explanation_reply(messages, schema)
    with pytest.raises(AIError, match='^' + code + '$'):
        task.run(deadline, reply)
    assert len(summaries) == len(calls) == 1


def test_summary_generation_failure_never_dispatches(explanation_task, monkeypatch):
    task, ctx, deadline, _ = explanation_task
    def fail_summary(*args):
        raise AIError('too_large')
    monkeypatch.setattr(module, 'build_summary', fail_summary)
    with pytest.raises(AIError, match='^too_large$'):
        task.run(deadline, lambda *a: pytest.fail('invalid summary dispatched'))


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_omitted_middle_still_gets_original_privacy_admission(kind):
    ctx = context()
    secret = 'EXAMPLE-MIDDLE-ONLY-CANARY'
    ctx.shared_config['api_key'] = secret
    samples = [{'data': '192.0.2.1 ' + 'x' * 900 + secret + 'x' * 900,
                'expected_ips': ['192.0.2.1'], 'usage': 'example', 'complete_expected': True}]
    snapshot = {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': kind, 'examples': samples}
    assert secret not in canonical(project_examples(snapshot)).decode()
    with pytest.raises(AIError, match='^sensitive_input$'):
        module.AssistantEngine(ctx, None).prepare(
            decoder_request(decoder_type=kind, samples=samples), {**ACTOR, 'role': 'admin'}, time.monotonic() + 15)
    assert decoder._active_child is None


def test_provenance_refuses_bytes_different_from_checked_outgoing_bundle(monkeypatch):
    actual = module.secret_free
    def changed(ctx, value, deadline, **kwargs):
        encoded = actual(ctx, value, deadline, **kwargs)
        return encoded + b' ' if set(value) == {'messages', 'schema'} else encoded
    monkeypatch.setattr(module, 'secret_free', changed)
    deadline = time.monotonic() + 15
    task = module.AssistantEngine(context(), None).prepare(decoder_request(), {**ACTOR, 'role': 'admin'}, deadline)
    try:
        with pytest.raises(AIError, match='^source_unavailable$'):
            task.run(deadline, lambda *a: pytest.fail('unbound provenance dispatched'))
    finally:
        task.dispose()
