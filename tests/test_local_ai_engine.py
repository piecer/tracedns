"""Real cached producers/verifiers with controlled native replies, never models."""
import copy
import hashlib
import importlib
import importlib.util
import json
import time

import pytest

from local_ai.contracts import AIError
from local_ai.provider import NativeReply
from test_local_ai_sources import ACTOR, context, original_job


def engine(ctx, jobs=None):
    assert importlib.util.find_spec('local_ai.engine') is not None, 'task engine missing'
    module = importlib.import_module('local_ai.engine')
    return module.AssistantEngine(ctx, jobs)


def explanation_reply(messages, schema):
    props = schema['properties']
    value = {key: props[key]['const'] for key in ('version', 'kind', 'language', 'snapshot_digest')}
    value.update(summary=[{'text': 'Inspect the retained evidence; this is not attribution.',
                           'evidence_ids': ['e1']}], counterpoints=[], limitations=[], next_checks=[])
    return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64,
                                         'eval_count': (1 << 63) - 1})


def test_pair_explanation_uses_real_original_result_without_enrichment_or_mutation(monkeypatch):
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    original = copy.deepcopy(jobs.jobs[selector['job_id']]['result'])
    config = copy.deepcopy(ctx.shared_config)
    deadline = time.monotonic() + 10
    prepared = engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en',
                                         'source': selector}, ACTOR, deadline)
    assert 0 < prepared.retained_bytes <= 65536
    calls = []
    def generate(messages, schema):
        calls.append((messages, schema))
        return explanation_reply(messages, schema)
    prepared.check(deadline)
    encoded = prepared.run(deadline, generate)
    assert type(encoded) is bytes and len(encoded) <= 32768
    result = json.loads(encoded)
    assert result['source_revision'] == 7
    assert result['interpretation']['snapshot_digest'] == result['snapshot_digest']
    canonical = json.dumps(result['snapshot'], ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    assert result['snapshot_digest'] == hashlib.sha256(canonical).hexdigest()
    assert 'origin_independence_unknown' in result['snapshot']['warnings']
    assert result['model']['eval_count'] == str((1 << 63) - 1)
    assert len(calls) == 1
    assert jobs.jobs[selector['job_id']]['result'] == original
    assert ctx.shared_config == config
    prepared.dispose()
    prepared.dispose()
    assert prepared.retained_bytes == 0
    with pytest.raises(AIError, match='source_revoked'):
        prepared.check(deadline)


def test_delivery_reads_actual_caches_once_and_keeps_historical_freshness(tmp_path, monkeypatch):
    from test_stage3_core_runtime import app_factory
    app = app_factory(tmp_path / 'ledger')
    ctx = context()
    ctx.shared_config, ctx.config_lock = app.cfg.raw, app.cfg.lock
    reads = []
    def diagnostics():
        reads.append('diagnostics')
        return app.delivery.store.diagnostics_snapshot()
    def health(**kwargs):
        assert kwargs == {'include_progress': True}
        reads.append('progress')
        return app.delivery.health_snapshot(**kwargs)
    ctx.delivery_diagnostics, ctx.delivery_health = diagnostics, health
    try:
        def forbidden(*args, **kwargs):
            pytest.fail('AI performed ledger/provider/config work')
        monkeypatch.setattr(app.delivery.store, '_one', forbidden)
        monkeypatch.setattr(app.service, 'commit', forbidden)
        monkeypatch.setattr(app.repo, 'capture', forbidden)
        deadline = time.monotonic() + 10
        task = engine(ctx).prepare({'kind': 'delivery', 'language': 'ko'}, ACTOR, deadline)
        assert reads == ['diagnostics', 'progress']
        # Ordinary monitor refresh is not hard revocation of this historical read.
        ctx.read_model.invalidate(hard=False)
        result = json.loads(task.run(deadline, explanation_reply))
        assert reads == ['diagnostics', 'progress']
        assert result['snapshot']['kind'] == 'delivery'
        assert 'snapshots_not_atomic' in result['snapshot']['warnings']
        values = {fact['key']: fact['value'] for fact in result['snapshot']['facts']}
        assert values['progress_lookup']['coverage'] == 'unknown'
        assert result['snapshot']['source']['diagnostics_observed_at']
        task.check(deadline)
        ctx.read_model.invalidate(hard=True)
        with pytest.raises(AIError, match='source_revoked'):
            task.check(deadline)
        task.dispose()
    finally:
        monkeypatch.undo()
        app.delivery.stop()


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_decoder_catalog_only_runs_real_factories_with_independent_holdout(kind):
    from test_local_ai_contracts import decoder_request
    ctx = context()
    key = 'custom_decoders' if kind == 'TXT' else 'custom_a_decoders'
    ctx.shared_config[key] = [{'name': 'fixture_ascii', 'steps': [{'op': 'ascii'}]}]
    samples = [
        {'data': '192.0.2.1', 'expected_ips': ['192.0.2.1'], 'usage': 'example', 'complete_expected': True},
        {'data': '198.51.100.17', 'expected_ips': ['198.51.100.17'], 'usage': 'validation', 'complete_expected': True},
    ]
    request = decoder_request(decoder_type=kind, samples=samples, generate=False)
    before = copy.deepcopy(ctx.shared_config)
    deadline = time.monotonic() + 15
    task = engine(ctx).prepare(request, {**ACTOR, 'role': 'admin'}, deadline)
    result = json.loads(task.run(deadline, lambda *args: pytest.fail('catalog-only model call')))
    assert result['model'] is None and result['generated'] is None and result['proposal'] is None
    report = result['catalog']
    candidate = next(c for c in report['candidates'] if c['name'] == 'fixture_ascii')
    assert report['complete'] is True and report['ranking_basis'] == 'examples_only'
    assert candidate['examples']['results'][0]['matched_ips'] == ['192.0.2.1']
    assert candidate['validation']['results'][0]['matched_ips'] == ['198.51.100.17']
    assert candidate['validation']['results'][0]['sample_index'] == 1
    assert ctx.shared_config == before
    assert '198.51.100.17' not in json.dumps(result['snapshot'])
    task.dispose()


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_explicit_generation_verifies_catalog_then_fixed_candidate_without_holdout_feedback(kind, monkeypatch):
    import base64
    from test_local_ai_contracts import decoder_request
    ctx = context()
    key = 'custom_decoders' if kind == 'TXT' else 'custom_a_decoders'
    steps = [{'op': 'base64'}, {'op': 'ascii'}]
    ctx.shared_config[key] = [{'name': 'fixture_existing', 'steps': steps}]
    samples = [{'data': base64.b64encode(ip.encode()).decode(), 'expected_ips': [ip],
                'usage': usage, 'complete_expected': True}
               for ip, usage in [('192.0.2.1', 'example'), ('198.51.100.17', 'validation')]]
    deadline = time.monotonic() + 15
    owner = engine(ctx)
    module = importlib.import_module('local_ai.engine')
    actual_evaluate = module.evaluate_catalog
    reports = []
    def observe(*args):
        report = actual_evaluate(*args)
        reports.append(report)
        return report
    monkeypatch.setattr(module, 'evaluate_catalog', observe)
    task = owner.prepare(decoder_request(decoder_type=kind, samples=samples), {**ACTOR, 'role': 'admin'}, deadline)
    calls = []
    def generate(messages, schema):
        calls.append(True)
        assert len(reports) == 1 and reports[0]['complete']
        existing = next(c for c in reports[0]['candidates'] if c['name'] == 'fixture_existing')
        assert existing['examples']['results'][0]['passed'], 'explicit generation applies despite catalog matches'
        sent = json.dumps([messages, schema])
        for forbidden in (samples[1]['data'], samples[1]['expected_ips'][0], 'matched_ips',
                          'ranking_basis', 'fixture_existing', 'sample_index'):
            assert forbidden not in sent
        props = schema['properties']
        value = {k: props[k]['const'] for k in ('version', 'kind', 'language', 'snapshot_digest')}
        value.update(candidates=[{'steps': steps}], insufficient_reason=None)
        import jsonschema
        jsonschema.Draft202012Validator(schema).validate(value)
        return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64})
    result = json.loads(task.run(deadline, generate))
    assert calls == [True]
    assert result['proposal']['candidates'] == [{'steps': steps}]
    generated = result['generated']
    assert generated['complete'] and generated['ranking_basis'] == 'fixed_generation_order'
    assert generated['candidates'][0]['examples']['results'][0]['passed']
    assert generated['candidates'][0]['validation']['results'][0]['passed']
    assert generated['candidates'][0]['validation']['results'][0]['sample_index'] == 1
    assert result['model']['model'] == 'fixture:local'
    task.dispose()


def empty_proposal_reply(messages, schema):
    props = schema['properties']
    value = {k: props[k]['const'] for k in ('version', 'kind', 'language', 'snapshot_digest')}
    value.update(candidates=[], insufficient_reason='unsupported_transformation')
    return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64})


def test_generation_snapshot_exact_and_plus_one_bytes_are_not_truncated():
    from test_local_ai_contracts import decoder_request
    rows = [{'data': str(i) + 'x' * 2047, 'expected_ips': ['192.0.2.1'],
             'usage': 'example', 'complete_expected': True} for i in range(4)]
    snapshot = {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': 'A', 'examples': rows}
    size = len(json.dumps(snapshot, ensure_ascii=False, separators=(',', ':')).encode())
    rows[-1]['data'] = rows[-1]['data'][:2048 - (size - 8192)]
    assert len(json.dumps(snapshot, separators=(',', ':')).encode()) == 8192
    ctx = context()
    deadline = time.monotonic() + 15
    task = engine(ctx).prepare(decoder_request(decoder_type='A', samples=rows), {**ACTOR, 'role': 'admin'}, deadline)
    seen = []
    def reply(messages, schema):
        seen.append(json.loads(messages[1]['content']))
        return empty_proposal_reply(messages, schema)
    result = json.loads(task.run(deadline, reply))
    assert seen == [snapshot] and result['snapshot'] == snapshot
    task.dispose()
    rows[-1]['data'] += 'x'
    with pytest.raises(AIError) as refused:
        engine(ctx).prepare(decoder_request(decoder_type='A', samples=rows), {**ACTOR, 'role': 'admin'}, deadline)
    assert refused.value.code == 'too_large'


def test_complete_result_exact_and_plus_one_refuses_without_dropping_catalog():
    from test_local_ai_contracts import decoder_request
    ctx = context()
    def run(name):
        ctx.shared_config['custom_a_decoders'] = [{'name': name, 'steps': [{'op': 'ascii'}]}]
        deadline = time.monotonic() + 15
        task = engine(ctx).prepare(decoder_request(decoder_type='A', generate=False), {**ACTOR, 'role': 'admin'}, deadline)
        try:
            return task.run(deadline, lambda *a: pytest.fail('unexpected model'))
        finally:
            task.dispose()
    baseline = run('x')
    target = 1 + 32768 - len(baseline)
    exact = run('x' * target)
    assert len(exact) == 32768
    assert len(json.loads(exact)['catalog']['candidates']) == len(json.loads(baseline)['catalog']['candidates'])
    with pytest.raises(AIError, match='too_large'):
        run('x' * (target + 1))


def test_pair_privacy_refuses_configured_secret_before_projection_digest(monkeypatch):
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    ctx.shared_config['api_key'] = selector['a']
    digests = []
    real_hash = hashlib.sha256
    def digest(data=b'', **kwargs):
        if data:
            digests.append(data)
        return real_hash(data, **kwargs)
    monkeypatch.setattr(hashlib, 'sha256', digest)
    with pytest.raises(AIError, match='sensitive_input'):
        engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en', 'source': selector},
                                  ACTOR, time.monotonic() + 10)
    assert not digests


def test_model_result_is_secret_checked_before_publication(monkeypatch):
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    ctx.shared_config['api_key'] = 'PRIVATE-RESULT-CANARY'
    deadline = time.monotonic() + 10
    task = engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en', 'source': selector}, ACTOR, deadline)
    def reply(messages, schema):
        value = json.loads(explanation_reply(messages, schema).content)
        value['summary'][0]['text'] = 'PRIVATE-RESULT-CANARY'
        return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64})
    with pytest.raises(AIError, match='sensitive_input'):
        task.run(deadline, reply)
    task.dispose()


@pytest.mark.parametrize('metadata', [
    {'model': 'fixture:local', 'model_digest': 'c' * 64, 'provider_url': 'http://private.invalid'},
    {'model': 'fixture:local', 'model_digest': 'c' * 64, 'eval_count': True},
    {'model': 'fixture:local', 'model_digest': 'c' * 64, 'eval_count': 1 << 63},
    {'model': 'fixture:local', 'model_digest': 'c' * 64, 'total_duration': -1},
    {'model': 'fixture:local', 'model_digest': 'c' * 64, 'done_reason': 'PRIVATE-EXCEPTION'},
    {'model': 'fixture:local', 'model_digest': 'C' * 64},
    {'model': 'x' * 257, 'model_digest': 'c' * 64},
])
def test_native_metadata_remains_closed_even_for_controlled_replies(monkeypatch, metadata):
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    deadline = time.monotonic() + 10
    task = engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en', 'source': selector}, ACTOR, deadline)
    def reply(messages, schema):
        return NativeReply(explanation_reply(messages, schema).content, metadata)
    with pytest.raises(AIError, match='invalid_model_output'):
        task.run(deadline, reply)
    task.dispose()


@pytest.mark.parametrize('stage', ['catalog', 'prompt', 'native', 'validation', 'generated', 'encoding', 'privacy'])
def test_original_deadline_fences_late_stages_without_extending_or_publishing(monkeypatch, stage):
    from types import SimpleNamespace
    from test_local_ai_contracts import decoder_request
    import local_ai.sources as source_module
    owner = engine(context())
    module = importlib.import_module('local_ai.engine')
    deadline = time.monotonic() + 15
    clock = [time.monotonic()]
    task = owner.prepare(decoder_request(decoder_type='A'), {**ACTOR, 'role': 'admin'}, deadline)
    monkeypatch.setattr(source_module, 'time', SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    calls = []
    def reply(messages, schema):
        calls.append(True)
        value = empty_proposal_reply(messages, schema)
        if stage == 'native':
            clock[0] = deadline
        return value
    target = {'catalog': 'evaluate_catalog', 'prompt': 'prompt', 'validation': 'validate_decoder',
              'generated': 'evaluate_generated', 'encoding': 'bounded_json', 'privacy': 'secret_free'}.get(stage)
    if target:
        original = getattr(module, target)
        def late(*args, **kwargs):
            result = original(*args, **kwargs)
            if target != 'bounded_json' or args[1] == 32768:
                if target != 'secret_free' or kwargs.get('max_bytes') == 32768:
                    clock[0] = deadline
            return result
        monkeypatch.setattr(module, target, late)
    # A caller-supplied larger deadline cannot reset the original admission clock.
    with pytest.raises(AIError, match='deadline_exceeded'):
        task.run(deadline + 1000, reply)
    assert len(calls) == (0 if stage in ('catalog', 'prompt') else 1)
    task.dispose()


def test_dispose_during_native_reply_cannot_publish_or_retain_inputs(monkeypatch):
    import threading
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    deadline = time.monotonic() + 10
    task = engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en', 'source': selector}, ACTOR, deadline)
    entered, release = threading.Event(), threading.Event()
    outcomes = []
    def reply(messages, schema):
        value = explanation_reply(messages, schema)
        entered.set()
        assert release.wait(3)
        return value
    def run():
        try:
            outcomes.append(task.run(deadline, reply))
        except AIError as exc:
            outcomes.append(exc.code)
    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(2)
        task.dispose()
        assert task.retained_bytes == 0
        assert task._payload is None and task._lease is None and task._ctx is None
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and outcomes == ['source_revoked']
    with pytest.raises(AIError, match='source_revoked'):
        task.run(deadline, lambda *a: pytest.fail('disposed task restarted'))


@pytest.mark.parametrize('deadline', [None, object(), True, float('nan'), float('inf')])
def test_task_checks_reject_invalid_deadlines_with_fixed_errors(monkeypatch, deadline):
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    task = engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en', 'source': selector},
                                     ACTOR, time.monotonic() + 10)
    with pytest.raises(AIError, match='invalid_request'):
        task.check(deadline)
    task.dispose()


def test_unexpected_generate_exception_never_becomes_public_or_log_prose(monkeypatch, caplog):
    ctx = context()
    jobs, selector, _ = original_job(monkeypatch, ctx)
    deadline = time.monotonic() + 10
    task = engine(ctx, jobs).prepare({'kind': 'relationship_pair', 'language': 'en', 'source': selector}, ACTOR, deadline)
    def fail(*args):
        raise RuntimeError('PRIVATE-CALLBACK-ERROR')
    with pytest.raises(AIError, match='provider_failed') as refused:
        task.run(deadline, fail)
    assert refused.value.__context__ is None
    assert 'PRIVATE-CALLBACK-ERROR' not in caplog.text
    task.dispose()


@pytest.mark.parametrize('field', ['delivery_diagnostics', 'delivery_health'])
def test_replaced_cached_delivery_owner_revokes_existing_task(tmp_path, field):
    from test_stage3_core_runtime import app_factory
    app = app_factory(tmp_path / 'ledger')
    ctx = context()
    ctx.delivery_diagnostics = app.delivery.store.diagnostics_snapshot
    ctx.delivery_health = app.delivery.health_snapshot
    try:
        deadline = time.monotonic() + 10
        task = engine(ctx).prepare({'kind': 'delivery', 'language': 'en'}, ACTOR, deadline)
        setattr(ctx, field, lambda **kwargs: pytest.fail('replacement source must not be read'))
        with pytest.raises(AIError, match='source_revoked'):
            task.run(deadline, lambda *a: pytest.fail('revoked delivery dispatched'))
        task.dispose()
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('change', ['preflight-extra-key', 'empty-with-null', 'nonempty-with-reason', 'content-rejected'])
def test_rejected_native_candidate_never_reaches_generated_verifier(monkeypatch, change):
    from test_local_ai_contracts import decoder_request, proposal
    deadline = time.monotonic() + 15
    task = engine(context()).prepare(decoder_request(), {**ACTOR, 'role': 'admin'}, deadline)
    module = importlib.import_module('local_ai.engine')
    monkeypatch.setattr(module, 'evaluate_generated', lambda *a: pytest.fail('invalid candidate was verified'))
    def reply(messages, schema):
        if change == 'content-rejected':
            return NativeReply(None, {'model': 'fixture:local', 'model_digest': 'c' * 64}, 'too_large')
        value = proposal(snapshot_digest=schema['properties']['snapshot_digest']['const'])
        if change == 'preflight-extra-key':
            value['candidates'][0]['steps'] = [{'op': 'base64', 'key': ''}, {'op': 'ascii', 'key': ''}]
        elif change == 'empty-with-null':
            value['candidates'] = []
        else:
            value['insufficient_reason'] = 'no_candidate'
        return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64})
    with pytest.raises(AIError, match='invalid_model_output'):
        task.run(deadline, reply)
    task.dispose()


def test_real_incomplete_catalog_verification_never_calls_model():
    from test_local_ai_contracts import decoder_request
    import local_ai.decoder as decoder
    ctx = context()
    ctx.shared_config['custom_decoders'] = [{'name': 'invalid_saved', 'steps': [{'op': 'no_such_operation'}]}]
    deadline = time.monotonic() + 15
    task = engine(ctx).prepare(decoder_request(), {**ACTOR, 'role': 'admin'}, deadline)
    with pytest.raises(AIError, match='verification_failed'):
        task.run(deadline, lambda *a: pytest.fail('incomplete catalog triggered generation'))
    assert decoder._active_child is None
    task.dispose()


def test_prompt_and_private_payload_meters_include_complete_encoded_shapes(monkeypatch):
    # Meter-only boundary: server instructions are lengthened, not user inputs.
    module = importlib.import_module('local_ai.engine')
    from local_ai.contracts import explanation_schema
    snapshot = {'kind': 'delivery', 'facts': []}
    schema = explanation_schema('delivery', 'en', 'a' * 64, ['e1'])
    messages = module.prompt(snapshot, schema)
    current = len(module.bounded_json({'messages': messages, 'schema': schema}, 16384))
    instruction = module.INSTRUCTIONS + 'x' * (16384 - current)
    monkeypatch.setattr(module, 'INSTRUCTIONS', instruction)
    exact = module.prompt(snapshot, schema)
    assert len(module.bounded_json({'messages': exact, 'schema': schema}, 16384)) == 16384
    monkeypatch.setattr(module, 'INSTRUCTIONS', instruction + 'x')
    with pytest.raises(AIError, match='too_large'):
        module.prompt(snapshot, schema)
    private = {'x': 'x' * (65536 - len(b'{"x":""}'))}
    assert len(module.bounded_json(private, 65536)) == 65536
    private['x'] += 'x'
    with pytest.raises(AIError, match='too_large'):
        module.bounded_json(private, 65536)


def test_verifier_only_results_are_one_shot_and_detach_request_input():
    from test_local_ai_contracts import decoder_request
    deadline = time.monotonic() + 15
    request = decoder_request(decoder_type='A', generate=False)
    task = engine(context()).prepare(request, {**ACTOR, 'role': 'admin'}, deadline)
    request['samples'][0]['data'] = 'edited_after_prepare'
    first = json.loads(task.run(deadline, lambda *a: pytest.fail('catalog model call')))
    assert first['snapshot']['examples'][0]['data'] != 'edited_after_prepare'
    with pytest.raises(AIError, match='invalid_request'):
        task.run(deadline, lambda *a: pytest.fail('task ran twice'))
    task.dispose()


def test_holdout_changes_never_change_generation_bytes_or_example_only_ranking():
    from test_local_ai_contracts import decoder_request
    outputs, inputs = [], []
    for expected in ('198.51.100.1', '203.0.113.17'):
        rows = [{'data': '192.0.2.1', 'expected_ips': ['192.0.2.1'], 'usage': 'example', 'complete_expected': True},
                {'data': '198.51.100.1', 'expected_ips': [expected], 'usage': 'validation', 'complete_expected': True}]
        deadline = time.monotonic() + 15
        task = engine(context()).prepare(decoder_request(decoder_type='A', samples=rows), {**ACTOR, 'role': 'admin'}, deadline)
        def reply(messages, schema):
            inputs.append(json.dumps([messages, schema], sort_keys=True))
            value = json.loads(empty_proposal_reply(messages, schema).content)
            value.update(candidates=[{'steps': [{'op': 'ascii'}]}], insufficient_reason=None)
            return NativeReply(json.dumps(value), {'model': 'fixture:local', 'model_digest': 'c' * 64})
        outputs.append(json.loads(task.run(deadline, reply)))
        task.dispose()
    assert inputs[0] == inputs[1]
    assert outputs[0]['proposal'] == outputs[1]['proposal']
    assert [c['name'] for c in outputs[0]['catalog']['candidates']] == [c['name'] for c in outputs[1]['catalog']['candidates']]
    assert outputs[0]['generated']['candidates'][0]['validation']['passed'] == 1
    assert outputs[1]['generated']['candidates'][0]['validation']['passed'] == 0


def test_late_preparation_failure_disposes_the_already_constructed_task(monkeypatch):
    from test_local_ai_contracts import decoder_request
    ctx = context()
    owner = engine(ctx)
    module = importlib.import_module('local_ai.engine')
    created = []
    original_init, original_check = module.PreparedTask.__init__, module.PreparedTask.check
    def track(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created.append(self)
    def revoke(self, deadline):
        ctx.read_model.invalidate(hard=True)
        original_check(self, deadline)
    monkeypatch.setattr(module.PreparedTask, '__init__', track)
    monkeypatch.setattr(module.PreparedTask, 'check', revoke)
    with pytest.raises(AIError, match='source_revoked'):
        owner.prepare(decoder_request(generate=False), {**ACTOR, 'role': 'admin'}, time.monotonic() + 10)
    assert len(created) == 1 and created[0].retained_bytes == 0
    assert created[0]._payload is None and created[0]._ctx is None


def test_delivery_keeps_real_historical_failure_after_later_success(tmp_path, monkeypatch):
    from test_stage3_core_runtime import app_factory, scan
    from test_delivery_store_claims import result as step_result
    app = app_factory(tmp_path / 'ledger')
    ctx = context()
    ctx.shared_config, ctx.config_lock = app.cfg.raw, app.cfg.lock
    ctx.delivery_diagnostics = app.delivery.store.diagnostics_snapshot
    ctx.delivery_health = app.delivery.health_snapshot
    try:
        binding = app.delivery.registry.descriptors()['teams']
        assert scan(app, monkeypatch, ['192.0.2.1'])[0]
        claim = app.delivery.store.claim_next(binding, app.clock())
        assert claim is not None
        app.delivery.store.finish_step(claim, step_result('blocked', reason='tls_error'), app.clock())
        app.clock.now += 1
        assert scan(app, monkeypatch, ['192.0.2.1', '192.0.2.2'])[0]
        claim = app.delivery.store.claim_next(binding, app.clock())
        assert claim is not None
        app.delivery.store.finish_step(claim, step_result('failed', reason='response_limit'), app.clock())
        app.clock.now += 1
        assert scan(app, monkeypatch, ['192.0.2.1', '192.0.2.2', '192.0.2.3'])[0]
        claim = app.delivery.store.claim_next(binding, app.clock())
        assert claim is not None
        app.delivery.store.finish_step(claim, step_result('acked'), app.clock())
        diagnostic = app.delivery.store.diagnostics_snapshot()
        assert diagnostic['channels']['teams']['latest_result']['state'] == 'acked'
        assert diagnostic['channels']['teams']['latest_failure']['reason'] == 'response_limit'
        monkeypatch.setattr(app.delivery.store, '_one', lambda *a: pytest.fail('AI accessed SQL'))
        deadline = time.monotonic() + 10
        task = engine(ctx).prepare({'kind': 'delivery', 'language': 'en'}, ACTOR, deadline)
        published = json.loads(task.run(deadline, explanation_reply))
        facts = {row['key']: row['value'] for row in published['snapshot']['facts']}
        assert facts['diagnostics_teams']['latest_result']['state'] == 'acked'
        assert facts['diagnostics_teams']['latest_failure']['reason'] == 'response_limit'
        assert facts['diagnostics_teams']['blocked_by_reason'] == [{'reason': 'tls_error', 'count': '1'}]
        assert diagnostic == app.delivery.store.diagnostics_snapshot()
        task.dispose()
    finally:
        monkeypatch.undo()
        app.delivery.stop()


def test_composition_imports_are_bound_to_this_candidate(record_testsuite_property):
    from pathlib import Path
    import sys
    candidate = Path(__file__).resolve().parents[1]
    modules = ['local_ai.engine', 'local_ai.sources', 'local_ai.contracts', 'local_ai.decoder',
               'local_ai.decoder_worker', 'local_ai.evidence', 'local_ai.privacy', 'local_ai.provider',
               'http_api.relationship_handlers', 'http_api.read_model']
    origins = {}
    for name in modules:
        loaded = importlib.import_module(name)
        path = Path(loaded.__file__).resolve()
        assert path == candidate.joinpath(*name.split('.')).with_suffix('.py')
        origins[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    record_testsuite_property('candidate_imports', json.dumps(origins, sort_keys=True))
    record_testsuite_property('python_executable', sys.executable)


def test_completed_source_checks_use_fresh_bounded_read_budget_not_generation_deadline(monkeypatch):
    from types import SimpleNamespace
    from test_local_ai_contracts import decoder_request
    import local_ai.sources as source_module
    deadline = time.monotonic() + 15
    task = engine(context()).prepare(decoder_request(decoder_type='A', generate=False),
                                      {**ACTOR, 'role': 'admin'}, deadline)
    assert task.run(deadline, lambda *a: pytest.fail('catalog-only model'))
    # Terminal retention outlives the admission-to-terminal generation deadline.
    monkeypatch.setattr(source_module, 'time', SimpleNamespace(monotonic=lambda: deadline + 1, time=time.time))
    task.check(deadline + 2)
    with pytest.raises(AIError, match='deadline_exceeded'):
        task.check(deadline + 1)
    with pytest.raises(AIError, match='invalid_request'):
        task.run(deadline + 2, lambda *a: pytest.fail('retained result triggered another model'))
    task.dispose()
