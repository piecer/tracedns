"""AI reads bounded existing facts; it neither repeats collection nor rewrites them."""
import copy
import importlib
import importlib.util
import json

import pytest

from test_stage3_core_runtime import app_factory


def test_delivery_projection_uses_real_cached_producers_and_separate_freshness(tmp_path):
    assert importlib.util.find_spec('local_ai.evidence') is not None, 'AI evidence projection missing'
    evidence = importlib.import_module('local_ai.evidence')
    app = app_factory(tmp_path / 'ledger')
    try:
        diagnostics = app.delivery.store.diagnostics_snapshot()
        progress = app.delivery.health_snapshot(include_progress=True)
        originals = copy.deepcopy((diagnostics, progress))
        snapshot = evidence.project_delivery(
            diagnostics, progress, diagnostics_captured_at=100001, progress_captured_at=100002,
        )
        assert snapshot['kind'] == 'delivery'
        assert snapshot['source']['diagnostics_observed_at'] == str(diagnostics['observed_at'])
        assert snapshot['source']['diagnostics_captured_at'] == '100001'
        assert snapshot['source']['progress_captured_at'] == '100002'
        assert 'snapshots_not_atomic' in snapshot['warnings']
        facts = {fact['key']: fact for fact in snapshot['facts']}
        assert facts['diagnostics_summary']['value']['coverage'] == diagnostics['coverage']
        assert facts['progress_lookup']['value']['coverage'] == progress['lookup']['coverage']
        assert len({fact['id'] for fact in snapshot['facts']}) == len(snapshot['facts'])
        assert (diagnostics, progress) == originals
    finally:
        app.delivery.stop()


def real_pair(monkeypatch, count=2, **options):
    from http_api import relationship_handlers as rh
    from test_relationship_analysis import _analyze

    def no_provider(*args, **kwargs):
        pytest.fail('fixture attempted intelligence lookup')

    monkeypatch.setattr(rh, 'get_ip_report', no_provider)
    monkeypatch.setattr(rh, 'begin_cache_batch', None)
    monkeypatch.setattr(rh, 'end_cache_batch', None)
    monkeypatch.setattr(rh, '_load_geoip_reader', lambda path: None)
    result = _analyze({'ips': [f'192.0.2.{i}' for i in range(1, count + 1)], 'include_vt': False,
                       'min_score': 1, 'pair_gate_enabled': False, **options})
    assert result['pairs'], 'real producer positive control must contain a pair'
    return result


def test_selected_pair_projection_preserves_producer_verdict_and_coverage(monkeypatch):
    evidence = importlib.import_module('local_ai.evidence')
    result = real_pair(monkeypatch)
    original = copy.deepcopy(result)
    pair = result['pairs'][0]
    snapshot = evidence.project_pair(pair, result['quality'], result['analysis_window'],
                                     source_job_id='a' * 32, has_misp_context=False)
    facts = {fact['key']: fact['value'] for fact in snapshot['facts']}
    assert snapshot['kind'] == 'relationship_pair'
    assert facts['pair_assessment']['verdict'] == pair['assessment']['verdict']
    assert facts['pair_assessment']['source_category_count'] == str(pair['assessment']['independent_source_count'])
    assert facts['quality']['analysis_complete'] == result['quality']['analysis_complete']
    assert snapshot['source']['analysis_as_of'] == str(result['analysis_window']['as_of'])
    assert 'origin_independence_unknown' in snapshot['warnings']
    assert 'not_attribution' in snapshot['warnings']
    assert result == original
    assert len(json.dumps(snapshot, ensure_ascii=False).encode()) <= 8192


def test_pair_keeps_genuine_producer_incompleteness_visible(monkeypatch):
    evidence = importlib.import_module('local_ai.evidence')
    result = real_pair(monkeypatch, count=100, candidate_limit=1000, top_pairs=5000)
    assert not result['quality']['analysis_complete']
    original = copy.deepcopy(result)
    snapshot = evidence.project_pair(result['pairs'][0], result['quality'], result['analysis_window'],
                                     source_job_id='a' * 32, has_misp_context=False)
    assert 'coverage_incomplete' in snapshot['warnings']
    assert set(result['quality']['warning_codes']) <= set(snapshot['warnings'])
    assert result == original


def test_pair_never_copies_unselected_provider_values(monkeypatch):
    evidence = importlib.import_module('local_ai.evidence')
    result = real_pair(monkeypatch)

    class NeverInspect:
        def __str__(self):
            raise AssertionError('unselected provider data inspected')

        def __deepcopy__(self, memo):
            raise AssertionError('unselected provider data copied')

    pair = result['pairs'][0]
    pair['private_provider_response'] = NeverInspect()
    for items in (pair['evidence'], pair['assessment']['evidence']):
        for item in items:
            item['value'] = NeverInspect()
    snapshot = evidence.project_pair(pair, result['quality'], result['analysis_window'],
                                     source_job_id='a' * 32, has_misp_context=False)
    assert 'raw_values_not_sent' in snapshot['warnings']
    assert 'private_provider_response' not in json.dumps(snapshot)


def test_misp_source_is_refused_before_any_projection():
    evidence = importlib.import_module('local_ai.evidence')
    with pytest.raises(ValueError) as rejected:
        evidence.project_pair(object(), object(), object(), source_job_id='a' * 32, has_misp_context=True)
    assert getattr(rejected.value, 'code') == 'source_unavailable'


def test_diagnostic_counter_values_remain_exact_for_browser(tmp_path):
    evidence = importlib.import_module('local_ai.evidence')
    app = app_factory(tmp_path / 'ledger')
    try:
        diagnostics = app.delivery.store.diagnostics_snapshot()
        progress = app.delivery.health_snapshot(include_progress=True)
        progress['failed_total'] = (1 << 63) - 1
        snapshot = evidence.project_delivery(diagnostics, progress,
            diagnostics_captured_at=100001, progress_captured_at=100002)
        values = {fact['key']: fact['value'] for fact in snapshot['facts']}
        assert values['progress_summary']['failed_total'] == str((1 << 63) - 1)
    finally:
        app.delivery.stop()
