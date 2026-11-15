"""Bounded, cache-only facts for local assistance; no provider or ledger I/O."""
import json
import ipaddress
import re
from typing import Any, cast

from http_api.delivery_diagnostics import DIAGNOSTICS_SCHEMA, _project as _diagnostics
from http_api.delivery_health import PROGRESS_SCHEMA, _project as _progress
from http_api.relationship_handlers import _EVIDENCE_SEMANTICS
from local_ai.contracts import AIError

MAX_PROJECTION_BYTES = 8 * 1024
MAX_COUNTER = (1 << 63) - 1
PAIR_TYPES = frozenset((
    'same_asn', 'same_owner', 'same_csp', 'same_country', 'same_network_exact',
    'same_network_overlap', 'same_rdap_name', 'same_rdap_type', 'same_rir',
    'same_prefix24', 'same_jarm', 'same_cert_sha256', 'vt_malicious_both',
    'vt_suspicious_both', 'vt_detector_overlap', 'vt_time_proximity',
    'shared_observed_domain', 'shared_decoder_provenance', 'coincident_dns_change',
))
QUALITY_WARNINGS = frozenset((
    'bucket_truncated', 'bucket_skipped', 'candidate_limit_reached',
    'candidate_work_limit_reached', 'pair_heap_truncated', 'pair_display_truncated',
    'local_context_truncated', 'vt_partial_coverage',
))


def _exact_numbers(value):
    """Keep validated 64-bit counters exact in JavaScript and model text."""
    if type(value) is int:
        return str(value)
    if type(value) is dict:
        return {key: _exact_numbers(child) for key, child in value.items()}
    if type(value) is list:
        return [_exact_numbers(child) for child in value]
    return value


def _timestamp(value):
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise AIError('source_unavailable', 409)
    return str(value)


def _finish(kind, source, groups, warnings):
    if len(groups) > 64:
        raise AIError('too_large', 413)
    result = {'version': 1, 'kind': kind, 'source': source,
              'facts': [{'id': f'e{index}', 'key': key, 'value': _exact_numbers(value)}
                        for index, (key, value) in enumerate(groups, 1)],
              'warnings': warnings}
    wire = json.dumps(result, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(wire) > MAX_PROJECTION_BYTES:
        raise AIError('too_large', 413)
    return result


def project_delivery(diagnostics, progress, *, diagnostics_captured_at, progress_captured_at):
    """Preserve distinct cache freshness; these reads are not one transaction."""
    try:
        diag = cast(dict[str, Any], _diagnostics(diagnostics, DIAGNOSTICS_SCHEMA))
        health = cast(dict[str, Any], _progress(progress, PROGRESS_SCHEMA, strict=True))
    except (ValueError, TypeError, KeyError, RecursionError):
        raise AIError('source_unavailable', 409) from None
    source = {
        'diagnostics_observed_at': _timestamp(diag['observed_at']),
        'diagnostics_captured_at': _timestamp(diagnostics_captured_at),
        'progress_captured_at': _timestamp(progress_captured_at),
    }
    groups = [
        ('diagnostics_summary', {key: value for key, value in diag.items()
                                 if key not in ('channels', 'recent_failures')}),
        ('diagnostics_teams', diag['channels']['teams']),
        ('diagnostics_misp', diag['channels']['misp']),
        ('diagnostics_recent_failures', diag['recent_failures']),
        ('progress_summary', {key: value for key, value in health.items()
                              if key not in ('channels', 'progress', 'recovery', 'lookup')}),
        ('progress_channels', health['channels']),
        ('progress_worker', health['progress']),
        ('progress_recovery', health['recovery']),
        ('progress_lookup', health['lookup']),
    ]
    warnings = ['snapshots_not_atomic', 'cached_observations_only']
    if diag['counts_stale'] or health['counts_stale']:
        warnings.append('counts_stale')
    if diag['coverage'] != 'covered' or health['coverage'] != 'covered':
        warnings.append('coverage_incomplete')
    if health['lookup']['coverage'] != 'complete' or health['lookup']['counts_stale']:
        warnings.append('lookup_coverage_incomplete')
    if not diag['storage_ok'] or not health['storage_ok']:
        warnings.append('storage_unavailable')
    return _finish('delivery', source, groups, warnings)


def _counter(value, maximum=MAX_COUNTER):
    if type(value) is not int or not 0 <= value <= maximum:
        raise AIError('source_unavailable', 409)
    return value


def _flag(value):
    if type(value) is not bool:
        raise AIError('source_unavailable', 409)
    return value


def _enum(value, choices):
    if type(value) is not str or value not in choices:
        raise AIError('source_unavailable', 409)
    return value


def project_pair(pair, quality, analysis_window, *, source_job_id, has_misp_context):
    """Project signal semantics, not arbitrary provider values or identifiers."""
    if has_misp_context is not False:
        raise AIError('source_unavailable', 409)
    if (any(type(value) is not dict for value in (pair, quality, analysis_window))
            or type(source_job_id) is not str or not re.fullmatch('[a-f0-9]{32}', source_job_id)):
        raise AIError('source_unavailable', 409)
    try:
        a, b = pair['a'], pair['b']
        if (type(a) is not str or type(b) is not str or len(a) > 15 or len(b) > 15
                or str(ipaddress.IPv4Address(a)) != a or str(ipaddress.IPv4Address(b)) != b or a == b):
            raise ValueError('invalid pair')
        assessment = pair['assessment']
        if type(assessment) is not dict:
            raise ValueError('invalid assessment')
        raw_evidence, normalized = pair['evidence'], assessment['evidence']
        if (type(raw_evidence) is not list or type(normalized) is not list
                or len(raw_evidence) > 32 or len(raw_evidence) != len(normalized)):
            raise ValueError('invalid evidence inventory')
        signals, seen, actual_sources = [], set(), set()
        for raw, item in zip(raw_evidence, normalized):
            if type(raw) is not dict or type(item) is not dict:
                raise ValueError('invalid signal')
            kind = _enum(item.get('type'), PAIR_TYPES)
            if kind in seen or raw.get('type') != kind:
                raise ValueError('inconsistent signal')
            seen.add(kind)
            family, source, specificity = _EVIDENCE_SEMANTICS[kind]
            if (item.get('family'), item.get('source'), item.get('specificity')) != (family, source, specificity):
                raise ValueError('inconsistent semantics')
            weight = _counter(item.get('weight'), 100)
            if type(raw.get('weight')) is not int or raw['weight'] != weight:
                raise ValueError('inconsistent weight')
            if source in ('virustotal', 'tracedns'):
                actual_sources.add(source)
            signals.append((f'evidence_{kind}', {'type': kind, 'family': family, 'source': source,
                           'specificity': specificity, 'weight': weight, 'value_omitted': True}))
        categories = assessment['independent_sources']
        if (type(categories) is not list or len(categories) > 2
                or any(type(item) is not str or item not in ('virustotal', 'tracedns') for item in categories)
                or len(categories) != len(set(categories)) or set(categories) != actual_sources):
            raise ValueError('invalid source categories')
        count = _counter(assessment['independent_source_count'], 2)
        if count != len(categories):
            raise ValueError('inconsistent source count')
        families = assessment['family_scores']
        if type(families) is not dict or len(families) > 4:
            raise ValueError('invalid family scores')
        family_scores = {_enum(key, ('infrastructure', 'tls', 'threat_intel', 'local_dns')):
                         _counter(value, 100) for key, value in families.items()}
        q: dict[str, Any] = {key: _flag(quality[key]) for key in (
            'analysis_complete', 'candidate_analysis_complete', 'cluster_topology_complete',
            'pair_detail_complete', 'enrichment_complete', 'candidate_limit_reached',
            'candidate_work_limit_reached', 'pair_heap_truncated', 'local_context_truncated', 'vt_enabled')}
        q.update({key: _counter(quality[key]) for key in (
            'candidate_limit', 'candidate_work_limit', 'candidate_enumeration_count',
            'unique_candidate_count', 'evaluated_candidate_count', 'deduped_candidate_count',
            'vt_attempted', 'vt_eligible_count', 'vt_skipped_non_global', 'vt_report_count')})
        codes = quality['warning_codes']
        if type(codes) is not list or len(codes) > len(QUALITY_WARNINGS):
            raise ValueError('invalid quality warnings')
        q['warning_codes'] = [_enum(code, QUALITY_WARNINGS) for code in codes]
        confidence = assessment['confidence']
        if type(confidence) is not dict or confidence.get('analysis_complete') is not q['analysis_complete']:
            raise ValueError('inconsistent confidence')
        scores = {
            'legacy_score': _counter(pair['score'], 100),
            'relationship_strength': _counter(pair['relationship_strength'], 100),
            'verdict': _enum(assessment['verdict'], ('insufficient_evidence', 'related_infrastructure', 'same_botnet_likely')),
            'evidence_score': _counter(assessment['evidence_score'], 100),
            'botnet_evidence_score': _counter(assessment['botnet_evidence_score'], 100),
            'raw_evidence_score': _counter(assessment['raw_evidence_score']),
            'source_category_count': count, 'source_categories': list(categories),
            'producer_confidence': _enum(confidence['level'], ('low', 'medium', 'high')),
        }
        source = {'job_id': source_job_id, 'a': a, 'b': b,
                  'analysis_as_of': _timestamp(analysis_window['as_of'])}
        window = {'as_of': _counter(analysis_window['as_of']),
                  'lookback_days': _counter(analysis_window['lookback_days']),
                  'cutoff': None if analysis_window['cutoff'] is None else _counter(analysis_window['cutoff'])}
    except (ValueError, KeyError, TypeError, RecursionError):
        raise AIError('source_unavailable', 409) from None
    warnings = ['origin_independence_unknown', 'not_attribution', 'observation_coverage_unknown',
                'cached_observations_only', 'raw_values_not_sent', *q['warning_codes']]
    if not q['analysis_complete']:
        warnings.append('coverage_incomplete')
    return _finish('relationship_pair', source,
                   [('pair_assessment', scores), ('family_scores', family_scores),
                    ('analysis_window', window), ('quality', q), *signals], warnings)
