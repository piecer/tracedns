"""Deterministic server facts, separate from unverified free-form AI prose."""
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any

from http_api.relationship_handlers import _build_pair_assessment
from http_api.delivery_diagnostics import DIAGNOSTICS_SCHEMA
from http_api.delivery_health import PROGRESS_SCHEMA
from local_ai.contracts import AIError
from local_ai.decoder import DecoderError, _bounded_json
from local_ai.evidence import MAX_COUNTER, MAX_PROJECTION_BYTES, PAIR_TYPES, project_delivery, project_pair

MAX_SUMMARY_BYTES = 6144
MAX_CLAIM_BYTES = 512
SUMMARY_CODES = MappingProxyType({
    'relationship_pair': MappingProxyType({
        'summary': ('pair_assessment', 'pair_signals'), 'counterpoints': (),
        'limitations': ('pair_scope', 'pair_coverage', 'pair_attribution'),
    }),
    'delivery': MappingProxyType({
        'summary': ('delivery_overview', 'delivery_teams', 'delivery_misp'),
        'counterpoints': ('delivery_recovery',),
        'limitations': ('delivery_snapshot_scope', 'delivery_capture_times', 'delivery_coverage', 'delivery_lookup'),
    }),
})

_PAIR_FLAGS = ('analysis_complete', 'candidate_analysis_complete', 'cluster_topology_complete',
               'pair_detail_complete', 'enrichment_complete', 'candidate_limit_reached',
               'candidate_work_limit_reached', 'pair_heap_truncated', 'local_context_truncated', 'vt_enabled')
_PAIR_COUNTS = ('candidate_limit', 'candidate_work_limit', 'candidate_enumeration_count',
                'unique_candidate_count', 'evaluated_candidate_count', 'deduped_candidate_count',
                'vt_attempted', 'vt_eligible_count', 'vt_skipped_non_global', 'vt_report_count')
_SCORE_COUNTS = ('legacy_score', 'relationship_strength', 'evidence_score', 'botnet_evidence_score',
                 'raw_evidence_score', 'source_category_count')


def _keys(value, keys):
    if type(value) is not dict or value.keys() != set(keys):
        raise AIError('source_unavailable')


def _count(value):
    if (type(value) is not str or len(value) > 19 or not re.fullmatch(r'0|[1-9][0-9]*', value)
            or int(value) > MAX_COUNTER):
        raise AIError('source_unavailable')
    return int(value)


def _pair_source(snapshot, facts):
    values = {key: fact['value'] for key, fact in facts.items()}
    required = {'pair_assessment', 'family_scores', 'analysis_window', 'quality'}
    if not required <= values.keys() or any(key not in required and key not in
                                           {'evidence_' + kind for kind in PAIR_TYPES} for key in values):
        raise AIError('source_unavailable')
    scores, quality, window = (values[key] for key in ('pair_assessment', 'quality', 'analysis_window'))
    _keys(scores, (*_SCORE_COUNTS, 'verdict', 'source_categories', 'producer_confidence'))
    _keys(quality, (*_PAIR_FLAGS, *_PAIR_COUNTS, 'warning_codes'))
    _keys(window, ('as_of', 'lookback_days', 'cutoff'))
    _keys(snapshot['source'], ('job_id', 'a', 'b', 'analysis_as_of'))
    numeric = {key: _count(scores[key]) for key in _SCORE_COUNTS}
    q = {key: quality[key] for key in (*_PAIR_FLAGS, 'warning_codes')}
    q.update({key: _count(quality[key]) for key in _PAIR_COUNTS})
    families = values['family_scores']
    if type(families) is not dict:
        raise AIError('source_unavailable')
    families = {key: _count(value) for key, value in families.items()}
    raw = []
    for key, value in values.items():
        if key in required:
            continue
        _keys(value, ('type', 'family', 'source', 'specificity', 'weight', 'value_omitted'))
        if key != 'evidence_' + value['type'] or value['value_omitted'] is not True:
            raise AIError('source_unavailable')
        raw.append({'type': value['type'], 'weight': _count(value['weight'])})
    actual = _build_pair_assessment(raw)
    for key in ('verdict', 'evidence_score', 'botnet_evidence_score', 'raw_evidence_score'):
        if actual[key] != (numeric[key] if key in numeric else scores[key]):
            raise AIError('source_unavailable')
    if actual['family_scores'] != families:
        raise AIError('source_unavailable')
    assessment = {**actual, 'independent_sources': scores['source_categories'],
                  'independent_source_count': numeric['source_category_count'],
                  'confidence': {'level': scores['producer_confidence'], 'analysis_complete': q['analysis_complete']}}
    source = snapshot['source']
    projected = project_pair(
        {'a': source['a'], 'b': source['b'], 'score': numeric['legacy_score'],
         'relationship_strength': numeric['relationship_strength'], 'evidence': raw, 'assessment': assessment},
        q, {key: None if key == 'cutoff' and window[key] is None else _count(window[key]) for key in window},
        source_job_id=source['job_id'], has_misp_context=False)
    if (projected['source'] != source or projected['warnings'] != snapshot['warnings']
            or {fact['key']: fact['value'] for fact in projected['facts']} != values):
        raise AIError('source_unavailable')


def _restore(value, schema) -> Any:
    """Validate the exact-number projection before reconstructing typed input."""
    kind = schema['type']
    if type(kind) is list:
        if value is None:
            return None
        kind = kind[0]
    if kind == 'object':
        _keys(value, schema['properties'])
        return {key: _restore(value[key], child) for key, child in schema['properties'].items()}
    if kind == 'array':
        if type(value) is not list or len(value) > schema['maxItems']:
            raise AIError('source_unavailable')
        return [_restore(item, schema['items']) for item in value]
    if kind == 'integer':
        value = _count(value)
        if not schema.get('minimum', 0) <= value <= schema.get('maximum', MAX_COUNTER):
            raise AIError('source_unavailable')
    elif kind == 'boolean':
        if type(value) is not bool:
            raise AIError('source_unavailable')
    elif type(value) is not str:
        raise AIError('source_unavailable')
    if ('enum' in schema and value not in schema['enum']) or ('const' in schema and value != schema['const']):
        raise AIError('source_unavailable')
    return value


def _delivery_source(snapshot, facts):
    _keys(facts, ('diagnostics_summary', 'diagnostics_teams', 'diagnostics_misp', 'diagnostics_recent_failures',
                  'progress_summary', 'progress_channels', 'progress_worker', 'progress_recovery', 'progress_lookup'))
    values = {key: fact['value'] for key, fact in facts.items()}
    _keys(values['diagnostics_summary'], DIAGNOSTICS_SCHEMA['properties'].keys() - {'channels', 'recent_failures'})
    _keys(values['progress_summary'], PROGRESS_SCHEMA['properties'].keys() - {'channels', 'progress', 'recovery', 'lookup'})
    diag = _restore({**values['diagnostics_summary'], 'channels': {
        channel: values['diagnostics_' + channel] for channel in ('teams', 'misp')},
        'recent_failures': values['diagnostics_recent_failures']}, DIAGNOSTICS_SCHEMA)
    for channel, records in diag['channels'].items():
        for field in ('latest_result', 'latest_failure'):
            record = records[field]
            if record is not None and (record['channel'] != channel
                                       or field == 'latest_failure' and record['state'] != 'failed'):
                raise AIError('source_unavailable')
    if any(record['state'] != 'failed' for record in diag['recent_failures']):
        raise AIError('source_unavailable')
    progress = _restore({**values['progress_summary'], 'channels': values['progress_channels'],
                         'progress': values['progress_worker'], 'recovery': values['progress_recovery'],
                         'lookup': values['progress_lookup']}, PROGRESS_SCHEMA)
    source = snapshot['source']
    _keys(source, ('diagnostics_observed_at', 'diagnostics_captured_at', 'progress_captured_at'))
    projected = project_delivery(diag, progress,
        diagnostics_captured_at=_count(source['diagnostics_captured_at']),
        progress_captured_at=_count(source['progress_captured_at']))
    if (projected['source'] != source or projected['warnings'] != snapshot['warnings']
            or {fact['key']: fact['value'] for fact in projected['facts']} != values):
        raise AIError('source_unavailable')


def _bounded_snapshot(snapshot):
    """Bound primitive shape and scalar work before copying, sorting or JSON."""
    remaining, nodes = MAX_PROJECTION_BYTES, 2048

    def visit(value, depth):
        nonlocal remaining, nodes
        nodes -= 1
        if nodes < 0:
            raise AIError('too_large')
        if depth > 12:
            raise AIError('source_unavailable')
        kind = type(value)
        if kind is str:
            if len(value) > remaining:
                raise AIError('too_large')
            remaining -= len(value.encode('utf-8')) + 2
        elif kind is int:
            if not 0 <= value <= MAX_COUNTER:
                raise AIError('source_unavailable')
            remaining -= 1
        elif value is None or kind is bool:
            remaining -= 4
        elif kind in (dict, list):
            if len(value) > (128 if kind is dict else 64):
                raise AIError('too_large')
            remaining -= 2
            if kind is dict:
                for key, child in value.items():
                    if type(key) is not str:
                        raise AIError('source_unavailable')
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in value:
                    visit(child, depth + 1)
        else:
            raise AIError('source_unavailable')
        if remaining < 0:
            raise AIError('too_large')

    try:
        visit(snapshot, 0)
        # The structural pass bounds traversal; the shared byte meter also
        # counts escaped strings, separators and full integer spellings before
        # either serializer can allocate an over-limit source representation.
        _bounded_json(snapshot, MAX_PROJECTION_BYTES)
        encoded = json.dumps(snapshot, sort_keys=True, ensure_ascii=False,
                             separators=(',', ':'), allow_nan=False).encode('utf-8')
    except DecoderError as exc:
        raise AIError('too_large' if exc.code == 'too_large' else 'source_unavailable') from None
    except (UnicodeError, RecursionError):
        raise AIError('source_unavailable') from None
    if len(encoded) > MAX_PROJECTION_BYTES:
        raise AIError('too_large')
    return encoded


def _admit(snapshot, language, snapshot_digest):
    if (type(language) is not str or language not in ('en', 'ko')
            or type(snapshot_digest) is not str or len(snapshot_digest) != 64
            or not re.fullmatch('[a-f0-9]{64}', snapshot_digest)):
        raise AIError('source_unavailable')
    encoded = _bounded_snapshot(snapshot)
    _keys(snapshot, ('version', 'kind', 'source', 'facts', 'warnings'))
    if (type(snapshot['version']) is not int or snapshot['version'] != 1
            or type(snapshot['kind']) is not str or snapshot['kind'] not in ('relationship_pair', 'delivery')):
        raise AIError('source_unavailable')
    if type(snapshot['facts']) is not list or not 1 <= len(snapshot['facts']) <= 64:
        raise AIError('source_unavailable')
    facts, ids = {}, set()
    for fact in snapshot['facts']:
        _keys(fact, ('id', 'key', 'value'))
        key, identity = fact['key'], fact['id']
        if (type(key) is not str or key in facts or type(identity) is not str
                or not re.fullmatch('e[1-9][0-9]{0,2}', identity) or identity in ids):
            raise AIError('source_unavailable')
        facts[key] = fact
        ids.add(identity)
    try:
        (_pair_source if snapshot['kind'] == 'relationship_pair' else _delivery_source)(snapshot, facts)
    except (KeyError, TypeError, UnicodeError, RecursionError):
        raise AIError('source_unavailable') from None
    if hashlib.sha256(encoded).hexdigest() != snapshot_digest:
        raise AIError('source_unavailable')
    return facts


_QUALITY_LABELS = {
    'bucket_truncated': ('bucket truncated', '버킷 절단'),
    'bucket_skipped': ('bucket skipped', '버킷 생략'),
    'candidate_limit_reached': ('candidate limit', '후보 한도'),
    'candidate_work_limit_reached': ('candidate work limit', '후보 작업 한도'),
    'pair_heap_truncated': ('pair heap truncated', '쌍 힙 절단'),
    'pair_display_truncated': ('pair display truncated', '쌍 표시 절단'),
    'local_context_truncated': ('local context truncated', '로컬 문맥 절단'),
    'vt_partial_coverage': ('VT partial', 'VT 부분'),
}

_SIGNALS = {
    'same_asn': ('same ASN', 'ASN 일치'), 'same_owner': ('same owner', '소유자 일치'),
    'same_csp': ('same cloud provider', '클라우드 일치'), 'same_country': ('same country', '국가 일치'),
    'same_network_exact': ('same network', '네트워크 일치'),
    'same_network_overlap': ('overlapping networks', '네트워크 중첩'),
    'same_rdap_name': ('same RDAP name', 'RDAP 이름 일치'),
    'same_rdap_type': ('same RDAP type', 'RDAP 유형 일치'), 'same_rir': ('same RIR', 'RIR 일치'),
    'same_prefix24': ('same /24 prefix', '/24 접두사 일치'), 'same_jarm': ('same JARM', 'JARM 일치'),
    'same_cert_sha256': ('same certificate hash', '인증서 해시 일치'),
    'vt_malicious_both': ('VT malicious labels on both', '양쪽 VT 악성 분류'),
    'vt_suspicious_both': ('VT suspicious labels on both', '양쪽 VT 의심 분류'),
    'vt_detector_overlap': ('overlapping VT detectors', 'VT 탐지기 중첩'),
    'vt_time_proximity': ('nearby VT analysis times', 'VT 분석 시각 근접'),
    'shared_observed_domain': ('shared observed domain', '공통 관측 도메인'),
    'shared_decoder_provenance': ('shared decoder provenance', '공통 디코더 출처'),
    'coincident_dns_change': ('nearby DNS changes', 'DNS 변경 시각 근접'),
}


def _claim(facts, code, text, *keys):
    if not 1 <= len(text.encode('utf-8')) <= MAX_CLAIM_BYTES:
        raise AIError('too_large')
    return {'code': code, 'text': text, 'evidence_ids': [facts[key]['id'] for key in keys]}


def _pair_summary(facts, ko):
    assessment = facts['pair_assessment']['value']
    text = (f"Producer verdict: {assessment['verdict'].replace('_', ' ')}. "
            f"Relationship strength {assessment['relationship_strength']}/100; "
            f"evidence score {assessment['evidence_score']}/100; "
            f"direct botnet evidence {assessment['botnet_evidence_score']}/100; "
            f"producer confidence {assessment['producer_confidence']}.")
    if ko:
        verdict = {'insufficient_evidence': '근거 부족', 'related_infrastructure': '관련 인프라'}[assessment['verdict']]
        confidence = {'low': '낮음', 'medium': '중간', 'high': '높음'}[assessment['producer_confidence']]
        text = (f"서버 판정: {verdict}. 관계 강도 {assessment['relationship_strength']}/100; "
                f"근거 점수 {assessment['evidence_score']}/100; 직접 봇넷 근거 "
                f"{assessment['botnet_evidence_score']}/100; 서버 신뢰도 {confidence}.")
    summary = [_claim(facts, 'pair_assessment', text, 'pair_assessment')]
    signals = sorted((fact for key, fact in facts.items() if key.startswith('evidence_')),
                     key=lambda fact: (-int(fact['value']['weight']), fact['value']['type']))
    top = signals[:3]
    labels = ', '.join(f"{_SIGNALS[fact['value']['type']][ko]} ({fact['value']['weight']})" for fact in top)
    if ko:
        text = f"상위 관측 신호 {len(signals)}개 중 {len(top)}개: {labels or '없음'}. 미표시·미관측은 부정 근거가 아닙니다."
    else:
        text = (f"Top observed signals ({len(top)} of {len(signals)}): {labels or 'none'}. "
                "Unlisted/absent signals are not negative evidence.")
    summary.append(_claim(facts, 'pair_signals', text, *(fact['key'] for fact in top)) if top
                   else _claim(facts, 'pair_signals', text, 'pair_assessment'))
    window = facts['analysis_window']['value']
    cutoff = window['cutoff'] if window['cutoff'] is not None else ('없음' if ko else 'none')
    scope = (f"캐시 관측만 사용. 기준 {window['as_of']}초; 조회 {window['lookback_days']}일; 시작 {cutoff}. "
             "관측 범위 미상; 원시 값 생략. 전체 사실은 원본 스냅샷에 있습니다." if ko else
             f"Only cached observations. As of {window['as_of']} seconds; lookback {window['lookback_days']} days; "
             f"cutoff {cutoff}. Observation scope: observation coverage unknown; raw values omitted. "
             "Full facts remain in the original snapshot.")
    q = facts['quality']['value']
    def flag(value):
        return _flag(value, ko)
    vt = ('VT 활성' if q['vt_enabled'] else 'VT 비활성') if ko else ('VT enabled' if q['vt_enabled'] else 'VT disabled')
    coverage = (f"처리 완료 {flag(q['analysis_complete'])}; 후보 {flag(q['candidate_analysis_complete'])}, "
                f"토폴로지 {flag(q['cluster_topology_complete'])}, 상세 {flag(q['pair_detail_complete'])}, "
                f"보강 {flag(q['enrichment_complete'])}. {vt}; 보고 {q['vt_report_count']}/{q['vt_eligible_count']}. "
                "처리 완료는 관측 범위 보장이 아닙니다." if ko else
                f"Pipeline complete {flag(q['analysis_complete'])}; candidates {flag(q['candidate_analysis_complete'])}, "
                f"topology {flag(q['cluster_topology_complete'])}, details {flag(q['pair_detail_complete'])}, "
                f"enrichment {flag(q['enrichment_complete'])}. {vt}; reports {q['vt_report_count']}/{q['vt_eligible_count']}. "
                "Pipeline completeness is not observation coverage.")
    if q['warning_codes']:
        coverage += (' 경고: ' if ko else ' Warnings: ') + ', '.join(
            _QUALITY_LABELS[code][ko] for code in q['warning_codes']) + '.'
    attribution = (f"출처 범주 {assessment['source_category_count']}개는 독립 원천 수가 아닙니다. "
                   "봇넷·행위자·호스트 감염 귀속 판단이 아닙니다. 직접 근거 0은 부재 증명이 아닙니다." if ko else
                   f"Source categories {assessment['source_category_count']} are not independent origins. "
                   "No botnet, actor or host-compromise attribution. Zero direct evidence is not evidence of absence.")
    limitations = [_claim(facts, 'pair_scope', scope, 'analysis_window'),
                   _claim(facts, 'pair_coverage', coverage, 'quality'),
                   _claim(facts, 'pair_attribution', attribution, 'pair_assessment')]
    return summary, [], limitations


_KO_STATES = {'disabled': '비활성', 'ok': '정상', 'degraded': '저하', 'blocked': '차단',
              'not_started': '시작 전', 'idle': '유휴', 'active': '진행 중', 'stalled': '정체',
              'recovering': '복구 중', 'failed': '실패', 'stopping': '중지 중', 'stopped': '중지됨',
              'acked': '승인', 'continue': '계속', 'retry': '재시도',
              'ready': '준비됨', 'backoff': '재시도 유예', 'uncertain': '불확실', 'awaiting_full': '전체 관측 대기',
              'unknown': '미상', 'covered': '포함', 'gap': '공백', 'rebaselining': '기준 재설정',
              'complete': '완전', 'partial': '부분'}


def _flag(value, ko):
    return ('예' if value else '아니오') if ko else ('yes' if value else 'no')


def _state(value, ko):
    return _KO_STATES[value] if ko else value.replace('_', ' ')


def _record_text(record, ko):
    if record is None:
        return '미관측' if ko else 'unobserved'
    text = (f"{_state(record['state'], ko)} {record['at']}초" if ko else
            f"{_state(record['state'], ko)} at {record['at']}s")
    reason = record['reason']
    if reason is not None:
        if reason in ('provider_tls', 'tls_error', 'tls_config'):
            label = 'TLS 실패' if ko else 'TLS failure'
        else:
            label = reason.replace('_', ' ')
        text += f" ({label})"
    return text


def _channel_summary(facts, channel, ko):
    enabled = facts['progress_channels']['value'][channel]['enabled']
    records = facts['diagnostics_' + channel]['value']
    result, failure = records['latest_result'], records['latest_failure']
    name = 'Teams' if channel == 'teams' else 'MISP'
    text = (f"{name}: 활성 {_flag(enabled, ko)}; 최근 결과: {_record_text(result, ko)}; "
            f"최근 실패: {_record_text(failure, ko)}." if ko else
            f"{name}: enabled {_flag(enabled, ko)}; latest result: {_record_text(result, ko)}; "
            f"latest failure: {_record_text(failure, ko)}.")
    if result is None or failure is None:
        text += ' 미관측은 실패 부재 증명 아님.' if ko else ' Unobserved is not proof of no failures.'
    if failure is not None:
        if result is not None and result['state'] == 'acked' and int(result['at']) > int(failure['at']):
            text += ' 승인 시각이 더 늦음.' if ko else ' ACK is later.'
        elif result is not None:
            text += ' 복구 순서 미확정.' if ko else ' Recovery ordering not established.'
        text += (' 실패 건 복구 입증 아님; 전체 정상 보장 아님.' if ko else
                 ' Failed receipt not proven repaired; not proof of overall health.')
    return _claim(facts, 'delivery_' + channel, text, 'progress_channels', 'diagnostics_' + channel)


def _optional(value, ko, *, observation=False):
    if value is None:
        return ('미관측' if ko else 'unobserved') if observation else ('미상' if ko else 'unknown')
    return value + ('초' if ko else 's')


def _delivery_qualifiers(facts, source, ko):
    d, p, r, lookup = (facts[key]['value'] for key in
                       ('diagnostics_summary', 'progress_summary', 'progress_recovery', 'progress_lookup'))
    recovery = (f"복구 상태: {_state(r['state'], ko)}; 부재 상태: {_state(r['absence_state'], ko)}. "
                f"기준 재설정 대상 {r['targets_rebaselining']}; 재시도까지 {_optional(r['retry_in_seconds'], ko)}. "
                "서로 다른 상태이며 전체 정상 보장이 아닙니다." if ko else
                f"Recovery state: {_state(r['state'], ko)}; absence state: {_state(r['absence_state'], ko)}. "
                f"Targets rebaselining {r['targets_rebaselining']}; retry in {_optional(r['retry_in_seconds'], ko)}. "
                "These are distinct states, not proof of overall health.")
    scope = ("캐시의 비원자적 관측이며 실시간 상태가 아닙니다. 집계 오래됨이 거짓이어도 현재 신선도 보장 아님. "
             "전체 사실은 원본 스냅샷에 있습니다." if ko else
             "Only cached observations; not atomic and not live health. A false counts-stale flag is not proof "
             "of freshness now. Full facts remain in the original snapshot.")
    times = (f"진단 관측 {source['diagnostics_observed_at']}초; 진단 캡처 {source['diagnostics_captured_at']}밀리초; "
             f"진행 캡처 {source['progress_captured_at']}밀리초. 캡처 시각과 이벤트 시각은 별개입니다." if ko else
             f"Capture times: diagnostics observed {source['diagnostics_observed_at']}s; "
             f"diagnostics captured {source['diagnostics_captured_at']}ms; progress captured {source['progress_captured_at']}ms. "
             "Capture times are distinct from event times.")
    coverage = (f"범위: 진단 {_state(d['coverage'], ko)}; 진행 {_state(p['coverage'], ko)}. "
                f"집계 완전 {_flag(p['accounting_complete'], ko)}; 추적 완전 {_flag(p['tracking_complete'], ko)}. "
                f"집계 오래됨: 진단 {_flag(d['counts_stale'], ko)}; 진행 {_flag(p['counts_stale'], ko)}; "
                f"집계 경과 {_optional(p['counts_age_seconds'], ko)}." if ko else
                f"Coverage: diagnostics {_state(d['coverage'], ko)}; progress {_state(p['coverage'], ko)}. "
                f"accounting complete {_flag(p['accounting_complete'], ko)}; tracking complete {_flag(p['tracking_complete'], ko)}. "
                f"counts stale: diagnostics {_flag(d['counts_stale'], ko)}; progress {_flag(p['counts_stale'], ko)}; "
                f"count age {_optional(p['counts_age_seconds'], ko)}.")
    lookup_text = (f"조회 범위 {_state(lookup['coverage'], ko)}; 집계 오래됨 {_flag(lookup['counts_stale'], ko)}. "
                   f"진행 {lookup['in_flight']}, 실패 대상 {lookup['failed_targets']}, 불확실 대상 {lookup['uncertain_targets']}. "
                   f"최근 시도 {_optional(lookup['last_attempt_at'], ko, observation=True)}; "
                   f"최근 성공 {_optional(lookup['last_success_at'], ko, observation=True)}." if ko else
                   f"Lookup coverage {_state(lookup['coverage'], ko)}; counts stale {_flag(lookup['counts_stale'], ko)}. "
                   f"In flight {lookup['in_flight']}, failed targets {lookup['failed_targets']}, uncertain targets {lookup['uncertain_targets']}. "
                   f"Last attempt {_optional(lookup['last_attempt_at'], ko, observation=True)}; "
                   f"last success {_optional(lookup['last_success_at'], ko, observation=True)}.")
    return ([_claim(facts, 'delivery_recovery', recovery, 'progress_recovery')], [
        _claim(facts, 'delivery_snapshot_scope', scope, 'diagnostics_summary', 'progress_summary'),
        _claim(facts, 'delivery_capture_times', times, 'diagnostics_summary', 'progress_summary'),
        _claim(facts, 'delivery_coverage', coverage, 'diagnostics_summary', 'progress_summary'),
        _claim(facts, 'delivery_lookup', lookup_text, 'progress_lookup')])


def _delivery_summary(facts, source, ko):
    p, d, worker = (facts[key]['value'] for key in ('progress_summary', 'diagnostics_summary', 'progress_worker'))
    text = (f"캡처 전체 상태: {_state(p['status'], ko)}; 작업자: {_state(worker['state'], ko)} "
            f"(실행 {_flag(p['worker_running'], ko)}). 대기 {p['pending']}, 재시도 대기 {p['retry_wait']}, "
            f"차단 {p['blocked']}. 저장소 플래그: 진단 {_flag(d['storage_ok'], ko)}; 진행 {_flag(p['storage_ok'], ko)}."
            if ko else
            f"Captured overall: {_state(p['status'], ko)}; worker: {_state(worker['state'], ko)} "
            f"(running {_flag(p['worker_running'], ko)}). Backlog pending {p['pending']}, retry wait {p['retry_wait']}, "
            f"blocked {p['blocked']}. Storage flags: diagnostics {_flag(d['storage_ok'], ko)}; "
            f"progress {_flag(p['storage_ok'], ko)}.")
    summary = [_claim(facts, 'delivery_overview', text, 'progress_summary', 'progress_worker', 'diagnostics_summary')]
    summary.extend(_channel_summary(facts, channel, ko) for channel in ('teams', 'misp'))
    counterpoints, limitations = _delivery_qualifiers(facts, source, ko)
    return summary, counterpoints, limitations


def build_summary(snapshot, language, snapshot_digest):
    """Build owned v1 server facts, not an AI result or publication authority.

    Caller must retain provider, audit, source-lease and authorization fences.
    Input is the original project_pair/project_delivery snapshot (8 KiB max),
    with SHA-256 of sorted compact ensure_ascii=False UTF-8 JSON. No mutation,
    clock read, model access, I/O or replacement of the free-prose contract.
    """
    facts = _admit(snapshot, language, snapshot_digest)
    summary, counterpoints, limitations = (_pair_summary(facts, language == 'ko')
        if snapshot['kind'] == 'relationship_pair' else _delivery_summary(facts, snapshot['source'], language == 'ko'))
    result = {'version': 1, 'kind': snapshot['kind'], 'language': language,
              'snapshot_digest': snapshot_digest, 'summary': summary,
              'counterpoints': counterpoints, 'limitations': limitations}
    try:
        _bounded_json(result, MAX_SUMMARY_BYTES)
    except DecoderError as exc:
        raise AIError('too_large' if exc.code == 'too_large' else 'source_unavailable') from None
    return result
