/* Lazy local assistance. Only Run creates a job; navigation only detaches. */
(() => {
  'use strict';
  const active = new Map();
  const kinds = ['relationship_pair', 'delivery', 'decoder_suggest'];
  const checks = {relationship_pair:['inspect_pair_evidence','inspect_pair_coverage'], delivery:['inspect_delivery_diagnostics','inspect_delivery_progress']};
  const checkFacts = {inspect_pair_evidence:'pair_assessment',inspect_pair_coverage:'quality',inspect_delivery_diagnostics:'diagnostics_summary',inspect_delivery_progress:'progress_summary'};
  const checkLabels = {inspect_pair_evidence:['Inspect retained pair evidence','보존된 관계 근거 확인'],inspect_pair_coverage:['Inspect retained pair coverage','보존된 관계 관찰 범위 확인'],inspect_delivery_diagnostics:['Inspect retained diagnostics','보존된 진단 확인'],inspect_delivery_progress:['Inspect retained progress','보존된 진행 상태 확인']};
  const qualityWarnings = ['bucket_truncated','bucket_skipped','candidate_limit_reached','candidate_work_limit_reached','pair_heap_truncated','pair_display_truncated','local_context_truncated','vt_partial_coverage'];
  const warningCodes = ['origin_independence_unknown','not_attribution','observation_coverage_unknown','cached_observations_only','raw_values_not_sent','coverage_incomplete','snapshots_not_atomic','counts_stale','lookup_coverage_incomplete','storage_unavailable',...qualityWarnings];
  const pairTypes = ['same_asn','same_owner','same_csp','same_country','same_network_exact','same_network_overlap','same_rdap_name','same_rdap_type','same_rir','same_prefix24','same_jarm','same_cert_sha256','vt_malicious_both','vt_suspicious_both','vt_detector_overlap','vt_time_proximity','shared_observed_domain','shared_decoder_provenance','coincident_dns_change'];
  const factKeys = {
    relationship_pair:['pair_assessment','family_scores','analysis_window','quality',...pairTypes.map(k=>'evidence_'+k)],
    delivery:['diagnostics_summary','diagnostics_teams','diagnostics_misp','diagnostics_recent_failures','progress_summary','progress_channels','progress_worker','progress_recovery','progress_lookup']
  };
  const text = {
    en:{title:'AI assistance',language:'Language',run:'Run',close:'Close',idle:'Run explicitly to request assistance. No automatic inference. Selected evidence may be sent to the configured provider.',working:'Request in progress…',completed:'Completed; audited result.',stale:'Previous result — inputs or owner changed. Run again before using actions.',facts:'Server facts and verdict',warnings:'Coverage and limitations (server)',interpretation:'AI interpretation — not verified fact',summary:'Summary',counterpoints:'Counterpoints',limitations:'AI limitations',next:'Next',previous:'Previous',checks:'Manual next checks',provenance:'Snapshot and model',citation:'Citations identify this snapshot; they do not prove the interpretation.',invalid:'Unsupported or invalid response. No result accepted.',failed:'Request failed. No automatic retry.',busy:'AI assistance is busy. No new job created.',disabled:'AI assistance is disabled. Ask an administrator to review AI provider settings.',security:'Security or audit storage is unavailable. Contact the administrator.',source:'Source is unavailable or changed. Select an eligible source again.',timeout:'Request timed out; acceptance or completion may be uncertain. No automatic retry.',closed:'Panel closed'},
    ko:{title:'AI 도움',language:'언어',run:'실행',close:'닫기',idle:'실행을 눌러 도움을 요청하세요. 자동 추론은 실행되지 않습니다. 선택된 근거가 설정된 제공자로 전송될 수 있습니다.',working:'요청 처리 중…',completed:'완료 — 감사 기록이 확인된 결과입니다.',stale:'이전 결과 — 입력 또는 소유자가 변경되었습니다. 작업 전에 다시 실행하세요.',facts:'서버 사실과 판정',warnings:'관찰 범위와 한계 (서버)',interpretation:'AI 해석 — 검증된 사실이 아님',summary:'요약',counterpoints:'반대 근거',limitations:'AI 한계',next:'다음',previous:'이전',checks:'수동 다음 확인',provenance:'스냅샷 및 모델',citation:'인용은 이 스냅샷을 가리키며 해석의 진실성을 증명하지 않습니다.',invalid:'지원하지 않거나 잘못된 응답입니다. 결과를 수락하지 않았습니다.',failed:'요청에 실패했습니다. 자동으로 재시도하지 않습니다.',busy:'AI 도움이 사용 중입니다. 새 작업을 만들지 않았습니다.',disabled:'AI가 비활성화되어 있습니다. 관리자에게 AI 제공자 설정을 문의하세요.',security:'보안 또는 감사 저장소를 사용할 수 없습니다. 관리자에게 문의하세요.',source:'소스를 사용할 수 없거나 변경되었습니다. 적격 소스를 다시 선택하세요.',timeout:'요청 시간이 초과되었습니다. 수락 또는 완료 여부가 불확실합니다. 자동 재시도는 없습니다.',closed:'패널 닫힘'}
  };
  Object.assign(text.en,{cancel:'Cancel',cancelPending:'Cancellation requested; stopping inference is not confirmed.',cancelFailed:'Cancellation was not confirmed. The underlying job may still be running.',cancelled:'Cancellation confirmed by the server.',auditPending:'Terminal outcome received; audit confirmation pending.',uncertain:'Acceptance is uncertain. No automatic retry; use Run to check availability before a new request.'});
  Object.assign(text.ko,{cancel:'취소',cancelPending:'취소를 요청했지만 추론 중지는 확인되지 않았습니다.',cancelFailed:'취소를 확인하지 못했습니다. 기존 작업이 계속 실행 중일 수 있습니다.',cancelled:'서버에서 취소를 확인했습니다.',auditPending:'종료 결과를 받았습니다. 감사 확인을 기다립니다.',uncertain:'수락 여부가 불확실합니다. 자동 재시도하지 않습니다. 실행으로 사용 가능 여부를 먼저 확인하세요.'});
  Object.assign(text.en,{unsettled:'Provider settlement is unknown. New inference is blocked; contact the administrator. No automatic retry.',stopped:'AI assistance is stopped. No new job created. Contact the administrator.'});
  Object.assign(text.ko,{unsettled:'제공자 추론 종료 여부를 알 수 없습니다. 새 추론이 차단되었습니다. 관리자에게 문의하세요. 자동 재시도는 없습니다.',stopped:'AI 도움이 중지되었습니다. 새 작업을 만들지 않았습니다. 관리자에게 문의하세요.'});
  Object.assign(text.en,{provider_auth_failed:'Provider authentication was rejected. Ask an administrator to check the configured key. No automatic retry.',provider_request_rejected:'Provider rejected the request. Ask an administrator to check the endpoint, model and token option. No automatic retry.',provider_rate_limited:'Provider rate limit reached. No automatic retry.'});
  Object.assign(text.ko,{provider_auth_failed:'제공자 인증이 거부되었습니다. 관리자에게 설정된 키 확인을 요청하세요. 자동 재시도는 없습니다.',provider_request_rejected:'제공자가 요청을 거부했습니다. 관리자에게 엔드포인트, 모델 및 토큰 옵션 확인을 요청하세요. 자동 재시도는 없습니다.',provider_rate_limited:'제공자 요청 한도에 도달했습니다. 자동 재시도는 없습니다.'});
  Object.assign(text.en,{samples:'Decoder samples',sample:'Sample',data:'Raw data',expected:'Expected IPv4 (comma or space separated)',usage:'Usage',example:'Example',validation:'Validation (not sent to model)',complete:'Complete expected set',add:'Add sample',remove:'Remove sample',generate:'Generate new candidates (uses configured model)',inputError:'Provide 1–6 distinct samples, at least one example, and 1–8 canonical expected IPv4 addresses per sample (raw data ≤2 KiB).',candidates:'Verified candidates',apply:'Apply to draft',draftOnly:'Draft only — Preview and revision-checked Save remain separate.',candidateWarning:'Candidate, not proof. Distinct inputs do not establish independent observations. Built-ins use defaults only.',noValidation:'No validation samples were supplied.',steps:'Decoder steps',examples:'Example results',validationResults:'Validation results',recommendation:'Recommendation only — built-in or verification did not qualify for draft application.',applied:'Applied to editor draft only.',catalogOnly:'Catalog recommendation only; no model requested.',insufficient:'No generated candidate; insufficient evidence or unsupported transformation.'});
  Object.assign(text.ko,{samples:'디코더 샘플',sample:'샘플',data:'원시 데이터',expected:'예상 IPv4 (쉼표 또는 공백 구분)',usage:'용도',example:'예제',validation:'검증 (모델에 전송하지 않음)',complete:'예상 목록이 완전함',add:'샘플 추가',remove:'샘플 삭제',generate:'새 후보 생성 (설정된 모델 사용)',inputError:'서로 다른 샘플 1–6개, 예제 최소 1개와 각 샘플의 정규 IPv4 주소 1–8개를 입력하세요 (원시 데이터 ≤2 KiB).',candidates:'검증된 후보',apply:'초안에 적용',draftOnly:'초안만 변경합니다. 미리보기와 리비전 확인 저장은 별도입니다.',candidateWarning:'후보이지 증명은 아닙니다. 다른 입력은 독립 관찰을 입증하지 않습니다. 내장 디코더는 기본값만 사용합니다.',noValidation:'검증용 샘플을 제공하지 않았습니다.',steps:'디코더 단계',examples:'예제 결과',validationResults:'검증 결과',recommendation:'추천 전용 — 내장 디코더이거나 초안 적용 검증을 통과하지 못했습니다.',applied:'편집기 초안에만 적용했습니다.',catalogOnly:'카탈로그 추천만 수행했습니다. 모델을 요청하지 않았습니다.',insufficient:'생성된 후보가 없습니다. 근거가 부족하거나 지원하지 않는 변환입니다.'});
  Object.assign(text.en,{serverSummary:'Server facts summary — deterministic, not AI',serverLimitations:'Server limitations',modelCoverage:'Model raw-data coverage',shownBytes:'shown UTF-8 bytes',omittedBytes:'omitted bytes',completeExamples:'complete examples',excerptedExamples:'excerpted examples',excerptWarning:'Separate prefix/suffix excerpts; the omitted middle was not shown to the model. Excerpts are not complete samples.',fullVerification:'Full originals and validation samples remain the verifier input; validation samples are not sent to the model.',allShown:'All example raw data was shown to the model.',commitment:'Server-recorded commitment to canonical messages + schema bytes; not browser verification of dispatch, HTTP/options, model attention, tokens or latency.'});
  Object.assign(text.ko,{serverSummary:'서버 사실 요약 — 결정적 결과, AI 아님',serverLimitations:'서버 한계',modelCoverage:'모델 원시 데이터 범위',shownBytes:'표시 UTF-8 바이트',omittedBytes:'생략 바이트',completeExamples:'전체 예제',excerptedExamples:'발췌 예제',excerptWarning:'접두사·접미사는 별도 발췌입니다. 생략된 중간 부분은 모델에 표시하지 않았으며 발췌는 전체 샘플이 아닙니다.',fullVerification:'전체 원본과 검증 샘플은 검증기의 입력으로 유지합니다. 검증 샘플은 모델에 전송하지 않습니다.',allShown:'모든 예제 원시 데이터를 모델에 표시했습니다.',commitment:'정규 메시지 + 스키마 바이트에 대한 서버 기록입니다. 브라우저가 전송, HTTP/옵션, 모델 주의, 토큰 또는 지연 시간을 검증한 것이 아닙니다.'});
  const warningText = {
    origin_independence_unknown:['Source categories do not prove independent origins.','소스 분류는 독립 출처를 증명하지 않습니다.'],
    not_attribution:['Relationship evidence is not attribution or proof of compromise.','관계 근거는 공격자 귀속 또는 침해의 증거가 아닙니다.'],
    observation_coverage_unknown:['Observation coverage is unknown.','관찰 범위는 알 수 없습니다.'],
    cached_observations_only:['Cached observations only; no new lookups.','캐시된 관찰만 사용하며 새 조회는 없습니다.'],
    raw_values_not_sent:['Raw provider values were not sent to the model.','원시 제공자 값은 모델에 전송하지 않았습니다.'],
    coverage_incomplete:['Coverage is incomplete.','관찰 범위가 불완전합니다.'],
    snapshots_not_atomic:['Diagnostics and progress were captured separately.','진단과 진행 상태는 별도로 수집되었습니다.'],
    counts_stale:['Counts may be stale.','개수가 오래된 값일 수 있습니다.'],
    lookup_coverage_incomplete:['Lookup coverage is incomplete.','조회 범위가 불완전합니다.'],
    storage_unavailable:['Storage is unavailable.','저장소를 사용할 수 없습니다.']
  };
  const errorCodes = ['invalid_request','sensitive_input','not_found','source_not_ready','source_unavailable','source_revoked','too_large','verification_failed','busy','invalid_model_output','provider_failed','provider_request_rejected','provider_auth_failed','provider_rate_limited','disabled','model_unavailable','provider_unsettled','audit_unavailable','privacy_unavailable','stopped','deadline_exceeded'];
  const bytes = value => new TextEncoder().encode(value).length;
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  // Accept native JSON prototypes across realms, not custom chains that can
  // inherit a serialization hook. Null-prototype records remain data-only.
  function nativePrototype(value, constructor, nullable=false) {
    const proto=Object.getPrototypeOf(value);
    if(proto===null)return nullable;
    const own=Object.getOwnPropertyDescriptor(proto,'constructor');
    return !!own && Object.hasOwn(own,'value') && typeof own.value==='function' &&
      Function.prototype.toString.call(own.value)===Function.prototype.toString.call(constructor) &&
      Object.getOwnPropertyDescriptor(own.value,'prototype')?.value===proto;
  }
  const record = value => object(value) && nativePrototype(value,Object,true);
  const dataProperty = (value,key) => {const d=Object.getOwnPropertyDescriptor(value,key);return !!d && d.enumerable && Object.hasOwn(d,'value');};
  const exact = (value, keys) => record(value) && Reflect.ownKeys(value).length === keys.length && keys.every(k=>dataProperty(value,k));
  const integer = n => Number.isSafeInteger(n) && n >= 0;
  const string = (value, limit) => typeof value === 'string' && value.length <= limit && bytes(value) <= limit;
  const hex = (value,n) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(value);
  const ipv4 = value => typeof value === 'string' && /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value) && value.split('.').every(p=>Number(p)<=255);
  const clone = value => JSON.parse(JSON.stringify(value));
  function validJSON(value, depth=0) {
    if (depth>16) return false;
    if (value===null || typeof value==='boolean') return true;
    if (typeof value==='string')return unicode(value);
    if (typeof value==='number') return Number.isFinite(value);
    if (Array.isArray(value)) return nativePrototype(value,Array) && value.length<=256 && Reflect.ownKeys(value).length===value.length+1 && Array.from({length:value.length},(_,i)=>i).every(i=>dataProperty(value,String(i)) && validJSON(value[i],depth+1));
    if(!record(value))return false;
    const keys=Reflect.ownKeys(value);
    return keys.length<=128 && keys.every(key=>typeof key==='string' && key!=='__proto__' && key!=='toJSON' && dataProperty(value,key) && validJSON(value[key],depth+1));
  }
  function fail(code='invalid') { const error = new Error('Local AI request refused.'); error.code=code; throw error; }
  function el(tag, value, className) {
    const node=document.createElement(tag); if(value!==undefined)node.textContent=value; if(className)node.className=className; return node;
  }
  function region(name, tag='section') { const node=el(tag);node.dataset.ai=name;return node; }
  function button(label, handler) {const node=el('button',label);node.type='button';node.addEventListener('click',handler);return node;}
  function baseRequest(options) {
    const base=options.getRequest();
    if(!object(base) || base.kind!==options.kind)fail('source');
    if(base.kind==='delivery' && exact(base,['kind']))return {kind:base.kind};
    if(base.kind==='decoder_suggest' && exact(base,['kind','decoder_type']) && ['TXT','A'].includes(base.decoder_type))return {kind:base.kind,decoder_type:base.decoder_type};
    if(base.kind==='relationship_pair' && exact(base,['kind','source']) && exact(base.source,['job_id','a','b']) && hex(base.source.job_id,32) && ipv4(base.source.a) && ipv4(base.source.b) && base.source.a!==base.source.b) return {kind:base.kind,source:{job_id:base.source.job_id,a:base.source.a,b:base.source.b}};
    fail('source');
  }
  // Frozen server projection shapes. Integer facts are decimal strings, not JS
  // numbers; this retains int64 values and refuses unknown nested semantics.
  const enumOf = values => value => typeof value==='string' && values.includes(value);
  const decimal = value => typeof value==='string' && /^(0|[1-9]\d{0,18})$/.test(value) && BigInt(value)<=9223372036854775807n;
  const flag = value => typeof value==='boolean';
  const nullable = check => value => value===null || check(value);
  const arrayOf = (check,max) => value => Array.isArray(value) && value.length<=max && value.every(check);
  const shape = spec => value => exact(value,Object.keys(spec)) && Object.entries(spec).every(([key,check])=>check(value[key]));
  const fields = (names,check) => Object.fromEntries(names.split(' ').map(key=>[key,check]));
  const reason=enumOf('delivery_storage delivery_capacity tracking_overflow old_binding_blocked client_unavailable configuration_unavailable provider_auth provider_tls provider_timeout provider_transport provider_rate_limit provider_unavailable provider_response provider_work_limit attempts_exhausted invalid_payload recovery_gap receipt_persistence history_persistence delivery_unknown destination_disabled destination_invalid adapter_unapplied removal_disabled tls_config tls_error provider_transient provider_http provider_protocol transport_error response_limit attribute_limit payload_invalid payload_limit sighting_absent'.split(' '));
  const coverage=enumOf(['covered','gap','rebaselining']);
  const providerDetail=shape({operation:enumOf(['unknown','teams_send','misp_read','misp_add','misp_delete','misp_sighting_read','misp_sighting_add']),http_status:nullable(v=>decimal(v) && Number(v)>=100 && Number(v)<=599),...fields('response_bytes response_limit attribute_count attribute_limit',nullable(decimal)),tls_kind:nullable(enumOf(['certificate_verify','ssl_failure'])),tls_verify:nullable(flag)});
  const diagnosticRecord=shape({at:decimal,channel:enumOf(['teams','misp']),state:enumOf(['acked','continue','retry','blocked','failed']),reason:nullable(reason),attempt:decimal,items:decimal,diagnostic:providerDetail});
  const diagnosticChannel=shape({latest_result:nullable(diagnosticRecord),latest_failure:nullable(diagnosticRecord),blocked_by_reason:arrayOf(shape({reason,count:decimal}),64)});
  const healthChannel=shape({enabled:flag,pending:decimal,blocked:decimal,last_success_at:nullable(decimal),last_error:nullable(reason)});
  const progressChannel=shape({state:enumOf(['disabled','idle','queued','retry_wait','blocked','active','stalled','unavailable']),...fields('last_attempt_at in_flight_age_seconds',nullable(decimal))});
  const factShapes={
    diagnostics_summary:shape({version:v=>v==='1',observed_at:decimal,...fields('counts_stale storage_ok worker_running',flag),coverage,storage_error:nullable(shape({at:decimal,stage:enumOf('open_owner open_db open_validate transaction_begin transaction_body transaction_commit transaction_readback health_refresh worker'.split(' ')),code:enumOf('sqlite_busy sqlite_full sqlite_readonly sqlite_corrupt sqlite_io sqlite_error permission_denied disk_full owner_lock os_error invalid_state worker_exception unknown'.split(' '))}))}),
    diagnostics_teams:diagnosticChannel,diagnostics_misp:diagnosticChannel,diagnostics_recent_failures:arrayOf(diagnosticRecord,10),
    progress_summary:shape({status:enumOf(['disabled','ok','degraded','blocked']),observation_policy:v=>v==='continue',...fields('storage_ok worker_running accounting_complete tracking_complete counts_stale',flag),coverage,...fields('missed_total missed_unpersisted failed_total acked_total pending retry_wait blocked',decimal),oldest_pending_age_seconds:nullable(decimal),capacity:shape(fields('used_receipts max_receipts used_payload_bytes max_payload_bytes',decimal)),last_error:nullable(reason),progress_version:v=>v==='1',counts_age_seconds:nullable(decimal)}),
    progress_channels:shape({teams:healthChannel,misp:healthChannel}),
    progress_worker:shape({state:enumOf(['not_started','idle','active','stalled','recovering','failed','stopping','stopped']),operation:nullable(enumOf(['recover_storage','seal_batches','claim','provider_step','finish_step','observation_hook','sightings_step'])),channel:nullable(enumOf(['teams','misp'])),...fields('last_progress_at last_progress_age_seconds in_flight_age_seconds',nullable(decimal)),stall_after_seconds:decimal,channels:shape({teams:progressChannel,misp:progressChannel})}),
    progress_recovery:shape({state:enumOf(['ready','recovering','backoff','uncertain','stopped','failed']),retry_in_seconds:nullable(decimal),targets_rebaselining:decimal,absence_state:enumOf(['ready','awaiting_full','unknown'])}),
    progress_lookup:shape({...fields('last_attempt_at last_success_at',nullable(decimal)),...fields('in_flight failed_targets uncertain_targets',decimal),coverage:enumOf(['complete','partial','unknown']),counts_stale:flag}),
    pair_assessment:shape({...fields('legacy_score relationship_strength evidence_score botnet_evidence_score',v=>decimal(v) && Number(v)<=100),raw_evidence_score:decimal,source_category_count:v=>decimal(v) && Number(v)<=2,source_categories:arrayOf(enumOf(['virustotal','tracedns']),2),verdict:enumOf(['insufficient_evidence','related_infrastructure','same_botnet_likely']),producer_confidence:enumOf(['low','medium','high'])}),
    family_scores:value=>object(value) && Object.keys(value).every(key=>['infrastructure','tls','threat_intel','local_dns'].includes(key) && decimal(value[key]) && Number(value[key])<=100),
    analysis_window:shape({as_of:decimal,lookback_days:decimal,cutoff:nullable(decimal)}),
    quality:shape({...fields('analysis_complete candidate_analysis_complete cluster_topology_complete pair_detail_complete enrichment_complete candidate_limit_reached candidate_work_limit_reached pair_heap_truncated local_context_truncated vt_enabled',flag),...fields('candidate_limit candidate_work_limit candidate_enumeration_count unique_candidate_count evaluated_candidate_count deduped_candidate_count vt_attempted vt_eligible_count vt_skipped_non_global vt_report_count',decimal),warning_codes:arrayOf(enumOf(qualityWarnings),qualityWarnings.length)})
  };
  const signalShape=shape({type:enumOf(pairTypes),family:enumOf(['infrastructure','tls','threat_intel','local_dns']),source:enumOf(['virustotal','tracedns','derived_ip']),specificity:enumOf(['low','medium','high']),weight:v=>decimal(v) && Number(v)<=100,value_omitted:v=>v===true});
  for(const kind of pairTypes)factShapes['evidence_'+kind]=value=>signalShape(value) && value.type===kind;
  function validSnapshotSource(source, request) {
    if(request.kind==='delivery')return shape(fields('diagnostics_observed_at diagnostics_captured_at progress_captured_at',decimal))(source);
    return exact(source,['job_id','a','b','analysis_as_of']) && ['job_id','a','b'].every(k=>source[k]===request.source[k]) && decimal(source.analysis_as_of);
  }
  function validSteps(steps, kind, generated) {
    if(!Array.isArray(steps) || steps.length<1 || steps.length>12)return false;
    return steps.every(step=>{
      if(!object(step) || typeof step.op!=='string')return false;
      if(!generated)return ['regex','base64','urlsafe_b64','xor_hex','extract_ip_prefix','ascii',...(kind==='A'?['xor32_ipv4']:[])].includes(step.op);
      if(['base64','urlsafe_b64','extract_ip_prefix','ascii'].includes(step.op))return exact(step,['op']);
      if(step.op==='xor_hex')return exact(step,['op','key']) && typeof step.key==='string' && /^(?:[a-fA-F0-9]{2}){1,64}$/.test(step.key);
      return kind==='A' && step.op==='xor32_ipv4' && exact(step,['op','key']) && typeof step.key==='string' && /^0x[a-fA-F0-9]{8}$/.test(step.key);
    });
  }
  function validSummary(summary, samples, usage) {
    const counters=['tested','passed','known_matches','missing_expected','unexpected_outputs','unverified_extra_outputs'];
    if(!exact(summary,[...counters,'results']) || counters.some(k=>!integer(summary[k])) || !Array.isArray(summary.results))return false;
    const indices=samples.map((s,i)=>s.usage===usage?i:-1).filter(i=>i>=0);
    if(summary.tested!==indices.length || summary.results.length!==indices.length)return false;
    const totals={tested:indices.length,passed:0,known_matches:0,missing_expected:0,unexpected_outputs:0,unverified_extra_outputs:0};
    for(let i=0;i<indices.length;i++) {
      const row=summary.results[i],sample=samples[indices[i]],fields=['matched_ips','missing_ips','unexpected_ips','unverified_extra_ips'];
      if(!exact(row,['sample_index','passed',...fields]) || row.sample_index!==indices[i] || typeof row.passed!=='boolean')return false;
      for(const key of fields)if(!Array.isArray(row[key]) || row[key].some(ip=>!ipv4(ip)) || new Set(row[key]).size!==row[key].length)return false;
      const expected=[...row.matched_ips,...row.missing_ips];
      if(new Set(expected).size!==expected.length || expected.length!==sample.expected_ips.length || expected.some(ip=>!sample.expected_ips.includes(ip)))return false;
      const extra=[...row.unexpected_ips,...row.unverified_extra_ips];
      if(new Set(extra).size!==extra.length || extra.some(ip=>expected.includes(ip)) || (sample.complete_expected?row.unverified_extra_ips:row.unexpected_ips).length)return false;
      if(row.passed!==(row.missing_ips.length===0 && row.unexpected_ips.length===0))return false;
      totals.passed+=Number(row.passed);totals.known_matches+=row.matched_ips.length;totals.missing_expected+=row.missing_ips.length;
      totals.unexpected_outputs+=row.unexpected_ips.length;totals.unverified_extra_outputs+=row.unverified_extra_ips.length;
    }
    return counters.every(key=>summary[key]===totals[key]);
  }
  function validReport(report, request, mode) {
    if(!exact(report,['kind','mode','complete','distinct_inputs','example_count','validation_count','evaluations','ranking_basis','candidates','limitations']) || report.kind!==request.decoder_type || report.mode!==mode || report.complete!==true || !Array.isArray(report.candidates) || report.candidates.length>(mode==='catalog'?32:3))return false;
    const examples=request.samples.filter(s=>s.usage==='example').length;
    if(report.distinct_inputs!==request.samples.length || report.example_count!==examples || report.validation_count!==request.samples.length-examples || report.evaluations!==report.candidates.length*request.samples.length || report.ranking_basis!==(mode==='catalog'?'examples_only':'fixed_generation_order'))return false;
    const limitations=['candidate_not_proof','distinct_inputs_not_independent_observations',...(mode==='catalog'?['builtin_defaults_only']:[]),...(examples===request.samples.length?['no_validation_samples']:[])];
    if(JSON.stringify(report.limitations)!==JSON.stringify(limitations))return false;
    const names=new Set();
    return report.candidates.every((candidate,index)=>{
      if(!exact(candidate,['name','source','steps','examples','validation']) || !string(candidate.name,32768) || !/^[A-Za-z0-9_-]+$/.test(candidate.name) || names.has(candidate.name))return false;
      names.add(candidate.name);
      if(mode==='generated'?(candidate.source!=='generated' || candidate.name!==`generated_${index+1}`):!['builtin','custom'].includes(candidate.source))return false;
      if(candidate.source==='builtin'?candidate.steps!==null:!validSteps(candidate.steps,request.decoder_type,candidate.source==='generated'))return false;
      return validSummary(candidate.examples,request.samples,'example') && validSummary(candidate.validation,request.samples,'validation');
    });
  }
  const sameJSON = (a,b) => {
    if(a===b)return true;
    if(Array.isArray(a))return Array.isArray(b) && a.length===b.length && a.every((v,i)=>sameJSON(v,b[i]));
    return object(a) && exact(b,Object.keys(a)) && Object.keys(a).every(key=>sameJSON(a[key],b[key]));
  };
  function validModelInput(input, snapshot, digest) {
    if(!exact(input,['version','policy','source_snapshot_digest','view','coverage','messages_schema_bytes','messages_schema_digest']) || input.version!==1 || input.policy!=='decoder_examples_utf8_v1' || input.source_snapshot_digest!==digest || !integer(input.messages_schema_bytes) || input.messages_schema_bytes<1 || input.messages_schema_bytes>16384 || !hex(input.messages_schema_digest,64) || bytes(JSON.stringify(input))>10240)return false;
    // Reproduce only the deterministic example projection, not message custody.
    // Browser validation does not prove dispatch, HTTP framing or model attention.
    const rows=snapshot.examples;
    if(!rows.length || rows.length>6 || rows.some(row=>!unicode(row.data) || !string(row.data,2048)))return false;
    const sizes=rows.map(row=>bytes(row.data)), quotas=sizes.map(()=>0);
    const original=sizes.reduce((a,b)=>a+b,0);
    let remaining=Math.min(original,1024);
    while(remaining)for(let i=0;i<sizes.length && remaining;i++)if(quotas[i]<sizes[i]){quotas[i]++;remaining--;}
    const view=clone(snapshot);let shown=0,complete=0;
    for(let i=0;i<rows.length;i++) {
      const row=view.examples[i], quota=quotas[i];
      if(sizes[i]<=quota){shown+=sizes[i];complete++;continue;}
      const scalars=Array.from(rows[i].data);
      const segment=(items,limit)=>{let used=0,parts=[];for(const part of items){const size=bytes(part);if(used+size>limit)break;used+=size;parts.push(part);}return parts;};
      const prefix=segment(scalars,Math.ceil(3*quota/4)).join('');
      const suffix=segment([...scalars].reverse(),Math.floor(quota/4)).reverse().join('');
      const count=bytes(prefix)+bytes(suffix);shown+=count;
      delete row.data;
      row.excerpt={original_utf8_bytes:sizes[i],prefix,suffix,omitted_utf8_bytes:sizes[i]-count};
    }
    const coverage={original_utf8_bytes:original,shown_utf8_bytes:shown,omitted_utf8_bytes:original-shown,complete_examples:complete,excerpted_examples:rows.length-complete};
    if(!sameJSON(view,input.view) || !sameJSON(coverage,input.coverage) || bytes(JSON.stringify(view))>8192 || bytes(JSON.stringify(view.examples.map(row=>row.expected_ips)))>1024)return false;
    const blank=clone(view);
    for(const row of blank.examples){row.expected_ips=[];if(Object.hasOwn(row,'data'))row.data='';else row.excerpt.prefix=row.excerpt.suffix='';}
    return bytes(JSON.stringify(blank))<=1024 && bytes(JSON.stringify({...input,view:blank}))<=2048;
  }
  function validDecoderResult(result, request) {
    if(!exact(result,['snapshot','snapshot_digest','source_revision','model','catalog','generated','proposal','model_input']) || !hex(result.snapshot_digest,64) || !integer(result.source_revision) || !validJSON(result) || bytes(JSON.stringify(result))>32768 || !validDecoderSnapshot(result.snapshot,request) || bytes(JSON.stringify(result.snapshot))>8192 || !validModel(result.model) || !validReport(result.catalog,request,'catalog'))return false;
    if(!request.generate)return result.proposal===null && result.generated===null && result.model===null && result.model_input===null;
    if(result.model===null || !validModelInput(result.model_input,result.snapshot,result.snapshot_digest))return false;
    const proposal=result.proposal;
    if(!exact(proposal,['version','kind','language','snapshot_digest','candidates','insufficient_reason']) || proposal.version!==1 || proposal.kind!=='decoder_suggest' || proposal.language!==request.language || proposal.snapshot_digest!==result.snapshot_digest || !Array.isArray(proposal.candidates) || proposal.candidates.length>3 || proposal.candidates.some(c=>!exact(c,['steps']) || !validSteps(c.steps,request.decoder_type,true)))return false;
    if(!proposal.candidates.length)return ['insufficient_examples','unsupported_transformation','no_candidate'].includes(proposal.insufficient_reason) && validReport(result.generated,request,'generated') && !result.generated.candidates.length;
    return proposal.insufficient_reason===null && validReport(result.generated,request,'generated') && result.generated.candidates.length===proposal.candidates.length && result.generated.candidates.every((c,i)=>JSON.stringify(c.steps)===JSON.stringify(proposal.candidates[i].steps));
  }
  function validDecoderSnapshot(snapshot, request) {
    if(!exact(snapshot,['version','kind','decoder_type','examples']) || snapshot.version!==1 ||
      snapshot.kind!=='decoder_suggest' || snapshot.decoder_type!==request.decoder_type || !Array.isArray(snapshot.examples))return false;
    const examples=request.samples.filter(sample=>sample.usage==='example');
    return snapshot.examples.length===examples.length && snapshot.examples.every((sample,index)=>{
      const expected=examples[index];
      return exact(sample,['data','expected_ips','usage','complete_expected']) && sample.data===expected.data &&
        sample.usage==='example' && sample.complete_expected===expected.complete_expected &&
        Array.isArray(sample.expected_ips) && sample.expected_ips.length===expected.expected_ips.length &&
        sample.expected_ips.every((ip,i)=>ip===expected.expected_ips[i]);
    });
  }
  function canApply(candidate) {
    const clean=s=>s.passed===s.tested && s.missing_expected===0 && s.unexpected_outputs===0 && s.unverified_extra_outputs===0;
    return ['custom','generated'].includes(candidate.source) && Array.isArray(candidate.steps) && candidate.steps.length>0 && candidate.examples.tested>0 && clean(candidate.examples) && clean(candidate.validation);
  }
  // Fixed server code/citation registry, independent of the model's free prose.
  const summaryCodes={
    relationship_pair:{summary:['pair_assessment','pair_signals'],counterpoints:[],limitations:['pair_scope','pair_coverage','pair_attribution']},
    delivery:{summary:['delivery_overview','delivery_teams','delivery_misp'],counterpoints:['delivery_recovery'],limitations:['delivery_snapshot_scope','delivery_capture_times','delivery_coverage','delivery_lookup']}
  };
  const summaryFacts={
    pair_assessment:['pair_assessment'],pair_scope:['analysis_window'],pair_coverage:['quality'],pair_attribution:['pair_assessment'],
    delivery_overview:['progress_summary','progress_worker','diagnostics_summary'],
    delivery_teams:['progress_channels','diagnostics_teams'],delivery_misp:['progress_channels','diagnostics_misp'],
    delivery_recovery:['progress_recovery'],delivery_snapshot_scope:['diagnostics_summary','progress_summary'],
    delivery_capture_times:['diagnostics_summary','progress_summary'],delivery_coverage:['diagnostics_summary','progress_summary'],delivery_lookup:['progress_lookup']
  };
  // Reject unpaired UTF-16 surrogates rather than silently UTF-8 replacing them.
  const unicode = value => typeof value==='string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
  function validFactsSummary(summary, snapshot, request, digest) {
    if(!exact(summary,['version','kind','language','snapshot_digest','summary','counterpoints','limitations']) || summary.version!==1 || summary.kind!==request.kind || summary.language!==request.language || summary.snapshot_digest!==digest || bytes(JSON.stringify(summary))>6144)return false;
    const facts=new Map(snapshot.facts.map(f=>[f.key,f]));
    const required=request.kind==='delivery'?factKeys.delivery:['pair_assessment','family_scores','analysis_window','quality'];
    if(required.some(key=>!facts.has(key)))return false;
    const top=snapshot.facts.filter(f=>f.key.startsWith('evidence_')).sort((a,b)=>Number(b.value.weight)-Number(a.value.weight) || (a.value.type<b.value.type?-1:a.value.type>b.value.type?1:0)).slice(0,3).map(f=>f.key);
    for(const [section,codes] of Object.entries(summaryCodes[request.kind])) {
      if(!Array.isArray(summary[section]) || summary[section].length!==codes.length)return false;
      for(let i=0;i<codes.length;i++) {
        const claim=summary[section][i], code=codes[i];
        if(!exact(claim,['code','text','evidence_ids']) || claim.code!==code || !string(claim.text,512) || !claim.text.length || !unicode(claim.text))return false;
        const keys=code==='pair_signals'?(top.length?top:['pair_assessment']):summaryFacts[code];
        if(!Array.isArray(claim.evidence_ids) || claim.evidence_ids.length!==keys.length || !keys.every((key,j)=>facts.has(key) && claim.evidence_ids[j]===facts.get(key).id))return false;
      }
    }
    return true;
  }
  function validResult(result, request) {
    if(request.kind==='decoder_suggest')return validDecoderResult(result,request);
    if(!exact(result,['snapshot','snapshot_digest','source_revision','model','interpretation','facts_summary']) || !hex(result.snapshot_digest,64) || !integer(result.source_revision) || !validJSON(result) || bytes(JSON.stringify(result))>32768)return false;
    const snapshot=result.snapshot, interpretation=result.interpretation, kind=request.kind;
    if(!exact(snapshot,['version','kind','source','facts','warnings']) || snapshot.version!==1 || snapshot.kind!==kind || !object(snapshot.source) || bytes(JSON.stringify(snapshot))>8192 || !Array.isArray(snapshot.facts) || !snapshot.facts.length || snapshot.facts.length>64 || !Array.isArray(snapshot.warnings) || snapshot.warnings.some(w=>!warningCodes.includes(w)))return false;
    const ids=new Set(), keys=new Set();
    for(const fact of snapshot.facts) {
      if(!exact(fact,['id','key','value']) || typeof fact.id!=='string' || !/^e[1-9][0-9]{0,2}$/.test(fact.id) || ids.has(fact.id) || keys.has(fact.key) || !factKeys[kind]?.includes(fact.key) || !factShapes[fact.key]?.(fact.value))return false;
      ids.add(fact.id);keys.add(fact.key);
    }
    if(!validSnapshotSource(snapshot.source,request))return false;
    if(!exact(interpretation,['version','kind','language','snapshot_digest','summary','counterpoints','limitations','next_checks']) || interpretation.version!==1 || interpretation.kind!==kind || interpretation.language!==request.language || interpretation.snapshot_digest!==result.snapshot_digest)return false;
    const citations = list => Array.isArray(list) && list.length>=1 && list.length<=4 && new Set(list).size===list.length && list.every(id=>typeof id==='string' && ids.has(id));
    for(const [key,min,max] of [['summary',1,3],['counterpoints',0,4],['limitations',0,4]]) {
      if(!Array.isArray(interpretation[key]) || interpretation[key].length<min || interpretation[key].length>max || interpretation[key].some(c=>!exact(c,['text','evidence_ids']) || !string(c.text,512) || !c.text.length || !citations(c.evidence_ids)))return false;
    }
    if(!Array.isArray(interpretation.next_checks) || interpretation.next_checks.length>3 || interpretation.next_checks.some(c=>!exact(c,['code','evidence_ids']) || !checks[kind]?.includes(c.code) || !citations(c.evidence_ids)))return false;
    return result.model!==null && validModel(result.model) && validFactsSummary(result.facts_summary,snapshot,request,result.snapshot_digest);
  }
  function validModel(model) {
    if(model!==null) {
      if(!record(model))return false;
      const keys=Reflect.ownKeys(model);
      if(keys.length>9 || keys.some(key=>typeof key!=='string' || !dataProperty(model,key)))return false;
      const counter=value=>typeof value==='string' && /^(?:0|[1-9][0-9]{0,18})(?![\s\S])/.test(value) && BigInt(value)<=9223372036854775807n;
      if(Object.hasOwn(model,'provider')) {
        const required=['provider','requested_model','reported_model','finish_reason','response_format'];
        const usage=['prompt_tokens','completion_tokens','total_tokens'];
        if(model.provider!=='openai_compatible' || required.some(key=>!keys.includes(key)) || keys.some(key=>!required.includes(key) && !usage.includes(key)) || model.response_format!=='json_object' || !['stop','length','content_filter'].includes(model.finish_reason))return false;
        for(const key of ['requested_model','reported_model'])if(typeof model[key]!=='string' || !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}(?![\s\S])/.test(model[key]))return false;
        if(usage.some(key=>Object.hasOwn(model,key) && !counter(model[key])))return false;
        return !usage.every(key=>Object.hasOwn(model,key)) || BigInt(model.prompt_tokens)+BigInt(model.completion_tokens)===BigInt(model.total_tokens);
      }
      if(!string(model.model,256) || !model.model.length || !unicode(model.model) || !hex(model.model_digest,64))return false;
      for(const [key,value] of Object.entries(model)) {
        if(['model','model_digest'].includes(key))continue;
        if(key==='done_reason' && ['stop','length'].includes(value))continue;
        if(!['eval_count','prompt_eval_count','total_duration','load_duration','prompt_eval_duration','eval_duration'].includes(key) || !counter(value))return false;
      }
    }
    return true;
  }
  function validEnvelope(job, request) {
    return exact(job,['job_id','kind','language','status','created_at','deadline_at','audit_status','error','result','cancel_requested']) && hex(job.job_id,32) && job.kind===request.kind && job.language===request.language && ['queued','running','cancel_pending','completed','failed','cancelled'].includes(job.status) && ['pending','success','failed'].includes(job.audit_status) && integer(job.created_at) && integer(job.deadline_at) && job.deadline_at>=job.created_at && typeof job.cancel_requested==='boolean' && (job.error===null || errorCodes.includes(job.error)) && validJSON(job) && bytes(JSON.stringify(job))<=32768;
  }
  function mount(container, options) {
    const kind=options?.kind;
    if(!container || !kinds.includes(kind) || typeof options.getRequest!=='function' || typeof options.isCurrent!=='function')throw new TypeError('Invalid local AI owner.');
    active.get(kind)?.dispose();
    let disposed=false, language=document.documentElement.lang==='ko'?'ko':'en', generation=0;
    let unsubscribe=()=>{}, pending=null, lastRequest=null, retained=null, statusKey='idle';
    const returnFocus=document.activeElement;
    const panel=el('section',undefined,'local-ai'), title=el('h3'), controls=el('div',undefined,'local-ai-controls');
    const languageLabel=el('label'), languageText=el('span'), languageInput=el('select');
    for(const [value,name] of [['en','English'],['ko','한국어']]){const option=el('option',name);option.value=value;languageInput.append(option);}
    languageInput.value=language;languageLabel.append(languageText,languageInput);
    const run=button('',start), cancel=button('',cancelClick), close=button('',closePanel), status=el('p',undefined,'local-ai-status'), results=region('results');
    const cancelError=region('cancel-error','p');cancelError.setAttribute('role','status');
    let cancelFailed=false, acceptanceUncertain=false;
    const transports=new Set();
    status.setAttribute('role','status');status.setAttribute('aria-live','polite');status.dataset.ai='status';
    controls.append(languageLabel,run,cancel,close);panel.append(title,controls,status,cancelError,results);container.replaceChildren(panel);
    const t=()=>text[language];
    const editor=region('sample-editors');
    let sampleRows=[{data:typeof options.initialData==='string'?options.initialData:'',expected:'',usage:'example',complete:true}];
    let generate=false;
    if(kind==='decoder_suggest')panel.insertBefore(editor,status);
    function edited() {
      generation++;pending?.wake?.();
      if(retained)renderResult(retained);
      translate();
    }
    function field(label,control) {
      const wrap=el('label'),caption=el('span',label);control.setAttribute('aria-label',label);wrap.append(caption,control);return wrap;
    }
    function paintSamples() {
      if(kind!=='decoder_suggest')return;
      editor.replaceChildren(el('h4',t().samples));
      sampleRows.forEach((sample,index)=>{
        const row=region('sample','fieldset');row.append(el('legend',`${t().sample} ${index+1}`));
        const data=el('textarea');data.value=sample.data;data.rows=3;data.spellcheck=false;
        data.addEventListener('input',()=>{sample.data=data.value;edited();});
        const expected=el('textarea');expected.value=sample.expected;expected.rows=2;expected.spellcheck=false;
        expected.addEventListener('input',()=>{sample.expected=expected.value;edited();});
        const usage=el('select');for(const [value,label] of [['example',t().example],['validation',t().validation]]){const option=el('option',label);option.value=value;usage.append(option);}usage.value=sample.usage;
        usage.addEventListener('change',()=>{sample.usage=usage.value;edited();});
        const complete=el('input');complete.type='checkbox';complete.checked=sample.complete;
        complete.addEventListener('change',()=>{sample.complete=complete.checked;edited();});
        const remove=button(t().remove,()=>{if(!current())return;sampleRows.splice(index,1);edited();paintSamples();editor.querySelector('textarea')?.focus();});remove.disabled=sampleRows.length===1;
        row.append(field(t().data,data),field(t().expected,expected),field(t().usage,usage),field(t().complete,complete),remove);editor.append(row);
      });
      const add=button(t().add,()=>{if(!current() || sampleRows.length>=6)return;sampleRows.push({data:'',expected:'',usage:'example',complete:true});edited();paintSamples();editor.querySelectorAll('textarea')[sampleRows.length*2-2].focus();});add.disabled=sampleRows.length>=6;
      const generationInput=el('input');generationInput.type='checkbox';generationInput.checked=generate;generationInput.addEventListener('change',()=>{generate=generationInput.checked;edited();});
      editor.append(add,field(t().generate,generationInput));
    }
    function fullRequest(base) {
      const request={...base,language};
      if(kind==='decoder_suggest') {
        const seen=new Set();
        request.samples=sampleRows.map(sample=>{
          const ips=sample.expected.trim()?sample.expected.trim().split(/[\s,]+/):[];
          if(!string(sample.data,2048) || seen.has(sample.data) || !ips.length || ips.length>8 || ips.some(ip=>!ipv4(ip)) || new Set(ips).size!==ips.length || !['example','validation'].includes(sample.usage))fail('inputError');
          seen.add(sample.data);return {data:sample.data,expected_ips:ips,usage:sample.usage,complete_expected:sample.complete};
        });
        if(!request.samples.some(s=>s.usage==='example'))fail('inputError');request.generate=generate;
      }
      if(bytes(JSON.stringify(request))>16384)fail('inputError');return request;
    }
    function current(owner) {
      if(disposed || window.TraceAuth?.accessInvalidated)return false;
      try {
        const base=baseRequest(options), accepted=options.isCurrent();
        return accepted===true && (!owner || (owner.generation===generation && owner.base===JSON.stringify(base)));
      }catch(_){return false;}
    }
    function translate() {
      panel.lang=language;panel.setAttribute('aria-label',t().title);title.textContent=t().title;
      languageText.textContent=t().language;languageInput.setAttribute('aria-label',t().language);
      run.textContent=t().run;close.textContent=t().close;status.textContent=(t()[statusKey] || t().failed)+(acceptanceUncertain?' '+t().uncertain:'');
      run.disabled=!!pending;cancel.textContent=t().cancel;
      cancel.disabled=!pending || pending.cancelRequested || pending.terminal || !pending.sent;
      cancel.hidden=!pending;cancelError.textContent=cancelFailed?t().cancelFailed:'';
    }
    // Definitive revocation or disappearance of an accepted job/source retires
    // history. Unavailability/readiness, unrelated selectors and local edits do not.
    function retiresSource(error, owner) {
      const sameSource=owner?.sent && owner.request.kind==='relationship_pair' &&
        retained?.owner.request.kind==='relationship_pair' &&
        ['job_id','a','b'].every(key=>owner.request.source[key]===retained.owner.request.source[key]);
      return error?.code==='source_revoked' || (error?.code==='not_found' && (!!owner?.id || sameSource));
    }
    function showError(error, owner) {
      if(owner && (!current(owner) || lastRequest!==owner))return;
      const code=error?.code;
      if(retiresSource(error,owner)){
        generation++;retained=null;lastRequest=null;clearResultView();
        if(owner){owner.terminal=true;owner.wake?.();}
      }
      const security=['audit_unavailable','security_unavailable'].includes(code);
      statusKey=['provider_auth_failed','provider_request_rejected','provider_rate_limited'].includes(code)?code:code==='inputError'?'inputError':security?'security':code==='provider_unsettled'?'unsettled':code==='stopped'?'stopped':code==='disabled'?'disabled':code==='busy'?'busy':code==='source' || ['not_found','source_not_ready','source_unavailable','source_revoked'].includes(code)?'source':code==='timeout'?'timeout':code==='invalid'?'invalid':'failed';
      if(security)window.TraceAuth?.message?.(t().security,'security');
      translate();
    }
    function changed() { language=languageInput.value;edited();paintSamples(); }
    // Every read includes auth wait and body decoding. Create has an independent
    // 15s lifetime: retirement must not hide an accepted acknowledgement.
    async function read(url, options={}) {
      if(typeof window.TraceAuth?.readJSON!=='function')fail('failed');
      const transport=new AbortController(), detachable=options.method!=='POST';let timer,abort;
      const settled=new Promise((_,reject)=>{
        abort=()=>{const error=new Error('Local AI transport ended.');error.code=transport.signal.reason==='timeout'?'timeout':'failed';reject(error);};
        transport.signal.addEventListener('abort',abort,{once:true});
        timer=setTimeout(()=>transport.abort('timeout'),15000);
      });
      if(detachable)transports.add(transport);
      try{return await Promise.race([window.TraceAuth.readJSON(url,{...options,credentials:'same-origin',cache:'no-store',timeoutMs:15000,signal:transport.signal}),settled]);}
      finally{clearTimeout(timer);transport.signal.removeEventListener('abort',abort);transports.delete(transport);}
    }
    function responseError(response) {
      if(exact(response,['error','code','request_id']) && response.error===response.code &&
        errorCodes.includes(response.code) && hex(response.request_id,32))fail(response.code);
    }
    function pause(owner) {
      return new Promise(resolve=>{
        const end=()=>{clearTimeout(owner.timer);owner.wake=null;resolve();};
        owner.wake=end;owner.timer=setTimeout(end,1000);
      });
    }
    function accept(owner, response) {
      responseError(response);
      if(!validEnvelope(response,owner.request) || (owner.id && response.job_id!==owner.id))fail();
      if(!owner.id) {
        owner.id=response.job_id;owner.created=response.created_at;owner.serverDeadline=response.deadline_at;
        owner.deadline=Math.min(owner.deadline,performance.now()+Math.max(0,response.deadline_at-Date.now())+15000);
      } else if(response.created_at!==owner.created || response.deadline_at!==owner.serverDeadline)fail();
      const terminal=['completed','failed','cancelled'].includes(response.status);
      if(response.result!==null && (response.status!=='completed' || response.audit_status!=='success'))fail();
      if(response.audit_status==='failed'){owner.terminal=true;showError({code:'audit_unavailable'},owner);return;}
      if(terminal && response.audit_status==='pending'){statusKey='auditPending';translate();return;}
      if(!terminal){if(!owner.readError)statusKey=owner.cancelRequested || response.status==='cancel_pending'?'cancelPending':'working';translate();return;}
      owner.terminal=true; // terminal receipt is recorded before any result callback
      if(response.status==='cancelled'){statusKey='cancelled';translate();return;}
      if(response.status==='failed'){showError({code:response.error},owner);return;}
      if(response.error!==null || !validResult(response.result,owner.request))fail();
      retained={result:clone(response.result),owner};statusKey='completed';renderResult(retained);translate();
      if(kind==='decoder_suggest')panel.append(editor); // Results precede the still-editable samples.
    }
    async function cancelClick() {
      const owner=pending;
      if(!owner || owner.terminal || owner.cancelRequested || !owner.sent || !current(owner))return;
      owner.cancelRequested=true;if(!owner.readError)statusKey='cancelPending';translate();
      await sendCancel(owner);
    }
    async function sendCancel(owner) {
      if(!owner.id || owner.cancelSent || owner.terminal || !current(owner))return;
      owner.cancelSent=true;
      try {
        const response=await read('/ai/jobs/'+encodeURIComponent(owner.id)+'/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
        if(!current(owner) || lastRequest!==owner)return;
        responseError(response);
        const {cancellation_requested:requested,cancellation_confirmed:confirmed,...envelope}=response || {};
        if(typeof requested!=='boolean' || typeof confirmed!=='boolean' || !validEnvelope(envelope,owner.request) || (confirmed && envelope.status!=='cancelled'))fail();
        // A pending cancel cannot replace a terminal GET received meanwhile.
        if(!owner.terminal)accept(owner,envelope);
        if(owner.terminal)owner.wake?.();
      }catch(error){
        if(current(owner) && lastRequest===owner){
          cancelFailed=true;
          if(retiresSource(error,owner))showError(error,owner);
          else {if(error?.code==='audit_unavailable')window.TraceAuth?.message?.(t().security,'security');translate();}
        }
      }
    }
    async function start() {
      if(pending || !current())return;
      let base,request;
      try{base=baseRequest(options);request=fullRequest(base);}catch(error){showError(error);return;}
      generation++;if(retained)renderResult(retained);
      const owner={base:JSON.stringify(base),generation,request,deadline:performance.now()+135000,id:null,terminal:false,cancelRequested:false,cancelSent:false,sent:false};
      pending=owner;lastRequest=owner;cancelFailed=false;acceptanceUncertain=false;statusKey='working';translate();
      try {
        const availability=await read('/ai/status');
        if(!current(owner))return;
        responseError(availability);
        if(!exact(availability,['enabled','accepting','provider_state','queued','active_job']) || typeof availability.enabled!=='boolean' || typeof availability.accepting!=='boolean' || !integer(availability.queued) || availability.queued>2 || !['ready','busy','unsettled','unavailable','disabled','stopped'].includes(availability.provider_state))fail();
        if(!availability.enabled || availability.provider_state==='disabled')fail('disabled');
        // This status describes scheduler/audit eligibility, never model health.
        if(availability.provider_state==='unavailable')fail('audit_unavailable');
        if(availability.provider_state==='unsettled')fail('provider_unsettled');
        if(availability.provider_state==='stopped')fail('stopped');
        if(!availability.accepting || availability.active_job!==null || availability.provider_state!=='ready')fail('busy');
        owner.sent=true;translate();
        const response=await read('/ai/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request)});
        if(!current(owner))return;
        accept(owner,response);
        if(owner.cancelRequested && !owner.terminal)void sendCancel(owner);
        while(!owner.terminal && current(owner)) {
          await pause(owner);
          if(!current(owner) || owner.terminal)return;
          if(performance.now()>=owner.deadline)fail('timeout');
          try {
            const receipt=await read('/ai/jobs/'+encodeURIComponent(owner.id));
            if(!current(owner) || owner.terminal)return;
            if(performance.now()>=owner.deadline)fail('timeout');
            accept(owner,receipt);
          }catch(error){
            if(!current(owner))return;
            owner.readError=true;showError(error,owner);
            if(['invalid','not_found','source_revoked','source_unavailable','audit_unavailable'].includes(error?.code) || performance.now()>=owner.deadline)break;
          }
        }
      } catch(error){if(current(owner)){showError(error,owner);if(owner.sent && !owner.id && !errorCodes.includes(error?.code)){acceptanceUncertain=true;translate();}}}
      finally{owner.wake?.();if(!disposed && pending===owner){pending=null;translate();}}
    }
    // A render owns its listeners, including queued lazy disclosure events.
    // Retire them on replacement as well as hard source/auth retirement.
    let resultView=new AbortController(), clearProvenance=()=>{};
    function clearResultView(){
      resultView.abort();clearProvenance();clearProvenance=()=>{};
      resultView=new AbortController();results.replaceChildren();
    }
    function resultButton(label, handler){
      const node=el('button',label);node.type='button';
      node.addEventListener('click',handler,{signal:resultView.signal});
      return node;
    }
    function provenanceDetail(value, owner, onOpen){
      const provenance=region('provenance'), disclosure=el('details'), body=el('div');
      disclosure.append(el('summary',t().provenance));
      const empty=()=>{body.replaceChildren();body.remove();};
      const toggle=()=>{
        empty();
        if(disclosure.open && !disposed){
          onOpen();
          if(value.model_input)body.append(el('p',text[owner.request.language].commitment));
          body.append(el('pre',JSON.stringify(value,null,2)));disclosure.append(body);
        }
      };
      disclosure.addEventListener('toggle',toggle,{signal:resultView.signal});
      clearProvenance=()=>{
        disclosure.open=false;empty();value=null;onOpen=null;
      };
      if(!current(owner))provenance.append(el('p',t().stale,'local-ai-warning'));
      provenance.append(disclosure);
      return {node:provenance,close:()=>{disclosure.open=false;empty();}};
    }
    function renderDecoder(saved) {
      const {result,owner}=saved, content=document.createDocumentFragment(), captured=text[owner.request.language];
      const modelCoverage=region('model-coverage');modelCoverage.lang=owner.request.language;
      modelCoverage.append(el('h4',captured.modelCoverage));
      if(result.model_input){
        const c=result.model_input.coverage;
        modelCoverage.append(el('p',`${c.shown_utf8_bytes} / ${c.original_utf8_bytes} ${captured.shownBytes} · ${c.omitted_utf8_bytes} ${captured.omittedBytes}. ${c.complete_examples} ${captured.completeExamples} · ${c.excerpted_examples} ${captured.excerptedExamples}.`),
          el('p',c.excerpted_examples?captured.excerptWarning:captured.allShown,c.excerpted_examples?'local-ai-warning':undefined),el('p',captured.fullVerification));
      }else modelCoverage.append(el('p',captured.catalogOnly));
      const provenance=provenanceDetail({snapshot_digest:result.snapshot_digest,source_revision:result.source_revision,created_at:owner.created,decoder_type:owner.request.decoder_type,language:owner.request.language,model:result.model,model_input:result.model_input,
        verification:{complete:result.catalog.complete,distinct_inputs:result.catalog.distinct_inputs,example_count:result.catalog.example_count,validation_count:result.catalog.validation_count,catalog_evaluations:result.catalog.evaluations,generated_evaluations:result.generated?.evaluations || 0,ranking_basis:result.catalog.ranking_basis}},owner,()=>{detail.replaceChildren();detailOwner=null;});
      const warnings=region('warnings');warnings.append(el('h4',t().warnings),el('p',t().candidateWarning));
      if(!result.catalog.validation_count)warnings.append(el('p',t().noValidation));
      if(!owner.request.generate)warnings.append(el('p',t().catalogOnly));
      if(result.proposal && !result.proposal.candidates.length)warnings.append(el('p',t().insufficient));
      const facts=region('facts');facts.append(el('h4',t().facts),el('p',`${t().example}: ${result.catalog.example_count} · ${t().validationResults}: ${result.catalog.validation_count} · ${t().candidates}: ${result.catalog.candidates.length + (result.generated?.candidates.length || 0)}`));
      const candidates=[...result.catalog.candidates,...(result.generated?.candidates || [])];
      const list=region('candidate-list','div'), detail=region('candidate-detail'), paging=el('div',undefined,'local-ai-controls');
      let page=0,detailOwner=null;const count=el('span');
      const previous=resultButton(t().previous,()=>{if(!current(owner))return;page--;paint();previous.focus();});previous.dataset.ai='candidates-previous';
      const next=resultButton(t().next,()=>{if(!current(owner))return;page++;paint();next.focus();});next.dataset.ai='candidates-next';
      function show(candidate) {
        if(!current(owner))return;detailOwner=candidate;
        provenance.close();
        detail.replaceChildren(el('h5',candidate.name+' · '+candidate.source),el('p',t().draftOnly));
        detail.append(el('h5',t().steps),el('pre',JSON.stringify(candidate.steps,null,2)));
        for(const [key,label] of [['examples',t().examples],['validation',t().validationResults]]) {
          detail.append(el('h5',label),el('pre',JSON.stringify(candidate[key],null,2)));
          for(const row of candidate[key].results)detail.append(el('pre',JSON.stringify({sample_index:row.sample_index,expected_ips:owner.request.samples[row.sample_index].expected_ips,complete_expected:owner.request.samples[row.sample_index].complete_expected},null,2)));
        }
        const apply=resultButton(t().apply,()=>{
          if(detailOwner!==candidate || !current(owner) || !canApply(candidate) || typeof options.onApply!=='function')return;
          try{options.onApply(clone(candidate),clone(result));statusKey='applied';translate();}catch(_){showError({code:'source'});}
        });
        apply.disabled=!canApply(candidate) || typeof options.onApply!=='function';
        if(apply.disabled)detail.append(el('p',t().recommendation));detail.append(apply);
        detail.tabIndex=-1;detail.focus();
      }
      function paint() {
        list.replaceChildren();detail.replaceChildren();detailOwner=null;
        for(const candidate of candidates.slice(page*5,page*5+5)){
          const b=resultButton(candidate.name+' · '+candidate.source,()=>show(candidate));b.dataset.candidateName=candidate.name;b.disabled=!current(owner);list.append(b);
        }
        previous.disabled=page===0;next.disabled=(page+1)*5>=candidates.length;count.textContent=`${page+1} / ${Math.max(1,Math.ceil(candidates.length/5))}`;
      }
      paging.append(previous,count,next);paint();content.append(modelCoverage,facts,warnings,el('h4',t().candidates),list,paging,detail,provenance.node);results.replaceChildren(content);
    }
    function renderResult(saved) {
      clearResultView();
      if(kind==='decoder_suggest'){renderDecoder(saved);return;}
      const {result,owner}=saved, content=document.createDocumentFragment();
      const provenance=provenanceDetail({snapshot_digest:result.snapshot_digest,source_revision:result.source_revision,source:result.snapshot.source,model:result.model},owner,()=>detail.replaceChildren());
      const warnings=region('warnings');warnings.append(el('h4',t().warnings));
      for(const code of result.snapshot.warnings)warnings.append(el('p',(warningText[code]?.[language==='ko'?1:0] || (language==='ko'?'생산자 범위 제한':'Producer coverage limit'))+' · '+code));
      const facts=region('facts'), list=region('fact-list','div'), detail=region('fact-detail'), paging=el('div',undefined,'local-ai-controls');
      facts.append(el('h4',t().facts));
      const captured=text[owner.request.language], overview=region('server-summary');
      overview.lang=owner.request.language;overview.append(el('h4',captured.serverSummary));
      for(const section of ['summary','counterpoints','limitations']) {
        if(!result.facts_summary[section].length)continue;
        if(section!=='summary')overview.append(el('h5',section==='limitations'?captured.serverLimitations:captured.counterpoints));
        for(const claim of result.facts_summary[section]){
          const row=el('div',undefined,'local-ai-claim');row.dataset.claimCode=claim.code;row.append(el('p',claim.text));
          for(const id of claim.evidence_ids){const b=resultButton(id,()=>openFact(result.snapshot.facts.find(f=>f.id===id)));b.disabled=!current(owner);row.append(b);}
          overview.append(row);
        }
      }
      let page=0;const count=el('span');
      const previous=resultButton(t().previous,()=>{if(!current(owner))return;page--;paintFacts();previous.focus();});previous.dataset.ai='facts-previous';
      const next=resultButton(t().next,()=>{if(!current(owner))return;page++;paintFacts();next.focus();});next.dataset.ai='facts-next';
      function openFact(fact){
        if(!current(owner))return;
        provenance.close();
        detail.replaceChildren(el('h5',fact.id+' · '+fact.key),el('p',result.snapshot_digest),el('pre',JSON.stringify(fact.value,null,2)));
        detail.tabIndex=-1;detail.focus();
      }
      function paintFacts(){
        list.replaceChildren();detail.replaceChildren();
        for(const fact of result.snapshot.facts.slice(page*5,page*5+5)) {const b=resultButton(fact.id+' · '+fact.key,()=>openFact(fact));b.dataset.factId=fact.id;b.disabled=!current(owner);list.append(b);}
        previous.disabled=page===0;next.disabled=(page+1)*5>=result.snapshot.facts.length;count.textContent=`${page+1} / ${Math.ceil(result.snapshot.facts.length/5)}`;
      }
      paging.append(previous,count,next);facts.append(list,paging,detail);paintFacts();
      const interpretation=region('interpretation');interpretation.lang=owner.request.language;interpretation.append(el('h4',captured.interpretation),el('p',captured.citation));
      for(const key of ['summary','counterpoints','limitations']) {
        if(!result.interpretation[key].length)continue;
        interpretation.append(el('h5',captured[key]));
        for(const claim of result.interpretation[key]) {
          const row=el('div',undefined,'local-ai-claim');row.append(el('p',claim.text));
          for(const id of claim.evidence_ids){const b=resultButton(id,()=>openFact(result.snapshot.facts.find(f=>f.id===id)));b.disabled=!current(owner);row.append(b);}
          interpretation.append(row);
        }
      }
      const actions=region('next-checks');actions.append(el('h4',t().checks));
      for(const check of result.interpretation.next_checks){
        const target=result.snapshot.facts.find(f=>f.key===checkFacts[check.code]);
        const b=resultButton(checkLabels[check.code][language==='ko'?1:0],()=>{
          if(!current(owner) || !checks[kind].includes(check.code) || !target)return;
          openFact(target);options.onAction?.(check.code,clone(result));
        });
        b.disabled=!current(owner) || !target;actions.append(b);
      }
      content.append(overview,warnings,interpretation,facts,actions,provenance.node);
      results.replaceChildren(content);
    }
    function dispose() {
      if(disposed)return;disposed=true;generation++;
      unsubscribe();window.removeEventListener('pagehide',dispose);languageInput.removeEventListener('change',changed);
      pending?.wake?.();for(const transport of transports)transport.abort('detached');
      run.removeEventListener('click',start);cancel.removeEventListener('click',cancelClick);close.removeEventListener('click',closePanel);
      for(const input of editor.querySelectorAll('textarea,input'))input.value='';
      editor.replaceChildren();clearResultView();
      panel.replaceChildren();panel.remove();retained=null;pending=null;lastRequest=null;sampleRows=[];options=null;
      if(active.get(kind)===controller)active.delete(kind);
    }
    function closePanel(){dispose();if(returnFocus?.isConnected)returnFocus.focus();}
    const controller=Object.freeze({dispose});
    languageInput.addEventListener('change',changed);window.addEventListener('pagehide',dispose);
    unsubscribe=window.TraceAuth?.onInvalidated?.(dispose)||(()=>{});active.set(kind,controller);translate();paintSamples();
    if(window.TraceAuth?.accessInvalidated)dispose();
    return controller;
  }
  window.TraceLocalAI=Object.freeze({mount});
})();
