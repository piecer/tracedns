import io
import json
import subprocess
from pathlib import Path

from http_api import relationship_handlers as rh


SOURCE = (Path(__file__).parents[1] / "dns_frontend.js").read_text(encoding="utf-8")


class _RelationshipHandler:
    def __init__(self, data):
        payload = json.dumps(data).encode("utf-8")
        self.headers = {"Content-Length": str(len(payload))}
        self.rfile = io.BytesIO(payload)
        self.shared_config = {}
        self.response = None
        self.code = None

    def _send_json(self, obj, code=200):
        self.response = obj
        self.code = code


def _backend_relationship_response(data):
    handler = _RelationshipHandler(data)
    rh.handle_ip_relationship_analysis(handler)
    assert handler.code == 200
    assert handler.response is not None
    return handler.response


def _function_source(name: str) -> str:
    starts = [
        start
        for prefix in (f"function {name}(", f"async function {name}(")
        if (start := SOURCE.find(prefix)) >= 0
    ]
    if not starts:
        raise AssertionError(f"missing function {name}")
    start = min(starts)
    brace = SOURCE.find("{", start)
    depth = 0
    quote = None
    escaped = False
    template_depth = 0
    for index in range(brace, len(SOURCE)):
        char = SOURCE[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote and template_depth == 0:
                quote = None
            elif quote == "`" and char == "$" and SOURCE[index + 1:index + 2] == "{":
                template_depth += 1
            elif quote == "`" and char == "}" and template_depth:
                template_depth -= 1
            continue
        if char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(f"unterminated function {name}")


def _run_node(functions: list[str], body: str) -> None:
    script = "\n".join(_function_source(name) for name in functions) + "\n" + body
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr


def test_input_summary_executes_token_unique_and_duplicate_counts():
    _run_node(["summarizeIpIntelInput"], r"""
const assert = require('assert');
assert.deepStrictEqual(summarizeIpIntelInput(''), {
  tokenCount: 0, uniqueCount: 0, duplicateCount: 0, isEmpty: true
});
assert.deepStrictEqual(summarizeIpIntelInput('1.1.1.1, 2.2.2.2\n1.1.1.1 | BAD bad'), {
  tokenCount: 5, uniqueCount: 4, duplicateCount: 1, isEmpty: false
});
""")


def test_misp_loader_posts_the_visible_event_id():
    _run_node(["loadIpIntelFromMisp"], r"""
const assert = require('assert');
const elements = {
  ipIntelMispEventId: {value: '7342'},
  ipIntelMeta: {textContent: ''},
  ipIntelInvalidBox: {textContent: ''}
};
global.document = {getElementById: id => elements[id] || null};
let request = null;
global.fetch = async (url, options) => {
  request = {url, options};
  return {
    ok: true,
    json: async () => ({status: 'ok', event_id: 7342, ips: [], invalid_values: []})
  };
};
global.setIpIntelInputValue = () => true;

(async () => {
  await loadIpIntelFromMisp(false);
  assert.strictEqual(request.url, '/misp/event-ips');
  assert.strictEqual(request.options.method, 'POST');
  assert.deepStrictEqual(JSON.parse(request.options.body), {event_id: '7342'});
  assert(elements.ipIntelMeta.textContent.includes('event 7342'));
})().catch(error => { console.error(error); process.exitCode = 1; });
""")


def test_map_visual_helpers_enforce_target_size_and_expose_numeric_risk():
    _run_node(["getIpRelMapRadius", "formatIpRelCountrySummary"], r"""
const assert = require('assert');
assert(getIpRelMapRadius(1, 100) >= 12);
assert.strictEqual(getIpRelMapRadius(100, 100), 32);
assert.strictEqual(formatIpRelCountrySummary({country:'us', ip_count:4, malicious_ips:1}), 'US: 4 IPs, 1 malicious (25%)');
assert.strictEqual(formatIpRelCountrySummary({country:'de', ip_count:0, malicious_ips:0}), 'DE: 0 IPs, 0 malicious (0%)');
""")


def test_result_model_executes_complete_incomplete_vt_partial_and_empty_states():
    _run_node(["buildIpRelationshipResultModel"], r"""
const assert = require('assert');
let model = buildIpRelationshipResultModel({
  valid_count: 4, invalid_count: 1, pair_count: 2, candidate_count: 10, clusters: [{ips:['A','B']}],
  quality: {analysis_complete: true, candidate_analysis_complete: true, evaluated_candidate_count: 10,
            vt_enabled: true, vt_report_count: 4, vt_eligible_count: 4}
});
assert.deepStrictEqual(model.metrics, {ips: 4, pairs: 2, clusters: 1, coverage: '100%'});
assert.strictEqual(model.quality.state, 'complete');
assert(model.quality.detail.includes('1 invalid input'));
model = buildIpRelationshipResultModel({valid_count: 2, candidate_count: 10, pairs: [], clusters: [], quality: {
  analysis_complete: false, candidate_analysis_complete: false,
  cluster_topology_complete: false, pair_detail_complete: true, enrichment_complete: true,
  evaluated_candidate_count: 4,
  warning_codes: ['candidate_limit_reached', 'local_context_truncated']
}});
assert.strictEqual(model.metrics.coverage, '40%');
assert.strictEqual(model.quality.state, 'incomplete');
assert(model.quality.detail.includes('Candidate'));
assert(model.quality.detail.includes('Local DNS context'));
assert(model.quality.detail.includes('Candidate discovery: partial'));
assert(model.quality.detail.includes('Cluster topology: partial'));
assert(model.quality.detail.includes('Pair details: complete'));
model = buildIpRelationshipResultModel({valid_count: 2, pair_count: 1, candidate_count: 10, clusters: [], quality: {
  analysis_complete: false, candidate_analysis_complete: true, enrichment_complete: false,
  evaluated_candidate_count: 10,
  vt_enabled: true, vt_report_count: 1, vt_eligible_count: 2,
  vt_report_coverage: 0.5, warning_codes: ['vt_partial_coverage']
}});
assert.strictEqual(model.quality.state, 'vt-partial');
assert(model.quality.label.includes('VT'));
assert.strictEqual(model.metrics.coverage, '50%');
model = buildIpRelationshipResultModel({valid_count: 3, pair_count: 0, candidate_count: 0, clusters: [], quality: {
  analysis_complete: true, candidate_analysis_complete: true, evaluated_candidate_count: 0, vt_enabled: false
}});
assert.strictEqual(model.quality.state, 'empty');
assert.strictEqual(model.metrics.pairs, 0);
assert(!JSON.stringify(model).includes('NaN'));
model = buildIpRelationshipResultModel({valid_count: 2, pair_count: 1, pairs:[{a:'1', b:'2'}]});
assert.strictEqual(model.metrics.coverage, 'Unknown');
assert.strictEqual(model.quality.state, 'neutral');
assert(model.quality.label.includes('unavailable'));
""")


def test_result_model_consumes_actual_backend_quality_schema(monkeypatch):
    ips = [f"11.0.0.{index}" for index in range(1, 51)]
    reports = {
        ip: {
            "asn": 64500,
            "as_owner": f"Host {index}",
            "country": f"X{index}",
            "raw": {"data": {"attributes": {}}},
        }
        for index, ip in enumerate(ips)
    }
    candidate_request = {
        "ips": ips,
        "include_vt": True,
        "vt_workers": 1,
        "min_score": 1,
        "pair_gate_enabled": False,
        "candidate_limit": 1000,
    }

    monkeypatch.setattr(rh, "get_ip_report", lambda ip, cache_only=False: reports[ip])
    candidate_only = _backend_relationship_response(candidate_request)

    monkeypatch.setattr(
        rh,
        "get_ip_report",
        lambda ip, cache_only=False: (
            {"raw": {"data": {"attributes": {}}}} if ip == "8.8.8.8" else None
        ),
    )
    vt_only = _backend_relationship_response({
        "ips": ["8.8.8.8", "2606:4700:4700::1111"],
        "include_vt": True,
        "vt_workers": 1,
    })

    monkeypatch.setattr(
        rh,
        "get_ip_report",
        lambda ip, cache_only=False: reports[ip] if ip != ips[-1] else None,
    )
    both = _backend_relationship_response(candidate_request)

    assert candidate_only["quality"]["warning_codes"] == [
        "candidate_limit_reached",
        "pair_display_truncated",
    ]
    assert vt_only["quality"]["warning_codes"] == ["vt_partial_coverage"]
    assert set(both["quality"]["warning_codes"]) == {
        "candidate_limit_reached",
        "pair_display_truncated",
        "vt_partial_coverage",
    }

    model_fields = (
        "valid_count",
        "invalid_count",
        "pair_count",
        "candidate_count",
        "clusters",
        "quality",
    )
    payloads = json.dumps([
        {key: response[key] for key in model_fields if key in response}
        for response in (candidate_only, vt_only, both)
    ])
    _run_node(["buildIpRelationshipResultModel"], f"""
const assert = require('assert');
const payloads = {payloads};
const models = payloads.map(buildIpRelationshipResultModel);
assert.strictEqual(models[0].quality.state, 'incomplete');
assert.strictEqual(models[0].metrics.coverage, 'Partial');
assert.strictEqual(models[1].quality.state, 'vt-partial');
assert.strictEqual(models[1].metrics.coverage, '50%');
assert.strictEqual(models[2].quality.state, 'incomplete');
assert(models[2].quality.detail.includes('Candidate'));
assert(models[2].quality.detail.includes('VirusTotal'));
""")


def test_filter_executes_case_insensitively_without_mutating_cache():
    _run_node(["relationshipValueMatches", "filterIpRelationshipResults"], r"""
const assert = require('assert');
const cache = {
  pairs: [
    {a:'One.EXAMPLE', b:'2.2.2.2', evidence:[{type:'same_owner', value:'Acme Hosting'}]},
    {a:'3.3.3.3', b:'4.4.4.4', evidence:[{type:'same_country', value:'DE'}]}
  ],
  clusters: [
    {ips:['1.1.1.1'], top_owner:[['ACME Networks', 1]], top_country:[['US', 1]]},
    {ips:['5.5.5.5'], top_owner:[['Other', 1]], top_country:[['DE', 1]]}
  ]
};
const before = JSON.stringify(cache);
let filtered = filterIpRelationshipResults(cache, 'aCmE');
assert.strictEqual(filtered.pairs.length, 1);
assert.strictEqual(filtered.clusters.length, 1);
filtered.pairs.pop();
assert.strictEqual(cache.pairs.length, 2);
assert.strictEqual(JSON.stringify(cache), before);
filtered = filterIpRelationshipResults(cache, 'DE');
assert.strictEqual(filtered.pairs.length, 1);
assert.strictEqual(filtered.pairs[0].a, '3.3.3.3');
assert.strictEqual(filtered.clusters.length, 1);
assert.strictEqual(filtered.clusters[0].ips[0], '5.5.5.5');
filtered = filterIpRelationshipResults(cache, '');
assert.notStrictEqual(filtered.pairs, cache.pairs);
assert.notStrictEqual(filtered.clusters, cache.clusters);
assert.deepStrictEqual(filtered.pairs, cache.pairs);
""")


def test_export_executes_canonical_serialization_and_deterministic_filename():
    _run_node(["stableJsonValue", "serializeIpRelationshipResult", "buildIpRelationshipExport"], r"""
const assert = require('assert');
const first = {z: 1, nested: {b: true, a: null}, pairs: [{b:'2', a:'1'}]};
const second = {pairs: [{a:'1', b:'2'}], nested: {a: null, b: true}, z: 1};
const one = buildIpRelationshipExport(first, new Date('2026-08-20T13:04:05Z'));
const two = buildIpRelationshipExport(second, new Date('2026-08-20T13:04:05Z'));
assert.strictEqual(one.content, two.content);
assert.strictEqual(one.filename, 'tracedns-ip-relationships-20260820-130405.json');
assert(one.content.endsWith('\n'));
assert.deepStrictEqual(JSON.parse(one.content), first);
const hostile = JSON.parse('{"__proto__":{"polluted":true},"ok":1}');
const stable = stableJsonValue(hostile);
assert.strictEqual(Object.prototype.hasOwnProperty.call(stable, '__proto__'), true);
assert.strictEqual(Object.getPrototypeOf(stable), Object.prototype);
assert.strictEqual(stable.polluted, undefined);
assert.deepStrictEqual(JSON.parse(serializeIpRelationshipResult(hostile)), hostile);
""")


def test_summary_renderer_updates_metrics_banner_and_neutral_fallback():
    _run_node(
        ["buildIpRelationshipResultModel", "renderIpRelationshipProductSummary"],
        r"""
const assert = require('assert');
const elements = {};
global.document = {getElementById:id=>elements[id] ||= {textContent:'', dataset:{}}};
let model = renderIpRelationshipProductSummary({
  valid_count: 4, pair_count: 2, candidate_count: 6, clusters:[{}],
  quality:{analysis_complete:true, candidate_analysis_complete:true, evaluated_candidate_count:6}
});
assert.deepStrictEqual([
  elements.ipRelMetricIps.textContent,
  elements.ipRelMetricPairs.textContent,
  elements.ipRelMetricClusters.textContent,
  elements.ipRelMetricCoverage.textContent
], ['4', '2', '1', '100%']);
assert.strictEqual(elements.ipRelQualityBanner.dataset.state, 'complete');
assert(elements.ipRelQualityBanner.textContent.includes('Complete analysis'));
model = renderIpRelationshipProductSummary({valid_count:2, pairs:[{a:'1',b:'2'}]});
assert.strictEqual(model.quality.state, 'neutral');
assert.strictEqual(elements.ipRelMetricCoverage.textContent, 'Unknown');
assert.strictEqual(elements.ipRelQualityBanner.dataset.state, 'neutral');
assert(!elements.ipRelQualityBanner.textContent.includes('NaN'));
""",
    )


def test_product_control_wiring_dispatches_filter_and_export_handlers():
    _run_node(["wireIpRelationshipProductControls"], r"""
const assert = require('assert');
function control(){
  return {listeners:{}, addEventListener(type, callback){this.listeners[type]=callback;}};
}
const input=control(), filter=control(), exportButton=control();
const elements={ipIntelInput:input, ipRelFilterInput:filter, exportIpRelationshipBtn:exportButton};
global.document={getElementById:id=>elements[id] || null};
global.updateIpIntelInputStats=()=>{};
global.markIpRelationshipResultsStale=()=>{};
global.setIpRelationshipRunState=()=>{};
let filterCalls=0, exportCalls=0;
global.renderFilteredIpRelationshipResults=()=>{filterCalls += 1;};
global.exportLastIpRelationshipResult=()=>{exportCalls += 1;};
wireIpRelationshipProductControls();
filter.listeners.input();
exportButton.listeners.click();
assert.strictEqual(filterCalls, 1);
assert.strictEqual(exportCalls, 1);
""")


def test_export_executes_browser_download_side_effects_and_empty_guard():
    _run_node(
        [
            "stableJsonValue",
            "serializeIpRelationshipResult",
            "buildIpRelationshipExport",
            "exportLastIpRelationshipResult",
        ],
        r"""
const assert = require('assert');
global.window={IP_REL_LAST_SUCCESS:null};
let created=0, revoked='', clicked=0, removed=0, appended=null;
global.Blob=class {constructor(parts, options){this.parts=parts; this.options=options;}};
global.URL={
  createObjectURL(blob){created += 1; assert.strictEqual(blob.options.type, 'application/json'); return 'blob:test';},
  revokeObjectURL(url){revoked=url;}
};
const link={href:'', download:'', click(){clicked += 1;}, remove(){removed += 1;}};
global.document={createElement:tag=>{assert.strictEqual(tag,'a'); return link;}, body:{appendChild(value){appended=value;}}};
assert.strictEqual(exportLastIpRelationshipResult(), false);
assert.strictEqual(created, 0);
window.IP_REL_LAST_SUCCESS={z:1};
assert.strictEqual(exportLastIpRelationshipResult(), true);
assert.strictEqual(created, 1);
assert.strictEqual(appended, link);
assert.strictEqual(link.href, 'blob:test');
assert(/^tracedns-ip-relationships-\d{8}-\d{6}\.json$/.test(link.download));
assert.strictEqual(clicked, 1);
assert.strictEqual(removed, 1);
assert.strictEqual(revoked, 'blob:test');
""",
    )


def test_run_state_and_tabs_execute_accessible_terminal_semantics():
    _run_node(["setIpRelationshipRunState", "setIpRelView"], r"""
const assert = require('assert');
function node(id) {
  return elements[id] ||= {
    id, textContent:'', disabled:false, hidden:false, style:{}, attrs:{},
    classList:{toggle(){}}, setAttribute(k,v){this.attrs[k]=String(v)},
    getAttribute(k){return this.attrs[k]}
  };
}
const elements = {};
global.document = {getElementById: node};
global.window = {IP_REL_CACHE:null};
global.renderIpRelGraphFromCache = () => {};
global.renderIpRelMapFromCache = () => {};
window.IP_REL_LAST_SUCCESS = {status:'ok'};
setIpRelationshipRunState('running', 'Analyzing relationship job');
assert.strictEqual(node('ipRelRunStatus').textContent, 'Analyzing relationship job');
assert.strictEqual(node('cancelIpRelationshipBtn').disabled, false);
assert.strictEqual(node('cancelIpRelationshipBtn').hidden, false);
assert.strictEqual(node('runIpRelationshipBtn').disabled, true);
assert.strictEqual(node('ipRelFilterInput').disabled, true);
assert.strictEqual(node('exportIpRelationshipBtn').disabled, true);
assert.strictEqual(node('ipIntelInput').disabled, true);
assert.strictEqual(node('ipRelProfileSelect').disabled, true);
assert.strictEqual(node('ipRelMinScore').disabled, true);
setIpRelationshipRunState('cancelled');
assert(node('ipRelRunStatus').textContent.toLowerCase().includes('cancel'));
assert.strictEqual(node('cancelIpRelationshipBtn').disabled, true);
assert.strictEqual(node('cancelIpRelationshipBtn').hidden, true);
assert.strictEqual(node('runIpRelationshipBtn').disabled, false);
assert.strictEqual(node('ipIntelInput').disabled, false);
assert.strictEqual(node('ipRelProfileSelect').disabled, false);
assert.strictEqual(node('ipRelMinScore').disabled, false);
setIpRelationshipRunState('complete');
assert.strictEqual(node('ipRelFilterInput').disabled, false);
assert.strictEqual(node('exportIpRelationshipBtn').disabled, false);
setIpRelView('graph');
assert.strictEqual(node('ipRelViewGraphBtn').getAttribute('aria-selected'), 'true');
assert.strictEqual(node('ipRelViewTableBtn').getAttribute('aria-selected'), 'false');
assert.strictEqual(node('ipRelGraphView').hidden, false);
assert.strictEqual(node('ipRelTableView').hidden, true);
assert.strictEqual(node('ipRelGraphView').getAttribute('aria-hidden'), 'false');
""")


def test_previous_result_is_marked_stale_after_inputs_change():
    _run_node(["setIpRelationshipRunState", "markIpRelationshipResultsStale"], r"""
const assert = require('assert');
function node(id){
  return elements[id] ||= {
    id, textContent:'', disabled:false, hidden:false, dataset:{},
    setAttribute(){}
  };
}
const elements = {};
global.document = {getElementById:node};
global.window = {IP_REL_LAST_SUCCESS:{status:'ok'}};
setIpRelationshipRunState('complete');
assert.strictEqual(markIpRelationshipResultsStale(), true);
assert.strictEqual(node('ipRelRunStatus').dataset.state, 'stale');
assert(node('ipRelRunStatus').textContent.includes('previous run'));
assert.strictEqual(node('ipRelFilterInput').disabled, false);
assert.strictEqual(node('exportIpRelationshipBtn').disabled, false);
assert.strictEqual(node('ipRelQualityBanner').dataset.state, 'stale');
""")


def test_input_listener_marks_previous_relationship_result_stale():
    _run_node(["wireIpRelationshipProductControls"], r"""
const assert = require('assert');
const listeners = {};
const input = {addEventListener(type, callback){ listeners[type] = callback; }};
global.document = {getElementById:id=>id === 'ipIntelInput' ? input : null};
global.updateIpIntelInputStats = () => {};
global.setIpRelationshipRunState = () => {};
let staleCalls = 0;
global.markIpRelationshipResultsStale = () => { staleCalls += 1; };
wireIpRelationshipProductControls();
listeners.input();
assert.strictEqual(staleCalls, 1);
""")


def test_profile_and_advanced_setting_handlers_mark_previous_result_stale():
    _run_node(["wireIpRelProfileControls"], r"""
const assert = require('assert');
const listeners = {};
function control(id, tagName='INPUT', type='number'){
  return {id, tagName, type, value:'balanced', addEventListener(kind, callback){ listeners[`${id}:${kind}`]=callback; }};
}
const elements = {
  ipRelProfileSelect: control('ipRelProfileSelect', 'SELECT', 'select-one'),
  ipRelMinScore: control('ipRelMinScore')
};
global.document = {getElementById:id=>elements[id] || null};
global.IP_REL_PROFILE_FIELD_IDS = ['ipRelMinScore'];
global.applyIpRelProfile = () => {};
global.readIpRelSettingsFromUi = () => ({});
global.saveCustomIpRelSettings = () => {};
global.persistCustomProfileIfSelected = () => {};
global.updateIpRelGateUi = () => {};
global.normalizeIpRelProfileName = value => value;
global.loadSelectedIpRelProfile = () => 'balanced';
let staleCalls = 0;
global.markIpRelationshipResultsStale = () => { staleCalls += 1; };
wireIpRelProfileControls();
listeners['ipRelProfileSelect:change']();
listeners['ipRelMinScore:change']();
assert.strictEqual(staleCalls, 2);
""")


def test_keyboard_activation_helper_accepts_enter_and_space_only():
    _run_node(["isKeyboardActivation"], r"""
const assert = require('assert');
assert.strictEqual(isKeyboardActivation({key:'Enter'}), true);
assert.strictEqual(isKeyboardActivation({key:' '}), true);
assert.strictEqual(isKeyboardActivation({key:'Spacebar'}), true);
assert.strictEqual(isKeyboardActivation({key:'Escape'}), false);
""")


def test_clicking_visualization_tab_restores_focus_for_arrow_navigation():
    _run_node(["isKeyboardActivation", "wireIpRelViewButtons"], r"""
const assert = require('assert');
const buttons = ['ipRelViewTableBtn', 'ipRelViewGraphBtn', 'ipRelViewMapBtn'].map(id=>({
  id,
  attributes:{},
  setAttribute(name, value){ this.attributes[name] = value; },
  focus(){ document.activeElement = this; }
}));
const byId = Object.fromEntries(buttons.map(button=>[button.id, button]));
global.document = {
  activeElement:{id:'body'},
  getElementById:id=>byId[id] || null
};
global.setIpRelView = () => { document.activeElement = {id:'visualization-canvas'}; };
wireIpRelViewButtons();
buttons[1].onclick();
assert.strictEqual(document.activeElement, buttons[1]);
buttons[1].onkeydown({key:'ArrowRight', preventDefault(){}});
assert.strictEqual(document.activeElement, buttons[2]);
""")


def test_failed_rerun_restores_the_previous_successful_result():
    _run_node(["restorePreviousIpRelationshipResult"], r"""
const assert = require('assert');
global.window = {};
global.document = {getElementById:()=>null};
const pairsBody = {};
const clustersBody = {};
const previous = {pairs:[{a:'1.1.1.1',b:'8.8.8.8'}], clusters:[{ips:['1.1.1.1']}]};
let summary = null;
let renderedPairs = null;
let renderedClusters = null;
global.renderIpRelationshipProductSummary = result => { summary = result; };
global.renderIpRelationshipPairsTable = (_body, rows) => { renderedPairs = rows; };
global.renderIpRelationshipClustersTable = (_body, rows) => { renderedClusters = rows; };
assert.strictEqual(restorePreviousIpRelationshipResult(null, pairsBody, clustersBody), false);
assert.strictEqual(restorePreviousIpRelationshipResult(previous, pairsBody, clustersBody), true);
assert.strictEqual(window.IP_REL_CACHE, previous);
assert.strictEqual(window.IP_REL_LAST_SUCCESS, previous);
assert.strictEqual(summary, previous);
assert.strictEqual(renderedPairs, previous.pairs);
assert.strictEqual(renderedClusters, previous.clusters);
""")


def test_per_ip_result_state_swaps_empty_message_and_result_content():
    _run_node(["setIpIntelResultState"], r"""
const assert = require('assert');
const empty = {hidden:false, textContent:''};
const content = {hidden:true};
global.document = {getElementById:id=>id === 'ipIntelResultsEmpty' ? empty : content};
setIpIntelResultState('loading');
assert.strictEqual(empty.hidden, false);
assert.strictEqual(content.hidden, true);
assert.strictEqual(empty.textContent, 'Enriching per-IP details…');
setIpIntelResultState('ready');
assert.strictEqual(empty.hidden, true);
assert.strictEqual(content.hidden, false);
setIpIntelResultState('error', 'Per-IP enrichment failed. Try again.');
assert.strictEqual(empty.hidden, false);
assert.strictEqual(content.hidden, true);
assert.strictEqual(empty.textContent, 'Per-IP enrichment failed. Try again.');
""")


def test_map_drilldown_returns_view_and_focus_to_table_tab():
    _run_node(["returnIpRelFocusToTable"], r"""
const assert = require('assert');
const button = {focus(){ document.activeElement = this; }};
global.document = {activeElement:null, getElementById:id=>id === 'ipRelViewTableBtn' ? button : null};
let view = '';
global.setIpRelView = name => { view = name; };
returnIpRelFocusToTable();
assert.strictEqual(view, 'table');
assert.strictEqual(document.activeElement, button);
""")


def test_misp_context_formatter_exposes_provenance_and_distribution():
    _run_node(["formatMispInputContext"], r"""
const assert = require('assert');
const text = formatMispInputContext({input_context:{misp:{
  event:{id:'42', producer:{name:'Producer'}},
  access:{tlp_tags:['tlp:amber+strict'], contains_restricted_attributes:true}
}}});
assert(text.includes('MISP event 42'));
assert(text.includes('producer Producer'));
assert(text.includes('tlp:amber+strict'));
assert(text.includes('restricted distribution'));
assert.strictEqual(formatMispInputContext({}), '');
""")


def test_pair_assessment_formatter_separates_relationship_strength_and_verdict():
    _run_node(["formatPairAssessment"], r"""
const assert = require('assert');
const current = formatPairAssessment({
  score: 84,
  relationship_strength: 84,
  assessment: {
    verdict: 'same_botnet_likely', evidence_score: 80, botnet_evidence_score: 75,
    confidence: {level: 'high'}
  }
});
assert.deepStrictEqual(current, {
  strength: 84,
  verdict: 'Likely same botnet',
  evidenceScore: 75,
  confidence: 'high'
});
const legacy = formatPairAssessment({score: 40});
assert.deepStrictEqual(legacy, {
  strength: 40,
  verdict: 'Relationship only',
  evidenceScore: null,
  confidence: 'unknown'
});
""")


def test_new_local_and_misp_evidence_have_human_readable_labels():
    _run_node(["summarizeEvidence", "evidenceTypeLabel"], r"""
const assert = require('assert');
const evidence = [
  {type:'coincident_dns_change', value:'240s'},
  {type:'shared_misp_event', value:'event-uuid'},
  {type:'shared_misp_campaign', value:'ExampleBot'}
];
assert.strictEqual(summarizeEvidence(evidence), 'DNS:CHANGE + MISP:EVENT + MISP:CAMPAIGN');
assert.strictEqual(evidenceTypeLabel('coincident_dns_change'), 'Coincident DNS Change');
assert.strictEqual(evidenceTypeLabel('shared_misp_event'), 'Shared MISP Event');
assert.strictEqual(evidenceTypeLabel('shared_misp_campaign'), 'Shared MISP Campaign');
""")


def test_pair_table_uses_keyboard_accessible_ip_drilldown_buttons():
    _run_node(["formatPairAssessment", "renderIpRelationshipPairsTable"], r"""
const assert = require('assert');
class Element {
  constructor(tag){ this.tagName=tag.toUpperCase(); this.children=[]; this.style={}; this.attrs={}; this.textContent=''; }
  appendChild(child){ this.children.push(child); return child; }
  setAttribute(key,value){ this.attrs[key]=String(value); }
}
global.document = {
  createElement:tag=>new Element(tag),
  createDocumentFragment:()=>new Element('fragment')
};
global.IP_REL_PAIR_TABLE_RENDER_LIMIT = 200;
global.isIPv4 = () => true;
let opened = '';
global.openQueryForValue = value => { opened = value; };
global.summarizeEvidence = () => '-';
global.formatEvidenceDetails = () => '-';
const tbody = new Element('tbody');
renderIpRelationshipPairsTable(tbody, [{a:'1.1.1.1', b:'8.8.8.8', score:84, evidence:[]}]);
const row = tbody.children[0].children[0];
const firstButton = row.children[0].children[0];
assert.strictEqual(firstButton.tagName, 'BUTTON');
assert.strictEqual(firstButton.textContent, '1.1.1.1');
assert(firstButton.attrs['aria-label'].includes('1.1.1.1'));
firstButton.onclick();
assert.strictEqual(opened, '1.1.1.1');
""")


def test_cluster_table_uses_native_button_and_executes_drilldown():
    _run_node(["setIpIntelInputValue", "renderIpRelationshipClustersTable"], r"""
const assert = require('assert');
class Element {
  constructor(tag){ this.tagName=tag.toUpperCase(); this.children=[]; this.style={}; this.attrs={}; this.textContent=''; this.value=''; }
  appendChild(child){ this.children.push(child); return child; }
  setAttribute(key,value){ this.attrs[key]=String(value); }
}
const input = new Element('textarea');
global.document = {
  createElement:tag=>new Element(tag),
  createDocumentFragment:()=>new Element('fragment'),
  getElementById:id=>id === 'ipIntelInput' ? input : null
};
global.IP_REL_CLUSTER_TABLE_RENDER_LIMIT = 100;
global.updateIpIntelInputStats = () => {};
global.markIpRelationshipResultsStale = () => {};
global.renderMergedIpIntelHints = () => {};
let analyses = 0;
global.analyzeIpIntel = async () => { analyses += 1; };
const tbody = new Element('tbody');
renderIpRelationshipClustersTable(tbody, [{size:2, ips:['1.1.1.1','8.8.8.8']}], false);
const row = tbody.children[0].children[0];
const button = row.children[0].children[0];
assert.strictEqual(button.tagName, 'BUTTON');
assert(button.attrs['aria-label'].includes('cluster 1'));
(async()=>{
  await button.onclick();
  assert.strictEqual(input.value, '1.1.1.1\n8.8.8.8');
  assert.strictEqual(analyses, 1);
})().catch(error=>{ console.error(error); process.exitCode=1; });
""")


def test_explicit_cancel_aborts_client_and_requests_server_cancel_once():
    _run_node(["cancelActiveIpRelationshipAnalysis"], r"""
const assert = require('assert');
let aborts = 0;
let serverCancels = 0;
global.ipRelAnalyzeController = {signal:{aborted:false}, abort(){this.signal.aborted=true; aborts += 1;}};
global.ipRelAnalyzeSeq = 7;
global.ipRelActiveJobId = 'job/42';
global.ipRelCancelRequestedJobs = new Set();
global.cancelIpRelationshipJob = async id => {assert.strictEqual(id, 'job/42'); serverCancels += 1; return true;};
global.document = {querySelector:()=>null};
global.setIpRelationshipRunState = state => assert.strictEqual(state, 'cancelled');
global.renderIpRelationshipError = () => {};
assert.strictEqual(cancelActiveIpRelationshipAnalysis(), true);
assert.strictEqual(cancelActiveIpRelationshipAnalysis(), false);
assert.strictEqual(aborts, 1);
setImmediate(() => {
  assert.strictEqual(serverCancels, 1);
});
""")
