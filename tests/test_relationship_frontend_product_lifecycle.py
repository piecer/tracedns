import subprocess
from pathlib import Path


SOURCE = (Path(__file__).parents[1] / "dns_frontend.js").read_text(encoding="utf-8")


def _function_source(name: str) -> str:
    for prefix in (f"function {name}(", f"async function {name}("):
        start = SOURCE.find(prefix)
        if start >= 0:
            break
    else:
        raise AssertionError(f"missing function {name}")
    brace = SOURCE.find("{", start)
    depth = 0
    quote = None
    escaped = False
    for index in range(brace, len(SOURCE)):
        char = SOURCE[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
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


def test_product_runtime_is_integrated_with_relationship_lifecycle():
    analyze_source = _function_source("analyzeIpRelationships")

    assert "typeof setIpRelationshipRunState === 'function'" in analyze_source
    assert "updateRelationshipRunState('running')" in analyze_source
    assert "window.IP_REL_LAST_SUCCESS = j" in analyze_source
    assert "renderIpRelationshipProductSummary(j)" in analyze_source
    assert "renderFilteredIpRelationshipResults()" in analyze_source
    assert "updateRelationshipRunState('complete')" in analyze_source
    assert "updateRelationshipRunState('cancelled', cancellationMessage)" in analyze_source
    assert "updateRelationshipRunState('error'," in analyze_source
    assert "ipRelActiveJobId = jobId" in analyze_source
    assert "ipRelActiveJobId = null" in analyze_source
    assert "restorePreviousIpRelationshipResult(previousSuccessfulResult" in analyze_source
    callback_start = analyze_source.index("fetchIpRelationshipJobResult(requestBody")
    stale_guard = analyze_source.index("if(isStale()) return", callback_start)
    ownership_write = analyze_source.index("ipRelActiveJobId = jobId", callback_start)
    assert stale_guard < ownership_write
    assert "finalizeIpRelationshipRun(controller)" in analyze_source


def test_overlapping_relationship_runs_release_every_busy_lease():
    sources = "\n".join(
        _function_source(name)
        for name in ("setIpIntelBusy", "finalizeIpRelationshipRun")
    )
    script = "let ipIntelBusyCount = 0; let ipRelAnalyzeController = null;\n" + sources + r"""
const assert = require('assert');
const run = {disabled:false};
global.document = {getElementById:id=>id === 'runIpRelationshipBtn' ? run : null};
const first = {id:'first'};
const second = {id:'second'};
ipRelAnalyzeController = second;
setIpIntelBusy(true);
setIpIntelBusy(true);
finalizeIpRelationshipRun(first);
assert.strictEqual(run.disabled, true);
assert.strictEqual(ipIntelBusyCount, 1);
finalizeIpRelationshipRun(second);
assert.strictEqual(run.disabled, false);
assert.strictEqual(ipIntelBusyCount, 0);
assert.strictEqual(ipRelAnalyzeController, null);
"""
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr


def test_complete_analysis_does_not_treat_candidate_safety_limit_as_denominator():
    model_source = _function_source("buildIpRelationshipResultModel")
    script = model_source + r"""
const assert = require('assert');
const complete = buildIpRelationshipResultModel({
  valid_count: 3,
  pair_count: 1,
  clusters: [{cluster_id: 'cluster-1'}],
  quality: {
    analysis_complete: true,
    candidate_limit: 500000,
    evaluated_candidate_count: 1,
    vt_enabled: false
  }
});
assert.strictEqual(complete.metrics.coverage, 'Complete');

const incomplete = buildIpRelationshipResultModel({
  valid_count: 3,
  pair_count: 1,
  quality: {
    analysis_complete: false,
    candidate_limit: 500000,
    evaluated_candidate_count: 500000,
    warning_codes: ['candidate_limit_reached']
  }
});
assert.strictEqual(incomplete.metrics.coverage, 'Partial');
"""
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr


def test_programmatic_input_setter_updates_summary_and_marks_results_stale():
    source = _function_source("setIpIntelInputValue")
    script = source + r"""
const assert = require('assert');
const input = {value:'1.1.1.1'};
global.document = {getElementById:id=>id === 'ipIntelInput' ? input : null};
let stats = 0, hints = 0, stale = 0;
global.updateIpIntelInputStats = () => { stats += 1; };
global.renderMergedIpIntelHints = () => { hints += 1; };
global.markIpRelationshipResultsStale = () => { stale += 1; };
assert.strictEqual(setIpIntelInputValue('2.2.2.2\n3.3.3.3'), true);
assert.strictEqual(input.value, '2.2.2.2\n3.3.3.3');
assert.deepStrictEqual([stats, hints, stale], [1, 1, 1]);
assert.strictEqual(setIpIntelInputValue('2.2.2.2\n3.3.3.3'), false);
assert.deepStrictEqual([stats, hints, stale], [1, 1, 1]);
"""
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr


def test_all_programmatic_ip_mutations_use_the_owned_setter():
    for name in (
        "loadIpIntelFromMisp",
        "renderIpRelMapFromCache",
        "renderIpRelationshipClustersTable",
    ):
        body = _function_source(name)
        assert "setIpIntelInputValue(ips.join('\\n'))" in body
        assert "ta.value = ips.join('\\n')" not in body


def test_empty_analysis_input_preserves_previous_result_as_stale():
    body = _function_source("analyzeIpRelationships")
    empty_branch = body.split("if(!raw){", 1)[1].split("return;", 1)[0]
    assert "if(previousSuccessfulResult)" in empty_branch
    assert "markIpRelationshipResultsStale()" in empty_branch
    assert "updateRelationshipRunState('idle'" in empty_branch


def test_restored_previous_result_relabels_visible_quality_banner():
    source = _function_source("restorePreviousIpRelationshipResult")
    script = source + r"""
const assert = require('assert');
const banner = {dataset:{state:'complete'}, textContent:'Complete analysis'};
global.document = {getElementById:id=>id === 'ipRelQualityBanner' ? banner : null};
global.window = {};
global.renderIpRelationshipProductSummary = () => {};
global.renderIpRelationshipPairsTable = () => {};
global.renderIpRelationshipClustersTable = () => {};
assert.strictEqual(restorePreviousIpRelationshipResult({pairs:[], clusters:[]}, {}, {}), true);
assert.strictEqual(banner.dataset.state, 'stale');
assert(banner.textContent.includes('Previous successful result'));
assert(banner.textContent.includes('latest run did not complete'));
assert(!banner.textContent.includes('Complete analysis'));
"""
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr


def test_cancel_failure_is_reported_only_if_no_new_run_has_started():
    source = _function_source("cancelActiveIpRelationshipAnalysis")
    script = source + r"""
const assert = require('assert');
let resolveCancel;
global.ipRelAnalyzeSeq = 7;
global.ipRelAnalyzeController = {signal:{aborted:false}, abort(){this.signal.aborted=true;}};
global.ipRelActiveJobId = 'job-1';
global.ipRelCancelRequestedJobs = new Set();
const states = [];
global.cancelIpRelationshipJob = () => new Promise(resolve=>{resolveCancel=resolve;});
global.setIpRelationshipRunState = (...args) => states.push(args);
global.renderIpRelationshipError = () => {};
global.document = {querySelector:()=>({})};
(async()=>{
  assert.strictEqual(cancelActiveIpRelationshipAnalysis(), true);
  resolveCancel(false);
  await new Promise(resolve=>setImmediate(resolve));
  assert.strictEqual(ipRelAnalyzeController.serverCancelUnconfirmed, true);
  assert(states.some(args=>String(args[1] || '').includes('could not be confirmed')));

  ipRelAnalyzeSeq = 8;
  ipRelAnalyzeController = {signal:{aborted:false}, abort(){this.signal.aborted=true;}};
  ipRelActiveJobId = 'job-2';
  assert.strictEqual(cancelActiveIpRelationshipAnalysis(), true);
  ipRelAnalyzeSeq = 9;
  resolveCancel(false);
  await new Promise(resolve=>setImmediate(resolve));
  assert.strictEqual(states.filter(args=>String(args[1] || '').includes('could not be confirmed')).length, 1);
})().catch(error=>{console.error(error); process.exit(1);});
"""
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
