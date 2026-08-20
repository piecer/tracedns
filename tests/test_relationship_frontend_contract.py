import re
import subprocess
from pathlib import Path


FRONTEND_SOURCE = (Path(__file__).parents[1] / "dns_frontend.js").read_text(encoding="utf-8")
FRONTEND_HTML = (Path(__file__).parents[1] / "dns_frontend.html").read_text(encoding="utf-8")


def _function_body(name: str, next_name: str) -> str:
    match = re.search(
        rf"async function {name}\([^)]*\)\s*\{{(?P<body>.*?)\n\}}\s*\n\s*async function {next_name}\(",
        FRONTEND_SOURCE,
        re.DOTALL,
    )
    assert match, f"could not locate {name} before {next_name}"
    return match.group("body")


def test_cancel_helper_posts_encoded_job_id_without_analysis_signal_and_swallows_failures():
    body = _function_body("cancelIpRelationshipJob", "fetchIpRelationshipJobResult")

    assert "encodeURIComponent(jobId)" in body
    assert re.search(r"fetch\(`/ip-relationship-jobs/\$\{encodeURIComponent\(jobId\)\}/cancel`", body)
    assert re.search(r"method:\s*['\"]POST['\"]", body)
    assert "signal:" not in body
    assert re.search(r"catch\s*\([^)]*\)\s*\{\s*return false;\s*\}", body, re.DOTALL)


def _plain_function_body(name: str, next_name: str) -> str:
    match = re.search(
        rf"function {name}\([^)]*\)\s*\{{(?P<body>.*?)\n\}}\s*\n\s*(?:async )?function {next_name}\(",
        FRONTEND_SOURCE,
        re.DOTALL,
    )
    assert match, f"could not locate {name} before {next_name}"
    return match.group("body")


def _run_node(script: str) -> None:
    subprocess.run(["node", "-e", script], check=True, text=True, capture_output=True)


def test_relationship_analysis_tracks_active_job_and_cancels_abort_once_before_terminal_result():
    poll_body = _function_body("fetchIpRelationshipJobResult", "analyzeIpRelationships")
    analyze_body = FRONTEND_SOURCE.split("async function analyzeIpRelationships(){", 1)[1]

    assert "onStatus(jobId, 'active')" in poll_body
    submit_options = poll_body.split("const submit = await fetch", 1)[1].split("});", 1)[0]
    assert "signal:" not in submit_options
    assert re.search(r"controller\.signal\.aborted.*?cancelIpRelationshipJob\(jobId\)", poll_body, re.DOTALL)
    assert re.search(r"jj\.status === 'completed'.*?onStatus\(jobId, 'terminal'\)", poll_body, re.DOTALL)
    assert re.search(
        r"jj\.status === 'failed'\s*\|\|\s*jj\.status === 'cancelled'.*?onStatus\(jobId, 'terminal'\)",
        poll_body,
        re.DOTALL,
    )

    assert "let activeRelationshipJobId = null;" in analyze_body
    assert "let relationshipJobTerminal = false;" in analyze_body
    assert "let relationshipJobCancelRequested = false;" in analyze_body
    assert re.search(
        r"if\(state === 'active'\)\s*\{\s*activeRelationshipJobId = jobId;\s*\}",
        analyze_body,
        re.DOTALL,
    )
    assert re.search(
        r"if\(state === 'terminal'\)\s*\{\s*relationshipJobTerminal = true;\s*\}",
        analyze_body,
        re.DOTALL,
    )
    assert re.search(
        r"if\(!activeRelationshipJobId \|\| relationshipJobTerminal \|\| relationshipJobCancelRequested\) return;.*?relationshipJobCancelRequested = true;.*?cancelIpRelationshipJob\(activeRelationshipJobId\);",
        analyze_body,
        re.DOTALL,
    )
    assert re.search(
        r"if\(isAbortError\(e\) \|\| isStale\(\)\)\s*\{.*?cancelActiveRelationshipJob\(\);.*?return;",
        analyze_body,
        re.DOTALL,
    )
    assert re.search(r"if\(!jobResult\.ok.*?cancelActiveRelationshipJob\(\);", analyze_body, re.DOTALL)
    assert "finalizeIpRelationshipRun(controller);" in analyze_body
    cleanup_body = _plain_function_body("finalizeIpRelationshipRun", "isAbortError")
    assert "ipRelAnalyzeController === controller" in cleanup_body
    assert "if(isCurrent) ipRelAnalyzeController = null;" in cleanup_body
    assert "setIpIntelBusy(false);" in cleanup_body


def test_successful_relationship_meta_consumes_quality_formatter():
    analyze_body = FRONTEND_SOURCE.split("async function analyzeIpRelationships(){", 1)[1]

    assert "formatIpRelationshipQuality(j)" in analyze_body
    assert re.search(r"txt\s*\+=\s*formatIpRelationshipQuality\(j\)", analyze_body)
    assert re.search(r"meta\.textContent\s*=\s*txt", analyze_body)


def test_relationship_errors_replace_loading_rows_with_terminal_messages():
    analyze_body = FRONTEND_SOURCE.split("async function analyzeIpRelationships(){", 1)[1]

    assert len(re.findall(r"renderIpRelationshipError\(pairsBody, clustersBody,", analyze_body)) >= 2


def test_relationship_quality_formatter_exposes_completeness_candidates_and_vt_coverage():
    body = _plain_function_body("formatIpRelationshipQuality", "cancelIpRelationshipJob")

    assert re.search(r"j\s*&&\s*j\.quality", body)
    assert "analysis_complete === false" in body
    assert "⚠" in body and "incomplete" in body.lower()
    assert "evaluated_candidate_count" in body
    assert "candidate_limit" in body
    assert "vt_report_count" in body
    assert "vt_eligible_count" in body
    assert "vt_skipped_non_global" in body
    assert "vt_report_coverage" in body
    assert "%" in body
    assert "Number.isFinite" in body


def test_relationship_quality_formatter_handles_legacy_results_and_maps_warning_codes():
    body = _plain_function_body("formatIpRelationshipQuality", "cancelIpRelationshipJob")

    assert re.search(r"if\s*\(\s*!quality\s*\).*?return\s+['\"]['\"]", body, re.DOTALL)
    for code in (
        "bucket_truncated",
        "bucket_skipped",
        "candidate_limit_reached",
        "pair_heap_truncated",
        "vt_partial_coverage",
    ):
        assert code in body

    # Only an explicit false value marks a response incomplete; true/absent must not.
    assert "analysis_complete === false" in body
    assert "!quality.analysis_complete" not in body
    assert "quality.vt_enabled === true" in body
    assert "replaceAll" not in body


def test_incomplete_quality_reaches_warning_region_and_status_is_accessible():
    body = _plain_function_body("setIpIntelRelationshipInsights", "clearIpIntelRelationshipInsights")

    assert "quality.analysis_complete === false" in body
    assert "Incomplete Relationship Analysis" in body
    assert re.search(r'id="ipRelMeta"[^>]*role="status"[^>]*aria-live="polite"', FRONTEND_HTML)


def test_submit_ack_abort_cancels_the_server_job_at_runtime():
    lifecycle_source = FRONTEND_SOURCE[
        FRONTEND_SOURCE.index("async function cancelIpRelationshipJob"):
        FRONTEND_SOURCE.index("async function analyzeIpRelationships")
    ]
    _run_node(f"""
const assert = require('assert');
{lifecycle_source}
let resolveSubmit;
const calls = [];
global.fetch = (url, options) => {{
  calls.push([url, options]);
  if(url === '/ip-relationship-jobs') {{
    return new Promise(resolve => {{ resolveSubmit = resolve; }});
  }}
  return Promise.resolve({{ ok: true, status: 200, json: async () => ({{}}) }});
}};
(async () => {{
  const controller = new AbortController();
  const resultPromise = fetchIpRelationshipJobResult(
    {{ ips: ['1.1.1.1'] }}, controller, () => {{}}
  );
  controller.abort();
  resolveSubmit({{
    ok: true,
    status: 202,
    json: async () => ({{ job_id: 'job/a' }})
  }});
  const result = await resultPromise;
  assert.strictEqual(result.status, 499);
  assert.deepStrictEqual(calls.map(call => call[0]), [
    '/ip-relationship-jobs',
    '/ip-relationship-jobs/job%2Fa/cancel'
  ]);
  assert.strictEqual(Object.hasOwn(calls[0][1], 'signal'), false);
}})().catch(error => {{ console.error(error); process.exit(1); }});
""")


def test_quality_formatter_executes_for_legacy_vt_off_and_partial_payloads():
    formatter_source = FRONTEND_SOURCE[
        FRONTEND_SOURCE.index("function formatIpRelationshipQuality"):
        FRONTEND_SOURCE.index("async function cancelIpRelationshipJob")
    ]
    _run_node(f"""
const assert = require('assert');
{formatter_source}
assert.strictEqual(formatIpRelationshipQuality({{}}), '');
const vtOff = formatIpRelationshipQuality({{ quality: {{
  analysis_complete: true,
  evaluated_candidate_count: 0,
  candidate_limit: 1000,
  vt_enabled: false
}} }});
assert(vtOff.includes('candidates evaluated 0 / limit 1000'));
assert(!vtOff.includes('VT reports'));
assert(!vtOff.includes('NaN'));
const partial = formatIpRelationshipQuality({{ quality: {{
  analysis_complete: false,
  evaluated_candidate_count: 12,
  candidate_limit: 1000,
  vt_enabled: true,
  vt_report_count: 1,
  vt_eligible_count: 2,
  vt_skipped_non_global: 3,
  vt_report_coverage: 0.5,
  warning_codes: ['vt_partial_coverage']
}} }});
assert(partial.includes('coverage 50%'));
assert(partial.includes('⚠ incomplete analysis'));
assert(!partial.includes('NaN'));
""")


def test_poll_timeout_cancels_once_and_renders_terminal_error_at_runtime():
    analyze_source = FRONTEND_SOURCE[
        FRONTEND_SOURCE.index("async function analyzeIpRelationships"):]
    _run_node(f"""
const assert = require('assert');
{analyze_source}
const elements = new Map();
function element(id) {{
  if(!elements.has(id)) elements.set(id, {{ value: '', checked: false, textContent: '', style: {{ display: 'block' }} }});
  return elements.get(id);
}}
element('ipIntelInput').value = '1.1.1.1';
global.document = {{
  getElementById: element,
  querySelector: selector => element(selector)
}};
global.window = {{}};
global.ipRelAnalyzeController = null;
global.ipRelAnalyzeSeq = 0;
global.computeIpIntelInputSignature = value => value;
global.parseBoundedInt = (_value, fallback) => fallback;
global.setIpIntelBusy = () => {{}};
global.finalizeIpRelationshipRun = controller => {{
  if(ipRelAnalyzeController === controller) ipRelAnalyzeController = null;
  setIpIntelBusy(false);
}};
global.setIpRelView = () => {{}};
global.setSummaryMessage = () => {{}};
global.clearIpIntelRelationshipInsights = () => {{}};
global.resetIpRelVisualCaches = () => {{}};
global.renderMergedIpIntelHints = () => {{}};
global.renderIpRelationshipError = (_pairs, _clusters, message) => {{
  assert.strictEqual(message, 'No data');
}};
global.restorePreviousIpRelationshipResult = () => false;
global.isAbortError = () => false;
let cancelCount = 0;
global.cancelIpRelationshipJob = async jobId => {{
  assert.strictEqual(jobId, 'job-timeout');
  cancelCount += 1;
  return true;
}};
global.fetchIpRelationshipJobResult = async (_body, _controller, onStatus) => {{
  onStatus('job-timeout', 'active');
  return {{ ok: false, status: 504, body: {{ error: 'relationship job timed out' }} }};
}};
(async () => {{
  await analyzeIpRelationships();
  await new Promise(resolve => setImmediate(resolve));
  assert.strictEqual(cancelCount, 1);
  assert(elements.get('ipRelMeta').textContent.includes('relationship job timed out'));
}})().catch(error => {{ console.error(error); process.exit(1); }});
""")
