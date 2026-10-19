/* Read-only, explicitly requested diagnostics. Independent of health polling. */
(() => {
  'use strict';
  const panel = document.getElementById('deliveryDiagnostics');
  if(!panel || !window.TraceAuth) return;
  const readButton = document.getElementById('diagnosticsRead');
  const cancelButton = document.getElementById('diagnosticsCancel');
  const downloadButton = document.getElementById('diagnosticsDownload');
  const status = document.getElementById('diagnosticsStatus');
  const details = document.getElementById('diagnosticsDetails');
  const reasons = [
    'delivery_storage','delivery_capacity','tracking_overflow','old_binding_blocked',
    'client_unavailable','configuration_unavailable','provider_auth','provider_tls',
    'provider_timeout','provider_transport','provider_rate_limit','provider_unavailable',
    'provider_response','provider_work_limit','attempts_exhausted','invalid_payload',
    'recovery_gap','receipt_persistence','history_persistence','delivery_unknown',
    'destination_disabled','destination_invalid','adapter_unapplied','removal_disabled',
    'tls_config','tls_error','provider_transient','provider_http','provider_protocol',
    'transport_error','response_limit','attribute_limit','payload_invalid','payload_limit','sighting_absent'
  ];
  const stages = ['open_owner','open_db','open_validate','transaction_begin','transaction_body',
    'transaction_commit','transaction_readback','health_refresh','worker'];
  const codes = ['sqlite_busy','sqlite_full','sqlite_readonly','sqlite_corrupt','sqlite_io','sqlite_error',
    'permission_denied','disk_full','owner_lock','os_error','invalid_state','worker_exception','unknown'];
  const enumeration = values => value => values.includes(value);
  const optional = check => value => value === null || check(value);
  const count = value => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 2 ** 63;
  const flag = value => typeof value === 'boolean';
  const array = (check, cap) => value => Array.isArray(value) && value.length <= cap && value.every(check);
  function closed(value, fields){
    return value !== null && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === Object.keys(fields).length &&
      Object.entries(fields).every(([key, check]) => Object.hasOwn(value, key) && check(value[key]));
  }
  const detail = value => closed(value, {
    operation:enumeration(['unknown','teams_send','misp_read','misp_add','misp_delete','misp_sighting_read','misp_sighting_add']),
    http_status:optional(n => Number.isInteger(n) && n >= 100 && n <= 599),
    response_bytes:optional(count), response_limit:optional(count), attribute_count:optional(count), attribute_limit:optional(count),
    tls_kind:optional(enumeration(['certificate_verify','ssl_failure'])), tls_verify:optional(flag)
  });
  const record = value => closed(value, {at:count, channel:enumeration(['teams','misp']),
    state:enumeration(['acked','continue','retry','blocked','failed']), reason:optional(enumeration(reasons)),
    attempt:count, items:count, diagnostic:detail});
  const channel = value => closed(value, {latest_result:optional(record), latest_failure:optional(record),
    blocked_by_reason:array(v => closed(v, {reason:enumeration(reasons), count}), 64)});
  function validate(value){
    if(!closed(value, {version:v => v === 1, observed_at:count, counts_stale:flag, storage_ok:flag,
      worker_running:flag, coverage:enumeration(['covered','gap','rebaselining']),
      storage_error:optional(v => closed(v, {at:count, stage:enumeration(stages), code:enumeration(codes)})),
      channels:v => closed(v, {teams:channel, misp:channel}), recent_failures:array(record, 10)
    })) throw new Error('Invalid diagnostics');
    return value;
  }
  async function readDiagnostics(response, signal){
    if(!response.ok || !response.body) throw new Error('Diagnostics unavailable');
    const reader = response.body.getReader();
    const cancel = () => { reader.cancel().catch(() => {}); };
    signal.addEventListener('abort', cancel, {once:true});
    let length = 0, text = '';
    const decoder = new TextDecoder('utf-8', {fatal:true});
    try {
      if(signal.aborted) throw new Error('Cancelled');
      while(true){
        const {done, value} = await reader.read();
        if(signal.aborted) throw new Error('Cancelled');
        if(done) break;
        length += value.byteLength;
        if(length > 32768) throw new Error('Diagnostics too large');
        text += decoder.decode(value, {stream:true});
      }
      text += decoder.decode();
      // Validate integer wire tokens before JS rounds them; keep their exact
      // spelling in the canonical download, never the untrusted response text.
      const encoded = text.replace(/"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g, token => {
        if(token.startsWith('"')) return token;
        if(!/^(0|[1-9]\d*)$/.test(token) || BigInt(token) > 9223372036854775807n) throw new Error('Invalid counter');
        return '"@number:' + token + '"';
      });
      const data = validate(JSON.parse(text));
      const json = JSON.stringify(JSON.parse(encoded), null, 2).replace(/"@number:(\d+)"/g, '$1');
      return {data, json};
    } finally {
      signal.removeEventListener('abort', cancel);
      cancel();
      reader.releaseLock();
    }
  }
  const number = value => value === null ? 'unknown' : Number.isSafeInteger(value) ? String(value) : 'precision unavailable';
  function timestamp(value){
    if(!Number.isSafeInteger(value) || value > 8640000000000) return 'precision unavailable';
    return new Date(value * 1000).toISOString();
  }
  function hint(reason, d){
    if(d && (d.tls_kind || ['provider_tls','tls_config','tls_error'].includes(reason)))
      return 'Check certificate trust chain, hostname, expiry and configured CA readability. Keep TLS verification enabled.';
    if(d && d.http_status === 302)
      return 'HTTP 302 redirect is not followed. Check the configured direct provider endpoint and reverse-proxy routing.';
    if(reason === 'response_limit') return 'Decoded response cap reached. Check provider response scope; do not bypass the configured cap.';
    if(reason === 'attribute_limit' || reason === 'provider_work_limit') return 'Attribute/work cap reached. Review event size and provider scope; do not bypass the cap.';
    if(['provider_auth'].includes(reason)) return 'Check provider credentials and least-privilege permissions with the administrator.';
    if(['provider_timeout','provider_transport','transport_error'].includes(reason)) return 'Check provider connectivity, DNS and proxy availability; no probe is made here.';
    if(['provider_rate_limit','provider_unavailable','provider_transient'].includes(reason)) return 'Check provider availability and rate limits; the worker owns scheduled retries.';
    if(['provider_http','provider_response','provider_protocol'].includes(reason)) return 'Check provider HTTP/API compatibility and reverse-proxy behavior; response bodies are intentionally omitted.';
    if(['delivery_storage','receipt_persistence','history_persistence','recovery_gap'].includes(reason)) return 'Check local disk space, permissions, ledger ownership and integrity. Do not delete the ledger.';
    if(['delivery_capacity','tracking_overflow'].includes(reason)) return 'Review pending delivery and configured capacity; observation can continue with incomplete notification coverage.';
    if(reason === 'old_binding_blocked') return 'Pending items belong to an older destination binding. Review the destination change; do not assume automatic rerouting.';
    if(['destination_disabled','destination_invalid','configuration_unavailable','client_unavailable','adapter_unapplied','removal_disabled'].includes(reason)) return 'Ask the administrator to review enabled destination settings, applied configuration and removal policy.';
    if(['payload_invalid','payload_limit','invalid_payload'].includes(reason)) return 'Review payload shape/size and application compatibility; payload data is intentionally omitted.';
    if(reason === 'attempts_exhausted') return 'Attempt budget exhausted. Investigate the last failure before considering any separate operational recovery.';
    if(reason === 'sighting_absent') return 'Review MISP attribute/sighting availability and permissions.';
    return 'No more specific safe evidence is available. Check local operator logs without sharing secrets.';
  }
  function recordLine(label, r){
    if(r === null) return `${label}: unknown — no retained result.`;
    const d = r.diagnostic;
    return `${label}: ${r.channel} ${r.state} · ${r.reason === null ? 'no reason reported' : r.reason} · at ${timestamp(r.at)} · attempt ${number(r.attempt)} · items ${number(r.items)}. ` +
      `Operation: ${d.operation} · HTTP: ${number(d.http_status)} · decoded response bytes: ${number(d.response_bytes)} / cap ${number(d.response_limit)} · attributes: ${number(d.attribute_count)} / cap ${number(d.attribute_limit)}. ` +
      `TLS verification: ${d.tls_verify === null ? 'unknown' : d.tls_verify ? 'enabled' : 'disabled'} · TLS classification: ${d.tls_kind || 'unknown'}. ` +
      (r.reason !== null || d.tls_kind || d.http_status === 302 ? hint(r.reason, d) : '');
  }
  let snapshot = null;
  function render(result){
    const h = result.data;
    const lines = [
      'Health last_error prioritizes the oldest blocked item, not necessarily the latest attempt. Compare latest result with latest terminal failure below; a later success does not erase retained failures.',
      'Retained terminal failure groups (latest first, at most 10), not cumulative failure counts. Items is the number of affected destination-items in each group. Failed items are not automatically replayed.',
      'Decoded bytes and attribute counts are observed lower bounds on rejected/truncated reads, not promised total sizes. Unknown details were not recorded, not zero.',
      `Storage: ${h.storage_ok ? 'available' : 'degraded'} · Worker: ${h.worker_running ? 'running' : 'not running'} · Coverage: ${h.coverage}.`,
      'Storage incident scope: latest observed in this process, volatile and not persisted; not necessarily active now.'
    ];
    if(h.storage_error){
      const e = h.storage_error;
      lines.push(`Latest process incident: ${e.code} at ${timestamp(e.at)} · stage ${e.stage}. Check disk space, permissions, exclusive ledger ownership and local logs; do not delete the ledger.`);
    } else lines.push('Latest process incident: none recorded in this process; prior process incidents are unknown.');
    if(!h.worker_running || h.storage_error?.stage === 'worker') lines.push('Worker check: review process lifecycle and local operator logs. This panel cannot restart the worker or replay deliveries.');
    for(const name of ['teams','misp']){
      const c = h.channels[name];
      lines.push(recordLine(`${name} latest result`, c.latest_result));
      lines.push(recordLine(`${name} latest terminal failure`, c.latest_failure));
      lines.push(`${name} blocked by reason: ${c.blocked_by_reason.length ? '' : 'none in cached snapshot'}`);
      for(const entry of c.blocked_by_reason) lines.push(`${entry.reason}: ${number(entry.count)} blocked items. ${hint(entry.reason, {})}`);
    }
    lines.push(`Recent retained failure groups: ${h.recent_failures.length}.`);
    for(const [i, r] of h.recent_failures.entries()) lines.push(recordLine(`Failure group ${i + 1}`, r));
    const fragment = document.createDocumentFragment();
    for(const line of lines){ const p = document.createElement('p'); p.textContent = line; fragment.appendChild(p); }
    details.replaceChildren(fragment);
    status.textContent = `${h.counts_stale ? 'Counts stale' : 'Cached counts at observation'} · observed ${timestamp(h.observed_at)} · last read ${new Date().toISOString()}. Snapshot only, not live; refresh explicitly.`;
    snapshot = result;
    downloadButton.disabled = false;
  }
  let active = null;
  let stopped = false;
  function forget(){
    snapshot = null;
    details.replaceChildren();
    downloadButton.disabled = true;
    panel.hidden = true;
  }
  async function refresh(){
    if(active || stopped || document.hidden) return;
    const controller = new AbortController();
    active = controller;
    readButton.disabled = true;
    cancelButton.disabled = false;
    downloadButton.disabled = true;
    status.textContent = 'Reading cached diagnostics…';
    let aborted;
    const cancelled = new Promise((_, reject) => {
      aborted = () => reject(new Error('Diagnostics cancelled'));
      controller.signal.addEventListener('abort', aborted, {once:true});
    });
    const timer = setTimeout(() => controller.abort(), 10000);
    const work = async () => {
      const user = await window.TraceAuth.ready;
      if(controller.signal.aborted) return;
      if(!user || !['admin','operator'].includes(user.role)) { forget(); return; }
      panel.hidden = false;
      const response = await fetch('/delivery-diagnostics', {method:'GET', cache:'no-store', signal:controller.signal});
      if(controller.signal.aborted) return;
      if(response.status === 401 || response.status === 403) { forget(); return; }
      const result = await readDiagnostics(response, controller.signal);
      if(!controller.signal.aborted && active === controller) render(result);
    };
    try {
      await Promise.race([work(), cancelled]);
    } catch(error) {
      if(['Permission denied for this action.', 'Sign-in failed or session expired.'].includes(error?.message)) forget();
      status.textContent = snapshot ? 'Diagnostics unavailable or cancelled — stale last successful snapshot. Refresh explicitly.' : 'Diagnostics unavailable or cancelled — unknown. Refresh explicitly.';
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener('abort', aborted);
      if(active === controller) active = null;
      readButton.disabled = false;
      readButton.textContent = 'Refresh diagnostics';
      cancelButton.disabled = true;
      downloadButton.disabled = !snapshot;
    }
  }
  downloadButton.addEventListener('click', () => {
    if(!snapshot || active || downloadButton.disabled) return;
    const url = URL.createObjectURL(new Blob([snapshot.json + '\n'], {type:'application/json'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'delivery-diagnostics.json';
    try { link.click(); }
    finally { setTimeout(() => URL.revokeObjectURL(url), 0); }
  });
  readButton.addEventListener('click', refresh);
  cancelButton.addEventListener('click', () => { if(active) active.abort(); });
  function pause(){
    if(active) active.abort();
    if(snapshot) status.textContent = 'Diagnostics paused — stale last successful snapshot. Refresh explicitly.';
  }
  document.addEventListener('visibilitychange', () => { if(document.hidden) pause(); });
  window.addEventListener('pagehide', () => { stopped = true; pause(); });
  window.addEventListener('pageshow', () => { stopped = false; });
})();
