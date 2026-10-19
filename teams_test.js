/* Manual saved-configuration Teams test; never reads a credential input. */
(() => {
  'use strict';
  const reasons = new Set(('delivery_storage delivery_capacity tracking_overflow old_binding_blocked client_unavailable configuration_unavailable provider_auth provider_tls provider_timeout provider_transport provider_rate_limit provider_unavailable provider_response provider_work_limit attempts_exhausted invalid_payload recovery_gap receipt_persistence history_persistence delivery_unknown destination_disabled destination_invalid adapter_unapplied removal_disabled tls_config tls_error provider_transient provider_http provider_protocol transport_error response_limit attribute_limit payload_invalid payload_limit sighting_absent test_in_progress test_cooldown configuration_changed runtime_unavailable').split(' '));
  const unknown = 'Delivery outcome unknown. Check Teams before sending another test; no automatic retry.';
  const notSent = new Set(['test_in_progress','test_cooldown','configuration_changed','runtime_unavailable',
    'destination_disabled','destination_invalid','adapter_unapplied','configuration_unavailable']);
  const keys = (value, names) => value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every(key => Object.hasOwn(value,key));
  function valid(value){
    if(!keys(value,['status','reason','retry_after','diagnostic']) ||
       !['accepted','failed','not_sent'].includes(value.status) ||
       !(value.reason === null || reasons.has(value.reason)) ||
       !(value.retry_after === null || Number.isInteger(value.retry_after) && value.retry_after >= 0 && value.retry_after <= 30)) return false;
    if(value.status === 'accepted' && value.reason !== null ||
       value.status === 'failed' && (value.reason === null || ['test_in_progress','test_cooldown','configuration_changed','runtime_unavailable'].includes(value.reason)) ||
       value.status === 'not_sent' && !notSent.has(value.reason)) return false;
    const d = value.diagnostic;
    return keys(d,['operation','http_status','response_bytes','response_limit','attribute_count','attribute_limit','tls_kind','tls_verify']) &&
      ['unknown','teams_send','misp_read','misp_add','misp_delete','misp_sighting_read','misp_sighting_add'].includes(d.operation) &&
      (d.http_status === null || Number.isInteger(d.http_status) && d.http_status >= 100 && d.http_status <= 599) &&
      ['response_bytes','response_limit','attribute_count','attribute_limit'].every(key => d[key] === null ||
        // Int64 maxima round to 2**63 in JSON.parse. These counters are not
        // displayed here; the HTTP boundary already validates exact integers.
        Number.isInteger(d[key]) && d[key] >= 0 && d[key] <= 2**63) &&
      (d.tls_kind === null || ['certificate_verify','ssl_failure'].includes(d.tls_kind)) &&
      (d.tls_verify === null || typeof d.tls_verify === 'boolean');
  }
  function message(value){
    if(!valid(value)) return unknown;
    const detail = value.diagnostic;
    const metrics = [];
    if(detail){
      if(Number.isInteger(detail.http_status) && detail.http_status >= 100 && detail.http_status <= 599) metrics.push('HTTP '+detail.http_status);
      if(['certificate_verify','ssl_failure'].includes(detail.tls_kind)) metrics.push('TLS '+detail.tls_kind);
      if(typeof detail.tls_verify === 'boolean') metrics.push('TLS verify '+detail.tls_verify);
    }
    const suffix = metrics.length ? ' ('+metrics.join('; ')+').' : '';
    if(value.status === 'accepted' && value.reason === null) return 'Teams accepted the test. This does not confirm that a person read it.'+suffix;
    if(value.status === 'failed'){
      if(['provider_timeout','provider_transport','transport_error','delivery_unknown','provider_protocol','response_limit'].includes(value.reason) ||
         detail.http_status >= 200 && detail.http_status < 300) return 'Test could not be confirmed ('+value.reason+'). '+unknown+suffix;
      return 'Test failed: '+value.reason+'. Review the saved settings and diagnostics; no automatic retry.'+suffix;
    }
    if(value.status === 'not_sent'){
      if(value.reason === 'test_cooldown' || value.reason === 'test_in_progress'){
        const wait = Number.isInteger(value.retry_after) && value.retry_after >= 0 && value.retry_after <= 30 ? value.retry_after : 30;
        return 'Test not sent: '+(value.reason === 'test_in_progress' ? 'another test is in progress. ' : 'cooldown. ')+
          'Wait '+wait+' seconds, then click manually if needed. No automatic retry.';
      }
      if(value.reason === 'runtime_unavailable') return 'Test not sent: runtime unavailable. Contact the administrator.';
      return 'Test not sent: '+value.reason+'. Review saved settings and click Load Alert Settings before testing again.';
    }
    return unknown;
  }
  let refresh = () => {};
  window.TraceTeamsTest = {
    settingsChanged: () => refresh(),
    bind(getRevision){
      const button = document.getElementById('teamsTestBtn');
      const status = document.getElementById('teamsTestStatus');
      if(!button || !status) return;
      let busy = false;
      const isAdmin = () => window.TraceAuth && window.TraceAuth.user && window.TraceAuth.user.role === 'admin';
      const validRevision = value => Number.isSafeInteger(value) && value >= 0;
      refresh = () => { button.hidden = !isAdmin(); button.disabled = !isAdmin() || busy || !validRevision(getRevision()); };
      button.addEventListener('click', async () => {
        const revision = getRevision();
        if(!isAdmin() || busy || !validRevision(revision)) return;
        if(!window.confirm('Send one real Teams message using saved, applied settings? Unsaved edits are ignored.')) return;
        busy = true; refresh();
        status.textContent = 'Sending one real Teams test using saved settings…';
        try {
          const value = await window.TraceAuth.readJSON('/teams/test', {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({revision})
          });
          status.textContent = message(value);
        } catch(_) {
          status.textContent = unknown;
        } finally { busy = false; refresh(); }
      });
      if(window.TraceAuth) window.TraceAuth.ready.then(refresh).catch(() => {});
    }
  };
})();
