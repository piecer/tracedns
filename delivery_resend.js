/* One bounded saved-target resend dialog. No draft destinations or automatic retries. */
(() => {
  'use strict';
  const reasons = new Set(('invalid_request target_not_found no_managed_ips snapshot_changed configuration_changed preview_expired preview_capacity resend_cooldown delivery_pending destination_unavailable delivery_capacity delivery_storage runtime_unavailable delivery_unknown').split(' '));
  const unknown = 'Admission outcome unknown. A send may already be queued. Check delivery health, diagnostics and the destinations before any new resend. No automatic retry.';
  const caution = 'Last-good/current saved observation; no live lookup. This is not a freshness or reachability guarantee.';
  const keys = (v, names) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === names.length && names.every(k=>Object.hasOwn(v,k));
  const integer = (n, max) => Number.isInteger(n) && n >= 0 && n <= max;
  const token = s => typeof s === 'string' && /^[a-f0-9]{32}$/.test(s) && s.length === 32;
  const channels = v => Array.isArray(v) && v.length <= 2 && v.every(s=>['teams','misp'].includes(s)) && new Set(v).size === v.length;
  const base = v => (v.reason === null || reasons.has(v.reason)) && (v.request_id === null || token(v.request_id)) &&
    channels(v.channels) && (v.retry_after === null || integer(v.retry_after,30));
  function validPreview(v){
    return keys(v,['status','reason','request_id','target','source_type','ips','observed_at','retained','channels','expires_in_seconds','retry_after']) &&
      base(v) && ['ready','not_ready'].includes(v.status) &&
      (v.target === null || typeof v.target === 'string' && v.target.length > 0 && v.target.length <= 4096) &&
      (v.source_type === null || ['A','TXT','ENS','SNS','DHT','RPC'].includes(v.source_type)) &&
      Array.isArray(v.ips) && v.ips.length <= 256 && new Set(v.ips).size === v.ips.length &&
      v.ips.every(ip=>typeof ip === 'string' && ip.length <= 45 && /^[a-fA-F0-9:.]+$/.test(ip)) &&
      (v.observed_at === null || integer(v.observed_at,2**63)) && typeof v.retained === 'boolean' && integer(v.expires_in_seconds,300) &&
      (v.status === 'ready' ? v.reason === null && token(v.request_id) && v.ips.length > 0 && v.channels.length > 0 &&
        v.target !== null && v.source_type !== null && v.expires_in_seconds > 0 : reasons.has(v.reason));
  }
  function validConfirm(v){
    return keys(v,['status','reason','request_id','ip_count','receipt_count','channels','retry_after']) && base(v) &&
      integer(v.ip_count,256) && integer(v.receipt_count,512) &&
      (['queued','already_queued'].includes(v.status) ? v.reason === null && token(v.request_id) && v.ip_count > 0 &&
        v.channels.length > 0 && v.receipt_count === v.ip_count * v.channels.length :
        v.status === 'unknown' ? v.reason === 'delivery_unknown' :
          v.status === 'not_queued' && reasons.has(v.reason) && v.reason !== 'delivery_unknown' && v.ip_count === 0 && v.receipt_count === 0);
  }
  let changed = () => {}, savedConfig = () => {}, savedAlerts = () => {}, invalidate = () => {};
  window.TraceDeliveryResend = {
    changed: () => changed(), savedConfig: () => savedConfig(), savedAlerts: () => savedAlerts(),
    invalidateConfig: () => invalidate(),
    bind(getRevision, identity){
      const byId = id => document.getElementById('deliveryResend'+id);
      const dialog=byId('Dialog'), status=byId('Status'), previewBtn=byId('PreviewBtn'), confirmBtn=byId('ConfirmBtn');
      const teams=byId('Teams'), misp=byId('Misp'), ips=byId('IPs'), source=byId('Source'), targetLabel=byId('Target');
      const outside=document.getElementById('domainSettingsStatus');
      if(!dialog || !window.TraceAuth) return;
      let dirty=true, alertDirty=false, blocked=false, uncertain=false, busy=false, confirming=false, finished=false;
      let selected=null, intent=null, controller=null, generation=0, opener=null;
      const isAdmin=()=>!blocked && window.TraceAuth.user && window.TraceAuth.user.role === 'admin';
      const revisionValid=()=>Number.isSafeInteger(getRevision()) && getRevision() >= 0;
      const clean=()=>!dirty && !alertDirty && revisionValid();
      const picked=()=>['teams','misp'].filter(c=>(c==='teams'?teams:misp).checked);
      const sameChannels=(a,b)=>a.length===b.length && a.every(c=>b.includes(c));
      const refresh=()=>{
        document.querySelectorAll('.delivery-resend-btn').forEach(button=>{
          button.hidden=!isAdmin(); button.disabled=!isAdmin() || busy || uncertain || !revisionValid();
        });
        previewBtn.disabled=!isAdmin() || !clean() || busy || finished || uncertain || !selected || !picked().length;
        confirmBtn.disabled=!isAdmin() || !clean() || busy || finished || uncertain || !intent;
        teams.disabled=misp.disabled=busy || finished || uncertain;
      };
      const clearPreview=()=>{intent=null;ips.replaceChildren();source.textContent=caution;refresh();};
      const warnUnknown=()=>{uncertain=true;status.textContent=outside.textContent=unknown;refresh();};
      const cancel=()=>{
        generation++; if(controller) controller.abort();
        if(confirming) warnUnknown();
        busy=false;confirming=false;controller=null;selected=null;intent=null;
        ips.replaceChildren();source.textContent=caution;dialog.close();refresh();
        if(opener && opener.isConnected) opener.focus();
      };
      changed=()=>{dirty=true;clearPreview();};
      savedConfig=()=>{dirty=false;clearPreview();};
      savedAlerts=()=>{alertDirty=false;clearPreview();};
      invalidate=()=>{dirty=true;clearPreview();};
      document.getElementById('settings').addEventListener('input',event=>{
        if(event.target.id==='domainSettingsSearch') return;
        if(document.getElementById('domainSettingsSection').contains(event.target)) changed();
        if(document.getElementById('alertsSection').contains(event.target)){alertDirty=true;clearPreview();}
      });
      document.getElementById('settings').addEventListener('change',event=>{
        if(event.target.id==='domainSettingsSearch') return;
        if(document.getElementById('domainSettingsSection').contains(event.target)) changed();
        if(document.getElementById('alertsSection').contains(event.target)){alertDirty=true;clearPreview();}
      });
      document.getElementById('domainTable').addEventListener('click',event=>{
        const button=event.target.closest('.delivery-resend-btn');
        if(!button || !isAdmin() || busy || uncertain) return;
        const row=button.closest('tr'), saved=row && row._original;
        if(!saved || !['A','TXT','ENS','SNS','DHT','RPC'].includes(String(saved.type||'A').toUpperCase())) return;
        if(!clean()){outside.textContent='Save or reload settings before resending current IPs. Unsaved edits are not used.';return;}
        selected={target:identity(saved),revision:getRevision()};opener=button;finished=false;
        teams.checked=misp.checked=true;targetLabel.textContent=saved.name;
        status.textContent='Select saved channels, then preview the exact IP list. Preview does not send.';
        clearPreview();dialog.showModal();previewBtn.focus();
      });
      [teams,misp].forEach(input=>input.addEventListener('change',()=>{
        clearPreview();status.textContent='Channel selection changed. Preview again before confirming.';
      }));
      const permissionFailure=error=>{
        if(!window.TraceAuth.user || error && error.message==='Permission denied for this action.') blocked=true;
      };
      const post=(path,body)=>window.TraceAuth.readJSON(path,{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(body),signal:controller.signal});
      previewBtn.addEventListener('click',async()=>{
        if(!isAdmin() || !clean() || busy || finished || uncertain || !selected || !picked().length) return;
        const current=++generation, selection={...selected,channels:picked()};
        clearPreview();busy=true;controller=new AbortController();refresh();status.textContent='Preparing saved IP preview…';
        try{
          const value=await post('/delivery-resend/preview',selection);
          if(current!==generation) return;
          if(!validPreview(value)) throw new Error('Invalid preview');
          if(value.status!=='ready'){
            status.textContent='Preview not ready: '+value.reason+'.'+(value.retry_after===null?'':' Wait '+value.retry_after+' seconds.')+' No send was requested.';
            return;
          }
          if(value.target!==selection.target || !sameChannels(value.channels,selection.channels) || !clean() ||
              getRevision()!==selection.revision) throw new Error('Changed preview');
          intent={...value,deadline:Date.now()+value.expires_in_seconds*1000,revision:selection.revision};
          const date=value.observed_at===null?null:new Date(value.observed_at*1000);
          const when=date && Number.isFinite(date.getTime())?date.toISOString():'not recorded';
          source.textContent=caution+' Source: '+value.source_type+'; observed at: '+when+'. '+
            (value.retained?'Retained/last-good data; latest success or freshness is not established. ':'Current saved data. ')+
            'Channels: '+value.channels.join(', ')+'. '+value.ips.length+' IPs; preview expires in '+value.expires_in_seconds+' seconds.';
          ips.replaceChildren(...value.ips.map(ip=>{const li=document.createElement('li');li.textContent=ip;return li;}));
          status.textContent='Review every IP and selected channel. Confirm deliberately resends duplicates using saved destinations.';
        }catch(error){
          if(current!==generation) return;
          permissionFailure(error);clearPreview();status.textContent='Preview unavailable or changed. No confirmation was sent. Check access and saved settings.';
        }finally{
          if(current===generation){busy=false;controller=null;refresh();}
        }
      });
      confirmBtn.addEventListener('click',async()=>{
        if(!isAdmin() || !clean() || busy || finished || uncertain || !intent) return;
        if(Date.now()>=intent.deadline || getRevision()!==intent.revision || !sameChannels(picked(),intent.channels)){
          clearPreview();status.textContent='Preview expired or changed. Preview again before confirming.';return;
        }
        const current=++generation, confirmed=intent;intent=null;busy=true;confirming=true;finished=true;
        controller=new AbortController();refresh();status.textContent='Submitting once for durable queue admission…';
        try{
          const value=await post('/delivery-resend',{request_id:confirmed.request_id});
          if(current!==generation) return;
          if(!validConfirm(value) || value.request_id!==null && value.request_id!==confirmed.request_id) throw new Error('Invalid admission result');
          if(value.status==='unknown'){warnUnknown();return;}
          if(value.status==='not_queued'){
            status.textContent='Not queued: '+value.reason+'.'+(value.retry_after===null?'':' Wait '+value.retry_after+' seconds.')+' No automatic retry.';
          }else{
            if(!sameChannels(value.channels,confirmed.channels) || value.ip_count!==confirmed.ips.length) throw new Error('Changed admission');
            status.textContent=(value.status==='already_queued'?'Already queued':'Queued')+': '+value.ip_count+' IPs, '+value.receipt_count+
              ' destination items ('+value.channels.join(', ')+'). Queue admission is not delivery ACK or human receipt. Check delivery health and diagnostics.';
          }
        }catch(error){if(current===generation){permissionFailure(error);warnUnknown();}}
        finally{if(current===generation){busy=false;confirming=false;controller=null;refresh();}}
      });
      byId('CancelBtn').addEventListener('click',cancel);
      window.TraceAuth.onInvalidated?.(() => {
        blocked=true;opener=null;cancel();targetLabel.textContent='';
        status.textContent='Access changed. Reload to check permissions. '+(uncertain?unknown:'');
      });
      byId('HealthLink').addEventListener('click',cancel);
      byId('DiagnosticsLink').addEventListener('click',cancel);
      dialog.addEventListener('cancel',event=>{event.preventDefault();cancel();});
      window.TraceAuth.ready.then(refresh).catch(()=>{blocked=true;refresh();});
      refresh();
    }
  };
})();
