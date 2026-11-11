'use strict';
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const app = fs.readFileSync('dns_frontend.js','utf8');
const html = fs.readFileSync('dns_frontend.html','utf8');
assert.equal((html.match(/id="deliveryResendDialog"/g)||[]).length,1,'one bounded shared modal');
assert(html.indexOf('src="/delivery_resend.js"') < html.indexOf('src="/dns_frontend.js"'));
assert(app.includes("resend.className = 'delivery-resend-btn'"),'saved target card action');
assert(app.includes('window.TraceDeliveryResend.bind(() => configRevision, domainConfigIdentity)'));
const css=fs.readFileSync('dns_frontend.css','utf8');
assert.match(css,/#deliveryResendDialog\s*\{[^}]*max-height:[^}]*overflow:auto/s,'modal bounded to viewport');
assert.match(css,/#deliveryResendIPs\s*\{[^}]*max-height:[^}]*overflow:auto/s,'complete scrollable list');
const tick = () => new Promise(setImmediate);
const token = 'a'.repeat(32);
function setup(role='admin'){
  const nodes = new Map(), calls = [], timers = new Map(); let nextTimer=0, revision=7;
  class Node {
    constructor(id=''){this.id=id;this.children=[];this.hidden=false;this.disabled=false;this.checked=true;this.textContent='';this.handlers={};this.dataset={};this.isConnected=true;}
    addEventListener(name, fn){(this.handlers[name] ||= []).push(fn);}
    async emit(name, event={}){for(const fn of this.handlers[name]||[]) await fn({target:this,preventDefault(){},...event});}
    append(...nodes){this.children.push(...nodes);}
    appendChild(node){this.append(node);return node;}
    replaceChildren(...nodes){this.children=nodes;this.textContent='';}
    setAttribute(){}
    showModal(){this.open=true;}
    close(){this.open=false;}
    focus(){this.focused=true;}
    closest(selector){return selector==='tr'?this.row:selector==='.delivery-resend-btn'?this:null;}
    contains(node){return node.section===this.id;}
  }
  const node=id=>{if(!nodes.has(id)) nodes.set(id,new Node(id));return nodes.get(id);};
  const button = new Node('resend');
  const row = new Node('row');row._original={name:'<img onerror=CANARY> Saved',type:'RPC',rpc_profile:'polygon_aes_gcm_v1'};button.row=row;
  let preview={status:'ready',reason:null,request_id:token,target:'<img onerror=canary> saved|RPC|polygon_aes_gcm_v1',source_type:'RPC',
    ips:['192.0.2.1'],observed_at:1700000000,retained:true,channels:['teams','misp'],expires_in_seconds:300,retry_after:null};
  let confirmation={status:'queued',reason:null,request_id:token,ip_count:1,receipt_count:2,channels:['teams','misp'],retry_after:null};
  let previewCode=200, confirmCode=202, transport=null;
  const context=vm.createContext({console,URL,Request,Response,Headers,AbortController,DOMException,Date,
    document:{getElementById:node,querySelectorAll:selector=>selector==='.delivery-resend-btn'?[button]:[],createElement:()=>new Node(),
      body:{prepend(){}},addEventListener(){}},
    location:{href:'http://localhost/',origin:'http://localhost',pathname:'/',replace(url){context.redirect=url;}},
    setTimeout:(fn,ms)=>{timers.set(++nextTimer,{fn,ms});return nextTimer;},clearTimeout:id=>timers.delete(id),
    fetch:async(url,options={})=>{
      const path=new URL(url,'http://localhost').pathname;
      if(path==='/auth/me') return new Response(JSON.stringify({user:{id:'actor-1',role},csrf_token:'test-csrf'}));
      calls.push({path,options});
      if(transport) return transport(path,options);
      return new Response(JSON.stringify(path.endsWith('/preview')?preview:confirmation),{status:path.endsWith('/preview')?previewCode:confirmCode});
    }});
  context.window=context;
  vm.runInContext(fs.readFileSync('auth_frontend.js','utf8'),context);
  vm.runInContext(fs.readFileSync('delivery_resend.js','utf8'),context);
  vm.runInContext(app.slice(app.indexOf('function normalizeDomainName('),app.indexOf('function domainStorageName(')),context);
  context.TraceDeliveryResend.bind(()=>revision,context.domainConfigIdentity);
  context.TraceDeliveryResend.savedConfig();
  const open=()=>node('domainTable').emit('click',{target:button});
  const click=id=>node(id).emit('click');
  return {context,node,calls,button,row,open,click,timers,
    setPreview:(value,code=200)=>{preview=value;previewCode=code;},get preview(){return preview;},
    setConfirm:(value,code=202)=>{confirmation=value;confirmCode=code;},get confirmation(){return confirmation;},
    transport:fn=>{transport=fn;},setRevision:value=>{revision=value;}};
}
(async()=>{
  const env=setup();await tick();
  const {node,calls,context}=env;
  assert.equal(context.domainConfigIdentity({name:'Example.ETH.',type:'ENS',ens_text_key:'key',ens_node:'ABC',ens_resolver:'DEF'}),'example.eth|ENS|key|abc|def');
  assert.equal(context.domainConfigIdentity({name:'Example.SOL',type:'SNS'}),'example.sol|SNS|TXT');
  assert.equal(env.button.hidden,false);assert.equal(env.button.disabled,false);
  await env.open();assert(node('deliveryResendDialog').open);assert.equal(calls.length,0);
  assert.equal(node('deliveryResendTarget').textContent,env.row._original.name);
  await env.click('deliveryResendPreviewBtn');
  assert.deepEqual(JSON.parse(calls[0].options.body),{target:env.preview.target,channels:['teams','misp'],revision:7});
  assert.equal(new Headers(calls[0].options.headers).get('X-CSRF-Token'),'test-csrf');
  assert.equal(calls[0].options.credentials,'same-origin');
  assert.equal(node('deliveryResendIPs').children.length,1);
  assert.match(node('deliveryResendSource').textContent,/last.good|saved observation/i);
  assert.match(node('deliveryResendSource').textContent,/no live lookup/i);
  assert.match(node('deliveryResendSource').textContent,/1700000000|2023/);
  assert.equal(node('deliveryResendConfirmBtn').disabled,false);
  await env.click('deliveryResendConfirmBtn');
  assert.deepEqual(JSON.parse(calls[1].options.body),{request_id:token});
  assert.equal(calls[1].path,'/delivery-resend');
  assert.match(node('deliveryResendStatus').textContent,/queued/i);
  assert.match(node('deliveryResendStatus').textContent,/not.*deliver|not.*ACK/i);
  await env.click('deliveryResendConfirmBtn');assert.equal(calls.length,2,'double click never sends twice');
  await env.click('deliveryResendDiagnosticsLink');assert(!node('deliveryResendDialog').open,'diagnostics link releases modal focus trap');
  await env.open();await env.click('deliveryResendPreviewBtn');await env.click('deliveryResendCancelBtn');
  assert.equal(calls.length,3,'preview + cancel does not confirm');
  for(const role of ['operator','viewer']){
    const other=setup(role);await tick();await other.open();
    assert(other.button.hidden);assert.equal(other.calls.length,0);assert(!other.node('deliveryResendDialog').open);
  }
  // Filtering is a read-only control, including its blur/change event.
  const filtered=setup();await tick();
  for(const name of ['input','change']) await filtered.node('settings').emit(name,{target:{id:'domainSettingsSearch',section:'domainSettingsSection'}});
  await filtered.open();assert(filtered.node('deliveryResendDialog').open,'filtering must not dirty saved settings');
  // New drafts and dirty saved settings never become request inputs.
  const dirty=setup();await tick();
  await dirty.node('settings').emit('input',{target:{id:'edited',section:'domainSettingsSection'}});
  await dirty.open();assert.equal(dirty.calls.length,0);assert(!dirty.node('deliveryResendDialog').open);
  assert.match(dirty.node('domainSettingsStatus').textContent,/save|reload/i);
  dirty.context.TraceDeliveryResend.savedConfig();await dirty.open();
  assert(dirty.node('deliveryResendDialog').open);
  // Every structured refusal reaches the widget through the actual wrapper.
  for(const [reason,code] of [['invalid_request',400],['target_not_found',404],['configuration_changed',409],['delivery_pending',409],['resend_cooldown',429],['runtime_unavailable',503]]){
    const refusal=setup();await tick();await refusal.open();
    refusal.setPreview({...refusal.preview,status:'not_ready',reason,request_id:null,ips:[],expires_in_seconds:0,retry_after:code===429?30:null},code);
    await refusal.click('deliveryResendPreviewBtn');
    assert.match(refusal.node('deliveryResendStatus').textContent,new RegExp(reason));
    assert(refusal.node('deliveryResendConfirmBtn').disabled);
    refusal.setConfirm({},code);
    await assert.rejects(refusal.context.fetch('/ordinary-write',{method:'POST'}),'ordinary fetch still throws');
    await assert.rejects(refusal.context.fetch('/delivery-resend',{method:'GET'}),'exception is POST-only');
    for(const path of ['/api/v1/delivery-resend/preview','/api/v1/delivery-resend']){
      assert.equal((await refusal.context.fetch(path,{method:'POST'})).status,code);
    }
  }
  for(const [reason,code] of [['configuration_changed',409],['delivery_pending',409],['resend_cooldown',429],['delivery_storage',503]]){
    const refusal=setup();await tick();await refusal.open();await refusal.click('deliveryResendPreviewBtn');
    refusal.setConfirm({...refusal.confirmation,status:'not_queued',reason,ip_count:0,receipt_count:0,retry_after:code===429?30:null},code);
    await refusal.click('deliveryResendConfirmBtn');
    assert.match(refusal.node('deliveryResendStatus').textContent,new RegExp('Not queued: '+reason));
    assert.equal(refusal.calls.length,2);
  }
  // Selection invalidates the old token; every accepted IP remains visible.
  const nullToken=setup();await tick();await nullToken.open();await nullToken.click('deliveryResendPreviewBtn');
  nullToken.setConfirm({...nullToken.confirmation,status:'not_queued',reason:'invalid_request',request_id:null,ip_count:0,receipt_count:0,channels:[]},400);
  await nullToken.click('deliveryResendConfirmBtn');
  assert.match(nullToken.node('deliveryResendStatus').textContent,/Not queued: invalid_request/);
  const selected=setup();await tick();await selected.open();await selected.click('deliveryResendPreviewBtn');
  selected.node('deliveryResendMisp').checked=false;await selected.node('deliveryResendMisp').emit('change');
  assert(selected.node('deliveryResendConfirmBtn').disabled);assert.equal(selected.node('deliveryResendIPs').children.length,0);
  selected.setPreview({...selected.preview,ips:Array.from({length:256},(_,i)=>'192.0.2.'+i),channels:['teams']});
  await selected.click('deliveryResendPreviewBtn');
  assert.deepEqual(JSON.parse(selected.calls[1].options.body).channels,['teams']);
  assert.equal(selected.node('deliveryResendIPs').children.length,256,'no truncation');
  selected.setConfirm({...selected.confirmation,ip_count:256,receipt_count:256,channels:['teams']});
  await selected.click('deliveryResendConfirmBtn');assert.match(selected.node('deliveryResendStatus').textContent,/256/);
  for(const invalid of [null,{}, {...env.preview,ips:Array(257).fill('192.0.2.1')},
      {...env.preview,source_type:'PRIVATE-CANARY'}, {...env.preview,target:'different'},
      {...env.preview,ips:['<img onerror=CANARY>']}, {...env.preview,extra:'PRIVATE-CANARY'}]){
    const bad=setup();await tick();await bad.open();bad.setPreview(invalid);await bad.click('deliveryResendPreviewBtn');
    assert(bad.node('deliveryResendConfirmBtn').disabled);assert.equal(bad.node('deliveryResendIPs').children.length,0);
    assert(!bad.node('deliveryResendStatus').textContent.includes('PRIVATE-CANARY'));
  }
  for(const invalid of [null,{}, {...env.confirmation,status:'unknown',reason:'delivery_unknown'},
      {...env.confirmation,channels:['teams']}, {...env.confirmation,request_id:'b'.repeat(32)}]){
    const bad=setup();await tick();await bad.open();await bad.click('deliveryResendPreviewBtn');bad.setConfirm(invalid,503);
    await bad.click('deliveryResendConfirmBtn');assert.match(bad.node('deliveryResendStatus').textContent,/outcome unknown/i);
    await bad.click('deliveryResendCancelBtn');await bad.open();assert(bad.button.disabled);assert.equal(bad.calls.length,2);
  }
  for(const statusCode of [401,403]){
    const denied=setup();await tick();await denied.open();await denied.click('deliveryResendPreviewBtn');
    denied.setConfirm({error:'PRIVATE-CANARY'},statusCode);await denied.click('deliveryResendConfirmBtn');
    assert.match(denied.node('deliveryResendStatus').textContent,/unknown/i);assert(denied.button.disabled);
    assert(!denied.node('deliveryResendStatus').textContent.includes('PRIVATE-CANARY'));
    if(statusCode===401) assert.equal(denied.context.redirect,'/login.html');
  }
  // Real auth lifetime aborts fetch/body, suppresses late publications, never retries.
  for(const phase of ['preview-cancel','confirm-cancel','confirm-timeout']){
    const pending=setup();await tick();await pending.open();
    if(phase!=='preview-cancel') await pending.click('deliveryResendPreviewBtn');
    let release,signal;

    pending.transport(async(_,options)=>{signal=options.signal;return new Promise(resolve=>{release=resolve;});});
    const work=pending.click(phase==='preview-cancel'?'deliveryResendPreviewBtn':'deliveryResendConfirmBtn');await tick();
    assert(pending.node('deliveryResendPreviewBtn').disabled);assert(pending.node('deliveryResendConfirmBtn').disabled);
    await pending.click('deliveryResendConfirmBtn');
    if(phase==='confirm-timeout'){
      for(const [id,t] of pending.timers) if(t.ms===15000){pending.timers.delete(id);t.fn();}
    }else await pending.click('deliveryResendCancelBtn');
    await work;assert(signal.aborted);
    const before=pending.node('deliveryResendStatus').textContent;
    release(new Response(JSON.stringify(phase==='preview-cancel'?pending.preview:pending.confirmation)));await tick();
    assert.equal(pending.node('deliveryResendStatus').textContent,before);
    assert.equal(pending.calls.length,phase==='preview-cancel'?1:2);
    assert.equal(pending.timers.size,0);
    if(phase!=='preview-cancel') assert.match(pending.node('domainSettingsStatus').textContent,/unknown/i);
  }
  assert(!fs.readFileSync('delivery_resend.js','utf8').includes('innerHTML'),'safe text only');
  console.log('Resend widget: saved identity, channels, bounds, roles, drafts, auth-fetch refusals, cancellation and unknown/no-retry passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
