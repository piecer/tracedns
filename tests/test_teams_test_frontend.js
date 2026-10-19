'use strict';
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('dns_frontend.js', 'utf8');
const html = fs.readFileSync('dns_frontend.html', 'utf8');
assert.equal((html.match(/id="teamsTestBtn"/g) || []).length, 1, 'one explicit actual-test button');
assert(html.indexOf('id="teamsTestBtn"') > html.indexOf('id="teams_webhook_front"'));
assert(html.indexOf('id="teamsTestBtn"') < html.indexOf('id="misp_url_front"'));
assert(html.includes('id="teamsTestStatus" role="status"'));
assert(html.indexOf('src="/teams_test.js"') < html.indexOf('src="/dns_frontend.js"'));
assert(source.includes('window.TraceTeamsTest.bind(() => alertRevision)'));
const tick = () => new Promise(setImmediate);
function setup(role='admin') {
  const elements = new Map(), calls = [], timers = new Map(); let next = 0;
  const node = id => {
    if(!elements.has(id)) elements.set(id, {hidden:true, disabled:true, textContent:'', value:'PRIVATE-DRAFT', dataset:{},
      classList:{add(){},remove(){}}, addEventListener(name,fn){this[name]=fn;}, setAttribute(){}});
    return elements.get(id);
  };
  let body = {status:'accepted',reason:null,retry_after:null,diagnostic:{operation:'teams_send',http_status:202,
    response_bytes:0,response_limit:4096,attribute_count:null,attribute_limit:null,tls_kind:null,tls_verify:true}};
  let code = 200;
  const context = vm.createContext({console, URL, Request, Response, Headers, AbortController, DOMException,
    document:{getElementById:node,querySelectorAll:()=>[],addEventListener(){},readyState:'loading'},
    location:{href:'http://localhost/',origin:'http://localhost',pathname:'/',replace(){}},
    setTimeout:(fn,ms)=>{timers.set(++next,{fn,ms});return next;},clearTimeout:id=>timers.delete(id),
    confirm:()=>true, setAlertSettingsStatus(){}, secretInput(){}, parseBoundedInt:()=>1,
    fetch:async (url, options={})=>{
      const path = new URL(url,'http://localhost').pathname;
      if(path==='/auth/me') return new Response(JSON.stringify({user:{role},csrf_token:'test-token'}));
      if(path==='/settings') return new Response(JSON.stringify({revision:7,settings:{alerts:{}}}));
      calls.push({path,options}); return new Response(JSON.stringify(body),{status:code});
    }});
  context.window=context;
  vm.runInContext(fs.readFileSync('auth_frontend.js','utf8'),context);
  vm.runInContext(fs.readFileSync('teams_test.js','utf8'),context);
  vm.runInContext('let alertRevision = null;'+source.slice(source.indexOf('async function loadAlertSettings(){'),source.indexOf('async function saveAlertSettings(){')),context);
  vm.runInContext('window.TraceTeamsTest.bind(() => alertRevision);',context);
  return {context,node,calls,timers,setResult:(value,status)=>{body=value;code=status;},get body(){return body;}};
}
(async()=>{
  const env = setup(); await tick();
  const {context,node,calls} = env;
  const button=node('teamsTestBtn'), status=node('teamsTestStatus');
  assert(button.disabled, 'unavailable until saved settings loaded');
  assert.equal(calls.length,0,'initialization does not send');
  await context.loadAlertSettings();
  assert.equal(button.disabled,false);
  context.confirm=()=>false;
  await button.click(); assert.equal(calls.length,0,'cancel is not a send');
  context.confirm=text=>{assert.match(text,/saved/i);assert.match(text,/real/i);return true;};
  await button.click();
  assert.equal(calls.length,1);
  assert.equal(calls[0].path,'/teams/test');
  assert.equal(calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(calls[0].options.body),{revision:7});
  assert.equal(new Headers(calls[0].options.headers).get('X-CSRF-Token'),'test-token');
  assert.equal(calls[0].options.credentials,'same-origin');
  assert.match(status.textContent,/accepted/i);assert.match(status.textContent,/not.*read/i);
  assert.equal(button.disabled,false);
  for(const role of ['viewer','operator']){
    const other=setup(role); await tick(); await other.context.loadAlertSettings(); await other.node('teamsTestBtn').click();
    assert.equal(other.calls.length,0);assert(other.node('teamsTestBtn').hidden);
  }
  for(const [reason,code,pattern] of [
    ['provider_tls',502,/failed.*provider_tls/i], ['provider_timeout',502,/unknown/i],
    ['test_cooldown',429,/not sent.*30.*seconds/i], ['test_in_progress',429,/not sent.*progress/i],
    ['configuration_changed',409,/not sent.*load alert settings/i],
    ['destination_disabled',409,/not sent.*saved.*settings/i], ['runtime_unavailable',503,/not sent.*unavailable/i]
  ]){
    env.setResult({...env.body,status:code===502?'failed':'not_sent',reason,retry_after:code===429?30:null,
      diagnostic:{...env.body.diagnostic,http_status:403,tls_kind:'certificate_verify',tls_verify:true}},code);
    await button.click();
    assert.match(status.textContent,pattern);
    if(reason==='provider_tls'){
      assert.match(status.textContent,/HTTP 403/);assert.match(status.textContent,/certificate_verify/);
      assert.match(status.textContent,/TLS verify.*true/);
    }
    assert.equal(button.disabled,false,'manual retry remains usable; server enforces cooldown');
  }
  for(const reason of ['response_limit','provider_protocol']){
    env.setResult({...env.body,status:'failed',reason,retry_after:null,
      diagnostic:{...env.body.diagnostic,http_status:200,tls_kind:null}},502);
    await button.click();
    assert.match(status.textContent,/outcome unknown/i,'2xx response parsing failure cannot prove no delivery');
    assert(status.textContent.includes(reason),'safe reason remains visible');
  }
  // Other callers keep the existing fail-closed wrapper behavior.
  await assert.rejects(context.fetch('/other-write',{method:'POST'}));
  // Malformed responses never claim accepted or reflect raw values.
  for(const value of [null, {}, {status:'accepted',reason:null}, {...env.body,status:'accepted',reason:null,diagnostic:{}},
    {...env.body,reason:'PRIVATE-CANARY'}, {...env.body,status:'accepted',reason:'provider_tls'}]){
    env.setResult(value,200); await button.click();
    assert.match(status.textContent,/unknown/i);assert(!status.textContent.includes('PRIVATE-CANARY'));
  }
  const savedFetch=context.fetch;
  context.fetch=async()=>{throw new Error('PRIVATE-NETWORK');};
  await button.click();assert.match(status.textContent,/unknown/);assert(!status.textContent.includes('PRIVATE-NETWORK'));
  await context.loadAlertSettings();
  assert(button.disabled,'failed settings reload invalidates the loaded revision');
  context.fetch=savedFetch;await context.loadAlertSettings();
  assert.equal(button.disabled,false);
  // Deterministically expire the real auth.readJSON lifetime, including a
  // transport or body that ignores abort; late completion must not repaint.
  const watchdog=setTimeout(()=>{console.error('deadline did not settle');process.exit(1);},5000);
  try {
    for(const phase of ['fetch','body']){
      let release, signal, sends=0;
      context.fetch=async(_,options)=>{
        sends++;signal=options.signal;
        const pending=new Promise(resolve=>{release=resolve;});
        return phase==='fetch'?pending:{json:()=>pending};
      };
      const pending=button.click();await tick();
      assert(button.disabled);assert.match(status.textContent,/sending.*saved/i);
      await button.click();assert.equal(sends,1,'busy blocks duplicate send');
      for(const [id,t] of env.timers) if(t.ms===15000){env.timers.delete(id);t.fn();}
      await pending;
      assert(signal.aborted);assert.equal(button.disabled,false);assert.match(status.textContent,/unknown/);
      const prior=status.textContent;
      release(phase==='fetch'?new Response(JSON.stringify({status:'accepted'})):{status:'accepted'});
      await tick();assert.equal(status.textContent,prior);assert.equal(sends,1,'no auto retry after timeout');
    }
  } finally {clearTimeout(watchdog);}
  assert.equal(env.timers.size,0,'lifetime timers disposed');
  context.fetch=savedFetch;
  const fresh=setup();await tick();await fresh.context.loadAlertSettings();
  fresh.context.TraceAuth.user=null;
  fresh.context.TraceTeamsTest.settingsChanged();
  assert(fresh.node('teamsTestBtn').disabled,'session loss disables the action');
  fresh.context.TraceAuth.user={role:'admin'};
  fresh.context.TraceTeamsTest.settingsChanged();
  assert.equal(fresh.node('teamsTestBtn').disabled,false,'recovered identity enables the loaded action');
  const huge={...fresh.body,diagnostic:{...fresh.body.diagnostic,response_bytes:2**63}};
  fresh.setResult(huge,200);await fresh.node('teamsTestBtn').click();
  assert.match(fresh.node('teamsTestStatus').textContent,/accepted/i,'rounded int64 diagnostic must not erase valid acceptance');
  console.log('Teams test button: wiring, roles, CSRF, outcomes, timeout and no retry passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
