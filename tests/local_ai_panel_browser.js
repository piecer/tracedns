/* Real Chromium component boundary; model/job/auth adapter are controlled fixtures. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
const {performance} = require('node:perf_hooks');
const {chromium, expect} = require(process.env.UI_PLAYWRIGHT_MODULE || '@playwright/test');
const [fixturePath, output, selection = 'all'] = process.argv.slice(2);
const fixtures = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const root = path.resolve(__dirname, '..');
const reports = [], observations = [];
const cases = [];
function test(name, run) { cases.push({name, run}); }
const copy = x => JSON.parse(JSON.stringify(x));
let fixtureEpoch=Date.now();

function harness(realAuth=false) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local AI component fixture</title>
<link rel="stylesheet" href="/dns_frontend.css"><link rel="stylesheet" href="/local_ai_frontend.css">
<style>body{padding:12px;background:var(--bg-1)}:root{--bg-1:#101820;--surface:#18242f;--surface-soft:#1e2c38;--ink:#edf5fa;--muted:#b6c4d1;--line:#465a69;--accent:#55d5c0;--danger:#ff9d8d}main{max-width:900px;margin:auto}</style>
<main><button id="outside">Outside panel</button><div id="panel"></div><div id="other"></div><p id="security" role="alert"></p></main>
<script>
// Explicit model of planned auth adapter: real fetch, credentials/CSRF, closed AI errors.
window.fixture={owner:1,base:{kind:'delivery'},applied:[],actions:[],reads:0,checks:0,invalidators:new Set(),messages:[]};
if(!${realAuth}){
const nativeFetch=window.fetch.bind(window);
window.fetch=async (url,options={})=>{
  const response=await nativeFetch(url,{...options,credentials:'same-origin',headers:{...options.headers,'X-CSRF-Token':'fixture-token'}});
  if(response.status===401||response.status===403){
    window.TraceAuth.accessInvalidated=true;
    for(const f of fixture.invalidators)f();
    const e=new Error('PRIVATE transport text');e.status=response.status;throw e;
  }
  if(response.headers.get('X-TraceDNS-Security-Error')){
    TraceAuth.message('Security or audit storage is unavailable. Contact the administrator.','security');
    const e=new Error('PRIVATE security text');e.code='security_unavailable';throw e;
  }
  if(!response.ok && ![400,404,409,413,422,429,502,503,504].includes(response.status)){
    const e=new Error('PRIVATE HTTP error');e.code='http_error';throw e;
  }
  return response;
};
window.TraceAuth={accessInvalidated:false,readJSON:async(url,options)=>{fixture.signals ??=[];fixture.signals.push({url,signal:options.signal});const response=await fetch(url,options);const data=await response.json();if(fixture.jsonBarrier && url===fixture.jsonBarrier.url){fixture.jsonBarrier.entered=true;await fixture.jsonBarrier.promise;}return data;},onInvalidated:f=>{fixture.invalidators.add(f);return()=>fixture.invalidators.delete(f);},message:(text,owner)=>{fixture.messages.push({text,owner});document.getElementById('security').textContent=text;}};
}
window.mountPanel=(kind='delivery',target='panel',initialData)=>{
 const owner=fixture.owner;fixture.base=kind==='relationship_pair'?{kind,source:${JSON.stringify(Object.fromEntries(['job_id','a','b'].map(k=>[k,fixtures.snapshots.relationship_pair.source[k]])))}}:kind==='decoder_suggest'?{kind,decoder_type:'TXT'}:{kind};
 window.controller=TraceLocalAI.mount(document.getElementById(target),{kind,initialData,getRequest:()=>{fixture.reads++;return fixture.base;},isCurrent:()=>{fixture.checks++;return owner===fixture.owner;},onApply:(candidate,result)=>fixture.applied.push({candidate,result}),onAction:(code,result)=>fixture.actions.push({code,result})});
};
</script>${realAuth?'<script src="/auth-wrapper.js"></script>':''}<script src="/local_ai_frontend.js"></script></html>`;
}
async function withPanel(browser, callback, realAuth=false) {
  fixtureEpoch=Date.now();
  const state = {requests: [], reply: null};
  const server = http.createServer(async (req, res) => {
    if (req.url.startsWith('/ai/')) {
      let body = ''; for await (const chunk of req) body += chunk;
      const record={path:req.url,method:req.method,headers:req.headers,body:body ? JSON.parse(body) : null,time:performance.now()};
      state.requests.push(record);res.on('finish',()=>{record.http_status=res.statusCode;});
      if (state.reply) return state.reply(req, res, body);
      res.writeHead(500, {'Content-Type':'application/json'});res.end('{}');return;
    }
    if(req.url==='/auth-wrapper.js' && realAuth){res.setHeader('Content-Type','text/javascript');res.end(fs.readFileSync(process.env.UI_PANEL_REAL_AUTH || path.join(root,'auth_frontend.js')));return;}
    if(req.url==='/auth/me' && realAuth){json(res,{user:{id:1,role:'admin',must_change_password:false},csrf_token:'real-wrapper-fixture',audit_available:true});return;}
    if (req.url === '/') {res.setHeader('Content-Type','text/html');res.end(harness(realAuth));return;}
    if (['/local_ai_frontend.js','/local_ai_frontend.css','/dns_frontend.css'].includes(req.url)) {
      const file = path.join(root,req.url.slice(1));
      if(fs.existsSync(file)){res.setHeader('Content-Type',req.url.endsWith('.js')?'text/javascript':'text/css');res.end(fs.readFileSync(file));return;}
    }
    res.writeHead(404);res.end();
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const context = await browser.newContext({viewport:{width:1100,height:900}});
  const page = await context.newPage();page.setDefaultTimeout(5000);
  const errors = [];page.on('pageerror',e=>errors.push(e.message));
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await callback(page,state,context);
    assert.deepEqual(errors,[], 'no unhandled browser exceptions');
  } finally {
    observations.push({requests:state.requests});
    await page.screenshot({path:path.join(output,`case-${reports.length+1}-final.png`),fullPage:true}).catch(()=>{});
    await context.close();
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    observations.push({label:'component cleanup',serverListening:server.listening,browserContexts:browser.contexts().length});
    assert.equal(server.listening,false);assert.equal(browser.contexts().length,0);
  }
}
async function mounted(page,kind='delivery',initialData) {
  assert.equal(await page.evaluate(()=>typeof window.TraceLocalAI?.mount),'function','production panel mount API must exist');
  await page.evaluate(({kind,initialData})=>mountPanel(kind,'panel',initialData),{kind,initialData});
}
async function bounded(page,label) {
  const count=await page.locator('#panel *').count();
  assert(count<500,`${label}: mounted ${count} descendants must be <500`);
  observations.push({label,count});
  return count;
}

test('mount',async browser=>withPanel(browser,async(page,state)=>{
  await mounted(page);
  await expect(page.getByRole('heading',{name:'Local AI assistance',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
  await page.getByLabel('Language', {exact:true}).selectOption('ko');
  await expect(page.getByRole('button',{name:'실행',exact:true})).toBeVisible();
  await page.getByLabel('언어',{exact:true}).selectOption('en');
  await page.getByRole('button',{name:'Run',exact:true}).focus();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button',{name:'Close',exact:true})).toBeFocused();
  await page.setViewportSize({width:360,height:800});
  const geometry=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,width:innerWidth}));
  assert(geometry.scroll<=geometry.width,'panel must fit 360px');
  await bounded(page,'mount narrow');
  await page.screenshot({path:path.join(output,'mount-ko-en-narrow.png'),fullPage:true});
  assert.deepEqual(state.requests,[],'mount/language/focus/resize must not fetch even status');
  await page.evaluate(()=>mountPanel('delivery','other'));
  assert.equal(await page.locator('#panel *').count(),0,'one controller per kind');
  await page.evaluate(()=>controller.dispose());
  assert.equal(await page.locator('#other *').count(),0);
  assert.equal(await page.evaluate(()=>fixture.invalidators.size),0,'auth listeners retired');
  await mounted(page);
  await page.getByRole('button',{name:'Close',exact:true}).click();
  assert.equal(await page.locator('#panel *').count(),0);
  await mounted(page);
  await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
  assert.equal(await page.locator('#panel *').count(),0);
  assert.equal(await page.evaluate(()=>fixture.invalidators.size),0);
}));

function json(res, data, status=200) {
  // Controlled refusals use the real HTTP producer's closed envelope.
  if(data && Object.keys(data).length===1 && Object.hasOwn(data,'error'))data={...data,code:data.error,request_id:'f'.repeat(32)};
  res.writeHead(status, {'Content-Type':'application/json'});res.end(JSON.stringify(data));
}
const ready = {enabled:true,accepting:true,provider_state:'ready',queued:0,active_job:null};
function explanation(kind, language='en') {
  const snapshot=copy(fixtures.snapshots[kind]), digest=fixtures.digests[kind];
  const text=language==='ko'?'모델 설명: 관찰 범위에 주의하세요.':'MODEL fixture: <img src=x onerror=alert(1)> [unsafe](https://example.invalid)';
  return {snapshot,snapshot_digest:digest,source_revision:7,model:{model:'fixture-local',model_digest:'c'.repeat(64),eval_count:'9223372036854775807'},
    interpretation:{version:1,kind,language,snapshot_digest:digest,summary:[{text,evidence_ids:['e1']}],counterpoints:[{text:'Controlled counterpoint',evidence_ids:['e2']}],limitations:[],next_checks:[{code:kind==='delivery'?'inspect_delivery_progress':'inspect_pair_coverage',evidence_ids:['e3']}]}};
}
function job(kind, language='en', overrides={}) {
  return {job_id:'b'.repeat(32),kind,language,status:'completed',created_at:fixtureEpoch,deadline_at:fixtureEpoch+120000,audit_status:'success',error:null,result:explanation(kind,language),cancel_requested:false,...overrides};
}

for (const kind of ['relationship_pair','delivery']) for(const language of ['en','ko']) {
  test(`explain-${kind}-${language}`,async browser=>withPanel(browser,async(page,state)=>{
    const result=explanation(kind,language);
    state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:job(kind,language,{result}));
    await mounted(page,kind);
    if(language==='ko') await page.getByLabel('Language',{exact:true}).selectOption('ko');
    const runLabel=language==='ko'?'실행':'Run';
    await page.getByRole('button',{name:runLabel,exact:true}).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('[data-ai="interpretation"]')).toContainText(result.interpretation.summary[0].text);
    await expect(page.locator('[data-ai="facts"]')).not.toContainText('MODEL fixture');
    await expect(page.locator('[data-ai="warnings"]')).toContainText(kind==='delivery'?'snapshots_not_atomic':'coverage_incomplete');
    await page.locator('[data-ai="provenance"] summary').click();
    await expect(page.locator('[data-ai="provenance"]')).toContainText(result.snapshot_digest);
    await expect(page.locator('[data-ai="provenance"]')).toContainText('9223372036854775807');
    await page.locator('[data-ai="provenance"] summary').click();
    await expect(page.locator('[data-ai="provenance"] pre')).toHaveCount(0);
    assert.equal(await page.locator('#panel img, #panel a, #panel iframe, #panel script').count(),0,'text only; never HTML/links');
    await page.locator('[data-ai="interpretation"]').getByRole('button',{name:'e1',exact:true}).click();
    await expect(page.locator('[data-ai="fact-detail"]')).toContainText(JSON.stringify(result.snapshot.facts[0].value,null,2));
    await expect(page.locator('[data-ai="fact-detail"]')).toContainText(result.snapshot_digest);
    await expect(page.locator('[data-ai="fact-detail"]')).toBeFocused();
    const found=[];
    do {
      const controls=page.locator('[data-ai="fact-list"] button');
      for(let i=0;i<await controls.count();i++){
        found.push(await controls.nth(i).getAttribute('data-fact-id'));await controls.nth(i).click();await bounded(page,'evidence detail');
      }
      const next=page.locator('[data-ai="facts-next"]');if(await next.isDisabled())break;await next.click();
    } while(true);
    assert.deepEqual(found,result.snapshot.facts.map(f=>f.id),'all producer facts reachable once');
    await page.locator('[data-ai="next-checks"] button').click();
    const actions=await page.evaluate(()=>fixture.actions);
    assert.equal(actions.length,1);assert.equal(actions[0].code,result.interpretation.next_checks[0].code);
    assert.deepEqual(actions[0].result.snapshot,result.snapshot);
    assert.equal(state.requests.filter(r=>r.method==='POST').length,1);
    assert.equal(state.requests[1].headers['x-csrf-token'],'fixture-token');
    assert.equal(state.requests[1].body.language,language);
    await page.setViewportSize({width:360,height:800});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await page.screenshot({path:path.join(output,`${kind}-${language}-narrow.png`),fullPage:true});
  }));
}

function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
async function waitFor(predicate){await expect.poll(predicate,{timeout:5000}).toBeTruthy();}

test('poll-audit',async browser=>withPanel(browser,async(page,state)=>{
  let polls=0;const body=deferred();
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.method==='POST')return json(res,job('delivery','en',{status:'queued',result:null,audit_status:'pending'}),202);
    polls++;
    if(polls===1){res.writeHead(200,{'Content-Type':'application/json'});const wire=JSON.stringify(job('delivery','en',{result:null,audit_status:'pending'}));res.write(wire.slice(0,30));await body.promise;res.end(wire.slice(30));return;}
    return json(res,job('delivery'));
  };
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();
  await waitFor(()=>polls===1);
  assert.equal(await page.locator('[data-ai="interpretation"]').count(),0,'no result before audit success');
  await page.waitForTimeout(1100);assert.equal(polls,1,'one outstanding read through body barrier');
  body.resolve();
  await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  assert.equal(polls,2);assert.equal(state.requests.filter(r=>r.method==='POST').length,1);
  const gets=state.requests.filter(r=>r.path.startsWith('/ai/jobs/')&&r.method==='GET');
  assert(gets[1].time-gets[0].time>=1000,'bounded polling interval');
}));

test('detach-create-body',async browser=>withPanel(browser,async(page,state)=>{
  const release=deferred();let held=false;
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    held=true;res.writeHead(202,{'Content-Type':'application/json'});const wire=JSON.stringify(job('delivery','en',{status:'running',result:null,audit_status:'pending'}));res.write(wire.slice(0,50));await release.promise;res.end(wire.slice(50));
  };
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await waitFor(()=>held);
  await page.getByRole('button',{name:'Close',exact:true}).click();
  await mounted(page);release.resolve();await page.waitForTimeout(100);
  assert.equal(state.requests.length,2,'late ACK must not read/cancel/mutate a successor');
  await expect(page.locator('[data-ai="status"]')).toContainText('Run explicitly');
  assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);
}));

test('cancel-before-ack',async browser=>withPanel(browser,async(page,state)=>{
  const ack=deferred();let created=false,polls=0,cancels=0;
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.url.endsWith('/cancel')){cancels++;return json(res,{...job('delivery','en',{status:'cancel_pending',audit_status:'pending',result:null,cancel_requested:true}),cancellation_requested:true,cancellation_confirmed:false});}
    if(req.method==='POST'){created=true;await ack.promise;return json(res,job('delivery','en',{status:'running',audit_status:'pending',result:null}),202);}
    polls++;return json(res,job('delivery','en',{status:polls===1?'cancel_pending':'cancelled',audit_status:polls===1?'pending':'success',result:null,cancel_requested:true}));
  };
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await waitFor(()=>created);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('[data-ai="status"]')).toContainText('not confirmed');
  assert.equal(cancels,0);ack.resolve();await waitFor(()=>cancels===1);
  await expect(page.locator('[data-ai="status"]')).toContainText('not confirmed');
  await expect(page.getByRole('button',{name:'Cancel',exact:true})).toBeDisabled();
  await expect(page.locator('[data-ai="status"]')).toContainText('Cancellation confirmed');
  assert.equal(cancels,1);assert(polls>=2);
}));

test('cancel-failure-keeps-polling',async browser=>withPanel(browser,async(page,state)=>{
  let cancels=0,polls=0;
  state.reply=(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.url.endsWith('/cancel')){cancels++;return json(res,{error:'provider_unsettled'},503);}
    if(req.method==='POST')return json(res,job('delivery','en',{status:'running',audit_status:'pending',result:null}),202);
    polls++;return json(res,job('delivery','en',polls<2?{status:'running',audit_status:'pending',result:null}:{status:'failed',error:'provider_failed',result:null}));
  };
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('[data-ai="cancel-error"]')).toContainText('Cancellation was not confirmed');
  await expect(page.locator('[data-ai="status"]')).toContainText('Request failed');
  await expect(page.locator('[data-ai="cancel-error"]')).toContainText('Cancellation was not confirmed');
  assert.equal(cancels,1);assert(polls>=2);assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);
}));

test('audit-failure-global',async browser=>withPanel(browser,async(page,state)=>{
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:job('delivery','en',{status:'failed',audit_status:'failed',result:null,error:'audit_unavailable'}));
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('#security')).toContainText('Security or audit storage');
  await expect(page.locator('[data-ai="status"]')).toContainText('Security or audit storage');
  assert.equal((await page.evaluate(()=>fixture.messages)).at(-1).owner,'security');
}));

test('busy-other-source-no-resume',async browser=>withPanel(browser,async(page,state)=>{
  state.reply=(req,res)=>json(res,{...ready,provider_state:'busy',active_job:{job_id:'d'.repeat(32),kind:'relationship_pair',status:'running'}});
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="status"]')).toContainText('busy');
  await page.waitForTimeout(1100);assert.equal(state.requests.length,1,'status active job never attaches another source');
  assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);
}));

function decoderResult(language='en',generate=true) {
  return {snapshot:copy(fixtures.decoder.snapshots.normal),snapshot_digest:'e'.repeat(64),source_revision:19,model:generate?{model:'fixture-local',model_digest:'c'.repeat(64)}:null,catalog:copy(fixtures.decoder.catalog),generated:generate?copy(fixtures.decoder.generated):null,proposal:generate?{version:1,kind:'decoder_suggest',language,snapshot_digest:'e'.repeat(64),candidates:copy(fixtures.decoder.proposal),insufficient_reason:null}:null};
}
function decoderJob(language='en',generate=true,result=decoderResult(language,generate)) {
  return {...job('delivery',language),kind:'decoder_suggest',result};
}
async function fillSamples(page,samples,language='en') {
  const ko=language==='ko';
  for(let i=0;i<samples.length;i++) {
    if(i)await page.getByRole('button',{name:ko?'샘플 추가':'Add sample',exact:true}).click();
    const row=page.locator('[data-ai="sample"]').nth(i);
    await row.getByLabel(ko?'원시 데이터':'Raw data',{exact:true}).fill(samples[i].data);
    await row.getByLabel(ko?'예상 IPv4 (쉼표 또는 공백 구분)':'Expected IPv4 (comma or space separated)',{exact:true}).fill(samples[i].expected_ips.join(', '));
    await row.getByLabel(ko?'용도':'Usage',{exact:true}).selectOption(samples[i].usage);
    await row.getByLabel(ko?'예상 목록이 완전함':'Complete expected set',{exact:true}).setChecked(samples[i].complete_expected);
  }
}
for(const language of ['en','ko']) test(`decoder-${language}`,async browser=>withPanel(browser,async(page,state)=>{
  const result=decoderResult(language);
  assert(Buffer.byteLength(JSON.stringify(decoderJob(language,true,result)))<=32768,'real maximal catalog envelope fits publication limit');
  state.reply=(req,res,body)=>json(res,req.url==='/ai/status'?ready:decoderJob(language,JSON.parse(body).generate));
  await mounted(page,'decoder_suggest',fixtures.decoder.samples[0].data);
  await expect(page.locator('[data-ai="sample"]').getByLabel('Raw data',{exact:true})).toHaveValue(fixtures.decoder.samples[0].data);
  await expect(page.locator('[data-ai="sample"]').getByLabel('Expected IPv4 (comma or space separated)',{exact:true})).toHaveValue('');
  if(language==='ko')await page.getByLabel('Language',{exact:true}).selectOption('ko');
  await fillSamples(page,fixtures.decoder.samples.slice(0,2),language);
  const generate=page.getByLabel(language==='ko'?'새 후보 생성 (로컬 모델 사용)':'Generate new candidates (uses local model)',{exact:true});
  await expect(generate).not.toBeChecked();await generate.check();
  assert.equal(state.requests.length,0,'edits and generation selection never fetch');
  await page.getByRole('button',{name:language==='ko'?'실행':'Run',exact:true}).click();
  await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  assert.deepEqual(state.requests[1].body,{kind:'decoder_suggest',decoder_type:'TXT',language,samples:fixtures.decoder.samples.slice(0,2),generate:true});
  assert.deepEqual(await page.evaluate(()=>fixture.applied),[],'never auto apply');
  const expected=[...result.catalog.candidates,...result.generated.candidates];const seen=[];
  let applied=false;
  do {
    const buttons=page.locator('[data-ai="candidate-list"] button');
    assert(await buttons.count()<=5);
    for(let i=0;i<await buttons.count();i++){
      const b=buttons.nth(i);seen.push(await b.getAttribute('data-candidate-name'));await b.click();
      assert.equal(await page.locator('[data-ai="candidate-detail"]').count(),1,'one mounted detail');
      const candidate=expected.find(c=>c.name===seen.at(-1));
      await expect(page.locator('[data-ai="candidate-detail"]')).toContainText(candidate.name);
      await expect(page.locator('[data-ai="candidate-detail"]')).toContainText('sample_index');
      const apply=page.getByRole('button',{name:language==='ko'?'초안에 적용':'Apply to draft',exact:true});
      const safe=candidate.source!=='builtin'&&candidate.examples.passed===candidate.examples.tested&&candidate.validation.passed===candidate.validation.tested;
      if(safe){await expect(apply).toBeEnabled();if(candidate.source==='generated'&&!applied){await apply.click();applied=true;}}
      else await expect(apply).toBeDisabled();
      await bounded(page,'max catalog candidate '+candidate.name);
    }
    const next=page.locator('[data-ai="candidates-next"]');if(await next.isDisabled())break;await next.click();
    assert.equal(await page.locator('[data-ai="candidate-detail"] *').count(),0,'page retires old detail');
  }while(true);
  assert.deepEqual(seen,expected.map(c=>c.name),'all 32+3 real candidates reachable');
  assert.equal((await page.evaluate(()=>fixture.applied)).length,1);
  assert.equal(state.requests.filter(r=>r.method==='POST').length,1,'apply is draft-only');
  await page.setViewportSize({width:360,height:800});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:path.join(output,`decoder-${language}-narrow.png`),fullPage:true});
  await page.locator('[data-ai="sample"]').first().getByLabel(language==='ko'?'원시 데이터':'Raw data',{exact:true}).fill('edited');
  await expect(page.locator('[data-ai="results"]')).toContainText(language==='ko'?'이전 결과':'Previous result');
  assert.equal(state.requests.length,2);
  await page.getByRole('button',{name:language==='ko'?'닫기':'Close',exact:true}).click();
  assert.equal(await page.locator('#panel *').count(),0);
}));

test('six-samples-no-auto',async browser=>withPanel(browser,async(page,state)=>{
  await mounted(page,'decoder_suggest');
  await fillSamples(page,fixtures.decoder.samples);
  await expect(page.getByRole('button',{name:'Add sample',exact:true})).toBeDisabled();
  assert.equal(await page.locator('[data-ai="sample"]').count(),6);await bounded(page,'six editors');
  assert.equal(state.requests.length,0);
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:{error:'too_large'},req.url==='/ai/status'?200:413);
  await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="status"]')).toContainText('Request failed');
  assert.deepEqual(state.requests[1].body.samples,fixtures.decoder.samples);assert.equal(state.requests[1].body.generate,false);
  await page.screenshot({path:path.join(output,'six-sample-editors.png'),fullPage:true});
}));

test('stale-rerun-preserves-coverage',async browser=>withPanel(browser,async(page,state)=>{
  let creates=0;
  state.reply=(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    creates++;json(res,creates===1?job('relationship_pair'):{error:'provider_failed'},creates===1?200:502);
  };
  await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="status"]')).toContainText('Request failed');
  await expect(page.locator('[data-ai="provenance"]')).toContainText('Previous result');
  await expect(page.locator('[data-ai="warnings"]')).toContainText('coverage_incomplete');
  await expect(page.locator('[data-ai="interpretation"] button').first()).toBeDisabled();
  assert.equal(creates,2);
}));

test('late-cancel-failure-preserves-primary',async browser=>withPanel(browser,async(page,state)=>{
  const release=deferred();let cancelStarted=false;
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.url.endsWith('/cancel')){cancelStarted=true;await release.promise;return json(res,{error:'provider_unsettled'},503);}
    return json(res,job('delivery','en',req.method==='POST'?{status:'running',audit_status:'pending',result:null}:{status:'failed',error:'provider_failed',result:null}));
  };
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await waitFor(()=>cancelStarted);await expect(page.locator('[data-ai="status"]')).toContainText('Request failed');
  release.resolve();
  await expect(page.locator('[data-ai="cancel-error"]')).toContainText('Cancellation was not confirmed');
  await expect(page.locator('[data-ai="status"]')).toContainText('Request failed');
}));

test('decoder-unknown-model-contract',async browser=>withPanel(browser,async(page,state)=>{
  const result=decoderResult();result.model.extra='PRIVATE unexpected model metadata';
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',true,result));
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples.slice(0,2));await page.getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
  await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="status"]')).toContainText('Unsupported or invalid response');
  assert.equal(await page.locator('[data-ai="candidate-list"]').count(),0);await expect(page.locator('#panel')).not.toContainText('PRIVATE');
}));

test('raw-sample-rejects-before-encoding',async browser=>withPanel(browser,async(page,state)=>{
  await mounted(page,'decoder_suggest');
  await page.evaluate(()=>{
    fixture.largeEncodes=0;
    const encode=TextEncoder.prototype.encode;
    TextEncoder.prototype.encode=function(value){if(typeof value==='string'&&value.length>2048)fixture.largeEncodes++;return encode.call(this,value);};
  });
  const raw='x'.repeat(100000);
  await page.getByLabel('Raw data',{exact:true}).fill(raw);
  await page.getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill('192.0.2.1');
  await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="status"]')).toContainText('Provide 1–6 distinct samples');
  assert.equal(await page.getByLabel('Raw data',{exact:true}).inputValue(),raw,'excess remains visible; no maxlength/truncation');
  assert.equal(await page.evaluate(()=>fixture.largeEncodes),0,'reject JS length before allocating UTF-8');
  assert.equal(state.requests.length,0);
  await page.getByLabel('Raw data',{exact:true}).fill('가'.repeat(1024));
  await page.getByRole('button',{name:'Run',exact:true}).click();
  assert.equal(state.requests.length,0,'UTF-8 bound still enforced below code-unit bound');
}));

test('decoder-snapshot-closed-producer-shape',async browser=>withPanel(browser,async(page,state)=>{
  let result=decoderResult();
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',true,result));
  async function runSnapshot(){
    await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples.slice(0,2));
    await page.getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
    await page.getByRole('button',{name:'Run',exact:true}).click();
  }
  await runSnapshot();await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  const mutations=[
    s=>{s.extra='PRIVATE';}, s=>{s.version=2;}, s=>{s.kind='delivery';}, s=>{s.decoder_type='A';},
    s=>{s.examples=[];}, s=>{delete s.examples[0].usage;}, s=>{s.examples[0].extra='PRIVATE';},
    s=>{s.examples[0].data='other';}, s=>{s.examples[0].expected_ips=['192.0.2.99'];},
    s=>{s.examples[0].complete_expected=false;}, s=>{s.examples[0].usage='validation';},
    s=>{s.examples.push(copy(fixtures.decoder.samples[1]));}
  ];
  for(const mutate of mutations){
    result=decoderResult();mutate(result.snapshot);await runSnapshot();
    await expect(page.locator('[data-ai="status"]')).toContainText('Unsupported or invalid response');
    assert.equal(await page.locator('[data-ai="candidate-list"]').count(),0);
    await expect(page.locator('#panel')).not.toContainText('PRIVATE');
  }
}));

for(const boundary of ['/ai/status','/ai/jobs']) for(const retirement of ['source','auth','pagehide']) {
  test(`json-${boundary.endsWith('status')?'status':'create'}-${retirement}`,async browser=>withPanel(browser,async(page,state)=>{
    state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:job('delivery'));
    await mounted(page);
    await page.evaluate(url=>{let release;fixture.jsonBarrier={url,entered:false,promise:new Promise(r=>release=r),release:()=>release()};},boundary);
    await page.getByRole('button',{name:'Run',exact:true}).click();
    await waitFor(()=>page.evaluate(()=>fixture.jsonBarrier.entered));
    await page.evaluate(retirement=>{
      if(retirement==='source')fixture.owner++;
      if(retirement==='auth'){TraceAuth.accessInvalidated=true;for(const f of fixture.invalidators)f();}
      if(retirement==='pagehide')dispatchEvent(new Event('pagehide'));
      fixture.jsonBarrier.release();
    },retirement);
    await page.waitForTimeout(75);
    assert.equal(state.requests.length,boundary==='/ai/status'?1:2,'fence after JSON barrier');
    assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);
    if(retirement!=='source'){
      assert.equal(await page.locator('#panel *').count(),0);assert.equal(await page.evaluate(()=>fixture.invalidators.size),0);
    }
    if(boundary==='/ai/jobs')assert.equal(await page.evaluate(()=>fixture.signals.find(s=>s.url==='/ai/jobs').signal.aborted),false,'detach cannot abort accepted create');
  }));
}

test('transport-create-15s',async browser=>withPanel(browser,async(page,state)=>{
  const release=deferred();let posted=false;
  state.reply=async(req,res)=>{if(req.url==='/ai/status')return json(res,ready);posted=true;await release.promise;json(res,job('delivery'));};
  await mounted(page);await page.clock.install();await page.getByRole('button',{name:'Run',exact:true}).click();await waitFor(()=>posted);
  await page.clock.runFor(15001);
  await expect(page.locator('[data-ai="status"]')).toContainText('Acceptance is uncertain');
  assert(await page.evaluate(()=>fixture.signals.find(s=>s.url==='/ai/jobs').signal.aborted));
  release.resolve();await page.waitForTimeout(50);
  assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);assert.equal(state.requests.length,2);
  await page.clock.runFor(20000);assert.equal(state.requests.length,2,'no automatic create retry');
}));

test('poll-original-deadline',async browser=>withPanel(browser,async(page,state)=>{
  let polls=0;const release=deferred();
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.method==='POST')return json(res,job('delivery','en',{status:'running',audit_status:'pending',result:null}));
    polls++;await release.promise;json(res,job('delivery'));
  };
  await mounted(page);await page.clock.install();await page.getByRole('button',{name:'Run',exact:true}).click();
  await waitFor(()=>state.requests.length===2);await page.waitForTimeout(50);await page.clock.runFor(1001);await waitFor(()=>polls===1);
  await page.clock.runFor(15001);await expect(page.locator('[data-ai="status"]')).toContainText('timed out');
  await page.clock.fastForward(140000);release.resolve();await page.waitForTimeout(50);
  await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
  const finalCount=state.requests.length;await page.clock.runFor(30000);assert.equal(state.requests.length,finalCount,'poll deadline never resets');
  assert.equal(await page.locator('[data-ai="interpretation"]').count(),0,'late receipt cannot publish');
  assert.equal(state.requests.filter(r=>r.method==='POST').length,1,'deadline is detach, never implicit cancellation');
}));

test('unknown-output-contracts',async browser=>withPanel(browser,async(page,state)=>{
  const mutations=[
    r=>{r.interpretation.next_checks[0].code='run_shell PRIVATE';},
    r=>{r.interpretation.summary[0].evidence_ids=['e999'];},
    r=>{r.interpretation.extra='PRIVATE';},
    r=>{r.snapshot.warnings.push('PRIVATE warning');},
    r=>{r.snapshot.source.extra='PRIVATE source';},
    r=>{r.snapshot.facts[0].value.extra='PRIVATE fact';},
    r=>{r.interpretation.summary[0].text=['PRIVATE'];},
    r=>{r.interpretation.snapshot_digest='f'.repeat(64);},
    r=>{r.model.eval_count=9223372036854775807;},
  ];
  for(const mutate of mutations){
    const result=explanation('delivery');mutate(result);
    state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:job('delivery','en',{result}));
    await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.locator('[data-ai="status"]')).toContainText('Unsupported or invalid response');
    assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);await expect(page.locator('#panel')).not.toContainText('PRIVATE');
    await page.evaluate(()=>controller.dispose());
  }
}));

async function openCandidate(page,name) {
  for(;;){const found=page.locator(`[data-candidate-name="${name}"]`);if(await found.count()){await found.click();return;}
    const next=page.locator('[data-ai="candidates-next"]');assert(!await next.isDisabled(),'candidate must be reachable');await next.click();}
}

test('decoder-catalog-draft-and-extras',async browser=>withPanel(browser,async(page,state)=>{
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',false));
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples.slice(0,2));
  await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  const custom=fixtures.decoder.catalog.candidates.find(c=>c.source==='custom');
  await openCandidate(page,custom.name);await page.keyboard.press('Tab');
  await expect(page.getByRole('button',{name:'Apply to draft',exact:true})).toBeFocused();await page.keyboard.press('Enter');
  const application=(await page.evaluate(()=>fixture.applied))[0];assert.deepEqual(application.candidate,custom);assert.equal(application.result.source_revision,19);
  assert.equal(state.requests[1].body.generate,false);assert.equal(state.requests.length,2);
  await page.evaluate(()=>controller.dispose());
  const extra=decoderResult();extra.snapshot=copy(fixtures.decoder.snapshots.extras);extra.catalog=fixtures.decoder.extras_catalog;extra.generated=fixtures.decoder.extras;extra.proposal.candidates=[{steps:[{op:'ascii'}]}];
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',true,extra));
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.extras_samples);await page.getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
  await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  await openCandidate(page,'generated_1');await expect(page.locator('[data-ai="candidate-detail"]')).toContainText('192.0.2.11');
  await expect(page.getByRole('button',{name:'Apply to draft',exact:true})).toBeDisabled();
  await expect(page.locator('[data-ai="warnings"]')).toContainText('No validation samples');
}));

test('decoder-A-and-invalid-steps',async browser=>withPanel(browser,async(page,state)=>{
  const result=decoderResult();result.snapshot=copy(fixtures.decoder.snapshots.a);result.catalog=fixtures.decoder.a.catalog;result.generated=fixtures.decoder.a.generated;result.proposal.candidates=fixtures.decoder.a.proposal;
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',true,result));
  await mounted(page,'decoder_suggest');await page.evaluate(()=>{fixture.base.decoder_type='A';});await fillSamples(page,fixtures.decoder.a.samples);await page.getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
  await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  await openCandidate(page,'generated_1');await page.getByRole('button',{name:'Apply to draft',exact:true}).click();
  assert.equal((await page.evaluate(()=>fixture.applied)).length,1);assert.equal(state.requests[1].body.decoder_type,'A');
  await page.evaluate(()=>controller.dispose());
  const invalid=decoderResult();invalid.proposal.candidates[0].steps[0].key='00';invalid.generated.candidates[0].steps[0].key='00';
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',true,invalid));
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples.slice(0,2));await page.getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
  await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="status"]')).toContainText('Unsupported or invalid response');
  assert.equal(await page.locator('[data-ai="candidate-list"]').count(),0,'never repair irrelevant generated keys');
}));

test('six-editor-complete-catalog-details',async browser=>withPanel(browser,async(page,state)=>{
  const result=decoderResult('en',false);result.catalog=fixtures.decoder.six_catalog;
  const wire=decoderJob('en',false,result);assert(Buffer.byteLength(JSON.stringify(wire))<=32768);
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:wire);
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples);await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  const seen=[];
  do {
    const buttons=page.locator('[data-ai="candidate-list"] button');
    for(let i=0;i<await buttons.count();i++){
      seen.push(await buttons.nth(i).getAttribute('data-candidate-name'));await buttons.nth(i).click();
      for(let j=0;j<6;j++)await expect(page.locator('[data-ai="candidate-detail"]')).toContainText(`"sample_index": ${j}`);
      await bounded(page,'six editors plus six-row detail');
    }
    const next=page.locator('[data-ai="candidates-next"]');if(await next.isDisabled())break;await next.click();
  }while(true);
  assert.deepEqual(seen,result.catalog.candidates.map(c=>c.name));
  await page.setViewportSize({width:360,height:800});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:path.join(output,'six-editors-six-detail-narrow.png'),fullPage:true});
  const tooLarge=decoderResult('en',false);tooLarge.catalog=fixtures.decoder.maximum;
  assert(Buffer.byteLength(JSON.stringify(decoderJob('en',false,tooLarge)))>32768,'max 32×6 real report exceeds envelope budget');
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',false,tooLarge));
  await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="status"]')).toContainText('Unsupported or invalid response');
  await expect(page.locator('[data-ai="provenance"]')).toContainText('Previous result');
  assert.equal(await page.locator('[data-ai="candidate-list"] button:enabled').count(),0,'oversize must not publish a prefix');
}));

test('max-evidence-and-claims',async browser=>withPanel(browser,async(page,state)=>{
  const result=explanation('relationship_pair');result.snapshot=fixtures.snapshots.maximum_pair;result.snapshot_digest=fixtures.digests.maximum_pair;result.interpretation.snapshot_digest=result.snapshot_digest;
  for(const [key,count] of [['summary',3],['counterpoints',4],['limitations',4]])result.interpretation[key]=Array.from({length:count},()=>({text:'Bounded model fixture '.padEnd(512,'x'),evidence_ids:result.snapshot.facts.slice(0,4).map(f=>f.id)}));
  result.interpretation.next_checks=Array.from({length:3},()=>({code:'inspect_pair_evidence',evidence_ids:['e1']}));
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:job('relationship_pair','en',{result}));
  await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  const ids=[];
  do{
    const buttons=page.locator('[data-ai="fact-list"] button');
    for(let i=0;i<await buttons.count();i++){ids.push(await buttons.nth(i).getAttribute('data-fact-id'));await buttons.nth(i).click();await bounded(page,'max facts and max claims');}
    const next=page.locator('[data-ai="facts-next"]');if(await next.isDisabled())break;await next.click();
  }while(true);
  assert.deepEqual(ids,result.snapshot.facts.map(f=>f.id));
  assert.equal(await page.locator('[data-ai="interpretation"] button').count(),44);
  await page.screenshot({path:path.join(output,'max-evidence-desktop.png'),fullPage:true});
}));

test('delivery-history-and-later-success',async browser=>withPanel(browser,async(page,state)=>{
  const result=explanation('delivery');result.snapshot=fixtures.snapshots.delivery_history;result.snapshot_digest=fixtures.digests.delivery_history;result.interpretation.snapshot_digest=result.snapshot_digest;
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:job('delivery','en',{result}));
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  const channel=result.snapshot.facts.find(f=>f.key==='diagnostics_misp');
  await page.locator('[data-ai="fact-list"]').getByRole('button',{name:channel.id+' · '+channel.key,exact:true}).click();
  await expect(page.locator('[data-ai="fact-detail"]')).toContainText('"latest_result"');await expect(page.locator('[data-ai="fact-detail"]')).toContainText('"acked"');
  await expect(page.locator('[data-ai="fact-detail"]')).toContainText('"latest_failure"');await expect(page.locator('[data-ai="fact-detail"]')).toContainText('provider_tls');
  const failures=result.snapshot.facts.find(f=>f.key==='diagnostics_recent_failures');assert.equal(failures.value.length,10);
  await page.locator('[data-ai="fact-list"]').getByRole('button',{name:failures.id+' · '+failures.key,exact:true}).click();
  await expect(page.locator('[data-ai="fact-detail"]')).toContainText(JSON.stringify(failures.value,null,2));
  await bounded(page,'10 retained failure rows');
}));

test('dark-label-contrast-and-focus',async browser=>withPanel(browser,async(page)=>{
  await page.locator('#outside').focus();await mounted(page,'decoder_suggest');
  const ratios=await page.locator('#panel label').evaluateAll(labels=>{
    const rgb=text=>text.match(/[\d.]+/g).slice(0,3).map(Number);
    const luminance=channels=>channels.map(c=>{c/=255;return c<=0.04045?c/12.92:((c+0.055)/1.055)**2.4;}).reduce((sum,c,i)=>sum+c*[0.2126,0.7152,0.0722][i],0);
    const bg=luminance(rgb(getComputedStyle(document.querySelector('.local-ai')).backgroundColor));
    return labels.map(label=>{const fg=luminance(rgb(getComputedStyle(label).color));return (Math.max(fg,bg)+0.05)/(Math.min(fg,bg)+0.05);});
  });
  observations.push({label:'dark-label-contrast',ratios});assert(ratios.every(r=>r>=4.5),'every native label must retain dark-theme contrast');
  await page.getByRole('button',{name:'Close',exact:true}).click();await expect(page.locator('#outside')).toBeFocused();
}));

test('poll-error-survives-cancel',async browser=>withPanel(browser,async(page,state)=>{
  state.reply=(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.url.endsWith('/cancel'))return json(res,{error:'provider_unsettled'},503);
    if(req.method==='POST')return json(res,job('delivery','en',{status:'running',audit_status:'pending',result:null}));
    json(res,{error:'provider_failed'},502);
  };
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="status"]')).toContainText('Request failed');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();await expect(page.locator('[data-ai="cancel-error"]')).toContainText('Cancellation was not confirmed');
  assert((await page.locator('[data-ai="status"]').textContent()).includes('Request failed'),'cancel failure must not temporarily overwrite primary read failure');
  await page.evaluate(()=>controller.dispose());
}));

test('closed-http-refusals-and-auth',async browser=>withPanel(browser,async(page,state)=>{
  for(const [status,code] of [[400,'invalid_request'],[404,'not_found'],[409,'source_revoked'],[413,'too_large'],[422,'verification_failed'],[429,'busy'],[502,'provider_failed'],[503,'audit_unavailable'],[504,'deadline_exceeded']]){
    const before=state.requests.length;
    state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:{error:code},req.url==='/ai/status'?200:status);
    await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    assert.equal(state.requests.length,before+2);assert.equal(state.requests.at(-1).http_status,status,'actual HTTP status is preserved');
    assert.equal(await page.locator('[data-ai="interpretation"]').count(),0);await expect(page.locator('[data-ai="status"]')).not.toContainText('Completed');
    await page.evaluate(()=>controller.dispose());
  }
  for(const status of [401,403]){
    state.reply=(req,res)=>json(res,{error:'PRIVATE HTTP body'},status);
    await page.evaluate(()=>{TraceAuth.accessInvalidated=false;});await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.locator('#panel')).toBeEmpty();assert.equal(await page.evaluate(()=>fixture.invalidators.size),0);
  }
  await page.evaluate(()=>{TraceAuth.accessInvalidated=false;});
  state.reply=(req,res)=>{res.writeHead(503,{'Content-Type':'application/json','X-TraceDNS-Security-Error':'security_unavailable'});res.end('{"error":"PRIVATE security body"}');};
  await mounted(page);await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('#security')).toContainText('Security or audit storage');await expect(page.locator('#panel')).not.toContainText('PRIVATE');
}));

test('dispose-clears-private-subtrees',async browser=>withPanel(browser,async(page,state)=>{
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',false));
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples.slice(0,2));await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  await page.evaluate(()=>{
    fixture.detached={editor:document.querySelector('[data-ai="sample-editors"]'),result:document.querySelector('[data-ai="results"]'),input:document.querySelector('[data-ai="sample"] textarea')};
    TraceAuth.accessInvalidated=true;for(const f of fixture.invalidators)f();
  });
  assert.deepEqual(await page.evaluate(()=>({editor:fixture.detached.editor.childElementCount,result:fixture.detached.result.childElementCount,input:fixture.detached.input.value})),{editor:0,result:0,input:''},'retired controller must clear retained detached private subtrees too');
  assert.equal(await page.locator('#panel *').count(),0);assert.equal(await page.evaluate(()=>fixture.invalidators.size),0);
}));

test('real-auth-wrapper-component',async browser=>withPanel(browser,async(page,state)=>{
  await page.evaluate(()=>TraceAuth.ready.then(()=>true));
  let mode='conflict';
  state.reply=(req,res)=>{
    if(mode==='forbidden')return json(res,{error:'PRIVATE forbidden'},403);
    if(req.url==='/ai/status')return json(res,ready);
    if(mode==='conflict')return json(res,{error:'source_revoked'},409);
    if(mode==='audit')return json(res,job('delivery','en',{status:'failed',audit_status:'failed',result:null,error:'audit_unavailable'}));
    if(mode==='security'){res.writeHead(503,{'Content-Type':'application/json','X-TraceDNS-Security-Error':'security_unavailable'});res.end('{"error":"PRIVATE security"}');return;}
    return json(res,job('delivery'));
  };
  await mounted(page);assert.equal(state.requests.length,0,'auth bootstrap is not a status/model request');
  await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="status"]')).toContainText('Source is unavailable');
  assert.equal(state.requests.at(-1).http_status,409);assert.equal(state.requests.at(-1).headers['x-csrf-token'],'real-wrapper-fixture');
  await expect(page.locator('#security-message')).toBeHidden(); // closed AI refusal remains local
  mode='ok';await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  mode='audit';await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('#security-message')).toContainText('Security or audit storage');
  assert.equal(state.requests.at(-1).http_status,200,'terminal audit failure arrives in HTTP200 envelope');
  mode='security';await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
  assert.equal(state.requests.at(-1).http_status,503);await expect(page.locator('#panel')).not.toContainText('PRIVATE');
  mode='forbidden';await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('#panel')).toBeEmpty();
  await expect(page.locator('#security-message')).toContainText('Permission denied');
  observations.push({label:'real auth wrapper with controlled auth/me',modelAndJobs:'controlled fixtures',notAcceptance:['server authentication','backend integration','native model']});
},true));

test('producer-long-catalog-name',async browser=>withPanel(browser,async(page,state)=>{
  const result=decoderResult('en',false);result.catalog=fixtures.decoder.long_name_catalog;
  state.reply=(req,res)=>json(res,req.url==='/ai/status'?ready:decoderJob('en',false,result));
  await mounted(page,'decoder_suggest');await fillSamples(page,fixtures.decoder.samples.slice(0,2));await page.getByRole('button',{name:'Run',exact:true}).click();await expect(page.locator('[data-ai="candidate-list"]')).toBeVisible();
  const name=result.catalog.candidates.find(c=>c.source==='custom').name;
  assert.equal(name.length,4096);await openCandidate(page,name);
  await expect(page.locator('[data-ai="candidate-detail"]')).toContainText(name);
  await page.setViewportSize({width:360,height:800});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await bounded(page,'untruncated original catalog name');
}));

// UI-R1: only actual source-retirement receipts and their retained callbacks.
for(const [entry,code] of [['poll','source_revoked'],['poll','not_found'],['cancel','source_revoked'],['cancel','not_found'],['terminal','source_revoked']]) {
  test(`retirement-${entry}-${code}`,async browser=>withPanel(browser,async(page,state)=>{
    let creates=0,refused=false;
    const queued=()=>job('relationship_pair','en',{job_id:'d'.repeat(32),status:'running',audit_status:'pending',result:null});
    state.reply=(req,res)=>{
      if(req.url==='/ai/status')return json(res,ready);
      if(req.url==='/ai/jobs'){
        creates++;
        if(creates===1)return json(res,job('relationship_pair'));
        if(entry==='terminal'){refused=true;return json(res,{...queued(),status:'failed',audit_status:'success',error:code});}
        return json(res,queued(),202);
      }
      if(entry==='poll'||req.url.endsWith('/cancel')){refused=true;return json(res,{error:code},code==='not_found'?404:409);}
      return json(res,queued());
    };
    await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
    await page.getByRole('button',{name:'Run',exact:true}).click();
    if(entry==='cancel')await page.getByRole('button',{name:'Cancel',exact:true}).click();
    await waitFor(()=>refused);
    await expect(page.locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
    await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0,'authoritative receipt retires all result sections');
    await page.getByLabel('Language',{exact:true}).selectOption('ko');
    assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0,'language edits cannot resurrect retired results');
    assert.equal(creates,2,'no automatic rerun');
    assert.equal(state.requests.filter(r=>r.path.endsWith('/cancel')).length,entry==='cancel'?1:0,'retirement never implicitly cancels');
    observations.push({label:`retirement ${entry} ${code}`,creates,resultChildren:0});
  }));
}

test('retirement-detached-lazy-callbacks',async browser=>withPanel(browser,async(page,state)=>{
  const refusal=deferred();let creates=0,held=false;
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    creates++;if(creates===1)return json(res,job('relationship_pair'));
    held=true;await refusal.promise;json(res,{error:'source_revoked'},409);
  };
  try {
    await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
    // Hold native DOM nodes, not a locator that stops observing on removal.
    await page.evaluate(()=>{fixture.oldView={disclosure:document.querySelector('[data-ai="provenance"] details'),
      action:document.querySelector('[data-ai="next-checks"] button'),fact:document.querySelector('[data-ai="fact-list"] button')};});
    await page.getByRole('button',{name:'Run',exact:true}).click();await waitFor(()=>held);
    await page.evaluate(()=>{fixture.retiringView={disclosure:document.querySelector('[data-ai="provenance"] details')};});
    await page.locator('[data-ai="provenance"] summary').click();
    await expect(page.locator('[data-ai="provenance"] pre')).toHaveCount(1);
    refusal.resolve();await expect(page.locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
    await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    const observed=await page.evaluate(()=>{
      for(const view of [fixture.oldView,fixture.retiringView]){
        view.disclosure.open=true;view.disclosure.dispatchEvent(new Event('toggle'));
        view.action?.click();view.fact?.click();
      }
      return {resultChildren:document.querySelector('[data-ai="results"]').childElementCount,
        metadata:[fixture.oldView,fixture.retiringView].map(view=>view.disclosure.querySelectorAll('pre').length),actions:fixture.actions.length};
    });
    observations.push({label:'detached callbacks after authoritative refusal',...observed});
    assert.deepEqual(observed,{resultChildren:0,metadata:[0,0],actions:0},'removed callbacks cannot disclose metadata or invoke an action');
    await page.getByLabel('Language',{exact:true}).selectOption('ko');
    assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0);
    assert.equal(creates,2);
  } finally {refusal.resolve();}
}));

test('late-retirement-cancel-keeps-newer-result',async browser=>withPanel(browser,async(page,state)=>{
  const cancelled=deferred();let creates=0,held=false;
  state.reply=async(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    if(req.url.endsWith('/cancel')){held=true;await cancelled.promise;return json(res,{error:'not_found'},404);}
    if(req.url==='/ai/jobs'){
      creates++;return json(res,job('delivery','en',{job_id:creates===1?'b'.repeat(32):'d'.repeat(32),
        ...(creates===1?{status:'running',audit_status:'pending',result:null}:{})}));
    }
    return json(res,job('delivery'));
  };
  try {
    await mounted(page);
    await page.evaluate(()=>{
      const read=TraceAuth.readJSON;
      TraceAuth.readJSON=async(url,options)=>{const response=await read(url,options);if(url.endsWith('/cancel'))fixture.cancelReadCompleted=true;return response;};
    });
    await page.getByRole('button',{name:'Run',exact:true}).click();
    await page.getByRole('button',{name:'Cancel',exact:true}).click();await waitFor(()=>held);
    await expect(page.locator('[data-ai="status"]')).toHaveText('Completed; audited result.');
    await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.locator('[data-ai="status"]')).toHaveText('Completed; audited result.');
    const delivered=page.waitForResponse(response=>new URL(response.url()).pathname.endsWith('/cancel'));
    cancelled.resolve();await delivered;
    // Observe body decoding before checking the settled UI continuation.
    await waitFor(()=>page.evaluate(()=>fixture.cancelReadCompleted===true));
    await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
    await expect(page.locator('[data-ai="status"]')).toHaveText('Completed; audited result.');
    await page.locator('[data-ai="next-checks"] button').click();
    assert.equal((await page.evaluate(()=>fixture.actions)).length,1,'newer result remains actionable');
    assert.equal(creates,2);
  } finally {cancelled.resolve();}
}));

test('nonrevoking-source-refusals-retain-history',async browser=>withPanel(browser,async(page,state)=>{
  let code=null,creates=0;
  state.reply=(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    creates++;json(res,code?{error:code}:job('relationship_pair'),code==='not_found'?404:code?409:200);
  };
  await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  const original=await page.locator('[data-ai="interpretation"]').textContent();
  for(code of ['source_not_ready','source_unavailable','not_found']){
    await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    await expect(page.locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
    // Unlike transient readiness/unavailability, this retries the accepted source.
    if(code==='not_found'){
      assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0,
        'same accepted original selector CREATE404 retires history before any new AI handle');
      await page.getByLabel('Language',{exact:true}).selectOption('ko');
      assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0);
      continue;
    }
    assert.equal(await page.locator('[data-ai="interpretation"]').textContent(),original);
    await expect(page.locator('[data-ai="warnings"]')).toContainText('coverage_incomplete');
    await expect(page.locator('[data-ai="interpretation"] button').first()).toBeDisabled();
    await page.locator('[data-ai="provenance"] summary').click();
    await expect(page.locator('[data-ai="provenance"] pre')).toContainText(fixtures.digests.relationship_pair);
  }
  assert.equal(creates,4,'explicit reruns only; only same-source 404 retires accepted history');
}));

test('same-source-create404-retires-history',async browser=>withPanel(browser,async(page,state)=>{
  await page.evaluate(()=>TraceAuth.ready.then(()=>true));
  let creates=0;
  state.reply=(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    creates++;return json(res,creates===1?job('relationship_pair'):{error:'not_found'},creates===1?200:404);
  };
  await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  const original=await page.locator('[data-ai="interpretation"] .local-ai-claim').allTextContents();
  await page.evaluate(()=>{
    const {job_id,a,b}=fixture.base.source;
    fixture.base={source:{b,job_id,a},kind:'relationship_pair'};
  });
  await page.getByLabel('Language',{exact:true}).selectOption('ko');
  assert.deepEqual(await page.locator('[data-ai="interpretation"] .local-ai-claim').allTextContents(),original,'language edit alone retains model claims and citations');
  assert.equal(state.requests.length,2,'local language/key-order changes never request work');
  await page.getByRole('button',{name:'실행',exact:true}).click();
  await expect(page.getByRole('button',{name:'실행',exact:true})).toBeEnabled();
  await expect(page.locator('[data-ai="status"]')).toContainText('소스를 사용할 수 없거나 변경되었습니다');
  assert.equal(state.requests.at(-1).http_status,404);
  const posts=state.requests.filter(r=>r.method==='POST');
  assert.equal(posts.length,2);
  assert.deepEqual(posts[1].body.source,posts[0].body.source,'same literal selector despite object key order');
  assert.notEqual(posts[1].body.language,posts[0].body.language,'source identity is not request/language equality');
  assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0,
    'CREATE404 for the retained original relationship retires all sections without a new AI handle');
  await page.getByLabel('언어',{exact:true}).selectOption('en');
  assert.equal(await page.locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0,'local edits cannot restore retired history');
  assert.equal(creates,2);assert.equal(state.requests.filter(r=>r.path.endsWith('/cancel')).length,0);
},true));

test('distinct-source-create404-retains-history',async browser=>withPanel(browser,async(page,state)=>{
  await page.evaluate(()=>TraceAuth.ready.then(()=>true));
  let creates=0;
  state.reply=(req,res)=>{
    if(req.url==='/ai/status')return json(res,ready);
    creates++;return json(res,creates===1?job('relationship_pair'):{error:'not_found'},creates===1?200:404);
  };
  await mounted(page,'relationship_pair');await page.getByRole('button',{name:'Run',exact:true}).click();
  await expect(page.locator('[data-ai="interpretation"]')).toBeVisible();
  const original=await page.locator('[data-ai="interpretation"]').textContent();
  const coverage=await page.locator('[data-ai="warnings"]').textContent();
  await page.locator('[data-ai="provenance"] summary').click();
  const metadata=await page.locator('[data-ai="provenance"] pre').textContent();
  const source=state.requests.find(r=>r.method==='POST').body.source;
  for(const [key,value] of [['job_id','e'.repeat(32)],['a','203.0.113.1'],['b','203.0.113.2']]){
    assert.notEqual(source[key],value);
    await page.evaluate(({source,key,value})=>{fixture.base.source={...source,[key]:value};},{source,key,value});
    await page.getByRole('button',{name:'Run',exact:true}).click();
    await expect(page.getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    await expect(page.locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
    assert.equal(state.requests.at(-1).http_status,404);
    assert.deepEqual(state.requests.at(-1).body.source,{...source,[key]:value});
    assert.equal(await page.locator('[data-ai="interpretation"]').textContent(),original,'unaccepted different selector cannot revoke original history');
    assert.equal(await page.locator('[data-ai="warnings"]').textContent(),coverage);
    await expect(page.locator('[data-ai="interpretation"] button').first()).toBeDisabled();
    await expect(page.locator('[data-ai="next-checks"] button')).toBeDisabled();
    await expect(page.locator('[data-ai="provenance"]')).toContainText('Previous result');
    await page.locator('[data-ai="provenance"] summary').click();
    assert.equal(await page.locator('[data-ai="provenance"] pre').textContent(),metadata);
  }
  assert.equal(creates,4,'one accepted source and three explicit distinct-selector refusals');
  assert.equal(state.requests.filter(r=>r.path.endsWith('/cancel')).length,0);
},true));

(async()=>{
  fs.mkdirSync(output,{recursive:true});
  const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
  try {
    const selected=cases.filter(c=>selection==='all'||selection.split(',').includes(c.name));
    assert(selected.length>0, 'at least one real browser case selected');
    for(const item of selected){
      const start=performance.now();let failure=null;
      try{await item.run(browser);}catch(error){failure=error.stack;}
      reports.push({name:item.name,seconds:(performance.now()-start)/1000,failure});
      console.log(`${failure?'FAIL':'PASS'} ${item.name}${failure?'\n'+failure:''}`);
    }
  } finally {
    await browser.close();
    fs.writeFileSync(path.join(output,'browser-results.json'),JSON.stringify({scope:'Real Chromium component; controlled job/model/auth adapter; separate real-auth-script case',node:process.version,sourceRoot:root,browser:browser.version(),browserConnectedAfterClose:browser.isConnected(),reports,observations},null,2));
    const xml=x=>String(x).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;');
    fs.writeFileSync(path.join(output,'browser-junit.xml'),`<testsuite name="local-ai-component" tests="${reports.length}" failures="${reports.filter(r=>r.failure).length}">${reports.map(r=>`<testcase name="${xml(r.name)}" time="${r.seconds}">${r.failure?`<failure message="${xml(r.failure)}"/>`:''}</testcase>`).join('')}</testsuite>`);
  }
  process.exitCode=reports.some(r=>r.failure)?1:0;
})().catch(error=>{console.error(error);process.exitCode=1;});
