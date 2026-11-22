/* Real app, auth, jobs, service, engine and producers. Only native peer replies are controlled. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {chromium, expect} = require(process.env.UI_PLAYWRIGHT_MODULE || '@playwright/test');
const [origin, control, output, selection] = process.argv.slice(2);
const observations = [], requests = [], responses = [], errors = [];
const cases = {};
let runResponseStart=0;
const panel = page => page.locator('.local-ai');
const state = async () => (await fetch(control)).json();
const configure = async (action, mode) => (await fetch(control, {
  method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action, mode})
})).json();
async function login(page) {
  await page.goto(origin + '/login.html');
  await page.evaluate(() => TraceAuth.ready);
  await expect(page.locator('#login-submit')).toBeEnabled();
  await page.fill('#username','fixture');
  await page.fill('#password','fixture-only-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.waitForLoadState('load');
  await page.evaluate(() => TraceAuth.ready);
  await expect(page.locator('#customList')).toContainText('fixture_5');
}
async function measure(page, label) {
  const data = await page.evaluate(() => ({
    total:document.querySelectorAll('*').length,
    component:document.querySelectorAll('.local-ai *').length,
    width:innerWidth, scroll:document.documentElement.scrollWidth
  }));
  observations.push({label,...data});
  assert(data.component < 500, label + ': component DOM must stay below 500');
  return data;
}
async function deliveryOpen(page) {
  if(!await page.locator('#deliveryOperations').evaluate(el=>el.open))
    await page.locator('#deliveryOperations > summary').click();
  await page.locator('#deliveryLocalAI').focus();
  await page.keyboard.press('Enter');
  await expect(panel(page)).toBeVisible();
}
async function completed(page, language='en') {
  await expect(panel(page).locator('[data-ai="status"]')).toHaveText(
    language==='ko'?'완료 — 감사 기록이 확인된 결과입니다.':'Completed; audited result.',{timeout:12000});
  const request=JSON.parse(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').at(-1).body);
  const accepted=()=>{
    const current=responses.slice(runResponseStart), id=current.filter(r=>r.path==='/ai/jobs').map(r=>JSON.parse(r.body)).at(-1)?.job_id;
    return current.map(r=>JSON.parse(r.body)).filter(r=>id&&r.job_id===id&&r.status==='completed'&&r.audit_status==='success'&&r.result&&r.kind===request.kind&&r.language===language).at(-1)?.result;
  };
  await expect.poll(()=>!!accepted()).toBe(true);
  const result=accepted();
  if(request.kind==='decoder_suggest'){
    await expect(panel(page).locator('[data-ai="model-coverage"]')).toHaveAttribute('lang',language);
    if(request.generate){
      assert(result.model && result.model_input,'actual generated response carries model identity and input provenance');
      const c=result.model_input.coverage;
      await expect(panel(page).locator('[data-ai="model-coverage"]')).toContainText(`${c.shown_utf8_bytes} / ${c.original_utf8_bytes}`);
    }else {assert.equal(result.model,null);assert.equal(result.model_input,null);}
  }else {
    assert(result.model && result.facts_summary,'actual explanation carries model identity and separate server facts');
    const summary=panel(page).locator('[data-ai="server-summary"]');
    await expect(summary).toHaveAttribute('lang',language);
    await expect(summary.locator('.local-ai-claim p')).toHaveText(['summary','counterpoints','limitations'].flatMap(key=>result.facts_summary[key].map(c=>c.text)));
    assert(await panel(page).evaluate(node=>{
      const summary=node.querySelector('[data-ai="server-summary"]'),warnings=node.querySelector('[data-ai="warnings"]'),ai=node.querySelector('[data-ai="interpretation"]');
      return !!(summary.compareDocumentPosition(ai)&Node.DOCUMENT_POSITION_FOLLOWING) && !!(warnings.compareDocumentPosition(ai)&Node.DOCUMENT_POSITION_FOLLOWING);
    }),'deterministic facts and limitations precede AI prose on the actual app');
  }
  return result;
}
async function run(page, language='en') {
  await panel(page).getByLabel(/^(Language|언어)$/).selectOption(language);
  runResponseStart=responses.length;
  await panel(page).getByRole('button',{name:language==='ko'?'실행':'Run',exact:true}).click();
}
cases.delivery = async page => {
  assert.equal((await state()).native.length,0);
  assert.equal(requests.filter(r=>r.path.startsWith('/ai/')).length,0);
  const baseline = await measure(page,'startup');
  await deliveryOpen(page);
  assert.equal(requests.filter(r=>r.path.startsWith('/ai/')).length,0,'opening is not inference/status');
  await run(page,'ko');
  await completed(page,'ko');
  await expect(panel(page).locator('[data-ai="interpretation"]')).toContainText('보존된 근거');
  await expect(panel(page).locator('[data-ai="warnings"]')).toContainText('snapshots_not_atomic');
  await panel(page).locator('[data-ai="interpretation"]').getByRole('button',{name:'e1',exact:true}).click();
  await expect(panel(page).locator('[data-ai="fact-detail"]')).toBeFocused();
  const rendered = await measure(page,'delivery-ko');
  observations.push({label:'delivery delta',delta:rendered.total-baseline.total});
  await page.screenshot({path:path.join(output,'delivery-ko.png'),fullPage:true});
  await page.setViewportSize({width:360,height:800});
  const narrow = await measure(page,'delivery narrow');
  assert(narrow.scroll<=narrow.width,'real page must fit narrow viewport');
  await page.screenshot({path:path.join(output,'delivery-narrow.png'),fullPage:true});
  await run(page,'en');
  await completed(page);
  await expect(panel(page).locator('[data-ai="interpretation"]')).toContainText('Inspect retained evidence');
  assert.equal(requests.filter(r=>r.path==='/ai/jobs' && r.method==='POST').length,2);
  assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,2);
  await panel(page).getByRole('button',{name:'Close',exact:true}).click();
  assert.equal(await panel(page).count(),0);
  await expect(page.locator('#deliveryLocalAI')).toBeFocused();
  await measure(page,'delivery closed');
  assert.equal((await state()).http.filter(r=>r.method!=='GET' && !r.path.startsWith('/ai/') && !r.path.startsWith('/auth/')).length,0);
};
async function decoderOpen(page, type='TXT') {
  await page.locator('#menuSettings').click();
  await page.locator('#settingsTabCustom').click();
  await page.locator('#custom_decoder_type').selectOption(type);
  await page.locator('#custom_name').fill('draft_new');
  await page.locator('#custom_steps').fill('[{"op":"ascii"}]');
  await page.locator('#custom_sample').fill('MTkyLjAuMi4x');
  await page.locator('#decoderLocalAI').click();
  await expect(panel(page)).toBeVisible();
}
async function decoderSamples(page, generate=true) {
  await panel(page).getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill('192.0.2.1');
  await panel(page).getByRole('button',{name:'Add sample',exact:true}).click();
  const validation=panel(page).locator('[data-ai="sample"]').nth(1);
  await validation.getByLabel('Raw data',{exact:true}).fill('MTk4LjUxLjEwMC4xNw==');
  await validation.getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill('198.51.100.17');
  await validation.getByLabel('Usage',{exact:true}).selectOption('validation');
  if(generate) await panel(page).getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
}
async function candidate(page, name) {
  const found=[];
  while(true) {
    found.push(...await panel(page).locator('[data-candidate-name]').evaluateAll(nodes=>nodes.map(n=>n.dataset.candidateName)));
    const selected=panel(page).locator(`[data-candidate-name="${name}"]`);
    if(await selected.count()) {await selected.click();return found;}
    const next=panel(page).locator('[data-ai="candidates-next"]');
    assert(!await next.isDisabled(),name+' must be reachable');
    await next.click();
  }
}
cases.decoder = async page => {
  await decoderOpen(page);
  assert.equal((await state()).native.length,0);
  await decoderSamples(page);
  // A different explicit writer commits after this editor loaded revision 0.
  const writer=await page.evaluate(async()=>{
    const response=await fetch('/decoders/custom',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({revision:0,name:'concurrent',decoder_type:'TXT',steps:[{op:'ascii'}]})});
    return {status:response.status,body:await response.json()};
  });
  assert.equal(writer.status,200);
  const before=await state();
  await run(page);
  const accepted=await completed(page);
  const reached=await candidate(page,'generated_1');
  assert(reached.length>5,'later candidate pages must be exercised');
  await expect(panel(page).locator('[data-ai="candidate-detail"]')).toContainText('198.51.100.17');
  await measure(page,'decoder verified candidate');
  await page.screenshot({path:path.join(output,'decoder-verified.png'),fullPage:true});
  await panel(page).locator('[data-ai="candidate-detail"]').screenshot({path:path.join(output,'decoder-holdout.png')});
  await panel(page).locator('[data-ai="provenance"] summary').click();
  assert.deepEqual(JSON.parse(await panel(page).locator('[data-ai="provenance"] pre').textContent()).model_input,accepted.model_input);
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toHaveCount(0);
  await candidate(page,'generated_1');
  const catalogReads=requests.filter(r=>r.path==='/decoders').length;
  await panel(page).getByRole('button',{name:'Apply to draft',exact:true}).click();
  await expect(page.locator('#custom_steps')).toHaveValue(JSON.stringify([{op:'base64'},{op:'ascii'}],null,2));
  assert.equal(requests.filter(r=>r.path==='/decoders').length,catalogReads,'apply never reloads catalog/revision');
  await page.locator('#custom_steps').screenshot({path:path.join(output,'decoder-applied-draft.png')});
  const after=await state();
  assert.deepEqual(after.config,before.config,'apply is not a write');
  assert.equal(after.http.filter(r=>r.path==='/decoders/custom/preview').length,0);
  const native=after.native.find(r=>r.path==='/api/chat');
  const sent=JSON.parse(native.body);
  const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
  const checked=Buffer.from(JSON.stringify(canonical({messages:sent.messages,schema:sent.format})),'utf8');
  assert.equal(accepted.model_input.messages_schema_bytes,checked.length);
  assert.equal(accepted.model_input.messages_schema_digest,require('node:crypto').createHash('sha256').update(checked).digest('hex'));
  assert.deepEqual(accepted.model_input.view,JSON.parse(sent.messages[1].content));
  const messages=JSON.stringify(sent.messages);
  assert(!messages.includes('198.51.100.17')&&!messages.includes('MTk4LjUxLjEwMC4xNw=='),'holdout never enters prompt');
  const draft=await page.locator('#custom_steps').inputValue();
  await page.locator('#registerCustom').click();
  await expect(page.locator('#customPreviewResult')).toContainText('Draft retained');
  assert.equal((await state()).http.filter(r=>r.path==='/decoders/custom' && r.status===409).length,1);
  assert.equal(await page.locator('#custom_steps').inputValue(),draft);
  assert.deepEqual((await state()).config,before.config);
  assert.equal((await state()).http.filter(r=>r.path==='/decoders/custom' && r.method==='POST').length,2,'one explicit concurrent save + one refused save; no retry');
};
cases['decoder-max-excerpt'] = async page => {
  await decoderOpen(page);
  const rows=Array.from({length:4},(_,i)=>{
    const ip=`192.0.2.${i+1}`;
    return {data:Buffer.from(ip+' '.repeat(1536-ip.length)).toString('base64'),
      expected_ips:[ip],usage:'example',complete_expected:true};
  });
  const snapshot={version:1,kind:'decoder_suggest',decoder_type:'TXT',examples:rows};
  const excess=Buffer.byteLength(JSON.stringify(snapshot))-8192;
  assert(excess>0 && excess%4===0);
  const last=rows.at(-1),decodedLength=(last.data.length-excess)/4*3,ip=last.expected_ips[0];
  last.data=Buffer.from(ip+' '.repeat(decodedLength-ip.length)).toString('base64');
  assert.equal(Buffer.byteLength(JSON.stringify(snapshot)),8192);
  for(let i=0;i<rows.length;i++){
    if(i)await panel(page).getByRole('button',{name:'Add sample',exact:true}).click();
    const row=panel(page).locator('[data-ai="sample"]').nth(i);
    await row.getByLabel('Raw data',{exact:true}).fill(rows[i].data);
    await row.getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill(rows[i].expected_ips[0]);
  }
  await panel(page).getByRole('button',{name:'Add sample',exact:true}).click();
  const holdout=panel(page).locator('[data-ai="sample"]').nth(4);
  await holdout.getByLabel('Raw data',{exact:true}).fill('MTk4LjUxLjEwMC4xNw==');
  await holdout.getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill('198.51.100.17');
  await holdout.getByLabel('Usage',{exact:true}).selectOption('validation');
  await panel(page).getByLabel('Generate new candidates (uses local model)',{exact:true}).check();
  await run(page);
  const accepted=await completed(page), input=accepted.model_input;
  assert.deepEqual(accepted.snapshot,snapshot);
  assert.equal(input.coverage.shown_utf8_bytes,1024);
  assert.equal(input.coverage.excerpted_examples,4);
  assert(input.coverage.omitted_utf8_bytes>0);
  assert.equal(accepted.generated.candidates[0].examples.passed,4);
  assert.equal(accepted.generated.candidates[0].validation.passed,1);
  await expect(panel(page).locator('[data-ai="model-coverage"]')).toContainText('omitted middle');
  const chats=(await state()).native.filter(r=>r.path==='/api/chat');
  assert.equal(chats.length,1);
  const sent=JSON.parse(chats[0].body);
  assert.deepEqual(JSON.parse(sent.messages[1].content),input.view);
  assert(!JSON.stringify(sent.messages).includes('198.51.100.17'));
  assert(!JSON.stringify(sent.messages).includes('MTk4LjUxLjEwMC4xNw=='));
  await panel(page).locator('[data-ai="provenance"] summary').click();
  assert.deepEqual(JSON.parse(await panel(page).locator('[data-ai="provenance"] pre').textContent()).model_input,input);
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="provenance"] details > *')).toHaveCount(1);
  await measure(page,'actual app maximum original and bounded model view');
  await page.screenshot({path:path.join(output,'decoder-max-excerpt.png'),fullPage:true});
};
// Persistent actual-app regressions promoted from independent review.
cases['review-manual-preview-save'] = async page => {
  await decoderOpen(page);await decoderSamples(page);
  const before=await state();
  await run(page);const accepted=await completed(page);
  const expected=accepted.generated.candidates[0].steps;
  await candidate(page,'generated_1');
  await panel(page).getByRole('button',{name:'Apply to draft',exact:true}).click();
  await expect(page.locator('#custom_steps')).toHaveValue(JSON.stringify(expected,null,2));
  assert.deepEqual((await state()).config,before.config);
  assert.equal(requests.filter(r=>r.path==='/decoders/custom/preview'||(r.path==='/decoders/custom'&&r.method==='POST')).length,0);
  const previewWait=page.waitForResponse(r=>new URL(r.url()).pathname==='/decoders/custom/preview');
  await page.locator('#previewCustom').click();
  const preview=await previewWait;assert.equal(preview.status(),200);
  const previewData=await preview.json();
  await expect(page.locator('#customPreviewResult')).toContainText('192.0.2.1');
  assert.deepEqual((await state()).config,before.config,'explicit Preview is not Save');
  const saveWait=page.waitForResponse(r=>new URL(r.url()).pathname==='/decoders/custom'&&r.request().method()==='POST');
  await page.locator('#registerCustom').click();
  const save=await saveWait;assert.equal(save.status(),200);
  const saved=await save.json();assert.equal(saved.status,'ok');
  await expect(page.locator('#customPreviewResult')).toContainText('Registered: draft_new [TXT]');
  const reread=await page.context().request.get(origin+'/decoders',{timeout:5000,failOnStatusCode:false});
  assert.equal(reread.status(),200);const catalog=await reread.json();
  assert.equal(catalog.revision,before.config.config_revision+1);
  assert.deepEqual(catalog.custom.find(row=>row.name==='draft_new').steps,expected);
  const after=await state();
  assert.deepEqual(after.config.custom_decoders.find(row=>row.name==='draft_new').steps,expected);
  assert.equal(after.config.config_revision,catalog.revision);
  assert.equal(requests.filter(r=>r.path==='/decoders/custom/preview').length,1);
  assert.equal(requests.filter(r=>r.path==='/decoders/custom'&&r.method==='POST').length,1);
  assert.equal(after.native.filter(r=>r.path==='/api/chat').length,1);
  observations.push({label:'review manual apply-preview-save',preview:previewData,save:saved,readback:catalog,expectedSteps:expected});
};

for(const fault of ['delivery-missing','delivery-wrong-citation','decoder-coverage','decoder-null-model']){
  cases['review-'+fault]=async page=>{
    const isDecoder=fault.startsWith('decoder');
    if(isDecoder){await decoderOpen(page);await decoderSamples(page);}else await deliveryOpen(page);
    const altered=[];
    await page.route(origin+'/ai/jobs**',async route=>{
      const real=await route.fetch({timeout:15000});
      const original=await real.json();
      if(original.status!=='completed'||original.audit_status!=='success'||!original.result){await route.fulfill({response:real});return;}
      const mutated=JSON.parse(JSON.stringify(original));
      if(fault==='delivery-missing')delete mutated.result.facts_summary;
      if(fault==='delivery-wrong-citation'){
        const claim=mutated.result.facts_summary.summary[0];
        claim.evidence_ids=[mutated.result.snapshot.facts.find(f=>!claim.evidence_ids.includes(f.id)).id];
      }
      if(fault==='decoder-coverage')mutated.result.model_input.coverage.omitted_utf8_bytes++;
      if(fault==='decoder-null-model')mutated.result.model=null;
      altered.push({original,mutated});
      await route.fulfill({response:real,json:mutated});
    });
    await run(page);
    await expect(panel(page).locator('[data-ai="status"]')).toHaveText('Unsupported or invalid response. No result accepted.',{timeout:12000});
    await expect(panel(page).locator('[data-ai="results"]')).toBeEmpty();
    await expect(panel(page).getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    assert.equal(altered.length,1,'one real audited producer result must reach mutation');
    assert.equal(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,1);
    assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,1);
    assert.equal(requests.filter(r=>r.path==='/decoders/custom/preview'||(r.path==='/decoders/custom'&&r.method==='POST')).length,0);
    const realRead=await page.context().request.get(origin+'/ai/jobs/'+altered[0].original.job_id,{timeout:5000,failOnStatusCode:false});
    assert.equal(realRead.status(),200);const persisted=await realRead.json();
    assert.deepEqual(persisted.result,altered[0].original.result,'mutation is transport-only, not changed producer state');
    observations.push({label:'review transport mutation',fault,...altered[0],persistedResultMatches:true});
  };
}
async function relationship(page) {
  await page.locator('#menuIpIntel').click();
  await page.locator('.ipintel-enrichment-settings > summary').click();
  await page.locator('#ipIntelIncludeVt').uncheck();
  await page.locator('#ipRelAdvancedSettings > summary').click();
  await page.locator('#ipRelMinScore').fill('1');
  await page.locator('#ipRelPairGateEnabled').uncheck();
  await page.locator('#ipIntelInput').fill('192.0.2.1\n192.0.2.2\n192.0.2.3');
  await page.locator('#runIpRelationshipBtn').click();
  await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state','complete');
  await page.locator('#ipRelPairsToggleBtn').click();
  await expect(page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/})).toHaveCount(3);
}
cases.pair = async page => {
  await relationship(page);
  const before=await page.evaluate(()=>JSON.stringify(window.IP_REL_LAST_SUCCESS));
  assert.equal((await state()).native.length,0);
  const source=(await state()).http.find(r=>r.path.startsWith('/ip-relationship-jobs/')&&r.method==='GET').path.split('/')[2].split('?')[0];
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await page.locator('#pairLocalAI').click();
  assert.equal((await state()).native.length,0);
  await run(page);
  await completed(page);
  const posted=requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST');
  assert.equal(posted.length,1);
  const request=JSON.parse(posted[0].body);
  assert.equal(request.source.job_id,source,'completed accepted source, not cleared transient job id');
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="provenance"]')).toContainText(source);
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="warnings"]')).toContainText('not_attribution');
  assert.equal(await page.evaluate(()=>JSON.stringify(window.IP_REL_LAST_SUCCESS)),before,'AI never changes original result/export');
  await measure(page,'pair result');
  await page.screenshot({path:path.join(output,'pair.png'),fullPage:true});
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).nth(1).click();
  assert.equal(await panel(page).count(),0,'selection detaches and wipes old AI');
  await page.locator('#pairLocalAI').click();
  await run(page,'ko');await completed(page,'ko');
  const second=JSON.parse(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST')[1].body);
  assert.equal(second.source.job_id,source);
  assert.notDeepEqual([second.source.a,second.source.b],[request.source.a,request.source.b]);
  await page.locator('#ipIntelInput').fill('not-an-ip');
  assert.equal(await panel(page).count(),0,'input generation change retires selection');
  await page.locator('#runIpRelationshipBtn').click();
  await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state','error');
  assert.equal(await page.evaluate(()=>JSON.stringify(window.IP_REL_LAST_SUCCESS)),before);
  await expect(page.locator('#ipRelQualityBanner')).toContainText('Previous successful result');
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await page.locator('#pairLocalAI').click();
  await run(page);await completed(page);
  const third=JSON.parse(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST')[2].body);
  assert.equal(third.source.job_id,source,'restored cache retains its original authority, never the failed successor');
  await page.locator('#menuStatus').click();
  assert.equal(await panel(page).count(),0);
  assert.equal((await state()).http.filter(r=>r.path.startsWith('/ai/')&&r.path.endsWith('/cancel')).length,0);
};
cases.refusal = async page => {
  await relationship(page);
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await page.locator('#pairLocalAI').click();
  await page.evaluate(async()=>{
    const response=await fetch('/decoders/custom',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({revision:0,name:'authority_change',decoder_type:'TXT',steps:[{op:'ascii'}]})});
    if(!response.ok)throw new Error('fixture concurrent writer failed');
  });
  await run(page);
  await expect(panel(page).locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
  assert.equal((await state()).native.length,0,'revoked original source cannot dispatch');
  assert.equal(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,1);
  assert.equal(await page.evaluate(()=>document.getElementById('security-message')?.textContent || ''),'','source errors remain local');
  const refusal=responses.map(r=>JSON.parse(r.body)).find(r=>r.code==='source_revoked');
  assert(refusal && refusal.error===refusal.code && typeof refusal.request_id==='string','actual closed HTTP error envelope observed');
};
cases['manual-check'] = async page => {
  await deliveryOpen(page);await run(page);await completed(page);
  const before=(await state()).native.length;
  await panel(page).locator('[data-ai="next-checks"] button').click();
  await expect(panel(page).locator('[data-ai="fact-detail"]')).toContainText('progress_summary');
  await expect(panel(page).locator('[data-ai="fact-detail"]')).toBeFocused();
  assert.equal((await state()).native.length,before,'manual inspection only');
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toContainText('snapshot_digest');
  await expect(panel(page).locator('[data-ai="fact-detail"]')).toBeEmpty();
  await panel(page).locator('[data-ai="fact-list"] button').first().click();
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toHaveCount(0);
};
cases['result-order'] = async page => {
  await page.setViewportSize({width:360,height:800});
  await deliveryOpen(page);await run(page);await completed(page);
  await panel(page).getByRole('heading',{name:'Local AI assistance',exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
  const summary=panel(page).locator('[data-ai="server-summary"]');
  await expect(summary).toBeInViewport();
  await expect(summary.locator('[data-claim-code="delivery_overview"]')).toBeInViewport();
  await expect(panel(page).locator('[data-ai="interpretation"]')).toBeVisible();
  assert.equal(await panel(page).locator('[data-ai="provenance"] pre').count(),0,'raw metadata is lazy, not a leading wall');
  await expect(panel(page).locator('[data-ai="warnings"]')).toBeVisible();
  const before=await measure(page,'result-first narrow');
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toContainText('snapshot_digest');
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toHaveCount(0);
  assert.equal((await measure(page,'metadata closed')).component,before.component);
  await panel(page).getByRole('heading',{name:'Local AI assistance',exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
  await page.screenshot({path:path.join(output,'result-first-narrow.png')});
};
for(const [mode,label] of [['unavailable','Security or audit storage'],['stopped','Local assistance is stopped'],['unsettled','Provider settlement is unknown'],['disabled','Local AI is disabled']]) {
  cases[mode]=async page=>{
    if(mode!=='disabled')await configure('availability',mode);
    await deliveryOpen(page);await run(page);
    await expect(panel(page).locator('[data-ai="status"]')).toContainText(label);
    if(mode==='unavailable')await expect(page.locator('#security-message')).toContainText('Security or audit storage');
    await expect(panel(page).getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    const observed=responses.filter(r=>r.path==='/ai/status').map(r=>JSON.parse(r.body));
    assert.equal(observed[0].provider_state,mode,'actual service status, not a synthetic response');
    assert.equal((await state()).native.length,0);
    assert.equal(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,0);
  };
}
cases['audit-pending'] = async page => {
  await configure('audit','gate');
  try {
    await deliveryOpen(page);await run(page);
    await expect.poll(async()=>(await state()).audit_entered).toBe(1);
    await expect(panel(page).locator('[data-ai="status"]')).toContainText('audit confirmation pending');
    assert.equal(await panel(page).locator('[data-ai="interpretation"]').count(),0);
    const availability=await page.evaluate(()=>TraceAuth.readJSON('/ai/status'));
    assert.equal(availability.active_job.status,'completed');
    const pending=await page.evaluate(id=>TraceAuth.readJSON('/ai/jobs/'+id),availability.active_job.job_id);
    assert.equal(pending.audit_status,'pending');assert.equal(pending.result,null);
    await decoderOpen(page);await decoderSamples(page,false);await run(page);
    await expect(panel(page).locator('[data-ai="status"]')).toContainText('busy');
    assert.equal(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,1,'terminal audit-pending must not attach across sources');
    await configure('audit','normal');
    await expect.poll(async()=>page.evaluate(id=>TraceAuth.readJSON('/ai/jobs/'+id).then(j=>j.audit_status),availability.active_job.job_id)).toBe('success');
    assert.equal(await panel(page).locator('[data-ai="interpretation"]').count(),0);
  } finally {await configure('audit','normal');}
};
cases['audit-failed'] = async page => {
  await configure('audit','failed');await deliveryOpen(page);await run(page);
  await expect(panel(page).locator('[data-ai="status"]')).toContainText('Security or audit storage');
  await expect(page.locator('#security-message')).toContainText('Security or audit storage');
  assert.equal(await panel(page).locator('[data-ai="interpretation"]').count(),0);
  assert(responses.some(r=>r.status===200&&JSON.parse(r.body).audit_status==='failed'),'real HTTP200 terminal audit error');
  await expect(panel(page)).not.toContainText('private fixture');
};
cases.cancel = async page => {
  await configure('native','gate');
  try {
    await deliveryOpen(page);await run(page);
    await expect.poll(async()=>(await state()).native_entered).toBe(1);
    await panel(page).getByRole('button',{name:'Cancel',exact:true}).click();
    await expect(panel(page).locator('[data-ai="status"]')).toContainText('stopping inference is not confirmed');
    // Local click intent is not the server's cancellation receipt. Keep the
    // real native request gated until the real cancellation is accepted.
    await expect.poll(()=>responses.filter(r=>r.path.endsWith('/cancel')).length).toBe(1);
    const cancellation=JSON.parse(responses.find(r=>r.path.endsWith('/cancel')).body);
    assert.equal(cancellation.cancellation_requested,true);
    assert.equal(cancellation.cancellation_confirmed,false);
    assert.equal(cancellation.status,'cancel_pending');
    assert.equal((await state()).interlock.blocked,true);
    await configure('native','normal');
    await expect(panel(page).locator('[data-ai="status"]')).toContainText('Cancellation confirmed');
    assert.equal(await panel(page).locator('[data-ai="interpretation"]').count(),0);
    assert.equal((await state()).interlock.blocked,false);
    assert.equal(requests.filter(r=>r.path.endsWith('/cancel')).length,1);
    assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,1);
  } finally {await configure('native','normal');}
};
cases['auth-retirement'] = async page => {
  await decoderOpen(page);await decoderSamples(page,false);await run(page);await completed(page);
  await page.evaluate(()=>{
    const editor=document.querySelector('[data-ai="sample-editors"]'), result=document.querySelector('[data-ai="results"]');
    const input=editor.querySelector('textarea');
    // Test-only synchronous receipt across real navigation; counts/booleans
    // only, never samples, prompts, model text or authentication material.
    TraceAuth.onInvalidated(status=>sessionStorage.setItem('local-ai-retirement-test',JSON.stringify({
      status,editor:editor.childElementCount,result:result.childElementCount,
      inputCleared:input.value==='',panels:document.querySelectorAll('.local-ai').length
    })));
  });
  await page.evaluate(()=>TraceAuth.json('/auth/sessions/revoke',{}));
  await page.evaluate(()=>{void TraceAuth.readJSON('/ai/status').catch(()=>null);});
  await expect(page).toHaveURL(/login\.html/);
  const retired=await page.evaluate(()=>{
    const value=sessionStorage.getItem('local-ai-retirement-test');sessionStorage.removeItem('local-ai-retirement-test');
    return value?JSON.parse(value):null;
  });
  observations.push({label:'actual revoked-session DOM',retired});
  assert.deepEqual(retired,{status:401,editor:0,result:0,inputCleared:true,panels:0});
  assert.equal((await state()).native.length,0);
  assert.equal(requests.filter(r=>r.path.endsWith('/cancel')).length,0);
};
cases['decoder-fences'] = async page => {
  const baseline=(await state()).config;
  await decoderOpen(page);await decoderSamples(page,false);await run(page);await completed(page);
  await candidate(page,'fixture_0');
  await page.locator('#custom_steps').fill('[{"op":"urlsafe_b64"}]');
  await expect(panel(page)).toHaveCount(0);
  await page.locator('#decoderLocalAI').click();await decoderSamples(page,false);await run(page);await completed(page);
  await page.locator('#custom_decoder_type').selectOption('A');
  await expect(panel(page)).toHaveCount(0);
  await page.locator('#decoderLocalAI').click();
  await page.locator('#settingsTabDomains').click();await expect(panel(page)).toHaveCount(0);
  await page.locator('#settingsTabCustom').click();await page.locator('#decoderLocalAI').click();
  await page.locator('#reloadCustom').click();await expect(panel(page)).toHaveCount(0);
  assert.equal((await state()).native.length,0,'catalog-only is zero model I/O');
  assert.deepEqual((await state()).config,baseline);
  assert.equal((await state()).http.filter(r=>r.path==='/decoders/custom/preview'||(r.path==='/decoders/custom'&&r.method!=='GET')).length,0);
};
cases['decoder-A'] = async page => {
  const type=selection==='decoder-A'?'A':'TXT', language=selection==='decoder-ko'?'ko':'en';
  await decoderOpen(page,type);await decoderSamples(page);await run(page,language);await completed(page,language);
  await candidate(page,'generated_1');
  await panel(page).locator('[data-ai="provenance"] summary').click();
  await expect(panel(page).locator('[data-ai="candidate-detail"]')).toBeEmpty();
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toContainText('ranking_basis');
  await candidate(page,'generated_1');
  await expect(panel(page).locator('[data-ai="provenance"] pre')).toHaveCount(0);
  await expect(panel(page).locator('[data-ai="candidate-detail"]')).toContainText('198.51.100.17');
  await panel(page).locator('[data-ai="candidate-detail"]').screenshot({path:path.join(output,'decoder-A-holdout.png')});
  await page.setViewportSize({width:360,height:800});
  const narrow=await measure(page,'decoder A narrow');
  assert(narrow.scroll<=narrow.width,'complete decoder page must reflow');
  await page.screenshot({path:path.join(output,'decoder-A-narrow.png'),fullPage:true});
  const baseline=(await state()).config;
  await panel(page).getByRole('button',{name:language==='ko'?'초안에 적용':'Apply to draft',exact:true}).click();
  await expect(page.locator('#custom_decoder_type')).toHaveValue(type);
  await expect(page.locator('#custom_steps')).toHaveValue(JSON.stringify([{op:'base64'},{op:'ascii'}],null,2));
  assert.deepEqual((await state()).config,baseline);
  await page.locator('#custom_steps').screenshot({path:path.join(output,'decoder-A-draft.png')});
};
cases['decoder-ko']=cases['decoder-A'];
cases['provider-failed']=async page=>{
  await configure('native','invalid');await deliveryOpen(page);await run(page);
  await expect(panel(page).locator('[data-ai="status"]')).toContainText('Request failed. No automatic retry.');
  await expect(page.locator('body')).not.toContainText('PRIVATE_PROVIDER_PROSE');
  assert.equal(await panel(page).locator('[data-ai="interpretation"]').count(),0);
  assert.equal(await page.evaluate(()=>document.getElementById('security-message')?.textContent||''),'');
  assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,1);
};
cases['source-exclusions']=async page=>{
  await relationship(page);
  // An equal-looking result without the private accepted owner must not gain
  // source authority by borrowing the most recent successful job ID.
  await page.evaluate(()=>{
    const copy=JSON.parse(JSON.stringify(window.IP_REL_CACHE));
    window.IP_REL_CACHE=copy;
    renderIpRelationshipPairsTable(document.querySelector('#ipRelPairsTable tbody'),copy.pairs);
  });
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await expect(page.locator('#pairLocalAI')).toHaveCount(0);
  await page.locator('#ipIntelMispEventId').fill('17');
  await page.locator('#runIpRelationshipBtn').click();
  await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state','complete');
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await expect(page.locator('#pairLocalAI'),'MISP-backed completed result is ineligible').toHaveCount(0);
  assert.equal((await state()).misp_fixture_reads,1);
  assert.equal((await state()).native.length,0);
};
cases['delayed-create'] = async page => {
  let release, observed=false;
  const barrier=new Promise(resolve=>release=resolve);
  await page.route('**/ai/jobs',async route=>{
    if(route.request().method()!=='POST')return route.continue();
    const response=await route.fetch();observed=true;
    await barrier;await route.fulfill({response});
  });
  try {
    await deliveryOpen(page);await run(page);
    await expect.poll(()=>observed).toBe(true);
    await page.locator('#deliveryOperations > summary').click();
    await expect(panel(page)).toHaveCount(0);
    release();
    await expect.poll(async()=>(await state()).audit_entered).toBe(1);
    await page.unrouteAll({behavior:'wait'});
    await deliveryOpen(page);
    assert.equal(await panel(page).locator('[data-ai="interpretation"]').count(),0);
    assert.equal(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,1);
    assert.equal(requests.filter(r=>r.path.endsWith('/cancel')).length,0);
    await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
    await expect(panel(page)).toHaveCount(0);
  } finally {release();}
};
cases['failed-rerun-retains-history'] = async page => {
  await relationship(page);
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await page.locator('#pairLocalAI').click();
  await run(page);await completed(page);
  const originalText=await panel(page).locator('[data-ai="interpretation"]').textContent();
  const originalCoverage=await panel(page).locator('[data-ai="warnings"]').textContent();
  await panel(page).locator('[data-ai="provenance"] summary').click();
  const originalMetadata=await panel(page).locator('[data-ai="provenance"] pre').textContent();
  await configure('native','invalid');
  try {
    await run(page);
    await expect(panel(page).locator('[data-ai="status"]')).toHaveText('Request failed. No automatic retry.');
    await expect(panel(page).getByRole('button',{name:'Run',exact:true})).toBeEnabled();
    assert.equal(await panel(page).locator('[data-ai="interpretation"]').textContent(),originalText);
    assert.equal(await panel(page).locator('[data-ai="warnings"]').textContent(),originalCoverage);
    await expect(panel(page).locator('[data-ai="interpretation"] button').first()).toBeDisabled();
    await expect(panel(page).locator('[data-ai="next-checks"] button')).toBeDisabled();
    await expect(panel(page).locator('[data-ai="provenance"]')).toContainText('Previous result');
    await panel(page).locator('[data-ai="provenance"] summary').click();
    assert.equal(await panel(page).locator('[data-ai="provenance"] pre').textContent(),originalMetadata);
    await expect(panel(page)).not.toContainText('PRIVATE_PROVIDER_PROSE');
    await expect.poll(()=>responses.some(r=>JSON.parse(r.body).error==='invalid_model_output')).toBe(true);
    const creates=requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST');
    assert.equal(creates.length,2,'only the two explicit runs');
    assert.deepEqual(JSON.parse(creates[1].body),JSON.parse(creates[0].body),'same original source, not a replacement');
    assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,2);
    assert.equal((await state()).config.config_revision,0,'no authoritative revision change');
    await page.screenshot({path:path.join(output,'failed-rerun-history.png'),fullPage:true});
    observations.push({label:'ordinary failed rerun retains historical text, coverage and metadata',creates:2,nativeChats:2});
  } finally {await configure('native','normal');}
};
cases['source-retirement-after-success'] = async page => {
  await relationship(page);
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await page.locator('#pairLocalAI').click();
  await run(page); await completed(page);
  await expect.poll(()=>responses.some(r=>JSON.parse(r.body).result?.interpretation)).toBe(true);
  const successful=responses.map(r=>JSON.parse(r.body)).find(r=>r.result?.interpretation);
  const originalText=successful.result.interpretation.summary[0].text;
  const beforeInspection=requests.filter(r=>r.path.startsWith('/ai/')||r.path.startsWith('/ip-relationship')).length;
  await panel(page).locator('[data-ai="next-checks"] button').click();
  await expect(panel(page).locator('[data-ai="fact-detail"]')).toContainText('quality');
  assert.equal(requests.filter(r=>r.path.startsWith('/ai/')||r.path.startsWith('/ip-relationship')).length,beforeInspection);
  const beforeEdit=requests.filter(r=>r.path.startsWith('/ai/')).length;
  await panel(page).getByLabel('Language',{exact:true}).selectOption('ko');
  await expect(panel(page).locator('[data-ai="interpretation"]')).toContainText(originalText);
  await expect(panel(page).locator('[data-ai="warnings"]')).toContainText('not_attribution');
  await expect(panel(page).locator('[data-ai="interpretation"] button').first()).toBeDisabled();
  await panel(page).getByLabel('언어',{exact:true}).selectOption('en');
  assert.equal(requests.filter(r=>r.path.startsWith('/ai/')).length,beforeEdit,'local edits do not revoke disclosed history or start work');
  const writer=await page.evaluate(async()=>{
    const r=await fetch('/decoders/custom',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({revision:0,name:'review_authority_transition',decoder_type:'TXT',steps:[{op:'ascii'}]})});
    return {status:r.status,body:await r.json()};
  });
  assert.equal(writer.status,200);
  assert.equal((await state()).config.config_revision,1,'read back real revision transition');
  await run(page);
  await expect(panel(page).locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
  await expect(panel(page).getByRole('button',{name:'Run',exact:true})).toBeEnabled();
  await expect.poll(()=>responses.some(r=>JSON.parse(r.body).code==='source_revoked')).toBe(true);
  const refusal=responses.find(r=>JSON.parse(r.body).code==='source_revoked');
  assert.equal(refusal.status,409);
  assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,1,'rejected source never dispatches another call');
  const oldJob=await page.evaluate(id=>TraceAuth.readJSON('/ai/jobs/'+id),successful.job_id);
  assert(['source_revoked','not_found'].includes(oldJob.code),'server has retired the accepted result');
  const beforeDisclosure=await panel(page).locator('[data-ai="results"]').evaluate(n=>({children:n.childElementCount,text:n.textContent,interpretations:n.querySelectorAll('[data-ai="interpretation"]').length}));
  if(await panel(page).locator('[data-ai="provenance"] summary').count()){
    await panel(page).locator('[data-ai="provenance"] summary').click();
    await expect(panel(page).locator('[data-ai="provenance"] pre')).toHaveCount(1);
  }
  observations.push({label:'authoritative source retirement after prior success',successfulJob:successful.job_id,
    source:successful.result.snapshot.source,refusal,oldJob,beforeDisclosure,
    metadataAfterRevocation:await panel(page).locator('[data-ai="provenance"] pre').count(),
    localEditHistoricalControl:true,noInspectionFetch:true});
  await page.screenshot({path:path.join(output,'source-retired-result-retained.png'),fullPage:true});
  assert.equal(beforeDisclosure.children,0,'authoritative source_revoked must retire retained AI result; this is not ordinary local-input staleness');
  assert.equal(await panel(page).locator('[data-ai="provenance"] pre').count(),0,'no newly expanded metadata after retirement');
  const creates=requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST');
  assert.equal(creates.length,2);
  assert.deepEqual(JSON.parse(creates[1].body),JSON.parse(creates[0].body),'rerun uses the identical original source');
  await panel(page).getByLabel('Language',{exact:true}).selectOption('ko');
  assert.equal(await panel(page).locator('[data-ai="results"]').evaluate(n=>n.childElementCount),0,'local edits cannot resurrect retired history');
  assert.equal((await state()).native.filter(r=>r.path==='/api/chat').length,1);
};

/* Normal public producer retention: no registry/config/clock mutation or model. */
cases['same-source-eviction-create-404'] = async page => {
  let producerRequest=null;
  page.on('request',request=>{
    if(new URL(request.url()).pathname==='/ip-relationship-jobs' && request.method()==='POST' && !producerRequest)
      producerRequest=JSON.parse(request.postData());
  });
  await relationship(page);
  assert(producerRequest,'capture the real UI producer request before bounded writer runs');
  await page.locator('#ipRelPairsTable').getByRole('button',{name:/^Inspect pair/}).first().click();
  await page.locator('#pairLocalAI').click();
  await run(page);await completed(page);
  await expect.poll(()=>responses.some(r=>JSON.parse(r.body).result?.interpretation)).toBe(true);
  const successful=responses.map(r=>JSON.parse(r.body)).find(r=>r.result?.interpretation);
  const firstCreate=JSON.parse(requests.find(r=>r.path==='/ai/jobs'&&r.method==='POST').body);
  const originalSource=firstCreate.source.job_id;
  const initialState=await state();
  assert.equal(initialState.config.config_revision,0);
  assert.equal(initialState.native.filter(r=>r.path==='/api/chat').length,1);
  const originalRead=await page.evaluate(async id=>{
    const response=await fetch('/ip-relationship-jobs/'+id+'?result=1');
    return {status:response.status,body:await response.json()};
  },originalSource);
  assert.equal(originalRead.status,200);
  assert.equal(originalRead.body.status,'completed');
  const producerReads=[];
  for(let i=0;i<32;i++){
    const created=await page.evaluate(async data=>{
      const response=await fetch('/ip-relationship-jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
      return {status:response.status,body:await response.json()};
    },producerRequest);
    observations.push({label:'explicit bounded producer create',index:i,...created});
    assert.equal(created.status,202,'public policy must admit every bounded ordinary producer; otherwise proof is inconclusive');
    let observed;
    await expect.poll(async()=>{
      observed=await page.evaluate(async id=>{
        const response=await fetch('/ip-relationship-jobs/'+id+'?result=1');
        const body=await response.json();
        return {status:response.status,body,resultBytes:body.result?new TextEncoder().encode(JSON.stringify(body.result)).length:0};
      },created.body.job_id);
      return observed.status===200 && observed.body.status==='completed';
    }).toBe(true);
    assert.equal(observed.body.status_code,200);
    assert.equal(observed.body.error,null);
    assert.equal(observed.body.audit_status,'recorded');
    producerReads.push(observed);
  }
  assert.equal(new Set(producerReads.map(r=>r.body.job_id)).size,32);
  assert(producerReads.every(r=>r.body.job_id!==originalSource));
  assert(producerReads.reduce((sum,r)=>sum+r.resultBytes,0)+new TextEncoder().encode(JSON.stringify(originalRead.body.result)).length<64*1024*1024,
    'the actual production count limit, not the byte limit, causes eviction');
  const retainedReadback=[];
  for(const id of [originalSource,...producerReads.map(r=>r.body.job_id)]){
    // Observer-only transport: same BrowserContext cookie jar, real public API.
    // The product's wrapped fetch still drives every UI action under test.
    const response=await page.context().request.get(origin+'/ip-relationship-jobs/'+id,
      {timeout:5000,failOnStatusCode:false});
    retainedReadback.push({id,status:response.status(),body:await response.json()});
  }
  assert.equal(retainedReadback[0].status,404,'original accepted source really evicted through ordinary retention policy');
  assert(retainedReadback.slice(1).every(r=>r.status===200 && r.body.status==='completed'));
  assert.equal((await state()).config.config_revision,0,'no configuration revocation or TTL override');
  observations.push({label:'real unchanged terminal retention',terminalLimit:32,producerRequest,originalRead,
    newSuccessfulJobs:producerReads.map(r=>({id:r.body.job_id,resultBytes:r.resultBytes})),retainedReadback});
  await run(page);
  await expect(panel(page).locator('[data-ai="status"]')).toContainText('Source is unavailable or changed');
  await expect(panel(page).getByRole('button',{name:'Run',exact:true})).toBeEnabled();
  await expect.poll(()=>responses.some(r=>r.path==='/ai/jobs' && r.status===404)).toBe(true);
  const refusal=responses.find(r=>r.path==='/ai/jobs' && r.status===404);
  assert.equal(JSON.parse(refusal.body).code,'not_found');
  const creates=requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST');
  assert.equal(creates.length,2,'exactly two user-initiated AI creates');
  assert.deepEqual(JSON.parse(creates[1].body),firstCreate,'identical previously accepted source and pair, not an unknown replacement');
  const after=await state();
  assert.equal(after.native.filter(r=>r.path==='/api/chat').length,1,'refused rerun dispatches no extra inference');
  assert.equal(after.config.config_revision,0);
  assert.equal(requests.filter(r=>r.path==='/ip-relationship-jobs'&&r.method==='POST').length,33,
    'initial UI run plus 32 explicit writer runs; AI did not initiate a producer');
  const oldAI=await page.evaluate(async id=>{
    const response=await fetch('/ai/jobs/'+id);return {status:response.status,body:await response.json()};
  },successful.job_id);
  assert([404,409].includes(oldAI.status));
  assert(['not_found','source_revoked'].includes(oldAI.body.code),'backend cannot retrieve the revoked original result');
  const beforeDisclosure=await panel(page).locator('[data-ai="results"]').evaluate(n=>({children:n.childElementCount,
    interpretations:n.querySelectorAll('[data-ai="interpretation"]').length,text:n.textContent}));
  if(await panel(page).locator('[data-ai="provenance"] summary').count()){
    await panel(page).locator('[data-ai="provenance"] summary').click();
    await expect(panel(page).locator('[data-ai="provenance"] pre')).toHaveCount(1);
  }
  const metadataAfterRefusal=await panel(page).locator('[data-ai="provenance"] pre').allTextContents();
  observations.push({label:'same-original-source create404 retirement',successfulJob:successful.job_id,
    originalSource,originalSelector:firstCreate.source,refusal,oldAI,beforeDisclosure,metadataAfterRefusal,
    producerCreates:33,aiCreates:2,nativeChats:1,configRevision:after.config.config_revision});
  await page.screenshot({path:path.join(output,'same-source-eviction-create404.png'),fullPage:true});
  assert.equal(beforeDisclosure.children,0,'known original source eviction plus identical-source CREATE404 must retire retained AI results');
  assert.equal(metadataAfterRefusal.length,0,'no new lazy metadata publication after authoritative same-source absence');
};

(async () => {
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1280,height:900}});
  const page = await context.newPage();page.setDefaultTimeout(5000);
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{
    const url=new URL(request.url());
    requests.push({method:request.method(),path:url.pathname,body:url.pathname.startsWith('/ai/')?request.postData():null});
    assert.equal(url.origin,origin,'browser must only contact owned application');
  });
  const responseReads=[];
  page.on('response',response=>{
    if(new URL(response.url()).pathname.startsWith('/ai/'))responseReads.push((async()=>{
      try{responses.push({path:new URL(response.url()).pathname,status:response.status(),body:await response.text()});}catch(_){/* detached read */}
    })());
  });
  let failed;
  try {
    await login(page);
    await cases[selection](page);
    assert.deepEqual(errors,[]);
  } catch(error) {failed=error;console.error(error.stack);}
  finally {
    await page.screenshot({path:path.join(output,'final.png'),fullPage:true}).catch(()=>{});
    await context.request.dispose();await context.close();await browser.close();
    await Promise.all(responseReads);
    fs.writeFileSync(path.join(output,'browser.json'),JSON.stringify({selection,requests,responses,observations,errors,passed:!failed},null,2));
  }
  if(failed)process.exitCode=1;
  else console.log('PASS '+selection);
})();
