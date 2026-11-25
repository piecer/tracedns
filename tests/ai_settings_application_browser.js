'use strict';
// No route interception: auth, settings, jobs, engine and result rendering are real.
const fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict');
const {chromium,expect}=require('@playwright/test');
const [origin,observer,endpoint,scenario,output]=process.argv.slice(2);
const KEY='SYNTHETIC-opaque!+/=:TOKEN', native=JSON.parse(process.env.AI_TEST_NATIVE_SETTINGS);
const requests=[], responses=[], pageErrors=[], messages=[], pendingBodies=[];
const panel=page=>page.locator('.local-ai');
const observe=async()=>{const r=await fetch(observer);assert.equal(r.status,200);return r.json();};
async function saved(page){
  await page.locator('#saveAISettings').click();
  await expect(page.locator('#aiSettingsStatus')).toContainText('Saved local settings');
  await expect(page.locator('#aiApiKey')).toHaveValue('');
  await expect(panel(page)).toHaveCount(0);
}
async function openDelivery(page){
  if(!await page.locator('#deliveryOperations').evaluate(e=>e.open))await page.locator('#deliveryOperations > summary').click();
  await page.locator('#deliveryLocalAI').click();await expect(panel(page)).toBeVisible();
}
async function run(page,language='en'){
  const start=responses.length;
  await panel(page).getByLabel(/^(Language|언어)$/).selectOption(language);
  await panel(page).getByRole('button',{name:language==='ko'?'실행':'Run',exact:true}).click();
  await expect.poll(()=>responses.slice(start).filter(r=>/^\/ai\/jobs(?:\/|$)/.test(r.path)).map(r=>r.json)
    .some(j=>['completed','failed'].includes(j.status)&&j.audit_status==='success'),{timeout:15000}).toBe(true);
  return responses.slice(start).map(r=>r.json).find(j=>['completed','failed'].includes(j.status)&&j.audit_status==='success');
}
async function completed(page,language='en'){
  await expect(panel(page).locator('[data-ai="status"]')).toHaveText(language==='ko'?'완료 — 감사 기록이 확인된 결과입니다.':'Completed; audited result.');
}
async function provenance(page,result){
  await panel(page).locator('[data-ai="provenance"] summary').click();
  const node=panel(page).locator('[data-ai="provenance"] pre');await expect(node).toBeVisible();
  assert.deepEqual(JSON.parse(await node.textContent()).model,result.model);
}
(async()=>{
  const browser=await chromium.launch({headless:true});let context,deadline;
  try{
    context=await browser.newContext();
    deadline=setTimeout(()=>void browser.close(),80000);
    context.on('request',r=>requests.push({path:new URL(r.url()).pathname,url:r.url(),method:r.method()}));
    context.on('response',r=>{
      const p=new URL(r.url()).pathname;
      if(p.startsWith('/ai/'))pendingBodies.push((async()=>{const wire=await r.text();assert(!wire.includes(KEY));responses.push({path:p,status:r.status(),wire,json:JSON.parse(wire)});})());
    });
    const page=await context.newPage();page.on('pageerror',e=>pageErrors.push(e.message));page.on('console',m=>messages.push(m.text()));
    await page.goto(origin+'/login.html');await page.evaluate(()=>TraceAuth.ready);
    await expect(page.locator('#login-submit')).toBeEnabled();
    await page.locator('#username').fill('fixture');await page.locator('#password').fill('fixture-only-password');
    await page.locator('#login-submit').click();await page.waitForURL('**/dns_frontend.html');await page.waitForLoadState('load');
    await page.goto(origin+'/dns_frontend.html#settings-ai');await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
    await page.locator('#aiProvider').selectOption('openai_compatible');await page.locator('#aiEnabled').check();
    await page.locator('#aiEndpointPolicy').selectOption('loopback');await page.locator('#aiTokenLimitField').selectOption('max_tokens');
    await page.locator('#aiBaseURL').fill(endpoint);await page.locator('#aiModel').fill('requested/alias');await page.locator('#aiApiKey').fill(KEY);
    await saved(page);
    let observed=await observe();assert.equal(observed.compatible_calls,0);assert.equal(observed.native_calls,0);
    assert.equal(requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,0);
    await page.locator('#loadAISettings').click();await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
    await expect(page.locator('#aiKeyConfigured')).toContainText('Key configured');
    await page.reload();await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
    await expect(page.locator('#aiBaseURL')).toHaveValue(endpoint);await expect(page.locator('#aiApiKey')).toHaveValue('');
    if(scenario==='decoder'){
      await page.locator('#settingsTabCustom').click();await page.locator('#reloadCustom').click();
      await expect.poll(()=>page.evaluate(()=>decoderRevision)).toBe(1);
      await page.locator('#custom_decoder_type').selectOption('TXT');await page.locator('#custom_name').fill('compatible_manual');
      await page.locator('#custom_steps').fill('[{"op":"ascii"}]');await page.locator('#custom_sample').fill('MTkyLjAuMi4x');
      await page.locator('#decoderLocalAI').click();
      await panel(page).getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill('192.0.2.1');
      await panel(page).getByRole('button',{name:'Add sample',exact:true}).click();
      const holdout=panel(page).locator('[data-ai="sample"]').nth(1);
      await holdout.getByLabel('Raw data',{exact:true}).fill('MTk4LjUxLjEwMC4xNw==');
      await holdout.getByLabel('Expected IPv4 (comma or space separated)',{exact:true}).fill('198.51.100.17');
      await holdout.getByLabel('Usage',{exact:true}).selectOption('validation');
      await panel(page).getByLabel(/^Generate new candidates/).check();
      const job=await run(page);await completed(page);assert.equal(job.result.model.provider,'openai_compatible');
      const candidate=job.result.generated.candidates[0];assert.equal(candidate.validation.passed,1);
      await provenance(page,job.result);
      while(!await panel(page).locator('[data-candidate-name="generated_1"]').count())await panel(page).locator('[data-ai="candidates-next"]').click();
      await panel(page).locator('[data-candidate-name="generated_1"]').click();await panel(page).getByRole('button',{name:'Apply to draft',exact:true}).click();
      await expect(page.locator('#custom_steps')).toHaveValue(JSON.stringify(candidate.steps,null,2));
      assert.deepEqual((await observe()).custom_names,[]);assert.equal((await observe()).revision,1);
      await page.locator('#previewCustom').click();await expect(page.locator('#customPreviewResult')).toContainText('192.0.2.1');
      assert.deepEqual((await observe()).custom_names,[]);
      await page.locator('#registerCustom').click();await expect(page.locator('#customPreviewResult')).toContainText('Registered: compatible_manual [TXT]');
      assert.deepEqual((await observe()).custom_names,['compatible_manual']);assert.equal((await observe()).revision,2);
    }else{
      await openDelivery(page);const language=scenario==='delivery-ko'?'ko':'en';const job=await run(page,language);
      const error={'auth-error':'provider_auth_failed','request-error':'provider_request_rejected','rate-error':'provider_rate_limited',uncertain:'provider_failed'}[scenario];
      if(error){
        assert.equal(job.error,error);assert.equal(job.result,null);assert.equal(job.status,'failed');
        const label={'auth-error':'Provider authentication was rejected','request-error':'Provider rejected the request','rate-error':'Provider rate limit reached',uncertain:'Request failed'}[scenario];
        await expect(panel(page).locator('[data-ai="status"]')).toContainText(label);
        assert.equal((await page.context().request.get(origin+'/auth/me')).status(),200);
        assert.equal((await observe()).blocked,scenario==='uncertain');
        await page.locator('#settingsTabAI').click();await page.locator('#aiEnabled').uncheck();await saved(page);
        assert.equal((await observe()).blocked,scenario==='uncertain');
      }else{
        await completed(page,language);const result=job.result;
        assert.equal(result.model.provider,'openai_compatible');assert.equal(result.model.requested_model,'requested/alias');
        assert.equal(result.model.reported_model,'reported/alias-2026');assert(!Object.hasOwn(result.model,'model_digest'));
        if(scenario.startsWith('delivery'))for(const k of ['prompt_tokens','completion_tokens','total_tokens'])assert(!Object.hasOwn(result.model,k));
        await expect(panel(page).locator('[data-ai="server-summary"] .local-ai-claim p')).toHaveText(['summary','counterpoints','limitations'].flatMap(k=>result.facts_summary[k].map(x=>x.text)));
        await expect(panel(page).locator('[data-ai="interpretation"]')).toContainText(language==='ko'?'보존된 근거':'Inspect retained evidence');
        await provenance(page,result);
        await expect(panel(page).locator('h3')).toHaveText(language==='ko'?'AI 도움':'AI assistance');
        if(scenario==='reconfigure'){
          await page.locator('#settingsTabAI').click();await page.locator('#aiProvider').selectOption('ollama');
          await page.locator('#aiBaseURL').fill(native.base_url);await page.locator('#aiModel').fill(native.model);
          await page.locator('#aiModelDigest').fill(native.model_digest);await page.locator('#aiClearKey').check();await saved(page);
          assert.equal((await observe()).native_calls,0);
          await openDelivery(page);const nativeJob=await run(page);await completed(page);assert.equal(nativeJob.result.model.model_digest,native.model_digest);
          await page.locator('#settingsTabAI').click();await page.locator('#aiProvider').selectOption('openai_compatible');
          await page.locator('#aiEndpointPolicy').selectOption('loopback');await page.locator('#aiBaseURL').fill(endpoint);
          await page.locator('#aiModel').fill('requested/anonymous');await saved(page);
          await expect(page.locator('#aiKeyConfigured')).toContainText('Key not configured');
          assert.equal((await observe()).compatible_calls,1);
          await openDelivery(page);const anonymous=await run(page);await completed(page);assert.equal(anonymous.result.model.requested_model,'requested/anonymous');
        }
      }
    }
    await Promise.all(pendingBodies);assert.deepEqual(pageErrors,[]);
    const exposed=await page.evaluate(()=>JSON.stringify({text:document.body.innerText,local:Object.entries(localStorage),session:Object.entries(sessionStorage),url:location.href,
      attrs:[...document.querySelectorAll('*')].flatMap(n=>[...n.attributes].map(a=>a.value))}));
    assert(!exposed.includes(KEY));assert(messages.every(m=>!m.includes(KEY)));assert(requests.every(r=>!r.url.includes(KEY)));
    assert(!requests.some(r=>r.url.startsWith(endpoint)),'browser must not call the provider');
    if(scenario==='delivery-ko'){
      await page.setViewportSize({width:390,height:844});
      const bounds=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,
        panel:document.querySelectorAll('.local-ai *').length}));
      assert(bounds.scroll<=bounds.width,'actual compatible result and settings must fit the narrow page');
      assert(bounds.panel<500,'compatible metadata must retain the bounded component DOM');
    }
    await page.screenshot({path:path.join(output,'result.png'),fullPage:true});
    fs.writeFileSync(path.join(output,'acceptance.json'),JSON.stringify({scope:'authenticated-real-api-controlled-provider',scenario,page_errors:pageErrors,
      settings_posts:requests.filter(r=>r.path==='/ai/settings'&&r.method==='POST').length,
      job_posts:requests.filter(r=>r.path==='/ai/jobs'&&r.method==='POST').length,observed:await observe()},null,2));
  }finally{
    clearTimeout(deadline);try{if(context)await context.close();}finally{await browser.close();}
  }
})().catch(e=>{console.error(e);process.exitCode=1;});
