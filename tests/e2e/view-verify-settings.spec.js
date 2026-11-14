const {test, expect} = require('@playwright/test');

// Shipped browser UI + disposable authenticated HTTP server. Provider replies
// intercepted below are synthetic shape fixtures, not provider acceptance.
async function login(page) {
  await page.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.fallback() : route.abort());
  await page.goto('/login.html');
  await expect(page.locator('#login-submit')).toBeEnabled();
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.waitForLoadState('load');
  await expect.poll(() => page.evaluate(() => typeof configRevision !== 'undefined' && configRevision !== null)).toBe(true);
}
function reply(domain, extra = {}) {
  return {domain, requested_type:'AUTO', selected_type:'A', detected_types:['A'],
    domain_object:{name:domain,type:'A'}, can_add:true, resolved_ips:['192.0.2.1'], managed_ips:['192.0.2.1'],
    by_server:[], decoder_candidates:[], ip_rows:[], notes:[], ...extra};
}

for(const body of ['{}','{"error":"PRIVATE-PROVIDER-TOKEN"}','PRIVATE-PROVIDER-TOKEN']) test(`Verify refuses unusable response ${body.length} safely`,async({page})=>{
  await login(page); await page.click('#menuDomainVerify');
  await page.fill('#verifyDomainName','invalid-response.test');
  await page.route('**/domain-precheck',r=>r.fulfill({status:200,contentType:'application/json',body}));
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Validation failed');
  expect(await page.locator('body').evaluate(el=>el.textContent.includes('PRIVATE-PROVIDER-TOKEN'))).toBe(false);
  await expect(page.locator('#addVerifiedDomainBtn')).toBeDisabled();
  await expect(page.locator('#security-message')).toBeHidden();
});

test('Verify exposes required inputs and eligibility, lazily pages evidence without new requests', async ({page}) => {
  const requests = [];
  const payload = reply('bounded.test', {
    decoder_candidates:Array.from({length:50}, (_,i) => ({decoder_type:'TXT',name:'decoder-'+i,score:i,ip_count:1,sample_ips:['192.0.2.1']})),
    by_server:Array.from({length:70}, (_,i) => ({server:'server-'+i,type:'A',status:'ok',values:Array.from({length:20}, (_,n)=>`raw-${i}-${n}`),managed_ips:['192.0.2.1'],method:'plain',error:''})),
    ip_rows:Array.from({length:600}, (_,i) => ({ip:`192.0.${Math.floor(i/250)}.${i%250+1}`,role:'managed',vt:null}))
  });
  await page.route('**/domain-precheck', route => {requests.push(route.request().postDataJSON()); return route.fulfill({json:payload});});
  await login(page);
  await page.click('#menuDomainVerify');
  await expect(page.locator('#verifyAdvanced')).toHaveCount(1);
  await expect(page.locator('#verifyAdvanced')).not.toHaveAttribute('open');
  await expect(page.locator('#verifyDomainName')).toBeVisible();
  await expect(page.locator('#verifyIncludeVt')).toBeChecked();
  await expect(page.locator('#verifyAnalyzeDecoders')).toBeChecked();
  await page.selectOption('#verifyDomainType', 'DHT');
  await expect(page.locator('#verifyDhtPublicKey')).toBeVisible();
  await expect(page.locator('#verifyDhtOptions')).toBeHidden();
  await page.selectOption('#verifyDomainType', 'RPC');
  await expect(page.locator('#verifyRpcProfile')).toBeVisible();
  await page.selectOption('#verifyDomainType', 'AUTO');
  await page.fill('#verifyDomainName', 'bounded.test');
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifySummary')).toContainText('Registration: eligible');
  await expect(page.locator('#domainVerifyDecoderTable tbody tr')).toHaveCount(0);
  await expect(page.locator('#domainVerifyServerTable tbody tr')).toHaveCount(0);
  await expect(page.locator('#domainVerifyIpTable tbody tr')).toHaveCount(0);
  const bounded = async () => expect(await page.locator('#domainverify *').count()).toBeLessThanOrEqual(500);
  await bounded();
  for(const [id,count] of [['verifyCandidates',50],['verifyServers',70],['verifyIps',600]]) {
    await page.locator(`#${id} > summary`).click();
    const panel = page.locator('#'+id);
    await expect(panel.locator('tbody tr').first()).toBeVisible();
    let seen = 0;
    while(true) {
      seen += await panel.locator('tbody tr').count();
      await bounded();
      const next = panel.getByRole('button',{name:'Next',exact:true});
      if(await next.isDisabled()) break;
      await next.click();
    }
    expect(seen).toBe(count);
  }
  await page.locator('#verifyRaw > summary').click();
  await expect(page.locator('#verifyRaw pre')).toContainText('bounded.test');
  expect(JSON.parse(await page.locator('#verifyRaw pre').textContent())).toEqual(payload);
  await bounded();
  expect(requests).toHaveLength(1);
  expect(requests[0]).toMatchObject({include_vt:true,analyze_decoders:true,vt_lookup_budget:200,vt_workers:8,decoder_top_n:8});
  await page.locator('#verifyCandidates > summary').click();
  await page.locator('#verifyCandidates').getByRole('button',{name:'Apply decoder and validate',exact:true}).first().click();
  await expect.poll(()=>requests.length).toBe(2);
  expect(requests[1].type).toBe('TXT');
  expect(requests[1].txt_decode).toMatch(/^decoder-/);
});

test('Verify fences edits, A/B completion, Clear and role loss including abort-ignoring replies', async ({page}) => {
  await login(page);
  await page.evaluate(() => {
    const original = window.fetch;
    window.verifyPending = [];
    window.fetch = (url, options) => {
      if(url !== '/domain-precheck') return original(url, options);
      return new Promise(resolve => window.verifyPending.push({options, resolve}));
    };
  });
  const complete = async (index, domain) => page.evaluate(({index, data}) => {
    window.verifyPending[index].resolve(new Response(JSON.stringify(data), {status:200,headers:{'Content-Type':'application/json'}}));
  }, {index, data:reply(domain)});
  await page.click('#menuDomainVerify');
  await page.fill('#verifyDomainName','a.test');
  await page.click('#runDomainVerifyBtn');
  await expect.poll(()=>page.evaluate(()=>window.verifyPending.length)).toBe(1);
  await page.fill('#verifyDomainName','b.test');
  expect(await page.evaluate(()=>window.verifyPending[0].options.signal?.aborted)).toBe(true);
  await expect(page.locator('#addVerifiedDomainBtn')).toBeDisabled();
  await page.click('#runDomainVerifyBtn');
  await complete(1,'b.test');
  await expect(page.locator('#domainVerifySummary')).toContainText('b.test');
  await complete(0,'a.test');
  await expect(page.locator('#domainVerifySummary')).toContainText('b.test');
  await page.click('#runDomainVerifyBtn');
  await page.click('#clearDomainVerifyBtn');
  await complete(2,'b.test');
  await expect(page.locator('#domainVerifySummary')).toHaveText('No validation result.');
  await expect(page.locator('#addVerifiedDomainBtn')).toBeDisabled();
  await page.fill('#verifyDomainName','private.test');
  await page.click('#runDomainVerifyBtn');
  await page.route('**/config', route=>route.fulfill({status:403,json:{error:'forbidden'}}));
  await page.evaluate(()=>fetch('/config').catch(error=>error.status));
  await complete(3,'private.test');
  await expect(page.locator('#domainVerifySummary')).not.toContainText('private.test');
  expect(await page.evaluate(()=>window.verifyPending[3].options.signal?.aborted)).toBe(true);
  expect(await page.evaluate(()=>window.DOMAIN_VERIFY_LAST)).toBeNull();
});

async function seedTarget(page) {
  await page.evaluate(async () => {
    const current = await (await fetch('/config')).json();
    const response = await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:current.revision,domains:[{name:'saved.test',type:'A'}]})});
    if(!response.ok) throw new Error('seed failed');
    await loadCfg();
  });
}

for(const exit of ['navigation','pagehide']) test(`Verify ${exit} fences an abort-ignoring completion`,async({page})=>{
  await login(page);
  await page.evaluate(()=>{
    const original=window.fetch;
    window.fetch=(url,options)=>url==='/domain-precheck'
      ? new Promise(resolve=>{window.pendingVerify={resolve,options};}) : original(url,options);
  });
  await page.click('#menuDomainVerify');
  await page.fill('#verifyDomainName','abandoned.test'); await page.click('#runDomainVerifyBtn');
  await expect.poll(()=>page.evaluate(()=>!!window.pendingVerify)).toBe(true);
  if(exit==='navigation') await page.click('#menuStatus');
  else await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
  expect(await page.evaluate(()=>window.pendingVerify.options.signal.aborted)).toBe(true);
  await page.evaluate(data=>window.pendingVerify.resolve(new Response(JSON.stringify(data),{status:200})),reply('abandoned.test'));
  await page.click('#menuDomainVerify');
  await expect(page.locator('#domainVerifySummary')).not.toContainText('abandoned.test');
  await expect(page.locator('#addVerifiedDomainBtn')).toBeDisabled();
});

test('Verify Add never rebases or replaces an unsaved target draft', async ({page}) => {
  await login(page); await seedTarget(page);
  await page.click('#menuSettings');
  const row = page.locator('#domainTable tbody tr').first();
  await row.locator('summary').click();
  await row.locator('.domain-name').fill('unsaved.test');
  const revision = await page.evaluate(()=>configRevision);
  await page.route('**/domain-precheck', route=>route.fulfill({json:reply('added.test')}));
  await page.click('#menuDomainVerify');
  await page.fill('#verifyDomainName','added.test');
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Validation complete');
  await page.click('#addVerifiedDomainBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Added domain');
  await page.click('#menuSettings');
  await expect(row.locator('.domain-name')).toHaveValue('unsaved.test');
  expect(await page.evaluate(()=>configRevision)).toBe(revision);
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Conflict');
  await expect(row.locator('.domain-name')).toHaveValue('unsaved.test');
  const saved = await page.evaluate(async()=> (await (await fetch('/config')).json()).domains);
  expect(saved.map(d=>d.name)).toEqual(['saved.test','added.test']);
});

test('Alert save uses the committed redacted response and keeps revision and apply warnings truthful', async ({page}) => {
  await login(page);
  await page.click('#menuSettings'); await page.click('#settingsTabAlerts');
  await expect.poll(()=>page.evaluate(()=>alertRevision)).not.toBeNull();
  let committed, reads = 0;
  await page.route('**/settings', async route => {
    if(route.request().method() === 'GET') { reads++; return route.fulfill({status:503,json:{error:'read unavailable'}}); }
    const response = await route.fetch();
    committed = {...await response.json(),warnings:['alerts_runtime_apply_failed']};
    await route.fulfill({response,json:committed});
  });
  await page.locator('#alertIntegrationAdvanced > summary').click();
  await page.fill('#vt_cache_ttl_days_front','19');
  await page.click('#saveAlertSettingsBtn');
  await expect(page.locator('#alertSettingsStatus')).toContainText('Saved with warnings');
  expect(await page.evaluate(()=>alertRevision)).toBe(committed.revision);
  expect(reads).toBe(0);
  await expect(page.locator('#alertSettingsStatus')).toContainText('alerts_runtime_apply_failed');
  await expect(page.locator('#alertSettingsStatus')).toContainText('revision '+committed.revision);
  await expect(page.locator('#vt_cache_ttl_days_front')).toHaveValue('19');
});

for(const scope of ['targets','alerts']) for(const action of ['load','save']) {
  test(`${scope} pending ${action} cannot overwrite later edits or rebase their revision`, async ({page}) => {
    await login(page); await seedTarget(page);
    await page.click('#menuSettings');
    let input, button, endpoint, readRevision, status;
    if(scope === 'targets') {
      await page.locator('#domainTable summary').first().click();
      input = page.locator('.domain-name').first(); button = '#'+(action === 'load' ? 'load' : 'save');
      endpoint = '/config'; readRevision = ()=>page.evaluate(()=>configRevision); status = '#domainSettingsStatus';
    } else {
      await page.click('#settingsTabAlerts');
      await page.evaluate(()=>loadAlertSettings());
      await page.locator('#alertIntegrationAdvanced > summary').click();
      input = page.locator('#push_event_id_front'); button = action === 'load' ? '#loadAlertSettingsBtn' : '#saveAlertSettingsBtn';
      endpoint = '/settings'; readRevision = ()=>page.evaluate(()=>alertRevision); status = '#alertSettingsStatus';
    }
    const revision = await readRevision();
    let release, received = false;
    const gate = new Promise(resolve=>{release=resolve;});
    await page.route('**'+endpoint, async route=>{
      const response = await route.fetch(); received = true;
      await gate; await route.fulfill({response});
    });
    await page.click(button);
    await expect.poll(()=>received).toBe(true);
    await input.fill(scope === 'targets' ? 'later-draft.test' : '4242');
    release();
    await expect(page.locator(status)).toContainText('draft retained');
    await expect(input).toHaveValue(scope === 'targets' ? 'later-draft.test' : '4242');
    expect(await readRevision()).toBe(revision);
    if(action === 'save') await expect(page.locator(status)).toContainText('revision');
  });
}

test('Settings separates advanced server and secret fields and describes Force Resolve admission exactly', async ({page}, testInfo) => {
  await login(page); await seedTarget(page);
  await page.click('#menuSettings');
  await expect(page.locator('#serverSettingsAdvanced')).toHaveCount(1);
  await expect(page.locator('#serverSettingsAdvanced')).not.toHaveAttribute('open');
  await expect(page.locator('#servers')).toBeHidden();
  await expect(page.locator('#forceResolveHelp')).toContainText('current form');
  await expect(page.locator('#forceResolveHelp')).toContainText('saved definitions');
  await page.locator('#domainTable summary').first().click();
  await page.locator('.domain-type').first().selectOption('AAAA');
  let request;
  await page.route('**/resolve', route=>{
    request = route.request().postDataJSON();
    return route.fulfill({json:{status:'ok',requested:true,job_id:'fixture-admission'}});
  });
  await page.click('#force');
  await expect(page.locator('#forceResolveStatus')).toContainText('admitted');
  await expect(page.locator('#forceResolveStatus')).toContainText('Completion not confirmed');
  expect(request).toEqual({domains:[{name:'saved.test',type:'AAAA'}]});
  await page.click('#settingsTabAlerts');
  await expect(page.locator('#alertIntegrationAdvanced')).not.toHaveAttribute('open');
  await expect(page.locator('#misp_key_front')).toBeHidden();
  await expect(page.locator('#alertConfigurationSummary')).toContainText('configuration');
  await expect(page.locator('#teamsTestHelp')).toBeVisible();
  for(const width of [1280,390]) {
    await page.setViewportSize({width,height:900});
    await page.screenshot({path:testInfo.outputPath(`settings-${width}.png`),fullPage:true,animations:'disabled'});
    await page.click('#menuDomainVerify');
    await page.selectOption('#verifyDomainType','DHT');
    await page.fill('#verifyDhtPublicKey','AB'.repeat(32));
    const geometry = await page.locator('#verifyDhtPublicKey').evaluate(el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,viewport:innerWidth,scroll:el.scrollWidth,client:el.clientWidth,containerScroll:document.querySelector('.container').scrollLeft};});
    expect(geometry.left>=0 && geometry.right<=geometry.viewport && geometry.scroll<=geometry.client+1, JSON.stringify(geometry)).toBe(true);
    await page.screenshot({path:testInfo.outputPath(`verify-${width}.png`),fullPage:true,animations:'disabled'});
    await page.click('#menuSettings');
  }
});

test('Verify Add cancels before mutation when inputs change during config read and owns unknown outcomes', async ({page}) => {
  await login(page); await seedTarget(page);
  await page.route('**/domain-precheck', route=>route.fulfill({json:reply('add-fence.test')}));
  await page.click('#menuDomainVerify');
  await page.fill('#verifyDomainName','add-fence.test');
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#addVerifiedDomainBtn')).toBeEnabled();
  let release, readStarted = false, writes = 0;
  const gate = new Promise(resolve=>{release=resolve;});
  await page.route('**/config', async route=>{
    if(route.request().method() === 'POST') {writes++; return route.fulfill({status:503,json:{error:'unavailable'}});}
    const response = await route.fetch(); readStarted = true; await gate; await route.fulfill({response});
  });
  await page.click('#addVerifiedDomainBtn');
  await expect.poll(()=>readStarted).toBe(true);
  await page.click('#clearDomainVerifyBtn');
  release();
  await page.waitForTimeout(100);
  expect(writes).toBe(0);
  await page.fill('#verifyDomainName','add-fence.test');
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#addVerifiedDomainBtn')).toBeEnabled();
  await page.click('#addVerifiedDomainBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('outcome is unknown');
  await expect(page.locator('#security-message')).toBeHidden();
  await page.waitForTimeout(3100);
  expect(writes).toBe(1);
  await expect(page.locator('#domainVerifyStatus')).toContainText('outcome is unknown');
});

for(const scope of ['targets','alerts']) for(const failure of ['conflict','transport','malformed']) {
  test(`${scope} ${failure} save retains draft and revision, stays local and never retries`, async ({page}) => {
    await login(page); await seedTarget(page);
    await page.click('#menuSettings');
    let input, button, endpoint, revision, currentRevision, status;
    if(scope === 'targets') {
      await page.locator('#domainTable summary').first().click();
      input = page.locator('.domain-name').first(); button = '#save'; endpoint = '/config';
      currentRevision = ()=>page.evaluate(()=>configRevision); status = '#domainSettingsStatus';
    } else {
      await page.click('#settingsTabAlerts'); await page.evaluate(()=>loadAlertSettings());
      await page.locator('#alertIntegrationAdvanced > summary').click();
      input = page.locator('#push_event_id_front'); button = '#saveAlertSettingsBtn'; endpoint = '/settings';
      currentRevision = ()=>page.evaluate(()=>alertRevision); status = '#alertSettingsStatus';
    }
    revision = await currentRevision();
    const draft = scope === 'targets' ? 'retained.test' : '5252';
    await input.fill(draft);
    let writes = 0;
    await page.route('**'+endpoint, route=>{
      if(route.request().method() !== 'POST') return route.continue();
      writes++;
      if(failure === 'transport') return route.abort('failed');
      if(failure === 'malformed') return route.fulfill({json:{status:'ok'}});
      return route.fulfill({status:409,json:{error:'configuration changed'}});
    });
    await page.click(button);
    await expect(page.locator(status)).toContainText(failure === 'conflict' ? 'Conflict' : 'outcome is unknown');
    await expect(input).toHaveValue(draft);
    expect(await currentRevision()).toBe(revision);
    await expect(page.locator('#security-message')).toBeHidden();
    await page.waitForTimeout(3100);
    expect(writes).toBe(1);
    await expect(page.locator(status)).toContainText(failure === 'conflict' ? 'Conflict' : 'outcome is unknown');
  });
}

for(const finish of ['edit','role-loss']) test(`Target removal receipt preserves later ${finish} state`, async ({page}) => {
  await login(page); await seedTarget(page);
  await page.click('#menuSettings');
  const row = page.locator('#domainTable tbody tr').first();
  await row.locator('summary').click();
  const revision = await page.evaluate(()=>configRevision);
  let release, received = false;
  const gate = new Promise(resolve=>{release=resolve;});
  await page.route('**/config', async route=>{
    if(route.request().method() !== 'POST') return route.continue();
    const response = await route.fetch(); received = true; await gate; await route.fulfill({response});
  });
  page.on('dialog', dialog=>dialog.accept());
  await row.getByRole('button',{name:'Remove'}).click();
  await expect.poll(()=>received).toBe(true);
  if(finish === 'edit') await row.locator('.domain-name').fill('newer-draft.test');
  else {
    await page.route('**/settings',route=>route.fulfill({status:403,json:{error:'forbidden'}}));
    await page.evaluate(()=>fetch('/settings').catch(()=>{}));
  }
  release();
  if(finish === 'edit') {
    await expect(page.locator('#domainSettingsStatus')).toContainText('draft retained');
    await expect(row.locator('.domain-name')).toHaveValue('newer-draft.test');
    expect(await page.evaluate(()=>configRevision)).toBe(revision);
  } else {
    await page.waitForTimeout(100);
    expect(await page.evaluate(()=>configRevision)).toBeNull();
    await expect(page.locator('#domainTable tbody tr')).toHaveCount(0);
    await expect(page.locator('#domainSettingsStatus')).not.toContainText('Removed domain and saved');
  }
});
