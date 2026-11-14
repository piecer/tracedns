const {test, expect} = require('@playwright/test');
const {withViewServer, loginView} = require('./view-helpers');

for(const exit of ['navigation','pagehide']) test(`Domain Analysis ${exit} retires selected evidence and management`,async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin);await page.click('#menuDomainAnalysis');
    await page.locator('#domainDomainStatsTable').getByRole('button',{name:'View',exact:true}).first().click();
    await page.locator('#domainAnalysisRaw > summary').click();
    await expect(page.locator('#domainAnalysisRaw pre')).toContainText('target-000.test');
    await page.click('#domainAnalysisManageBtn');
    if(exit==='navigation') await page.click('#menuStatus');
    else await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
    await expect(page.locator('#domainAnalysisDetail *')).toHaveCount(0);
    expect(await page.evaluate(()=>domainAnalysisManageMode)).toBe(false);
    await expect(page.locator('#domainDomainStatsTable input[type=checkbox]')).toHaveCount(0);
  });
});

async function removable(page){
  await page.evaluate(async()=>{
    const config=await TraceAuth.json('/config');
    await TraceAuth.json('/config',{revision:config.revision,domains:[...config.domains,{name:'removable.test',type:'A'}]});
  });
  await page.click('#menuDomainAnalysis');
  const row=page.locator('#domainDomainStatsTable tbody tr').filter({hasText:'removable.test'});
  await expect(row).toContainText('No-data');
  await page.click('#domainAnalysisManageBtn');
  await row.getByRole('checkbox').check();
}

for(const status of [409,503,200]) test(`Domain removal refusal ${status} is local, persistent and not a false success`,async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin);await removable(page);
    let writes=0;
    await page.route('**/config',route=>{
      if(route.request().method()!=='POST') return route.continue();
      writes++;return route.fulfill({status,json:status===200?{status:'ok'}:{error:'PRIVATE-PROVIDER-TOKEN'}});
    });
    page.once('dialog',d=>d.accept());await page.click('#removeSelectedDomainsBtn');
    await expect(page.locator('#domainRemoveStatus')).toContainText('Remove failed');
    await page.waitForTimeout(3300);
    await expect(page.locator('#domainRemoveStatus')).toContainText('Remove failed');
    await expect(page.locator('#security-message')).toBeHidden();
    expect(await page.locator('body').evaluate(el=>el.textContent.includes('PRIVATE-PROVIDER-TOKEN'))).toBe(false);
    expect(writes).toBe(1);
  });
});

test('late removal receipt cannot reopen access or publish into a retired view',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin);await removable(page);
    let release,received=false;const gate=new Promise(resolve=>{release=resolve;});
    await page.route('**/config',async route=>{
      if(route.request().method()!=='POST') return route.continue();
      const response=await route.fetch();received=true;await gate;await route.fulfill({response});
    });
    await page.evaluate(()=>{const remove=removeDomainsFromConfig;removeDomainsFromConfig=(...args)=>window.removalFinished=remove(...args);});
    page.once('dialog',d=>d.accept());await page.click('#removeSelectedDomainsBtn');
    await expect.poll(()=>received).toBe(true);
    await page.route('**/settings',r=>r.fulfill({status:403,body:'Forbidden'}));
    await page.evaluate(()=>fetch('/settings').catch(()=>{}));
    await page.click('#menuStatus'); release();await page.evaluate(()=>window.removalFinished);
    await page.click('#menuDomainAnalysis');
    await expect(page.locator('#domainAnalysisManageBtn')).toBeHidden();
    await expect(page.locator('#domainRemoveStatus')).not.toContainText('Removed');
    expect(await page.evaluate(()=>canManageDomainAnalysis())).toBe(false);
  });
});

// Real prepared HTTP producer, disposable auth, synthetic local targets; no providers.
test('Manage mode is explicit, clears removal selection and never rebases settings drafts', async ({page}) => {
  await withViewServer({rows:12}, async origin => {
    await loginView(page, origin);
    await page.click('#pauseRefreshBtn');
    await page.evaluate(async () => {
      const config = await (await fetch('/config')).json();
      const response = await fetch('/config', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({revision:config.revision,domains:[...config.domains,{name:'no-data.test',type:'A'}]})});
      if(!response.ok) throw new Error('fixture target seed failed');
      await loadCfg();
    });
    await page.click('#menuSettings');
    const draft = page.locator('#domainTable tbody tr').first();
    await draft.locator('summary').click();
    await draft.locator('.domain-name').fill('unsaved.test');
    const revision = await page.evaluate(()=>configRevision);
    await page.click('#menuDomainAnalysis');
    const noData = page.locator('#domainDomainStatsTable tbody tr').filter({hasText:'no-data.test'});
    await expect(noData).toContainText('No-data');
    await expect(page.locator('#domainDomainStatsTable input[type=checkbox]')).toHaveCount(0);
    await expect(page.locator('#removeSelectedDomainsBtn')).toBeHidden();
    await page.getByRole('button', {name:'Manage domains',exact:true}).click();
    await expect(noData.getByRole('checkbox')).toBeEnabled();
    await expect(page.locator('#domainDomainStatsTable tbody tr').filter({hasText:'target-000.test'}).getByRole('checkbox')).toBeDisabled();
    await page.click('#selectNonResolvingDomainsBtn');
    await expect(noData.getByRole('checkbox')).toBeChecked();
    await page.getByRole('button', {name:'Close management',exact:true}).click();
    expect(await page.evaluate(()=>getDomainAnalysisSelectionSet().size)).toBe(0);
    await expect(page.locator('#domainDomainStatsTable input[type=checkbox]')).toHaveCount(0);
    await page.getByRole('button', {name:'Manage domains',exact:true}).click();
    await expect(noData.getByRole('checkbox')).not.toBeChecked();
    await noData.getByRole('checkbox').check();
    const writes = [];
    page.on('request', r=>{if(r.method()==='POST') writes.push(new URL(r.url()).pathname);});
    page.once('dialog', dialog=>dialog.dismiss());
    await page.click('#removeSelectedDomainsBtn');
    expect(writes).toEqual([]);
    page.once('dialog', dialog=>dialog.accept());
    await page.click('#removeSelectedDomainsBtn');
    await expect(page.locator('#domainRemoveStatus')).toContainText('Removed');
    const saved = await page.evaluate(async()=> (await (await fetch('/config')).json()));
    expect(saved.domains.map(d=>typeof d==='string'?d:d.name)).not.toContain('no-data.test');
    expect(saved.domains).toHaveLength(12);
    expect(writes).toEqual(['/config']);
    await page.click('#menuSettings');
    await expect(draft.locator('.domain-name')).toHaveValue('unsaved.test');
    expect(await page.evaluate(()=>configRevision)).toBe(revision);
    await page.click('#save');
    await expect(page.locator('#domainSettingsStatus')).toContainText('Conflict');
    await expect(draft.locator('.domain-name')).toHaveValue('unsaved.test');
  });
});
test('Domain Analysis starts with compact results and one lazy selected target', async ({page}, info) => {
  await withViewServer({rows:12}, async origin => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await loginView(page, origin);
    await page.click('#pauseRefreshBtn');
    await page.click('#menuDomainAnalysis');
    await expect(page.locator('#domainDomainStatsTable tbody tr')).toHaveCount(12);
    await expect(page.locator('#domainanalysis_page_meta')).toContainText('12');
    await expect(page.getByLabel('Search all domains (substring)')).toBeVisible();
    await expect(page.locator('#domainAnalysisTable tbody tr')).toHaveCount(0);
    await expect(page.locator('#domainAsSummaryTable tbody tr')).toHaveCount(0);
    await expect(page.locator('#domainCountrySummaryTable tbody tr')).toHaveCount(0);
    await expect(page.locator('#domainAsCountrySummaryTable tbody tr')).toHaveCount(0);
    const before = await page.locator('#domainanalysis *').count();
    const requests = [];
    page.on('request', r => requests.push({path:new URL(r.url()).pathname, method:r.method()}));
    const rows = page.locator('#domainDomainStatsTable tbody tr');
    await rows.filter({hasText:'target-000.test'}).getByRole('button',{name:'View',exact:true}).click();
    await expect(page.locator('#domainAnalysisDetail')).toBeVisible();
    await expect(page.locator('#domainAnalysisDetail h4')).toHaveText('target-000.test');
    await expect(page.locator('#domainAnalysisTable tbody tr')).toHaveCount(0);
    await page.locator('#domainAnalysisEvidence > summary').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#domainAnalysisTable tbody')).toContainText('11.0.0.1');
    await page.locator('#domainAnalysisRaw > summary').click();
    await expect(page.locator('#domainAnalysisRaw pre')).toContainText('target-000.test');
    await page.locator('#domainAnalysisSummaries > summary').click();
    await expect(page.locator('#domainAsSummaryTable tbody tr').first()).toBeVisible();
    expect(await page.locator('#domainanalysis *').count() - before).toBeLessThanOrEqual(500);
    await rows.filter({hasText:'target-001.test'}).getByRole('button',{name:'View',exact:true}).click();
    await expect(page.locator('#domainAnalysisDetail h4')).toHaveText('target-001.test');
    await expect(page.locator('#domainAnalysisTable tbody tr')).toHaveCount(0);
    await expect(page.locator('#domainAnalysisRaw pre')).toHaveCount(0);
    await expect(page.locator('#domainAsSummaryTable tbody tr')).toHaveCount(0);
    await page.click('#closeDomainAnalysisDetail');
    await expect(page.locator('#domainAnalysisDetail')).toBeHidden();
    expect(requests.filter(r=>r.method==='POST' || r.path==='/domain-analysis' || /vt|query/.test(r.path))).toEqual([]);
    expect(errors).toEqual([]);
    await info.attach('requests', {body:JSON.stringify(requests), contentType:'application/json'});
  });
});

for(const width of [1366,390]) test(`Real 250-target pages, unchanged focus and query scope at ${width}`, async ({page}, info) => {
  await withViewServer({rows:250}, async origin => {
    await page.setViewportSize({width,height:844});
    await loginView(page, origin);
    await page.click('#pauseRefreshBtn');
    await page.evaluate(()=>{document.getElementById('domain_analysis_include_vt').checked=false;});
    await page.click('#menuDomainAnalysis');
    const rows = page.locator('#domainDomainStatsTable tbody tr');
    await expect(rows).toHaveCount(100);
    await expect(page.locator('#domainanalysis_page_meta')).toContainText('250');
    await page.screenshot({path:info.outputPath('domain-default.png')});
    const geometry = await page.evaluate(()=>({
      row:document.querySelector('#domainDomainStatsTable tbody tr').getBoundingClientRect().toJSON(),
      overflow:document.documentElement.scrollWidth > innerWidth,
      mounted:document.querySelectorAll('#domainanalysis *').length
    }));
    await info.attach('default-geometry',{body:JSON.stringify(geometry),contentType:'application/json'});
    expect(geometry.overflow).toBe(false);
    expect(geometry.row.bottom).toBeLessThanOrEqual(844);
    await page.selectOption('#domainAnalysisDomainSelect','target-000.test');
    await page.locator('#domainAnalysisEvidence > summary').click();
    await page.locator('#domainAnalysisRaw > summary').click();
    await expect(page.locator('#domainAnalysisTable tbody tr')).toHaveCount(1);
    await page.locator('#domainAnalysisEvidence > summary').focus();
    await page.evaluate(()=>{
      window.domainBefore={focus:document.activeElement,detail:document.getElementById('domainAnalysisDetail').firstChild,
        row:document.querySelector('#domainAnalysisTable tbody tr')};
    });
    const response = page.waitForResponse(r=>new URL(r.url()).pathname==='/domain-analysis');
    await page.evaluate(()=>refreshDomainAnalysis());
    expect((await (await response).json()).unchanged).toBe(true);
    expect(await page.evaluate(()=>({
      focus:document.activeElement===domainBefore.focus,
      detail:document.getElementById('domainAnalysisDetail').firstChild===domainBefore.detail,
      row:document.querySelector('#domainAnalysisTable tbody tr')===domainBefore.row,
      open:document.getElementById('domainAnalysisEvidence').open
    }))).toEqual({focus:true,detail:true,row:true,open:true});
    let release, arrived = false;
    const gate = new Promise(resolve=>{release=resolve;});
    await page.route('**/domain-analysis?**', async route=>{
      if(new URL(route.request().url()).searchParams.get('offset')!=='100') return route.fallback();
      const reply = await route.fetch(); arrived = true;
      await gate; await route.fulfill({response:reply});
    });
    try {
      await page.click('#domainanalysis_next_btn');
      await expect.poll(()=>arrived).toBe(true);
      await expect(page.locator('#domainAnalysisDetail')).toBeHidden();
      await expect(page.locator('#domainAnalysisDomainSelect')).toBeDisabled();
      // Retained previous-page rows are not an owner for the incoming page.
      await expect(rows.first().getByRole('button',{name:/View/})).toBeDisabled();
    } finally { release(); }
    await expect(rows.first()).toContainText('target-100.test');
    await expect(page.locator('#domainAnalysisDomainSelect')).toBeEnabled();
    await page.unroute('**/domain-analysis?**');
    await page.click('#domainanalysis_next_btn');
    await expect(rows).toHaveCount(50);
    await expect(rows.last()).toContainText('target-249.test');
    await page.selectOption('#domainAnalysisDomainSelect','target-249.test');
    await expect(page.locator('#domainAnalysisDetail h4')).toHaveText('target-249.test');
    const queryResponse = page.waitForResponse(r=>new URL(r.url()).pathname==='/domain-analysis' && new URL(r.url()).searchParams.get('q')==='target-000');
    await page.fill('#domain_analysis_query','target-000');
    await queryResponse;
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('target-000.test');
    await expect(page.locator('#domainAnalysisDetail')).toBeHidden();
    await expect(page.locator('#domainAnalysisDomainSelect')).toHaveValue('');
  });
});


for(const role of ['viewer','operator']) test(`Real ${role} session gates management and direct removal handlers`, async ({page, browser}) => {
  await withViewServer({rows:12}, async origin => {
    await loginView(page, origin);
    await page.evaluate(async role=>{
      await TraceAuth.json('/admin/users', {username:role,password:'temporary-password',role});
      const config = await TraceAuth.json('/config');
      await TraceAuth.json('/config', {revision:config.revision,domains:[...config.domains,{name:'no-data.test',type:'A'}]});
    }, role);
    const context = await browser.newContext();
    try {
      const actor = await context.newPage();
      await loginView(actor, origin, role, 'temporary-password', false);
      await expect(actor.locator('#password-submit')).toBeEnabled();
      await actor.fill('#current-password','temporary-password');
      await actor.fill('#new-password','changed-password');
      await actor.fill('#confirm-password','changed-password');
      await actor.click('#password-submit');
      await expect(actor).toHaveURL(/login\.html/);
      await loginView(actor, origin, role, 'changed-password');
      await actor.click('#pauseRefreshBtn');
      await actor.click('#menuDomainAnalysis');
      await expect(actor.locator('#domainDomainStatsTable tbody tr')).toHaveCount(13);
      await expect(actor.locator('#domainDomainStatsTable input[type=checkbox]')).toHaveCount(0);
      const writes = [];
      actor.on('request',r=>{if(r.method()==='POST') writes.push(new URL(r.url()).pathname);});
      if(role==='viewer') {
        await expect(actor.locator('#domainAnalysisManageBtn')).toBeHidden();
        expect(await actor.evaluate(async()=>{
          setDomainAnalysisManageMode(true);
          selectNonResolvingDomainsForBulk();
          return removeDomainsFromConfig(['no-data.test']);
        })).toBe(false);
        await expect(actor.locator('#domainDomainStatsTable input[type=checkbox]')).toHaveCount(0);
        expect(writes).toEqual([]);
      } else {
        await actor.click('#domainAnalysisManageBtn');
        const noData = actor.locator('#domainDomainStatsTable tbody tr').filter({hasText:'no-data.test'});
        await noData.getByRole('checkbox').check();
        actor.once('dialog',dialog=>dialog.accept());
        await actor.click('#removeSelectedDomainsBtn');
        await expect(actor.locator('#domainRemoveStatus')).toContainText('Removed');
        expect(writes).toEqual(['/config']);
        const saved = await actor.evaluate(()=>TraceAuth.json('/config'));
        expect(saved.domains).toHaveLength(12);
        expect(saved.domains.map(d=>typeof d==='string'?d:d.name)).not.toContain('no-data.test');
        await actor.click('#domainAnalysisManageBtn');
        expect(await actor.evaluate(()=>removeDomainsFromConfig(['target-000.test']))).toBe(false);
        expect(writes).toEqual(['/config']);
      }
    } finally { await context.close(); }
  });
});

test('Labeled rich-page fixture: all cached evidence is paged, text-safe and bounded without provider reads', async ({page}, info) => {
  await withViewServer({rows:12}, async origin => {
    await loginView(page, origin);
    await page.click('#pauseRefreshBtn');
    let fixture;
    // Extend an actual producer DTO only in its existing fields. This is a
    // synthetic cached-enrichment/max-page scenario, NOT a live VT result.
    await page.route('**/domain-analysis?**', async route=>{
      const response = await route.fetch(), data = await response.json();
      if(!Array.isArray(data.domains)) return route.fulfill({response});
      const domain = structuredClone(data.domains[0]);
      domain.domain = 'Research label [DHT:' + 'ab'.repeat(32) + ']';
      domain.record_types = ['DHT'];
      domain.resolved_ips = [];
      domain.ip_rows = Array.from({length:data.page.limit}, (_,i)=>({role:'decoded',ip:`11.1.0.${i+1}`,
        vt:{asn:64000+i,as_owner:`Literal <img src=x onerror=alert(1)> owner-${i}`,country:`C${i}`,malicious:0,suspicious:0}}));
      domain.decoded_ips = domain.ip_rows.map(row=>row.ip);
      domain.as_summary = domain.ip_rows.map(row=>({asn:row.vt.asn,as_owner:row.vt.as_owner,country:row.vt.country,count:1}));
      domain.ip_rows_total = domain.ip_rows.length;
      domain.ip_rows_offset = 0; domain.ip_rows_truncated = false;
      fixture = domain;
      const total = domain.ip_rows.length;
      await route.fulfill({response,json:{...data,domains:[domain],domains_total_count:1,view_version:'labeled-rich-page-fixture',
        page:{...data.page,offset:0,displayed:total,total,next_offset:null,previous_offset:null,domains_total:1}}});
    });
    await page.click('#menuDomainAnalysis');
    await expect(page.locator('#domainDomainStatsTable tbody tr')).toHaveCount(1);
    const before = await page.locator('#domainanalysis *').count();
    const requests = [];
    page.on('request',r=>requests.push({path:new URL(r.url()).pathname,method:r.method()}));
    await page.locator('#domainDomainStatsTable').getByRole('button',{name:'View',exact:true}).click();
    await expect(page.locator('#domainAnalysisDetail h4')).toHaveText(fixture.domain);
    await page.locator('#domainAnalysisEvidence > summary').click();
    await page.locator('#domainAnalysisRaw > summary').click();
    await page.locator('#domainAnalysisSummaries > summary').click();
    await expect(page.locator('#domainAsSummaryTable tbody tr')).toHaveCount(8);
    const counts = [];
    const bounded = async()=>{
      const count = await page.locator('#domainanalysis *').count() - before;
      counts.push(count); expect(count).toBeLessThanOrEqual(500);
    };
    for(const [id,column,expected] of [
      ['domainAnalysisTable',1,fixture.ip_rows.map(row=>row.ip)],
      ['domainAsSummaryTable',0,fixture.as_summary.map(row=>String(row.asn))],
      ['domainCountrySummaryTable',0,fixture.as_summary.map(row=>row.country)],
      ['domainAsCountrySummaryTable',0,fixture.as_summary.map(row=>String(row.asn))]
    ]) {
      const table = page.locator('#'+id), panel = table.locator('..');
      const seen = [];
      while(true) {
        seen.push(...await table.locator(`tbody td:nth-child(${column+1})`).allTextContents());
        await bounded();
        const next = panel.getByRole('button',{name:'Next',exact:true});
        if(await next.isDisabled()) break;
        await next.click();
      }
      expect(seen).toEqual(expected);
    }
    expect(JSON.parse(await page.locator('#domainAnalysisRaw pre').textContent())).toEqual(fixture);
    await expect(page.locator('#domainanalysis img')).toHaveCount(0);
    for(let i=0;i<20;i++) {
      await page.locator('#domainAnalysisEvidence > summary').click();
      await bounded();
    }
    await page.locator('#domainAnalysisSummaries > summary').click();
    await expect(page.locator('#domainAnalysisSummaryContent *')).toHaveCount(0);
    expect(requests).toEqual([]);
    await info.attach('bounded-census',{body:JSON.stringify({counts,requests,fixture}),contentType:'application/json'});
  });
});
