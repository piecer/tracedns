const {test,expect}=require('@playwright/test');
const {withViewServer,loginView}=require('./view-helpers');

test('IPv4 query renders the real matches contract and independent MISP failure',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin);
    await page.route('**/misp/search?**',r=>r.fulfill({status:503,body:'PRIVATE-PROVIDER-ERROR'}));
    await page.click('#menuQuery'); await page.fill('#queryValue','11.0.0.1'); await page.click('#doQuery');
    await expect(page.locator('#queryResult')).toContainText('target-000.test');
    await expect(page.locator('#queryLocalStatus')).toContainText('Current read complete');
    await expect(page.locator('#queryMispStatus')).toContainText('MISP read failed');
    await expect(page.locator('#security-message')).toBeHidden();
    await expect(page.locator('#query')).not.toContainText('PRIVATE-PROVIDER-ERROR');
    await page.locator('#queryResult details > summary').first().click();
    await expect(page.locator('#queryResult pre')).toContainText('11.0.0.1');
  });
});

test('Query A-B-A fences abandoned results and browser cancellation retains prior results',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await page.click('#menuQuery');
    let release, reached; const pending=new Promise(r=>{release=r;}); const started=new Promise(r=>{reached=r;});
    let calls=0;
    await page.route('**/ip?**',async route=>{
      const n=++calls;
      if(n===1){reached();await pending;}
      const ip=new URL(route.request().url()).searchParams.get('ip');
      await route.fulfill({json:{ip,matches:[{domain:n===1?'OBSOLETE-A':'accepted-'+n,type:'current',rtype:'A',ts:n,values:[ip]}]}});
    });
    await page.route('**/misp/search?**',r=>r.fulfill({json:{status:'ok',attributes:[],count:0}}));
    await page.evaluate(()=>{window.firstQuery=runQuery('11.0.0.1');}); await started;
    await page.evaluate(()=>runQuery('11.0.0.2'));
    await page.evaluate(()=>runQuery('11.0.0.1'));
    release(); await page.evaluate(()=>window.firstQuery);
    await expect(page.locator('#queryResult')).toContainText('accepted-3');
    await expect(page.locator('#query')).not.toContainText('OBSOLETE-A');
    let unblock; const stall=new Promise(r=>{unblock=r;});
    await page.route('**/ip?**',async route=>{await stall;await route.fulfill({json:{ip:'11.0.0.1',matches:[]}});});
    await page.evaluate(()=>{window.cancelledQuery=runQuery('11.0.0.1');});
    await page.click('#cancelQuery');
    await expect(page.locator('#queryStatus')).toContainText('Browser read cancelled');
    await expect(page.locator('#queryResult')).toContainText('accepted-3');
    unblock(); await page.evaluate(()=>window.cancelledQuery);
    await expect(page.locator('#queryResult')).toContainText('accepted-3');
  });
});

test('fragment query keeps current and MISP success when one History read fails',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await page.click('#menuQuery');
    await page.route('**/history?**',route=>new URL(route.request().url()).searchParams.get('domain')==='target-000.test'
      ?route.fulfill({status:503,body:'PRIVATE-HISTORY'})
      :route.fulfill({json:{history:{events:[{type:'TXT',ts:1,values:['needle-history']}]}}}));
    await page.route('**/misp/search?**',r=>r.fulfill({json:{status:'ok',attributes:[{value:'needle-misp',type:'text',event_id:'fixture'}],count:1}}));
    await page.fill('#queryValue','needle'); await page.click('#doQuery');
    await expect(page.locator('#queryHistoryStatus')).toContainText('partial');
    await expect(page.locator('#queryHistoryResult')).toContainText('11 matches');
    await expect(page.locator('#queryMispResult')).toContainText('needle-misp');
    await expect(page.locator('#queryResult')).toContainText('No current matches');
    await expect(page.locator('#query')).not.toContainText('PRIVATE-HISTORY');
    await expect(page.locator('#security-message')).toBeHidden();
  });
});

test('failed local reads are not empty successes and navigation never repeats Query or MISP',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await page.click('#menuQuery');
    let localReads=0,externalReads=0;
    await page.route('**/ip?**',r=>{localReads++;return r.fulfill({status:503,body:'PRIVATE-LOCAL'});});
    await page.route('**/misp/search?**',r=>{externalReads++;return r.fulfill({json:{status:'ok',attributes:[],count:0}});});
    await page.fill('#queryValue','11.0.0.1'); await page.click('#doQuery');
    await expect(page.locator('#queryLocalStatus')).toContainText('Current read failed');
    await expect(page.locator('#queryMispStatus')).toContainText('MISP read complete');
    await expect(page.locator('#queryResult')).not.toContainText('No current matches');
    for(let i=0;i<20;i++){
      await page.click('#menuStatus'); await page.click('#menuQuery');
    }
    expect(localReads).toBe(1); expect(externalReads).toBe(1);
    await expect(page.locator('#security-message')).toBeHidden();
  });
});
