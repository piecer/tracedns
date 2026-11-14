const {test, expect} = require('@playwright/test');
const {withViewServer, loginView} = require('./view-helpers');

test('ordinary polling errors have one local owner and recover without erasing loss', async ({page}) => {
  await withViewServer({delivery:'overflow'}, async origin => {
    await page.clock.install();
    await loginView(page, origin);
    await expect(page.locator('#deliveryWarnings')).toContainText('4 not admitted');
    let fail = true;
    await page.route('**/delivery-health*', route => fail ? route.fulfill({status:503,body:'PRIVATE-ERROR'}) : route.continue());
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryStatus')).toContainText('stale');
    await expect(page.locator('#security-message')).toBeHidden();
    const identity = await page.locator('#deliveryStatus').getAttribute('data-feedback-id');
    expect(identity).toBeTruthy();
    await page.clock.runFor(15001);
    expect(await page.locator('#deliveryStatus').getAttribute('data-feedback-id')).toBe(identity);
    await expect(page.locator('#deliveryWarnings')).toContainText('4 not admitted');
    fail = false;
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryStatus')).not.toContainText('unavailable — stale');
    await expect(page.locator('#deliveryStatus')).not.toHaveAttribute('data-feedback-id');
    await expect(page.locator('#deliveryWarnings')).toContainText('4 not admitted');
    await expect(page.locator('#security-message')).toBeHidden();
  });
});

test('prepared read failure is local and a valid same-query read recovers', async ({page}) => {
  await withViewServer({}, async origin => {
    await loginView(page, origin);
    await page.route('**/results?**', route => route.fulfill({status:503,body:'PRIVATE-ERROR'}));
    await page.evaluate(() => refreshResults());
    await expect(page.locator('#status-refresh-status')).toContainText('stale');
    await expect(page.locator('#security-message')).toBeHidden();
    await expect(page.locator('#resultsTable tbody tr').first()).toContainText('target-000.test');
    await page.unroute('**/results?**');
    await page.evaluate(() => refreshResults());
    await expect(page.locator('#status-refresh-status')).toContainText('Snapshot from');
    await expect(page.locator('#status-refresh-status')).not.toContainText('failed');
  });
});

test('settings conflict remains visible with its draft and no duplicate global error', async ({page}) => {
  await withViewServer({}, async origin => {
    await page.clock.install();
    await loginView(page, origin);
    await page.click('#menuSettings');
    await page.click('#settingsTabAlerts');
    await expect(page.locator('#alertSettingsStatus')).toHaveText('Loaded');
    await page.locator('#alertIntegrationAdvanced > summary').click();
    await page.fill('#push_event_id_front', '1234');
    await page.route('**/settings', route => route.request().method()==='POST'
      ? route.fulfill({status:409,body:'{}'}) : route.continue());
    await page.click('#saveAlertSettingsBtn');
    await expect(page.locator('#alertSettingsStatus')).toContainText('Save failed');
    await page.clock.runFor(10000);
    await expect(page.locator('#alertSettingsStatus')).toContainText('Save failed');
    await expect(page.locator('#push_event_id_front')).toHaveValue('1234');
    await expect(page.locator('#security-message')).toBeHidden();
  });
});

test('History owns failure and late target A cannot overwrite B', async ({page}) => {
  await withViewServer({}, async origin => {
    await loginView(page, origin);
    let releaseA;
    const blocked = new Promise(resolve => { releaseA = resolve; });
    await page.route('**/history?**', async route => {
      const target = new URL(route.request().url()).searchParams.get('domain');
      if(target === 'target-000.test') await blocked;
      if(target === 'target-002.test') return route.fulfill({status:503, body:'PRIVATE-ERROR'});
      await route.fulfill({json:{history:{meta:{},events:[{ts:1,server:'fixture',type:'A',values:[target]}]}}});
    });
    await page.evaluate(() => { window.pendingHistory = loadHistory('target-000.test'); });
    await page.evaluate(() => loadHistory('target-001.test'));
    await expect(page.locator('#historyBox')).toContainText('target-001.test');
    releaseA();
    await page.evaluate(() => window.pendingHistory);
    await expect(page.locator('#historyBox')).not.toContainText('target-000.test');
    await page.evaluate(() => loadHistory('target-002.test'));
    await expect(page.locator('#historyBox')).toContainText('History read failed');
    await expect(page.locator('#historyBox')).toContainText('target-002.test');
    await expect(page.locator('#security-message')).toBeHidden();
    await expect(page.locator('#log')).not.toContainText('history load failed');
  });
});

test('access revocation discards protected snapshots and sensitive form drafts', async ({page}) => {
  await withViewServer({delivery:'overflow'}, async origin => {
    await loginView(page, origin);
    await expect(page.locator('#deliveryWarnings')).toContainText('4 not admitted');
    await page.click('#menuSettings');
    await page.click('#settingsTabAlerts');
    await page.locator('#alertIntegrationAdvanced > summary').click();
    await page.fill('#misp_key_front', 'fixture-private-draft');
    await page.route('**/settings', route => route.fulfill({status:403,body:'PRIVATE-DENIAL'}));
    await page.evaluate(() => fetch('/settings').catch(() => {}));
    await expect(page.locator('#security-message')).toContainText('Permission denied');
    await expect(page.locator('#deliveryHealth')).toBeHidden();
    await expect(page.locator('#deliveryWarnings')).toHaveText('');
    await expect(page.locator('#deliveryDetails')).toHaveText('');
    await expect(page.locator('#misp_key_front')).toHaveValue('');
    await expect(page.locator('#settings')).toBeHidden();
  });
});

test('unread metrics are unknown, then scoped to the accepted Status page', async ({page}) => {
  await withViewServer({}, async origin => {
    await page.route('**/results?**', route => route.fulfill({status:202,json:{snapshot:{ready:false}}}));
    await loginView(page, origin, 'admin', 'test-admin-password', false);
    await expect(page.locator('#metricStatusRows')).toHaveText('—');
    await expect(page.locator('#metricDecoded')).toHaveText('—');
    await expect(page.locator('#metricUpdated')).toHaveText('—');
    await page.unroute('**/results?**');
    await expect.poll(async () => { await page.evaluate(()=>refreshResults()); return page.locator('#metricStatusRows').textContent(); }).toBe('12');
    await expect(page.locator('#overviewGrid')).toContainText('current Status page');
    await expect(page.locator('#overviewGrid')).toContainText('Status read (browser)');
    const accepted = await page.locator('#metricUpdated').textContent();
    await page.click('#menuSettings');
    await page.click('#load');
    await expect(page.locator('#metricUpdated')).toHaveText(accepted);
  });
});

test('Status mounts one selected detail lazily and keeps it across unchanged refresh', async ({page}) => {
  await withViewServer({}, async origin => {
    await loginView(page, origin);
    expect(await page.locator('#resultsTable thead th').allTextContents()).toEqual(['Target','Type','Observation','Managed IPs','Last observed','Details']);
    await expect(page.locator('#targetDetail')).toBeHidden();
    await expect(page.locator('#targetDetail *')).toHaveCount(0);
    await expect(page.locator('#historyBox')).toHaveCount(0);
    const requests = [];
    page.on('request', r=>requests.push({path:new URL(r.url()).pathname,method:r.method()}));
    const first = page.locator('#resultsTable tbody tr').first().getByRole('button', {name:'Details',exact:true});
    await first.click();
    await expect(page.locator('#targetDetailHeading')).toHaveText('target-000.test');
    await page.locator('#targetEvidence > summary').click();
    await expect(page.locator('#targetEvidence')).toContainText('11.0.0.1');
    await page.evaluate(()=>{window.keptDetail=document.querySelector('#targetEvidence');});
    await page.evaluate(()=>refreshResults());
    expect(await page.evaluate(()=>window.keptDetail===document.querySelector('#targetEvidence'))).toBe(true);
    await expect(page.locator('#targetEvidence')).toHaveAttribute('open','');
    expect(requests.filter(r=>r.method==='POST'||r.path==='/misp/search'||r.path==='/history')).toHaveLength(0);
    await page.locator('#resultsTable tbody tr').nth(1).getByRole('button',{name:'Details',exact:true}).click();
    await expect(page.locator('#targetDetailHeading')).toHaveText('target-001.test');
    await expect(page.locator('#targetDetail')).not.toContainText('11.0.0.1');
    expect(await page.locator('#targetDetail *').count()).toBeLessThanOrEqual(500);
    await page.locator('#closeTargetDetail').click();
    await expect(page.locator('#targetDetail *')).toHaveCount(0);
    await expect(page.locator('#resultsTable tbody tr').nth(1).getByRole('button',{name:'Details',exact:true})).toBeFocused();
  });
});

test('History pages at most 50 events, lazily exposes raw evidence and reaches every event', async ({page}) => {
  await withViewServer({}, async origin => {
    await loginView(page, origin);
    let reads = 0;
    await page.route('**/history?**', route => {
      reads++;
      return route.fulfill({json:{history:{meta:{},events:Array.from({length:123},(_,i)=>({
        ts:i+1,server:'fixture',type:'TXT',old:{values:['old-'+i]},new:{values:['event-'+i]}
      }))}}});
    });
    await page.locator('#resultsTable tbody tr').first().getByRole('button',{name:'Details',exact:true}).click();
    expect(reads).toBe(0);
    await page.click('#targetHistory');
    await expect(page.locator('.history-event')).toHaveCount(50);
    await expect(page.locator('.history-event pre')).toHaveCount(0);
    await expect(page.locator('#historyBox')).toContainText('Entire history response');
    const seen = [];
    while(true){
      seen.push(...await page.locator('.history-event').evaluateAll(nodes=>nodes.map(n=>Number(n.dataset.index))));
      for(const summary of await page.locator('.history-event > summary').all()) await summary.click();
      expect(await page.locator('#targetDetail *').count()).toBeLessThanOrEqual(500);
      if(await page.locator('#historyNext').isDisabled()) break;
      await page.click('#historyNext');
    }
    expect(seen).toEqual(Array.from({length:123},(_,i)=>i));
    await expect(page.locator('.history-event').last()).toContainText('event-122');
    expect(reads).toBe(1);
  });
});

test('IP views separate retained-count provenance from the basic list without extra lookup', async ({page}) => {
  await withViewServer({}, async origin => {
    await loginView(page, origin);
    await page.click('#menuIPs');
    await expect(page.locator('#ipsTable tbody tr').first()).toContainText('11.0.');
    expect(await page.locator('#ipsTable thead th').allTextContents()).toEqual(['IP','Related targets','Last observed','Enrichment','Details']);
    const requests=[];
    page.on('request',r=>requests.push({path:new URL(r.url()).pathname,method:r.method()}));
    await page.locator('#ipsTable tbody tr').first().getByRole('button',{name:'Details',exact:true}).click();
    await expect(page.locator('#ipDetail')).toContainText('Retained occurrences');
    await expect(page.locator('#ipDetail')).toContainText('not independent queries');
    expect(requests.filter(r=>r.method==='POST'||r.path==='/misp/search'||r.path==='/ip')).toHaveLength(0);
    await page.click('#menuValidIPs');
    await expect(page.locator('#ipDetail')).toHaveCount(0);
    await expect(page.locator('#validips')).toContainText('does not apply');
    await expect(page.locator('#metricValidIps')).not.toHaveText('—');
  });
});
