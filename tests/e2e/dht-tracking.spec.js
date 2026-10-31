const {test, expect} = require('@playwright/test');

// Real Chromium + shipped UI + disposable auth/static server. DHT/config API
// responses below are explicitly synthetic interceptions, NOT live DHT proof.
const key = 'AB'.repeat(32);
const label = 'Synthetic research label.';
const dates = {created_at:'2026-01-02T03:04:05+00:00', updated_at:'2026-01-02T03:04:05+00:00'};
const unknownTarget = {name:'future.test', type:'FUTURE', future_options:{keep:['exact', 7]}};
const options = {duration:3,max_queries:12,timeout:1,rate:4,concurrency:2,max_nodes:20};

async function syntheticConfig(page) {
  const state = {config:{revision:1, domains:[unknownTarget], domain_metadata:{}, servers:[], interval:60, configured:{}}, writes:[], errors:[], external:[]};
  page.on('pageerror', error=>state.errors.push(error.message));
  await page.route('**/*', route=>{
    if (new URL(route.request().url()).hostname !== '127.0.0.1') {
      state.external.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  await page.route('**/config', async route=>{
    if(route.request().method() === 'POST') {
      const data = route.request().postDataJSON();
      state.writes.push(data);
      if(data.revision !== state.config.revision) return route.fulfill({status:409, json:{error:'configuration conflict'}});
      const metadata = {...state.config.domain_metadata};
      for(const target of data.domains) {
        if(target.type === 'DHT') metadata[`${target.name.toLowerCase()}|DHT|${target.dht_public_key.toLowerCase()}`] = dates;
      }
      state.config = {...state.config, ...data, revision:state.config.revision+1, domain_metadata:metadata};
      return route.fulfill({json:{status:'ok', revision:state.config.revision, config:state.config}});
    }
    return route.fulfill({json:state.config});
  });
  await page.goto('/login.html');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  // Startup's load handler selects Status; don't race it with a menu click.
  await page.waitForLoadState('load');
  await expect(page.locator('#domainTable tbody tr')).toHaveCount(state.config.domains.length);
  return state;
}

test('synthetic DHT settings validate, preserve filtered targets and reload full identifiers/dates', async ({page})=>{
  const state = await syntheticConfig(page);
  await page.click('#menuSettings');
  await expect(page.locator('#domainTable tbody tr')).toHaveCount(1);
  await page.click('#addDomain');
  const draft = page.locator('#domainTable tbody tr').last();
  await draft.locator('.domain-name').fill(label);
  // Fast semantic RED, rather than waiting for a selectOption timeout.
  await expect(draft.locator('.domain-type option[value="DHT"]')).toHaveCount(1);
  await draft.locator('.domain-type').selectOption('DHT');
  await expect(draft.getByLabel('DHT public key')).toBeVisible();
  await expect(draft.getByLabel('ENS node', {exact:true})).toBeHidden();
  await draft.locator('.dht-public-key').fill('0x'+key);
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('exactly 64 hexadecimal');
  expect(state.writes).toHaveLength(0);
  await draft.locator('.dht-public-key').fill(key);
  await draft.locator('.dht-options').fill('{"not_allowed":true}');
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Unknown DHT lookup options');
  expect(state.writes).toHaveLength(0);
  await draft.locator('.dht-options').fill(JSON.stringify(options));
  // Filtering by key must not discard hidden originals or unsaved drafts.
  await page.fill('#domainSettingsSearch', key.toLowerCase());
  await expect(page.locator('#domainSettingsSummary')).toHaveText('1 of 2 targets shown');
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Settings saved');
  expect(state.config.domains).toEqual([unknownTarget, {name:label,type:'DHT',dht_public_key:key,dht_options:options}]);
  await page.reload();
  await page.click('#menuSettings');
  const restored = page.locator('#domainTable tbody tr').filter({hasText:label});
  await restored.locator('summary').click();
  await expect(restored.locator('.dht-public-key')).toHaveValue(key);
  expect(JSON.parse(await restored.locator('.dht-options').inputValue())).toEqual(options);
  await expect(restored.locator('.domain-created time')).toHaveAttribute('datetime', dates.created_at);
  await expect(restored.locator('.domain-updated time')).toHaveAttribute('datetime', dates.updated_at);
  for(const width of [1280,390]) {
    await page.setViewportSize({width,height:900});
    for(const selector of ['.dht-public-key','.dht-key-display','.dht-options']) {
      const geometry = await restored.locator(selector).evaluate(el=>{
        const r = el.getBoundingClientRect();
        return {wrap:el.scrollWidth<=el.clientWidth+1, visible:r.left>=0 && r.right<=innerWidth};
      });
      expect(geometry).toEqual({wrap:true,visible:true});
    }
  }
  // Textarea edits must participate in draft change detection.
  await restored.locator('.dht-options').fill('{"max_queries":6}');
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Settings saved');
  expect(state.config.domains[1].dht_options).toEqual({max_queries:6});
  expect(state.config.domains[0]).toEqual(unknownTarget);
  // Conflict retains the edited key and original server-owned dates.
  await restored.locator('summary').click();
  await restored.locator('.dht-public-key').fill('CD'.repeat(32));
  state.config.revision++;
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Save failed');
  await expect(restored.locator('.dht-public-key')).toHaveValue('CD'.repeat(32));
  await expect(restored.locator('.domain-created time')).toHaveAttribute('datetime', dates.created_at);
  expect(state.errors).toEqual([]);
  expect(state.external).toEqual([]);
});

test('synthetic typed DHT precheck validates before transport and adds distinct keys', async ({page})=>{
  const state = await syntheticConfig(page);
  const requests = [];
  await page.route('**/domain-precheck', async route=>{
    const data = route.request().postDataJSON();
    requests.push(data);
    return route.fulfill({json:{domain:data.domain, requested_type:'DHT', selected_type:'DHT', detected_types:['DHT'],
      domain_object:{name:data.domain,type:'DHT',dht_public_key:data.dht_public_key,dht_options:data.dht_options},
      dht_public_key:data.dht_public_key,
      dht_record:{seq:'9223372036854775807',target:'cd'.repeat(20),signature_valid:true,value_sha256:'ef'.repeat(32)},
      dht_observation:{status:'initial',observed_at:1700000000,coverage:{complete:false,queries:2}},
      can_add:true, managed_ips:['192.0.2.9'], resolved_ips:[], by_server:[], ip_rows:[], notes:[]}});
  });
  await page.click('#menuDomainVerify');
  await expect(page.locator('#verifyDomainType option[value="DHT"]')).toHaveCount(1);
  await page.selectOption('#verifyDomainType', 'DHT');
  await page.fill('#verifyDomainName', label);
  await expect(page.locator('#verifyDhtPublicKey')).toBeVisible();
  await expect(page.locator('#verifyEnsDecode')).toBeDisabled();
  await expect(page.locator('#verifySnsDecode')).toBeDisabled();
  await expect(page.locator('#verifyTxtDecode')).toBeDisabled();
  await expect(page.locator('#verifyAnalyzeDecoders')).toBeDisabled();
  await page.fill('#verifyDhtPublicKey', key+' ');
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('exactly 64 hexadecimal');
  expect(requests).toEqual([]);
  await page.fill('#verifyDhtPublicKey', key);
  await page.fill('#verifyDhtOptions', '[]');
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('must be a JSON object');
  expect(requests).toEqual([]);
  await page.fill('#verifyDhtOptions', JSON.stringify(options));
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Validation complete');
  expect(requests[0]).toMatchObject({domain:label,type:'DHT',dht_public_key:key,dht_options:options,analyze_decoders:false});
  await expect(page.locator('#domainVerifySummary')).toContainText('Last-confirmed sequence: 9223372036854775807');
  await expect(page.locator('#domainVerifySummary')).toContainText('Value SHA-256: '+'ef'.repeat(32));
  await page.click('#addVerifiedDomainBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Added domain');
  await page.fill('#verifyDhtPublicKey', 'CD'.repeat(32));
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Validation complete');
  await page.click('#addVerifiedDomainBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Added domain');
  expect(state.config.domains).toHaveLength(3);
  expect(state.config.domains[0]).toEqual(unknownTarget);
  expect(state.config.domains.slice(1).map(x=>x.dht_public_key)).toEqual([key,'CD'.repeat(32)]);
  await page.click('#clearDomainVerifyBtn');
  await expect(page.locator('#verifyDhtPublicKey')).toHaveValue('');
  await expect(page.locator('#verifyDhtOptions')).toHaveValue('');
  expect(state.errors).toEqual([]);
  expect(state.external).toEqual([]);
});

test('synthetic missed lookup remains registerable without claiming retrieval or requesting VT', async ({page})=>{
  const state = await syntheticConfig(page);
  let request;
  await page.route('**/domain-precheck', route=>{
    request = route.request().postDataJSON();
    return route.fulfill({json:{domain:label,requested_type:'DHT',selected_type:'DHT',detected_types:[],can_add:true,
      domain_obj:{name:label,type:'DHT',dht_public_key:request.dht_public_key},
      dht_observation:{status:'no_verified_record',observed_at:1700000000,coverage:{complete:false}},
      by_server:[{server:'DHT',type:'DHT',status:'error',values:[],managed_ips:[],error:'No verified record in bounded lookup'}],
      managed_ips:[],resolved_ips:[],notes:['Configuration is valid; no verified record found. VT enrichment disabled for read-only DHT precheck.']}});
  });
  await page.click('#menuDomainVerify');
  await page.selectOption('#verifyDomainType', 'DHT');
  await page.fill('#verifyDomainName', label);
  await page.fill('#verifyDhtPublicKey', key);
  await expect(page.locator('#verifyIncludeVt')).toBeDisabled();
  await page.click('#runDomainVerifyBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('DHT lookup: no_verified_record');
  await expect(page.locator('#domainVerifySummary')).toContainText('No last-confirmed record available');
  await expect(page.locator('#domainVerifySummary')).toContainText('VT enrichment disabled');
  expect(request.include_vt).toBe(false);
  await expect(page.locator('#addVerifiedDomainBtn')).toHaveText('Add DHT target');
  await page.click('#addVerifiedDomainBtn');
  await expect(page.locator('#domainVerifyStatus')).toContainText('Added domain');
  expect(state.config.domains[1]).toEqual({name:label,type:'DHT',dht_public_key:key});
  expect(state.errors).toEqual([]);
  expect(state.external).toEqual([]);
});

test('synthetic DHT status separates retained records from every latest attempt and missing evidence', async ({page})=>{
  const state = await syntheticConfig(page);
  const storage = `${label} [DHT:${key.toLowerCase()}]`;
  const seq = '9223372036854775807';
  const data = {snapshot:{ready:true,stale:false,generated_at:1700000000}, view_version:'dht-1',
    page:{offset:0,limit:100,displayed:1,total:1,unit:'targets',next_offset:null,previous_offset:null},
    results_agg:{[storage]:{type:'DHT',record_types:['DHT'],values:['signed-bytes-not-an-IP'],decoded_ips:['192.0.2.9'],
      dht_public_keys:[key.toLowerCase()],dht_targets:['cd'.repeat(20)],dht_sequences:[seq],servers:['DHT'],ts:1699999900}},
    domain_meta:{[storage]:{dht_observation:{status:'initial',observed_at:1700000000,seq,coverage:{complete:false,queries:2}}}}};
  await page.route('**/results?*', route=>route.fulfill({json:data}));
  for(const status of ['initial','updated','unchanged','no_verified_record','stale_only','same_seq_conflict','signed_dns_invalid','cancelled']) {
    data.domain_meta[storage].dht_observation.status = status;
    data.domain_meta[storage].dht_observation.seq = status === 'stale_only' ? '0' : seq;
    await page.click('#menuQuery');
    await page.click('#menuStatus');
    const row = page.locator('#resultsTable tbody tr').first();
    await expect(row.locator('.dht-evidence')).toContainText('Latest lookup attempt: '+status);
    await expect(row.locator('.dht-evidence')).toContainText('Last-confirmed sequence: '+seq);
    await expect(row.locator('.dht-evidence')).toContainText('2023');
    await expect(row.locator('.dht-evidence')).toContainText('Coverage: {"complete":false,"queries":2}');
    await expect(row).toContainText(key.toLowerCase());
    await expect(row.locator('td').nth(3)).toContainText('192.0.2.9');
    await expect(page.locator('#metricDecoded')).toHaveText('1');
    expect(await row.locator('.dht-evidence').evaluate(el=>({wrap:getComputedStyle(el).whiteSpace, overflow:getComputedStyle(el).textOverflow})))
      .toEqual({wrap:'pre-wrap',overflow:'clip'});
  }
  data.results_agg = {};
  data.domain_meta[storage].dht_observation = {status:'no_verified_record',observed_at:1700000001};
  await page.click('#menuQuery');
  await page.click('#menuStatus');
  await expect(page.locator('#resultsTable tbody tr')).toHaveCount(1);
  const empty = page.locator('#resultsTable .dht-evidence');
  await expect(empty).toContainText('No last-confirmed record available');
  await expect(empty).toContainText('Coverage: unknown');
  await expect(empty).toContainText(key.toLowerCase());
  await expect(page.locator('#metricDecoded')).toHaveText('0');
  expect(state.errors).toEqual([]);
  expect(state.external).toEqual([]);
});
