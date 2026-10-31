const {test, expect} = require('@playwright/test');
const {spawn} = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

async function start(root) {
  const env = {...process.env}; delete env.PYTHONPATH;
  const child = spawn(process.env.PYTHON || path.resolve('.venv/bin/python'),
    ['tests/e2e/dht_server.py', root], {env, stdio:['ignore','pipe','pipe']});
  let errors = '';
  child.stderr.on('data', chunk=>{ errors = (errors+chunk).slice(-12000); });
  const exited = new Promise(resolve=>child.once('exit', (code, signal)=>resolve({code, signal})));
  try {
    const ready = await new Promise((resolve, reject)=>{
      let text = '';
      const timer = setTimeout(()=>reject(new Error('DHT fixture startup timeout: '+errors)), 15000);
      child.stdout.on('data', chunk=>{
        text += chunk;
        for(const line of text.split('\n')) {
          try { const data=JSON.parse(line); if(data.port) {clearTimeout(timer);resolve(data);} } catch {}
        }
      });
      child.once('exit', ()=>{clearTimeout(timer);reject(new Error('DHT fixture exited: '+errors));});
    });
    const origin = `http://127.0.0.1:${ready.port}`;
    await expect.poll(async()=>{
      try { return (await fetch(origin+'/login.html')).status; } catch { return 0; }
    }, {timeout:10000}).toBe(200);
    return {origin, key:ready.key, child, exited, errors:()=>errors};
  } catch(error) {
    child.kill('SIGTERM'); await exited; throw error;
  }
}

async function stop(server) {
  server.child.kill('SIGTERM');
  let timer;
  const result = await Promise.race([server.exited,
    new Promise(resolve=>{timer=setTimeout(()=>{server.child.kill('SIGKILL');resolve({timeout:true});},10000);})]);
  clearTimeout(timer);
  expect(result, server.errors()).toEqual({code:0, signal:null});
}

test('real API and worker preserve signed DHT state through browser registration, miss and restart', async ({browser}, testInfo)=>{
  test.setTimeout(90000);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tracedns-dht-browser-'));
  let server = await start(root);
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e=>errors.push(e.message));
  await context.route('**/*', route=>new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
  const label = 'Real API synthetic signed DNS.';
  try {
    await page.goto(server.origin+'/login.html');
    await page.fill('#username','admin'); await page.fill('#password','test-admin-password');
    await page.click('#login-submit');
    await expect(page).not.toHaveURL(/login\.html/);
    await page.waitForLoadState('load');
    await page.click('#menuDomainVerify');
    await page.selectOption('#verifyDomainType', 'DHT');
    await page.fill('#verifyDomainName', label);
    await page.fill('#verifyDhtPublicKey', server.key);
    await page.fill('#verifyDhtOptions', '{"duration":1,"max_queries":4}');
    await page.click('#runDomainVerifyBtn');
    await expect(page.locator('#domainVerifySummary')).toContainText('Last-confirmed sequence: 9007199254740993');
    await page.click('#addVerifiedDomainBtn');
    await expect(page.locator('#domainVerifyStatus')).toContainText('Added domain');
    await page.reload(); await page.waitForLoadState('load');
    await page.click('#menuSettings');
    const card = page.locator('#domainTable tbody tr').filter({hasText:label});
    await card.locator('summary').click();
    await expect(card.locator('.dht-public-key')).toHaveValue(server.key);
    await expect(card.locator('.domain-created time')).toHaveAttribute('datetime', /T/);
    await page.click('#menuStatus');
    await expect(page.locator('#resultsTable')).toContainText('9007199254740993', {timeout:15000});
    await expect(page.locator('#resultsTable')).toContainText('192.0.2.123');
    await expect(page.locator('#resultsTable')).toContainText('Selected record signature: valid');
    const evidence = page.locator('#resultsTable .dht-evidence details');
    await expect(evidence).toBeVisible();
    await expect(evidence).not.toHaveAttribute('open');
    await evidence.locator('summary').click();
    await expect(evidence.locator('pre')).toContainText('Coverage:');
    await evidence.locator('summary').click();
    await page.screenshot({path:testInfo.outputPath('dht-real-api-confirmed.png'), fullPage:true});
    const columns = await page.locator('#resultsTable').evaluate(table=>{
      const headers = [...table.querySelectorAll('thead th')];
      return [...table.querySelector('tbody tr').cells].map((cell,index)=>({
        display:getComputedStyle(cell).display,
        aligned:Math.abs(cell.getBoundingClientRect().left-headers[index].getBoundingClientRect().left)<2
      }));
    });
    expect(columns).toEqual(Array.from({length:8},()=>({display:'table-cell',aligned:true})));
    await fs.writeFile(path.join(root,'mode'), 'miss');
    await page.click('#menuSettings'); await page.click('#force'); await page.click('#menuStatus');
    await expect(page.locator('#resultsTable')).toContainText('no_verified_record', {timeout:15000});
    await expect(page.locator('#resultsTable')).toContainText('192.0.2.123');
    await stop(server); server = null;
    server = await start(root);
    await page.goto(server.origin+'/'); await page.waitForLoadState('load');
    await expect(page.locator('#resultsTable')).toContainText('9007199254740993', {timeout:15000});
    await expect(page.locator('#resultsTable')).toContainText('192.0.2.123');
    await expect(page.locator('#resultsTable')).toContainText('no_verified_record');
    await page.screenshot({path:testInfo.outputPath('dht-real-api-restarted.png'), fullPage:true});
    const saved = JSON.parse(await fs.readFile(path.join(root,'config.json'),'utf8'));
    expect(saved.domains).toEqual([{name:label,type:'DHT',dht_public_key:server.key,dht_options:{duration:1,max_queries:4}}]);
    await page.click('#menuIPs');
    await expect(page.locator('#ipsTable')).toContainText('192.0.2.123', {timeout:15000});
    expect(errors).toEqual([]);
  } finally {
    await context.close();
    try { if(server) await stop(server); } finally { await fs.rm(root,{recursive:true,force:true}); }
  }
});
