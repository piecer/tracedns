const {test, expect} = require('@playwright/test');
const {spawn} = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

async function start(root) {
  const env = {...process.env}; delete env.PYTHONPATH;
  const child = spawn(process.env.PYTHON || path.resolve('.venv/bin/python'),
    ['tests/e2e/rpc_server.py', root], {env, stdio:['ignore','pipe','pipe']});
  let errors = '';
  child.stderr.on('data', chunk=>{ errors = (errors+chunk).slice(-12000); });
  const exited = new Promise(resolve=>child.once('exit', (code, signal)=>resolve({code, signal})));
  let timer;
  try {
    const ready = await new Promise((resolve, reject)=>{
      let text = '';
      timer = setTimeout(()=>reject(new Error('RPC fixture startup timeout: '+errors)),15000);
      child.on('error', reject);
      child.stdout.on('data', chunk=>{
        text += chunk;
        for(const line of text.split('\n')) {
          try { const data=JSON.parse(line); if(data.port) resolve(data); } catch {}
        }
      });
      child.once('exit', ()=>reject(new Error('RPC fixture exited: '+errors)));
    });
    clearTimeout(timer);
    const origin = `http://127.0.0.1:${ready.port}`;
    await expect.poll(async()=>{
      try { return (await fetch(origin+'/login.html')).status; } catch { return 0; }
    }, {timeout:10000}).toBe(200);
    return {origin, child, exited, errors:()=>errors};
  } catch(error) {
    clearTimeout(timer);
    child.kill('SIGKILL'); await exited; throw error;
  }
}

async function stop(server) {
  server.child.kill('SIGTERM');
  let timer;
  const result = await Promise.race([server.exited,
    new Promise(resolve=>{timer=setTimeout(()=>{server.child.kill('SIGKILL');resolve({timeout:true});},10000);})]);
  clearTimeout(timer);
  await server.exited;
  expect(result, server.errors()).toEqual({code:0, signal:null});
}

test('RPC browser registration reaches actual worker, C2 results, history, failure retention and restart', async ({browser}, testInfo)=>{
  test.setTimeout(90000);
  const root = await fs.mkdtemp(path.join(os.tmpdir(),'tracedns-rpc-browser-'));
  let server, context;
  try {
    server = await start(root);
    context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error=>errors.push(error.message));
    await context.route('**/*', route=>new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
    await page.goto(server.origin+'/login.html');
    await page.fill('#username','admin'); await page.fill('#password','test-admin-password');
    await page.click('#login-submit');
    await expect(page).not.toHaveURL(/login\.html/);
    await page.waitForLoadState('load');
    await page.click('#menuDomainVerify');
    await expect(page.locator('#verifyDomainType option[value="RPC"]')).toHaveCount(1);
    await page.selectOption('#verifyDomainType','RPC');
    await page.fill('#verifyDomainName','Polygon captured config.');
    await expect(page.locator('#verifyRpcProfile')).toBeVisible();
    await expect(page.locator('#verifyIncludeVt')).toBeDisabled();
    await expect(page.locator('#verifyAnalyzeDecoders')).toBeDisabled();
    await page.click('#runDomainVerifyBtn');
    await expect(page.locator('#domainVerifyStatus')).toContainText('RPC lookup: authenticated');
    await expect(page.locator('#domainVerifySummary')).toContainText('139.170.223.9:18082');
    await expect(page.locator('#domainVerifySummary')).toContainText('185.100.87.214:443');
    await page.click('#addVerifiedDomainBtn');
    await expect(page.locator('#domainVerifyStatus')).toContainText('Added domain');
    await page.reload(); await page.waitForLoadState('load');
    await page.click('#menuSettings');
    const card = page.locator('#domainTable tbody tr').filter({hasText:'Polygon captured config.'});
    await card.locator('summary').click();
    await expect(card.locator('.rpc-profile')).toHaveValue('polygon_aes_gcm_v1');
    await expect(card.locator('.domain-created time')).toHaveAttribute('datetime', /T/);
    await card.locator('.domain-name').fill('Polygon renamed config.');
    await page.click('#save');
    await expect(page.locator('#domainSettingsStatus')).toContainText('Settings saved');
    await page.click('#force');
    await page.click('#menuStatus');
    await expect(page.locator('#resultsTable')).toContainText('139.170.223.9', {timeout:15000});
    await page.locator('#resultsTable tbody tr').first().getByRole('button',{name:'Details',exact:true}).click();
    await page.locator('#targetEvidence > summary').click();
    await expect(page.locator('#targetEvidence .rpc-evidence')).toContainText('Last authenticated C2 endpoints');
    await expect(page.locator('#targetEvidence .rpc-evidence')).toContainText('139.170.223.9:18082');
    await expect(page.locator('#metricDecoded')).toHaveText('4');
    const evidence = page.locator('#targetEvidence .rpc-evidence details');
    await evidence.locator('summary').click();
    await expect(evidence.locator('pre')).toContainText('Auxiliary roles (not C2)');
    await expect(evidence.locator('pre')).toContainText('185.100.87.214:443');
    await page.screenshot({path:testInfo.outputPath('rpc-confirmed.png'),fullPage:true});
    await fs.writeFile(path.join(root,'miss'),'1');
    await page.click('#menuSettings'); await page.click('#force'); await page.click('#menuStatus');
    await expect(page.locator('#resultsTable')).toContainText('RPC: error', {timeout:15000});
    await page.locator('#resultsTable tbody tr').first().getByRole('button',{name:'Details',exact:true}).click();
    await page.locator('#targetEvidence > summary').click();
    await expect(page.locator('#targetEvidence .rpc-evidence')).toContainText('Latest RPC attempt: error');
    await expect(page.locator('#resultsTable')).toContainText('139.170.223.9');
    await expect(page.locator('#metricDecoded')).toHaveText('4');
    await stop(server); server = null;
    server = await start(root);
    await page.goto(server.origin+'/'); await page.waitForLoadState('load');
    await expect(page.locator('#resultsTable')).toContainText('RPC: error', {timeout:15000});
    await page.locator('#resultsTable tbody tr').first().getByRole('button',{name:'Details',exact:true}).click();
    await page.locator('#targetEvidence > summary').click();
    await expect(page.locator('#targetEvidence .rpc-evidence')).toContainText('Latest RPC attempt: error');
    await expect(page.locator('#resultsTable')).toContainText('139.170.223.9');
    await page.click('#menuIPs');
    await expect(page.locator('#ipsTable')).toContainText('139.170.223.9', {timeout:15000});
    await expect(page.locator('#ipsTable')).not.toContainText('185.100.87.214');
    const saved = JSON.parse(await fs.readFile(path.join(root,'config.json'),'utf8'));
    expect(saved.domains).toEqual([{name:'Polygon renamed config.',type:'RPC',rpc_profile:'polygon_aes_gcm_v1'}]);
    expect(errors).toEqual([]);
  } finally {
    if(context) await context.close();
    try {if(server) await stop(server);} finally {await fs.rm(root,{recursive:true,force:true});}
  }
});
