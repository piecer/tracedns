const {test, expect} = require('@playwright/test');
const {spawn} = require('node:child_process');
const {once} = require('node:events');

async function fixtureServer(){
  const child = spawn(process.env.PYTHON || '.venv/bin/python', ['tests/e2e/read_server.py'],
    {stdio:['pipe','pipe','pipe'], env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
  const port = await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGTERM');reject(new Error('read fixture startup timeout'));},10000);
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',()=>{clearTimeout(timer);reject(new Error('read fixture exited before binding'));});
    child.stdout.on('data',chunk=>{const match=String(chunk).match(/PORT=(\d+)/);if(match){clearTimeout(timer);resolve(Number(match[1]));}});
  });
  return {child,origin:`http://127.0.0.1:${port}`};
}

test('real prepared HTTP pages recover without reload and retain unchanged rows', async({page})=>{
  const {child,origin}=await fixtureServer();
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  try{
    await page.goto(origin+'/login.html');
    await page.fill('#username','admin');
    await page.fill('#password','test-admin-password');
    await page.click('#login-submit');
    await expect(page).not.toHaveURL(/login\.html/);
    await expect(page.locator('#resultsTable tbody tr').first()).toContainText('a000.test');
    expect(await page.locator('#resultsTable tbody tr').count()).toBeLessThanOrEqual(200);
    await page.evaluate(()=>{window.__keptStatus=document.querySelector('#resultsTable tbody tr');});
    const response=page.waitForResponse(r=>r.url().includes('/results?')&&r.url().includes('if_version='));
    await page.evaluate(()=>refreshResults());
    const same=await (await response).json();
    expect(same.unchanged).toBe(true);
    expect(await page.evaluate(()=>window.__keptStatus===document.querySelector('#resultsTable tbody tr'))).toBe(true);
    const before=await page.locator('#resultsTable tbody tr').first().innerText();
    child.stdin.write('tick\n');
    await expect.poll(async()=>{await page.evaluate(()=>refreshResults());return page.locator('#resultsTable tbody tr').first().innerText();}).not.toBe(before);
    expect(await page.evaluate(()=>window.__keptStatus===document.querySelector('#resultsTable tbody tr'))).toBe(true);
    await page.locator('#status').getByRole('button',{name:/next/i}).click();
    await expect(page.locator('#resultsTable tbody tr').first()).not.toContainText('a000.test');

    await page.click('#menuIPs');
    await expect(page.locator('#ipsTable tbody tr').first()).toContainText('11.');
    expect(await page.locator('#ipsTable tbody tr').count()).toBeLessThanOrEqual(200);
    await page.evaluate(()=>{window.__keptIp=document.querySelector('#ipsTable tbody tr');});
    // Transport fault injection, while data itself comes from the real producer.
    await page.route('**/ips?**',route=>route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({snapshot:{ready:false,status:'building'}})}));
    await page.click('#ips_refresh_btn');
    await expect(page.locator('#ips-refresh-status')).toContainText('Preparing snapshot');
    expect(await page.evaluate(()=>window.__keptIp===document.querySelector('#ipsTable tbody tr'))).toBe(true);
    await page.unroute('**/ips?**');
    await page.click('#ips_refresh_btn');
    await expect(page.locator('#ips-refresh-status')).toContainText('Snapshot from');
    await expect(page.locator('#ips-refresh-status')).not.toContainText('Preparing snapshot');
    await expect(page.locator('#ipsTable tbody tr').first()).toContainText('11.');

    await page.click('#menuValidIPs');
    await expect(page.locator('#validIpsTable tbody tr').first()).toContainText('11.');
    expect(await page.locator('#validIpsTable tbody tr').count()).toBeLessThanOrEqual(200);
    await page.click('#menuDomainAnalysis');
    await expect(page.locator('#domainAnalysisTable tbody tr').first()).toContainText('a000.test');
    expect(await page.locator('#domainAnalysisTable tbody tr').count()).toBeLessThanOrEqual(200);
    expect(errors).toEqual([]);
  }finally{
    const exited=once(child,'exit');
    child.kill('SIGTERM');
    await exited;
  }
});
