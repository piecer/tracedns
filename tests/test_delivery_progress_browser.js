const {chromium} = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const output = process.env.STAGE4_BROWSER_OUTPUT;
  fs.mkdirSync(output,{recursive:true});
  const url = `http://127.0.0.1:${process.env.STAGE4_PORT}`;
  const browser = await chromium.launch({headless:true});
  const errors = [], requests = [], starts = [], health = [];
  try {
    const page = await browser.newPage({viewport:{width:1280,height:900}});
    page.on('pageerror', e=>errors.push(e.message));
    page.on('console', m=>{ if(m.type()==='error') errors.push(m.text()); });
    page.on('request', r=>{
      requests.push(r.url());
      assert(r.url().startsWith(url+'/'), 'external browser request');
      if(new URL(r.url()).pathname==='/delivery-health') starts.push(Date.now());
    });
    page.on('response', async r=>{
      if(new URL(r.url()).pathname==='/delivery-health'){
        try { health.push(await r.json()); }
        catch(error){ health.push({status:r.status(),bodyUnavailable:String(error)}); }
      }
    });
    await page.goto(url+'/login.html');
    await page.fill('#username','admin');
    await page.fill('#password','test-admin-password');
    await page.click('#login-submit');
    const panel = page.locator('#deliveryHealth');
    await panel.getByText('Teams dispatch: active', {exact:false}).waitFor();
    assert((await panel.innerText()).includes('ACKed: 0'));
    const control = name=>page.request.post(url+'/__fixture/'+name,{headers:{'X-Fixture-Token':process.env.STAGE4_TOKEN}});
    assert.equal((await control('advance')).status(),204);
    await panel.getByText('Teams dispatch: stalled', {exact:false}).waitFor({timeout:22000});
    let text = await panel.innerText();
    assert(text.includes('MISP dispatch: unavailable'));
    assert(text.includes('Failed targets: 1'));
    assert(text.includes('Uncertain targets: 1'));
    assert(text.includes('Targets rebaselining: 1'));
    assert(text.includes('Full-only absence gate: awaiting_full'));
    const age1 = Number(text.match(/Oldest outstanding age: (\d+)/)[1]);
    assert(age1>=60);
    await panel.screenshot({path:path.join(output,'stalled-wide.png')});
    await page.setViewportSize({width:390,height:900});
    assert(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1 && el.getBoundingClientRect().right<=innerWidth));
    await panel.screenshot({path:path.join(output,'stalled-narrow.png')});
    await control('advance');
    await page.waitForFunction(age=>Number(document.querySelector('#deliveryHealth').textContent.match(/Oldest outstanding age: (\d+)/)?.[1])>age,age1,{timeout:22000});
    assert((await panel.innerText()).includes('ACKed: 0'));
    await control('release');
    await panel.getByText('ACKed: 2', {exact:false}).waitFor({timeout:22000});
    text=await panel.innerText();
    assert(text.includes('Targets rebaselining: 1'));
    assert(text.includes('Uncertain targets: 1'));
    assert(!text.includes('Teams dispatch: stalled'));
    await panel.screenshot({path:path.join(output,'released-narrow.png')});
    await control('legacy');
    await page.locator('#deliveryStatus').getByText('progress unavailable on this server',{exact:false}).waitFor({timeout:22000});
    await panel.screenshot({path:path.join(output,'legacy-fallback.png')});
    await control('failed');
    await page.locator('#deliveryStatus').getByText('progress: failed',{exact:false}).waitFor({timeout:22000});
    await panel.screenshot({path:path.join(output,'failed-narrow.png')});
    assert(starts.length>=6);
    for(let i=1;i<starts.length;i++) assert(starts[i]-starts[i-1]>=14900, 'poll pacing');
    assert(requests.filter(u=>new URL(u).pathname==='/delivery-health').every(u=>u.endsWith('?progress=1')));
    assert.deepEqual(errors,[]);
    text = await panel.innerText();
    fs.writeFileSync(path.join(output,'browser.json'),JSON.stringify({errors,requests,starts,health,text,accessible:await panel.ariaSnapshot()},null,2));
    console.log(JSON.stringify({polls:starts.length,age1,acked:2,errors}));
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;});
