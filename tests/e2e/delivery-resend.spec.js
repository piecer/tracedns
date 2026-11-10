const {test, expect} = require('@playwright/test');
const {spawn, execFileSync} = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const python = process.env.PYTHON || path.resolve('.venv/bin/python');

async function start(root) {
  const env = {...process.env}; delete env.PYTHONPATH;
  const child = spawn(python, ['tests/e2e/delivery_resend_server.py', root],
    {env, stdio:['ignore','pipe','pipe']});
  let errors = '', text = '', timer;
  child.stderr.on('data', bytes=>{ errors = (errors+bytes).slice(-12000); });
  const exited = new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  try {
    const port = await new Promise((resolve,reject)=>{
      timer = setTimeout(()=>reject(new Error('Resend fixture startup timeout: '+errors)),15000);
      child.once('error',reject);
      child.once('exit',()=>reject(new Error('Resend fixture exited: '+errors)));
      child.stdout.on('data',bytes=>{
        text = (text+bytes).slice(-16000);
        for(const line of text.split('\n')) {
          try { const value = JSON.parse(line); if(value.port) resolve(value.port); } catch {}
        }
      });
    });
    clearTimeout(timer);
    const origin = `http://127.0.0.1:${port}`;
    await expect.poll(async()=>{
      try { return (await fetch(origin+'/login.html')).status; } catch { return 0; }
    },{timeout:10000}).toBe(200);
    return {origin,child,exited,errors:()=>errors};
  } catch(error) {
    clearTimeout(timer); child.kill('SIGKILL'); await exited; throw error;
  }
}

async function stop(server) {
  server.child.kill('SIGTERM');
  let timer;
  const result = await Promise.race([server.exited,new Promise(resolve=>{
    timer=setTimeout(()=>{server.child.kill('SIGKILL');resolve({timeout:true});},10000);
  })]);
  clearTimeout(timer); await server.exited;
  expect(result,server.errors()).toEqual({code:0,signal:null});
}

async function login(page,origin) {
  await page.goto(origin+'/login.html');
  await expect(page.locator('#login-submit')).toBeEnabled();
  await page.fill('#username','admin'); await page.fill('#password','test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/); await page.waitForLoadState('load');
  await expect.poll(async()=>{
    const health=await page.evaluate(async()=> (await fetch('/delivery-health?progress=1')).json());
    return !!health.lookup?.last_success_at && health.lookup.in_flight===0;
  },{timeout:15000}).toBe(true);
  await page.click('#menuSettings');
}

async function calls(root) {
  try { return (await fs.readFile(path.join(root,'provider-calls.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
  catch(error) { if(error.code==='ENOENT') return []; throw error; }
}

function detector(root) {
  const script = 'import sqlite3,json,sys,pathlib; p=pathlib.Path(sys.argv[1]); db=sqlite3.connect((p/"delivery.sqlite").as_uri()+"?mode=ro",uri=True); tables=("cursor","recent","baseline","grace","reappearance","failed_addition"); print(json.dumps({"tables":{t:db.execute("SELECT * FROM "+t+" ORDER BY 1").fetchall() for t in tables},"history":{f.name:f.read_text() for f in sorted(p.glob("*.json"))}})); db.close()';
  return JSON.parse(execFileSync(python,['-c',script,path.join(root,'config.json.history')],{encoding:'utf8'}));
}

async function openTarget(page,name) {
  const card=page.locator('#domainTable tbody tr').filter({hasText:name});
  await expect(card.locator('.delivery-resend-btn')).toBeVisible({timeout:5000});
  await card.locator('.delivery-resend-btn').click();
  await expect(page.locator('#deliveryResendDialog')).toBeVisible();
}

for(const lostResponse of [false,true]) {
  test(`target resend uses real durable worker; response loss=${lostResponse}`,async({browser},testInfo)=>{
    test.setTimeout(90000);
    const root=await fs.mkdtemp(path.join(os.tmpdir(),'tracedns-resend-browser-'));
    let server,context;
    try {
      server=await start(root);
      context=await browser.newContext();
      await context.route('**/*',route=>new URL(route.request().url()).hostname==='127.0.0.1'?route.continue():route.abort());
      const page=await context.newPage();
      const errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      await login(page,server.origin);
      const before=detector(root);
      expect(await calls(root)).toEqual([]);
      await openTarget(page,'Resend RPC');
      await page.click('#deliveryResendPreviewBtn');
      await expect(page.locator('#deliveryResendIPs')).toContainText('139.170.223.9');
      await expect(page.locator('#deliveryResendIPs')).not.toContainText('185.100.87.214');
      await page.click('#deliveryResendCancelBtn');
      expect(await calls(root)).toEqual([]);
      expect(detector(root)).toEqual(before);
      await openTarget(page,'Resend RPC');
      await page.click('#deliveryResendPreviewBtn');
      await expect(page.locator('#deliveryResendConfirmBtn')).toBeEnabled();
      await page.setViewportSize({width:390,height:900});
      const dialog=page.locator('#deliveryResendDialog');
      expect(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1 && el.getBoundingClientRect().right<=innerWidth+1)).toBe(true);
      await page.screenshot({path:testInfo.outputPath('resend-preview-mobile.png'),fullPage:true});
      await testInfo.attach('resend-preview-accessibility',{body:await dialog.ariaSnapshot(),contentType:'text/plain'});
      let posts=0, requestId;
      page.on('request',r=>{
        if(new URL(r.url()).pathname==='/delivery-resend' && r.method()==='POST'){
          posts++; requestId=r.postDataJSON().request_id;
        }
      });
      if(lostResponse) {
        await page.route('**/delivery-resend',async route=>{
          await route.fetch(); // Commit the genuine request, lose only its reply.
          await route.abort('failed');
        });
      }
      await page.click('#deliveryResendConfirmBtn');
      await expect(page.locator('#deliveryResendStatus')).toContainText(lostResponse ? /unknown/i : /queued/i);
      await expect.poll(async()=>{
        const h=await page.evaluate(async()=> (await fetch('/delivery-health')).json());
        return h.acked_total;
      },{timeout:15000}).toBe(8);
      expect(posts).toBe(1);
      let observed=await calls(root);
      expect(observed.filter(c=>c.channel==='teams'&&c.operation==='send')).toHaveLength(1);
      expect(observed.filter(c=>c.channel==='misp'&&c.operation==='add')).toHaveLength(4);
      expect(detector(root)).toEqual(before);
      if(lostResponse) await page.unroute('**/delivery-resend');
      // A deliberate same-request retry must not enqueue again, even after ACK.
      const duplicate=await page.evaluate(async id=>(await fetch('/delivery-resend',{
        method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:id})})).json(),requestId);
      expect(duplicate.status).toBe('already_queued');
      expect(duplicate.receipt_count).toBe(8);
      if(!lostResponse) {
        await page.click('#deliveryResendCancelBtn');
        await openTarget(page,'Other RPC');
        await page.uncheck('#deliveryResendMisp');
        await page.click('#deliveryResendPreviewBtn');
        await expect(page.locator('#deliveryResendConfirmBtn')).toBeEnabled();
        await page.click('#deliveryResendConfirmBtn');
        await expect(page.locator('#deliveryResendStatus')).toContainText(/queued/i);
        await expect.poll(async()=>{
          const h=await page.evaluate(async()=> (await fetch('/delivery-health')).json()); return h.acked_total;
        }).toBe(12);
        observed=await calls(root);
        expect(observed.filter(c=>c.channel==='teams'&&c.operation==='send')).toHaveLength(2);
        expect(observed.filter(c=>c.channel==='misp'&&c.operation==='add')).toHaveLength(4);
        expect(detector(root)).toEqual(before);
      }
      await stop(server);server=null;
      server=await start(root);
      await page.goto(server.origin+'/'); await page.waitForLoadState('load');
      const restarted=await page.evaluate(async id=>(await fetch('/api/v1/delivery-resend',{
        method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:id})})).json(),requestId);
      expect(restarted.status).toBe('already_queued');
      expect(restarted.receipt_count).toBe(lostResponse?8:4);
      expect(await calls(root)).toEqual(observed);
      expect(errors).toEqual([]);
    } finally {
      try {if(context) await context.close();} finally {
        try {if(server) await stop(server);} finally {await fs.rm(root,{recursive:true,force:true});}
      }
    }
  });
}

test('real role sessions cannot resend and unsaved edits cannot select a different target',async({browser})=>{
  test.setTimeout(90000);
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'tracedns-resend-roles-'));
  let server,adminContext;
  try {
    server=await start(root);
    adminContext=await browser.newContext();
    const admin=await adminContext.newPage();
    await login(admin,server.origin);
    const card=admin.locator('#domainTable tbody tr').first();
    await expect(card.locator('.domain-full-name')).toHaveText('Resend RPC');
    await card.locator('summary').click();
    await card.locator('.domain-name').fill('Unsaved RPC target');
    await card.locator('.delivery-resend-btn').click();
    await expect(admin.locator('#domainSettingsStatus')).toContainText('Save or reload settings');
    await expect(admin.locator('#deliveryResendDialog')).not.toBeVisible();
    expect(await calls(root)).toEqual([]);
    for(const role of ['operator','viewer']) {
      const context=await browser.newContext();
      try {
        const page=await context.newPage();
        await page.goto(server.origin+'/login.html');
        await expect(page.locator('#login-submit')).toBeEnabled();
        await page.fill('#username',role); await page.fill('#password','test-role-password');
        await page.click('#login-submit');
        await expect(page).not.toHaveURL(/login\.html/); await page.waitForLoadState('load');
        await expect(page.locator('#current-user')).toContainText(role);
        if(role==='operator') await page.click('#menuSettings');
        expect(await page.locator('.delivery-resend-btn:visible').count()).toBe(0);
        const csrf=await (await context.request.get(server.origin+'/auth/csrf')).json();
        for(const suffix of ['/delivery-resend','/api/v1/delivery-resend']) {
          const response=await context.request.post(server.origin+suffix,{
            headers:{Origin:server.origin,'X-CSRF-Token':csrf.csrf_token},
            data:{request_id:'a'.repeat(32)}
          });
          expect(response.status()).toBe(403);
        }
      } finally {await context.close();}
    }
    expect(await calls(root)).toEqual([]);
  } finally {
    try {if(adminContext) await adminContext.close();} finally {
      try {if(server) await stop(server);} finally {await fs.rm(root,{recursive:true,force:true});}
    }
  }
});
