const {test, expect} = require('@playwright/test');
const {spawn} = require('node:child_process');
const {once} = require('node:events');

async function owner(scenario, run) {
  const child = spawn(process.env.PYTHON || '.venv/bin/python',
    ['tests/e2e/server.py', '--port', '0', '--delivery', scenario]);
  let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  try {
    const info = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Fixture startup timeout: ' + stderr)), 15000);
      child.once('exit', code => { clearTimeout(timer); reject(new Error('Fixture exit ' + code + ': ' + stderr)); });
      child.stdout.once('data', bytes => { clearTimeout(timer); resolve(JSON.parse(String(bytes))); });
    });
    await run(`http://127.0.0.1:${info.port}`);
  } finally {
    if(child.exitCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      await exited;
      clearTimeout(timer);
    }
  }
}

async function login(page, username = 'admin', password = 'test-admin-password') {
  await page.goto(new URL('/login.html', page.url().startsWith('http') ? page.url() : 'http://127.0.0.1:18765').href);
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
}

for(const scenario of ['backlog', 'acked', 'overflow', 'degraded']) {
  test(`real DeliveryStore cached HTTP renders ${scenario} without private payload`, async ({page}, testInfo) => {
    await owner(scenario, async url => {
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(url + '/login.html');
      await login(page);
      const panel = page.locator('#deliveryHealth');
      await expect(panel).toContainText(`ACKed: ${scenario === 'acked' ? 2 : 0}`);
      await expect(panel).toContainText(`Pending: ${scenario === 'acked' ? 0 : 2}`);
      await expect(panel).toContainText('Teams');
      await expect(panel).toContainText('MISP');
      await expect(panel).not.toContainText(/PRIVATE-CANARY|192\.0\.2|private-canary|binding_id|sent/i);
      if(scenario === 'overflow') await expect(panel).toContainText('4 destination-items not admitted');
      if(scenario === 'degraded') {
        await expect(panel).toContainText('lower bound');
        await expect(panel).toContainText('Volatile known misses: 3');
        await expect(panel).toContainText('Counts stale');
      }
      await expect(page.locator('#deliveryChecked')).not.toContainText('unknown');
      await expect(page.locator('#deliveryStatus')).toHaveAttribute('aria-live', 'polite');
      expect(await panel.locator('*').count()).toBeLessThanOrEqual(24);
      const accessible = await panel.ariaSnapshot();
      expect(accessible).toContain('Notification delivery');
      expect(accessible).toContain('Observation continues');
      await testInfo.attach('delivery-accessibility', {body:accessible, contentType:'text/plain'});
      await panel.screenshot({path:testInfo.outputPath(`delivery-${scenario}-1280.png`)});
      await page.setViewportSize({width:390,height:900});
      expect(await panel.evaluate(el => el.scrollWidth <= el.clientWidth + 1 && el.getBoundingClientRect().right <= innerWidth)).toBe(true);
      await panel.screenshot({path:testInfo.outputPath(`delivery-${scenario}-390.png`)});
      expect(errors).toEqual([]);
    });
  });
}

test('polling recovers from HTTP and malformed failures while keeping last good stale', async ({page}) => {
  await owner('backlog', async url => {
    await page.clock.install();
    let mode = 'http';
    let calls = 0;
    await page.route('**/delivery-health', async route => {
      calls++;
      if(mode === 'http') return route.fulfill({status:503, body:'<img src=x onerror=alert(1)>PRIVATE-ERROR'});
      if(mode === 'invalid') return route.fulfill({body:'not json PRIVATE-ERROR'});
      await route.continue();
    });
    await page.goto(url + '/login.html');
    await login(page);
    await expect(page.locator('#deliveryStatus')).toContainText('unavailable');
    expect(calls).toBe(1);
    mode = 'good';
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    const lastRead = await page.locator('#deliveryChecked').textContent();
    mode = 'invalid';
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryStatus')).toContainText('stale');
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    await expect(page.locator('#deliveryChecked')).toHaveText(lastRead);
    await expect(page.locator('#deliveryHealth')).not.toContainText('PRIVATE-ERROR');
    mode = 'good';
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryStatus')).not.toContainText('unavailable');
    expect(calls).toBe(4);
  });
});

test('oversized bodies and out-of-range integer tokens fail closed', async ({page}) => {
  await owner('backlog', async url => {
    let mutation = 'oversized';
    await page.route('**/delivery-health', async route => {
      const response = await route.fetch();
      const data = await response.json();
      let body = JSON.stringify(data);
      if(mutation === 'oversized') body = ' '.repeat(4097) + body;
      else body = body.replace('"missed_total":0', '"missed_total":9223372036854775808');
      await route.fulfill({response, body});
    });
    await page.goto(url + '/login.html');
    await login(page);
    await expect(page.locator('#deliveryStatus')).toContainText('unavailable');
    await expect(page.locator('#deliveryDetails')).toContainText('Unknown');
    mutation = 'integer';
    await page.reload();
    await expect(page.locator('#deliveryStatus')).toContainText('unavailable');
    await expect(page.locator('#deliveryDetails')).toContainText('Unknown');
  });
});

test('delayed auth cannot compress the interval between actual health requests', async ({page}) => {
  await owner('backlog', async url => {
    await page.goto(url + '/login.html');
    await login(page);
    await page.clock.install();
    await page.addInitScript(() => {
      const original = window.fetch;
      window.healthStarts = [];
      window.fetch = (input, options) => {
        if(new URL(input, location.href).pathname === '/delivery-health') window.healthStarts.push(performance.now());
        return original(input, options);
      };
    });
    let release;
    const blocked = new Promise(resolve => { release = resolve; });
    await page.route('**/auth/me', async route => { await blocked; await route.continue(); });
    let calls = 0;
    await page.route('**/delivery-health', route => { calls++; return route.continue(); });
    await page.reload();
    await page.clock.runFor(8000);
    release();
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    expect(calls).toBe(1);
    await page.clock.runFor(7001);
    await page.clock.runFor(8000);
    await expect.poll(() => calls).toBe(2);
    const starts = await page.evaluate(() => window.healthStarts);
    expect(starts[1] - starts[0]).toBeGreaterThanOrEqual(15000);
  });
});

test('private CA control validates, preserves blank, clears explicitly and keeps draft revision', async ({page}) => {
  await owner('backlog', async url => {
    const {execFileSync} = require('node:child_process');
    const fs = require('node:fs');
    const path = require('node:path');
    const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'delivery-ca-browser-'));
    const bundle = path.join(dir, 'PRIVATE-CA-CANARY.pem');
    const cert = execFileSync(process.env.PYTHON || '.venv/bin/python', ['-c', 'from requests.certs import where; print(where())'], {encoding:'utf8'}).trim();
    fs.copyFileSync(cert, bundle);
    try {
      await page.goto(url + '/login.html');
      await login(page);
      await page.click('#menuSettings');
      await page.click('#settingsTabAlerts');
      const input = page.locator('#misp_ca_bundle_front');
      await expect(input).toBeVisible();
      await expect(input).toHaveValue('');
      const settings = () => page.evaluate(async () => (await fetch('/settings')).json());
      const initial = await settings();
      await input.fill('relative-PRIVATE-CA-CANARY.pem');
      await page.click('#saveAlertSettingsBtn');
      await expect(page.locator('#alertSettingsStatus')).toContainText('absolute PEM path');
      expect((await settings()).revision).toBe(initial.revision);
      await input.fill(bundle);
      const sent = page.waitForRequest(r => r.url().endsWith('/settings') && r.method() === 'POST');
      await page.click('#saveAlertSettingsBtn');
      expect((await sent).postDataJSON().revision).toBe(initial.revision);
      await expect(input).toHaveValue('');
      await expect(input).toHaveAttribute('placeholder', /Configured/);
      await expect(page.locator('#alertSettingsStatus')).toHaveText('Saved');
      await page.evaluate(() => {
        window.caSaveFinished = false;
        const el = document.getElementById('alertSettingsStatus');
        const observer = new MutationObserver(() => {
          if(el.textContent === 'Saved') { window.caSaveFinished = true; observer.disconnect(); }
        });
        observer.observe(el, {childList:true});
      });
      await page.click('#saveAlertSettingsBtn');
      await expect.poll(() => page.evaluate(() => window.caSaveFinished)).toBe(true);
      const configured = await settings();
      expect(configured.settings.alerts.configured.misp_ca_bundle).toBe(true);
      expect(JSON.stringify(configured)).not.toContain('PRIVATE-CA-CANARY');
      expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('PRIVATE-CA-CANARY');
      // Background config reads / tab switches must not rebase this alert draft.
      await input.fill(bundle);
      await page.evaluate(async revision => {
        await fetch('/config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({revision, interval:61})});
      }, configured.revision);
      await page.click('#settingsTabDomains');
      await page.click('#settingsTabAlerts');
      const stale = page.waitForRequest(r => r.url().endsWith('/settings') && r.method() === 'POST');
      await page.click('#saveAlertSettingsBtn');
      expect((await stale).postDataJSON().revision).toBe(configured.revision);
      await expect(page.locator('#alertSettingsStatus')).toContainText('Save failed');
      await expect(input).toHaveValue(bundle);
      await page.click('#loadAlertSettingsBtn');
      await expect(input).toHaveValue('');
      await page.check('#clear-misp_ca_bundle_front');
      const clear = page.waitForRequest(r => r.url().endsWith('/settings') && r.method() === 'POST');
      await page.click('#saveAlertSettingsBtn');
      expect((await clear).postDataJSON().clear_fields).toContain('misp_ca_bundle');
      await expect(input).toHaveAttribute('placeholder', 'Not configured');
      await page.setViewportSize({width:390,height:900});
      expect(await input.evaluate(el => el.getBoundingClientRect().right <= innerWidth)).toBe(true);
    } finally {
      fs.rmSync(dir, {recursive:true});
    }
  });
});

for(const failure of ['network', 'fetch', 'body']) {
  test(`bounded ${failure} failure releases busy state and recovers`, async ({page}) => {
    await owner('backlog', async url => {
      await page.clock.install();
      await page.addInitScript(failure => {
        const original = window.fetch;
        window.healthMode = failure;
        window.healthCalls = [];
        window.healthAborts = 0;
        window.healthBodyCancels = 0;
        window.fetch = (input, options = {}) => {
          if(new URL(input, location.href).pathname !== '/delivery-health') return original(input, options);
          window.healthCalls.push(performance.now());
          options.signal.addEventListener('abort', () => window.healthAborts++, {once:true});
          if(window.healthMode === 'network') return Promise.reject(new TypeError('PRIVATE-NETWORK-CANARY'));
          if(window.healthMode === 'fetch') return new Promise(() => {});
          if(window.healthMode === 'body') return Promise.resolve(new Response(new ReadableStream({cancel(){window.healthBodyCancels++;}})));
          return original(input, options);
        };
      }, failure);
      await page.goto(url + '/login.html');
      await login(page);
      await expect(page.locator('#deliveryHealth')).toBeVisible();
      await expect.poll(() => page.evaluate(() => window.healthCalls.length)).toBe(1);
      await page.clock.runFor(10001);
      await expect(page.locator('#deliveryStatus')).toContainText('unavailable');
      expect(await page.evaluate(() => window.healthCalls.length)).toBe(1);
      if(failure !== 'network') expect(await page.evaluate(() => window.healthAborts)).toBe(1);
      if(failure === 'body') expect(await page.evaluate(() => window.healthBodyCancels)).toBe(1);
      await page.evaluate(() => { window.healthMode = 'good'; });
      await page.clock.runFor(failure === 'network' ? 5001 : 15001);
      await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
      const calls = await page.evaluate(() => window.healthCalls);
      expect(calls).toHaveLength(2);
      expect(calls[1] - calls[0]).toBeGreaterThanOrEqual(15000);
      await expect(page.locator('#deliveryHealth')).not.toContainText('PRIVATE-NETWORK-CANARY');
    });
  });
}

test('visibility and page lifecycle cancel inflight, suppress hidden polling and retain rate limit', async ({page}) => {
  await owner('backlog', async url => {
    await page.clock.install();
    await page.addInitScript(() => {
      const original = window.fetch;
      window.healthCalls = [];
      window.healthAborts = 0;
      window.healthMode = 'stall';
      window.fetch = (input, options = {}) => {
        if(new URL(input, location.href).pathname !== '/delivery-health') return original(input, options);
        window.healthCalls.push(performance.now());
        if(window.healthMode !== 'stall') return original(input, options);
        return new Promise((_, reject) => options.signal.addEventListener('abort', () => {
          window.healthAborts++; reject(new Error('aborted'));
        }, {once:true}));
      };
    });
    await page.goto(url + '/login.html');
    await login(page);
    await expect.poll(() => page.evaluate(() => window.healthCalls.length)).toBe(1);
    // Synthetic visibility transitions on the real shipped DOM, deterministic clock.
    const visible = async hidden => page.evaluate(hidden => {
      Object.defineProperty(document, 'hidden', {configurable:true, value:hidden});
      document.dispatchEvent(new Event('visibilitychange'));
    }, hidden);
    await visible(true);
    await expect.poll(() => page.evaluate(() => window.healthAborts)).toBe(1);
    await page.evaluate(() => { window.healthMode = 'good'; });
    for(let i=0; i<8; i++) { await visible(false); await visible(true); }
    await page.clock.runFor(5000);
    expect(await page.evaluate(() => window.healthCalls.length)).toBe(1);
    await visible(false);
    await page.clock.runFor(5000);
    expect(await page.evaluate(() => window.healthCalls.length)).toBe(1);
    await page.clock.runFor(5001);
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    await visible(true);
    await page.clock.runFor(60000);
    expect(await page.evaluate(() => window.healthCalls.length)).toBe(2);
    await visible(false);
    await page.clock.runFor(1);
    await expect.poll(() => page.evaluate(() => window.healthCalls.length)).toBe(3);
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    await page.clock.runFor(60000);
    expect(await page.evaluate(() => window.healthCalls.length)).toBe(3);
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow')));
    await page.clock.runFor(1);
    await expect.poll(() => page.evaluate(() => window.healthCalls.length)).toBe(4);
    const starts = await page.evaluate(() => window.healthCalls);
    expect(starts.slice(1).every((at,i) => at - starts[i] >= 15000)).toBe(true);
  });
});

test('auth startup failure recovers into real delivery screen without reload', async ({page}) => {
  await owner('backlog', async url => {
    await page.goto(url + '/login.html');
    await login(page);
    await page.clock.install();
    let fail = true;
    await page.route('**/auth/me', route => fail ? route.fulfill({status:503, body:'PRIVATE-AUTH'}) : route.continue());
    await page.reload();
    await expect(page.locator('#security-message')).toContainText('Authentication unavailable');
    fail = false;
    await page.clock.runFor(16000);
    await expect(page.locator('#deliveryHealth')).toBeVisible();
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    await expect(page.locator('#security-message')).not.toContainText('Authentication unavailable');
  });
});

test('real viewer makes no health requests; operator may read but not edit alert settings', async ({page, browser}) => {
  await owner('backlog', async url => {
    await page.goto(url + '/login.html');
    await login(page);
    await page.goto(url + '/accounts.html');
    for(const role of ['viewer','operator']) {
      await page.fill('#create-username', 'delivery-' + role);
      await page.fill('#create-password', 'temporary-password');
      await page.selectOption('#create-role', role);
      await page.click('#create-user');
      await expect(page.locator('#users')).toContainText('delivery-' + role);
      const context = await browser.newContext();
      try {
        const client = await context.newPage();
        await client.goto(url + '/login.html');
        await login(client, 'delivery-' + role, 'temporary-password');
        await expect(client).toHaveURL(/account\.html/);
        await client.fill('#current-password', 'temporary-password');
        await client.fill('#new-password', 'changed-password');
        await client.fill('#confirm-password', 'changed-password');
        await client.click('#password-submit');
        await expect(client).toHaveURL(/login\.html/);
        await client.clock.install();
        let calls = 0;
        client.on('request', r => { if(r.url().endsWith('/delivery-health')) calls++; });
        await login(client, 'delivery-' + role, 'changed-password');
        await expect(client.locator('#current-user')).toContainText('delivery-' + role);
        if(role === 'viewer') {
          await client.clock.runFor(61000);
          await expect(client.locator('#deliveryHealth')).toBeHidden();
          expect(calls).toBe(0);
          expect((await client.request.get(url + '/api/v1/delivery-health')).status()).toBe(403);
        } else {
          await expect(client.locator('#deliveryDetails')).toContainText('Pending: 2');
          expect((await client.request.get(url + '/api/v1/delivery-health')).status()).toBe(200);
          await expect(client.locator('#alertsSection')).toBeHidden();
        }
      } finally { await context.close(); }
    }
  });
});

test('strict malformed fields, unsafe counts and unknown loss do not become zero or HTML', async ({page}) => {
  await owner('backlog', async url => {
    let mode = 'missing';
    await page.route('**/delivery-health', async route => {
      const response = await route.fetch();
      const h = await response.json();
      if(mode === 'missing') delete h.pending;
      if(mode === 'malicious') h.last_error = '<img src=x onerror=alert(1)>PRIVATE-CANARY';
      if(mode === 'precision') {
        h.missed_total = Number.MAX_SAFE_INTEGER + 1;
        h.capacity.max_receipts = 0;
        h.channels.misp.last_error = 'provider_tls';
        h.accounting_complete = false;
      }
      await route.fulfill({response, json:h});
    });
    await page.clock.install();
    await page.goto(url + '/login.html');
    await login(page);
    await expect(page.locator('#deliveryStatus')).toContainText('unavailable');
    await expect(page.locator('#deliveryDetails')).toContainText('Unknown');
    mode = 'malicious';
    await page.evaluate(() => {
      window.healthStatusWrites = 0;
      new MutationObserver(() => window.healthStatusWrites++).observe(document.getElementById('deliveryStatus'), {childList:true});
    });
    await page.clock.runFor(15001);
    await expect.poll(() => page.evaluate(() => window.healthStatusWrites)).toBe(1);
    await expect(page.locator('#deliveryHealth')).not.toContainText('PRIVATE-CANARY');
    await expect(page.locator('#deliveryHealth img')).toHaveCount(0);
    mode = 'precision';
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryDetails')).toContainText('precision unavailable');
    await expect(page.locator('#deliveryDetails')).toContainText('lower bound');
    await expect(page.locator('#deliveryDetails')).toContainText('Receipt capacity: unknown');
    await expect(page.locator('#deliveryDetails')).toContainText('provider tls');
    await expect(page.locator('#deliveryDetails')).not.toContainText('9007199254740992');
    mode = 'good';
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    // Recovery cannot erase uncertainty already observed in this document.
    await expect(page.locator('#deliveryDetails')).toContainText('lower bound');
  });
});

test('permission revocation stops polling rather than repeatedly emitting 403', async ({page}) => {
  await owner('backlog', async url => {
    await page.clock.install();
    await page.goto(url + '/login.html');
    await login(page);
    await expect(page.locator('#deliveryDetails')).toContainText('Pending: 2');
    let denied = 0;
    await page.route('**/delivery-health', route => { denied++; return route.fulfill({status:403, body:'PRIVATE-DENIAL'}); });
    await page.clock.runFor(15001);
    await expect(page.locator('#deliveryHealth')).toBeHidden();
    await page.clock.runFor(61000);
    expect(denied).toBe(1);
  });
});

test('delivery starts unknown and absent owner is never healthy or zero', async ({page}) => {
  await owner('noowner', async url => {
    await page.goto(url + '/login.html');
    await login(page);
    await expect(page.locator('#deliveryHealth')).toBeVisible();
    await expect(page.locator('#deliveryStatus')).toContainText('unavailable');
    await expect(page.locator('#deliveryDetails')).toContainText('Unknown');
    await expect(page.locator('#deliveryHealth')).toContainText('Observation continues');
    await expect(page.locator('#deliveryHealth')).not.toContainText('0');
    await expect(page.locator('#deliveryHealth button')).toHaveCount(0);
  });
});
