'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const [mode, root, origin, out] = process.argv.slice(2);
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const drain = async () => { for(let i=0;i<50;i++) await Promise.resolve(); };

async function subscribers() {
  let attempts = 0, now = 0, delivered = 0, removed = 0, late = 0;
  const user = {role:'admin', username:'fixture'};
  const context = vm.createContext({URL, Request, Response, Headers, AbortController, DOMException,
    setTimeout, clearTimeout, console, Date:class extends Date {static now(){return now;}},
    location:{href:'http://localhost/dns_frontend.html',origin:'http://localhost',pathname:'/dns_frontend.html',replace(){}},
    document:{getElementById(){return null;}},
    fetch:async url => {
      if(String(url).endsWith('/auth/me')) {
        if(++attempts === 1) throw new Error('transient test transport failure');
        return new Response(JSON.stringify({csrf_token:'fixture-token', user}));
      }
      return new Response('{}', {status:403});
    },
  });
  context.window = context;
  const source = fs.readFileSync(path.join(root, 'auth_frontend.js'), 'utf8');
  vm.runInContext(source, context);
  const auth = context.TraceAuth;
  await assert.rejects(auth.ready);
  assert.equal(typeof auth.onReady, 'function', 'one-shot readiness consumers need successful recovery notification');
  auth.onReady(() => { throw new Error('failing subscriber'); });
  auth.onReady(async () => { throw new Error('async failing subscriber'); });
  const unsubscribe = auth.onReady(actual => { assert.equal(actual.role,'admin'); delivered++; });
  const remove = auth.onReady(() => removed++);
  remove(); remove();
  assert.equal(delivered, 0, 'failure is not readiness');
  await assert.rejects(auth.ready);
  assert.equal(attempts, 1, 'subscriber registration cannot bypass auth backoff');
  now = 1000;
  assert.equal((await auth.ready).role, 'admin');
  await drain();
  assert.equal(delivered, 1, 'subscriber exception must not skip the next owner');
  assert.equal(removed, 0);
  assert.equal(auth.user.role, 'admin', 'subscriber exception cannot poison auth');
  const removeLate = auth.onReady(() => late++);
  const removeBeforeDelivery = auth.onReady(() => removed++);
  removeBeforeDelivery();
  await drain();
  assert.equal(late, 1, 'late registration must observe successful auth');
  assert.equal(removed, 0, 'queued late delivery respects disposal');
  await auth.ready; await auth.ready; await drain();
  assert.equal(delivered, 1); assert.equal(late, 1); assert.equal(attempts, 2);
  unsubscribe(); removeLate();
  await assert.rejects(context.fetch('/forbidden'));
  auth.onReady(() => removed++);
  await drain();
  assert.equal(auth.accessInvalidated, true);
  assert.equal(removed, 0, 'invalidated access is not successful readiness');
  console.log(JSON.stringify({mode, passed:true, attempts, delivered, late, source_sha256:digest(source)}));
}

async function browserRegression() {
  const {chromium, expect} = require(path.join(root, 'node_modules/@playwright/test'));
  const browser = await chromium.launch({headless:true});
  let context, page;
  const requests = [], errors = [], sources = [], pendingSources = [];
  const report = {scope:'real-server-auth-settings', passed:false};
  try {
    context = await browser.newContext();
    page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => requests.push({path:new URL(request.url()).pathname, method:request.method()}));
    const cdp = await context.newCDPSession(page);
    cdp.on('Debugger.scriptParsed', event => {
      if(!event.url) return;
      const name = new URL(event.url).pathname.slice(1);
      if(!['dns_frontend.js','auth_frontend.js'].includes(name)) return;
      pendingSources.push(cdp.send('Debugger.getScriptSource', {scriptId:event.scriptId}).then(result => {
        const bytes = Buffer.from(result.scriptSource);
        const expected = fs.readFileSync(path.join(root, name));
        sources.push({name, url:event.url, sha256:digest(bytes), expected_sha256:digest(expected)});
        assert(bytes.equals(expected), 'executed JS must equal the tested source');
      }).catch(error => { errors.push(String(error)); }));
    });
    await cdp.send('Debugger.enable');
    await page.goto(origin + '/login.html');
    await expect(page.locator('#login-submit')).toBeEnabled();
    await page.locator('#username').fill('fixture');
    await page.locator('#password').fill('fixture-only-password');
    await page.locator('#login-submit').click();
    await page.waitForURL('**/dns_frontend.html');
    await page.waitForLoadState('load');
    await context.addInitScript(() => {
      window.aiRecoveryStatuses = [];
      new MutationObserver(() => {
        const text = document.getElementById('aiSettingsStatus')?.textContent;
        if(text && window.aiRecoveryStatuses.at(-1) !== text) window.aiRecoveryStatuses.push(text);
      }).observe(document, {childList:true, subtree:true, characterData:true});
    });
    let faults = 0;
    await context.route('**/auth/me', route => !faults++ ? route.abort('failed') : route.continue());
    await page.goto(origin + '/dns_frontend.html#settings-ai');
    // Finish the previous document's hash-triggered read before the new lifetime.
    await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
    requests.length = 0;
    await page.reload(); // Same hash alone does not create a new auth lifetime.
    await expect(page.locator('#current-user')).toContainText('fixture (admin)', {timeout:12000});
    assert.equal(await page.evaluate(() => TraceAuth.user.role), 'admin');
    assert(faults >= 2, 'actual auth retry must complete');
    report.auth_requests = faults;
    report.status_history = await page.evaluate(() => window.aiRecoveryStatuses);
    // No tab switch, visibility workaround, synthetic click or private-state repair.
    await expect(page.locator('#loadAISettings')).toBeEnabled();
    assert(report.status_history.some(text => /Load failed/.test(text)), 'failed auth must leave truthful retryable feedback');
    await expect(page.locator('#aiSettingsStatus')).toContainText('explicitly Load');
    await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', true);
    await expect(page.locator('#saveAISettings')).toBeDisabled();
    assert.equal(requests.filter(r => r.path === '/ai/settings').length, 0, 'recovery cannot auto-load or save');
    await expect(page.locator('#security-nav')).toHaveCount(1);
    const receipt = page.waitForResponse(r => new URL(r.url()).pathname === '/ai/settings');
    await page.locator('#loadAISettings').click();
    const response = await receipt;
    assert.equal(response.status(), 200);
    const wire = await response.json();
    assert.equal(wire.revision, 0);
    await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
    await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', false);
    await expect(page.locator('#saveAISettings')).toBeEnabled();
    assert.equal(requests.filter(r => r.path === '/ai/settings' && r.method === 'GET').length, 1);
    assert(!requests.some(r => r.path === '/ai/settings' && r.method === 'POST'));
    assert(!requests.some(r => r.path.startsWith('/ai/jobs')));
    assert.deepEqual(errors, []);
    report.passed = true;
  } finally {
    try {
      await Promise.all(pendingSources);
      if(report.passed) for(const name of ['dns_frontend.js','auth_frontend.js']) assert(sources.some(row => row.name === name));
      report.passed = report.passed && errors.length === 0;
      fs.writeFileSync(path.join(out, 'auth-recovery.json'), JSON.stringify({...report, errors, requests, sources}, null, 2));
      assert.deepEqual(errors, [], 'page execution and exact source observation must succeed');
    } finally {
      try { if(context) await context.close(); } finally { await browser.close(); }
    }
  }
}

async function ownerFences(owner) {
  const receipts = JSON.parse(fs.readFileSync(0, 'utf8'));
  const nodes = new Map(), windowEvents = new Map(), documentEvents = new Map();
  const active = new Set(), registered = [], invalidators = [], calls = [];
  const listen = (map, name, fn) => { if(!map.has(name)) map.set(name, []); map.get(name).push(fn); };
  const fire = (map, name, event = {}) => { for(const fn of map.get(name) || []) fn(event); };
  const node = id => {
    if(!nodes.has(id)) {
      const events = new Map();
      nodes.set(id, {id, events, value:'', checked:false, textContent:'', hidden:false, isConnected:true,
        disabled:['aiSettingsFields','saveAISettings','loadAISettings'].includes(id),
        addEventListener:(name, fn) => listen(events, name, fn), matches:() => true});
    }
    return nodes.get(id);
  };
  const auth = {user:null, accessInvalidated:false,
    ready:Promise.reject(new Error('transient initial auth failure')),
    onReady:fn => { active.add(fn); registered.push(fn); return () => active.delete(fn); },
    onInvalidated:fn => { invalidators.push(fn); },
    readJSON:(url, options) => new Promise(resolve => calls.push({url, options, resolve})),
  };
  const context = vm.createContext({AbortController, console,
    window:{TraceAuth:auth, addEventListener:(name,fn) => listen(windowEvents,name,fn)},
    document:{getElementById:node, addEventListener:(name,fn) => listen(documentEvents,name,fn)},
    retireLocalAI(){},
  });
  const source = fs.readFileSync(path.join(root, 'dns_frontend.js'), 'utf8');
  const start = source.indexOf('const aiSettingsPanel = (() => {');
  const end = source.indexOf('\nfunction settingsDraftStamp', start);
  assert(start >= 0 && end > start);
  vm.runInContext(source.slice(start, end) + '\nthis.openPanel = () => aiSettingsPanel.open();', context);
  const clickLoad = () => fire(node('loadAISettings').events, 'click');
  const submit = () => fire(node('aiSettingsForm').events, 'submit', {preventDefault(){}});
  const edit = (id, value) => { node(id).value = value; fire(node('aiSettingsForm').events, 'input', {target:node(id)}); };
  const staleNotifications = () => { for(const fn of registered) fn(auth.user); };
  context.openPanel(); await drain();
  assert.match(node('aiSettingsStatus').textContent, /Load failed/);
  assert.equal(registered.length, 1);
  assert.equal(node('loadAISettings').disabled, true);
  if(owner === 'invalidated') { auth.accessInvalidated = true; invalidators.forEach(fn => fn(403)); }
  if(owner === 'logout') fire(documentEvents, 'click', {target:{closest:selector => selector === '#logout'}});
  if(owner === 'retired') fire(windowEvents, 'pagehide');
  if(owner === 'disconnected') node('aiSettingsForm').isConnected = false;
  auth.user = owner === 'unknown' ? null : {role:['viewer','operator'].includes(owner) ? owner : 'admin', must_change_password:owner === 'password'};
  auth.ready = Promise.resolve(auth.user);
  for(const fn of [...active]) fn(auth.user);
  await drain();
  assert.equal(active.size, 0, 'each recovery subscription is disposed after delivery or retirement');
  const permitted = ['draft-pending-save','malformed-receipt'].includes(owner);
  assert.equal(node('loadAISettings').disabled, !permitted);
  assert.equal(node('aiSettingsFields').disabled, true);
  assert.equal(node('saveAISettings').disabled, true);
  assert.equal(calls.length, 0, 'notification is never a settings request');
  if(!permitted) {
    staleNotifications(); context.openPanel(); submit();
    await drain();
    assert.equal(node('loadAISettings').disabled, true);
    assert.equal(node('aiSettingsFields').disabled, true);
    assert.equal(node('saveAISettings').disabled, true);
    assert.equal(calls.length, 0);
    if(['invalidated','logout'].includes(owner)) {
      // Even a subsequent admin observation and pageshow cannot renew permanent ownership.
      auth.accessInvalidated = false;
      fire(windowEvents, 'pageshow'); staleNotifications(); clickLoad(); submit(); await drain();
      assert.equal(node('loadAISettings').disabled, true);
      assert.equal(node('aiSettingsFields').disabled, true);
      assert.equal(calls.length, 0);
    }
  } else {
    clickLoad(); await drain();
    assert.equal(calls.length, 1);
    assert.equal(node('aiSettingsFields').disabled, true, 'auth is not a settings receipt');
    calls[0].resolve(owner === 'malformed-receipt' ? {...receipts.get, revision:'7'} : receipts.get);
    await drain();
    if(owner === 'malformed-receipt') {
      staleNotifications();
      assert.match(node('aiSettingsStatus').textContent, /Load failed/);
      assert.equal(node('aiSettingsFields').disabled, true);
      assert.equal(node('saveAISettings').disabled, true);
      assert.equal(calls.length, 1);
    } else {
      assert.equal(node('aiSettingsFields').disabled, false);
      edit('aiModel', 'submitted-model'); edit('aiApiKey', 'SYNTHETIC-RECOVERY-A');
      staleNotifications(); staleNotifications();
      assert.equal(node('aiModel').value, 'submitted-model');
      assert.equal(node('aiApiKey').value, 'SYNTHETIC-RECOVERY-A');
      assert.equal(calls.length, 1);
      submit(); await drain();
      assert.equal(calls.length, 2);
      assert.equal(calls[1].options.method, 'POST');
      assert.equal(JSON.parse(calls[1].options.body).revision, 7, 'recovery cannot rebase a loaded revision');
      edit('aiModel', 'later-draft'); edit('aiApiKey', 'SYNTHETIC-RECOVERY-B'); edit('aiApiKey', 'SYNTHETIC-RECOVERY-A');
      staleNotifications(); clickLoad(); submit(); await drain();
      assert.equal(calls.length, 2, 'pending save excludes reads and repeated writes');
      assert.equal(node('loadAISettings').disabled, true);
      calls[1].resolve(receipts.post); await drain();
      staleNotifications(); submit(); await drain();
      assert.equal(node('aiModel').value, 'later-draft');
      assert.equal(node('aiApiKey').value, 'SYNTHETIC-RECOVERY-A', 'later ABA key edit survives receipt and stale notifications');
      assert.equal(node('saveAISettings').disabled, true);
      assert.match(node('aiSettingsStatus').textContent, /Later draft retained with its original revision/);
      assert.equal(calls.length, 2, 'notification cannot retry a POST or reload');
    }
  }
  console.log(JSON.stringify({scope:'extracted-panel-controlled-auth', owner, passed:true,
    calls:calls.map(call => ({url:call.url, method:call.options.method || 'GET'})), source_sha256:digest(source)}));
}

(async () => {
  if(mode.startsWith('owner-')) await ownerFences(mode.slice(6));
  else if(mode === 'subscribers') await subscribers();
  else if(mode === 'browser') await browserRegression();
  else throw new Error('Unknown test mode');
})().catch(error => { console.error(error); process.exitCode = 1; });
