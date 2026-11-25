'use strict';
// Component seam: ONLY /ai/settings is intercepted. No provider/API E2E claim.
const {chromium, expect} = require('@playwright/test');
const {spawnSync} = require('node:child_process');
const assert = require('node:assert/strict');
const origin = process.env.AI_SETTINGS_ORIGIN;
const scenario = process.env.AI_SETTINGS_SCENARIO;
function produce(value = {}) {
  const result = spawnSync(process.env.AI_SETTINGS_PYTHON,
    ['-B', 'tests/ai_settings_ui_fixture.py'], {input:JSON.stringify(value), encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
(async () => {
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext();
  const errors = [], requests = [], consoleMessages = [];
  context.on('request', r => requests.push({url:r.url(), method:r.method(), body:r.postData()}));
  context.on('page', page => {
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => consoleMessages.push(m.text()));
  });
  const remote = {enabled:true, provider:'openai_compatible', base_url:'https://gateway.example.test/v1',
    model:'fixture-model', endpoint_policy:'public_https', token_limit_field:'max_completion_tokens', api_key:'SYNTHETIC-UI-SAVED-KEY'};
  let state = produce(['inert-load','remote-save'].includes(scenario) ? {} : {stored:remote});
  if(scenario === 'native-loaded') state = produce({stored:{provider:'ollama', enabled:true,
    base_url:'http://127.0.0.1:11434', model:'fixture:local', model_digest:'a'.repeat(64)}});
  if(scenario === 'loopback-anonymous') state = produce({stored:{provider:'openai_compatible', enabled:true,
    base_url:'http://localhost:11434/v1', model:'fixture-model', endpoint_policy:'loopback'}});
  await context.addInitScript(() => {
    window.secretStorageViolations = 0;
    const set = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value){
      if(String(key).includes('SYNTHETIC-UI-') || String(value).includes('SYNTHETIC-UI-')) window.secretStorageViolations++;
      return set.call(this, key, value);
    };
  });
  let gets = 0, posts = [], postHook = null, getHook = null;
  await context.route('**/ai/settings', async route => {
    if(route.request().method() === 'POST') {
      const data = route.request().postDataJSON(); posts.push(data);
      if(postHook) return postHook(route, data);
      assert.equal(data.revision, state.revision);
      try {
        state = produce({stored:state.stored, revision:state.revision,
          patch:data.settings, clear_fields:data.clear_fields});
      } catch(_) {
        await route.fulfill({status:400, contentType:'application/json', body:'{"code":"invalid_request"}'});
        return;
      }
      await route.fulfill({contentType:'application/json', body:state.wire});
    } else {
      gets++;
      if(getHook) return getHook(route);
      await route.fulfill({contentType:'application/json', body:produce({stored:state.stored, revision:state.revision}).wire});
    }
  });
  try {
    const page = await context.newPage();
    await page.goto(origin + '/login.html');
    await expect(page.locator('#login-submit')).toBeEnabled();
    await page.locator('#username').fill(scenario.startsWith('auth-') ? 'fixture-role' : 'fixture');
    await page.locator('#password').fill('fixture-only-password');
    await page.locator('#login-submit').click();
    await page.waitForURL('**/dns_frontend.html');
    await page.waitForLoadState('load');
    let initialRelease, initialEntered = false;
    if(scenario === 'initial-gate') {
      const gate = new Promise(resolve => { initialRelease = resolve; });
      getHook = async route => { initialEntered = true; await gate; await route.fulfill({contentType:'application/json', body:state.wire}); };
    }
    await page.goto(origin + '/dns_frontend.html#settings-ai');
    if(scenario === 'inert-load') {
      await expect(page.locator('#aiSettingsSection')).toBeVisible();
      await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', false);
      await expect(page.locator('#aiProvider')).toHaveValue('ollama');
      await expect(page.locator('#aiBaseURL')).toHaveValue('');
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      await page.locator('#settingsTabDomains').click();
      await page.locator('#settingsTabAI').click();
      assert.equal(gets, 1, 'switching tabs must not silently reload');
      await page.locator('#loadAISettings').click();
      await expect.poll(() => gets).toBe(2);
      await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', false);
      const inert = await browser.newContext({javaScriptEnabled:false, storageState:await context.storageState()});
      try {
        const p = await inert.newPage();
        await p.goto(origin + '/dns_frontend.html#settings-ai');
        await expect(p.locator('#aiSettingsFields')).toHaveJSProperty('disabled', true);
        await expect(p.locator('#saveAISettings')).toBeDisabled();
        await expect(p.locator('#aiApiKey')).toBeDisabled();
        assert.equal(await p.locator('#aiApiKey').getAttribute('name'), null);
        await expect(p.locator('#aiSettingsForm')).toHaveAttribute('method', 'post');
        // Adversarial absent-handler control: even if another script enables
        // the native controls, ordinary typing/Enter must not serialize a key.
        await p.evaluate(() => {
          document.getElementById('settings').classList.add('active');
          document.getElementById('aiSettingsSection').style.display = 'block';
          document.getElementById('aiRemoteFields').hidden = false;
          document.getElementById('aiSettingsFields').disabled = false;
          document.getElementById('saveAISettings').disabled = false;
        });
        await p.locator('#aiApiKey').fill('SYNTHETIC-UI-NATIVE-CANARY');
        const native = p.waitForRequest(r => r.url().endsWith('/ai/settings'));
        await p.locator('#aiApiKey').press('Enter');
        const attempted = await native;
        assert.equal(attempted.method(), 'POST');
        assert.ok(!(attempted.postData() || '').includes('SYNTHETIC-UI-'));
        assert.ok(!attempted.url().includes('SYNTHETIC-UI-'));
      } finally { await inert.close(); }
      assert.equal(posts.length, 0);
    } else if(scenario === 'remote-save') {
      await expect(page.locator('#aiProvider')).toBeEnabled();
      await page.locator('#aiProvider').selectOption('openai_compatible');
      await expect(page.locator('#aiRemoteFields')).toBeVisible();
      await expect(page.locator('#aiNativeFields')).not.toBeVisible();
      await page.locator('#aiEnabled').check();
      await page.locator('#aiBaseURL').fill('https://gateway.example.test/tenant/v1/');
      await page.locator('#aiModel').fill('fixture-model');
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.deepEqual(posts, [{revision:0, settings:{enabled:true, provider:'openai_compatible',
        base_url:'https://gateway.example.test/tenant/v1/', model:'fixture-model',
        endpoint_policy:'public_https', token_limit_field:'max_completion_tokens', api_key:'SYNTHETIC-UI-KEY-A'}}]);
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      await page.locator('#loadAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      await expect(page.locator('#aiKeyConfigured')).toContainText('configured');
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      assert.equal(gets, 2);
      assert.ok(!state.wire.includes('SYNTHETIC-UI-KEY-A'));
      assert.ok(!(await page.locator('body').innerText()).includes('SYNTHETIC-UI-KEY-A'));
    } else if(scenario === 'binding-clear') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await page.locator('#aiModel').fill('new-model');
      await page.locator('#aiApiKey').fill('   ');
      await page.locator('#aiTokenLimitField').selectOption('max_tokens');
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.equal(state.stored.api_key, remote.api_key);
      assert.equal(posts[0].settings.api_key, undefined);
      await page.locator('#aiBaseURL').fill(remote.base_url + '/');
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('replacement');
      assert.equal(posts.length, 1, 'destination binding must refuse before POST');
      await page.locator('#aiEnabled').uncheck();
      await page.locator('#aiClearKey').check();
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.deepEqual(posts[1].clear_fields, ['api_key']);
      assert.equal(state.stored.api_key, undefined);
      await page.locator('#aiProvider').selectOption('ollama');
      await page.locator('#aiBaseURL').fill('http://127.0.0.1:11434');
      await page.locator('#aiModel').fill('fixture:local');
      await page.locator('#aiModelDigest').fill('a'.repeat(64));
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.equal(posts[2].settings.endpoint_policy, undefined);
      assert.equal(posts[2].settings.token_limit_field, undefined);
      assert.equal(state.stored.provider, 'ollama');
    } else if(scenario === 'write-later') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      let release;
      const gate = new Promise(resolve => { release = resolve; });
      postHook = async (route, data) => {
        state = produce({stored:state.stored, revision:state.revision, patch:data.settings});
        await gate;
        await route.fulfill({contentType:'application/json', body:state.wire});
      };
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#saveAISettings').click();
      await expect.poll(() => posts.length).toBe(1);
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-B');
      await page.locator('#aiModel').fill('later-draft');
      release();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Later draft retained');
      await expect(page.locator('#aiModel')).toHaveValue('later-draft');
      await expect(page.locator('#aiApiKey')).toHaveValue('SYNTHETIC-UI-KEY-B');
      await expect(page.locator('#saveAISettings')).toBeDisabled();
      assert.equal(posts[0].revision, 0);
      assert.equal(posts[0].settings.model, 'fixture-model');
      assert.equal(posts[0].settings.api_key, 'SYNTHETIC-UI-KEY-A');
      await page.locator('#loadAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await expect(page.locator('#saveAISettings')).toBeEnabled();
    } else if(scenario.startsWith('error-')) {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await page.locator('#aiModel').fill('unsaved-model');
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      const kind = scenario.slice(6);
      postHook = async (route, data) => {
        if(kind === 'network') return route.abort('failed');
        if(kind === 'audit') state = produce({stored:state.stored, revision:state.revision, patch:data.settings});
        await route.fulfill({status:kind === 'audit' ? 503 : Number(kind), contentType:'application/json',
          headers:kind === 'audit' ? {'X-TraceDNS-Security-Error':'security_unavailable'} : {},
          body:JSON.stringify({code:kind === '409' ? 'config_revision_conflict' : 'invalid_request',
            revision:99, error:'SYNTHETIC-ERROR-DO-NOT-ECHO'})});
      };
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText(kind === '409' ? 'Conflict' : kind === '400' ? 'Invalid settings' : 'outcome unknown');
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      await expect(page.locator('#aiModel')).toHaveValue('unsaved-model');
      if(kind !== '400') await expect(page.locator('#saveAISettings')).toBeDisabled();
      assert.equal(posts.length, 1);
      assert.equal(gets, 1, 'no automatic reload/rebase after failure');
      assert.ok(!(await page.locator('body').innerText()).includes('SYNTHETIC-ERROR-DO-NOT-ECHO'));
      await page.locator('#loadAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      await expect(page.locator('#saveAISettings')).toBeEnabled();
      await expect(page.locator('#aiModel')).toHaveValue(kind === 'audit' ? 'unsaved-model' : 'fixture-model');
    } else if(scenario === 'closed-receipts') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      const mutations = [
        j => { j.settings.api_key = 'SYNTHETIC-UNEXPECTED-KEY'; },
        j => { j.extra = true; }, j => { j.revision = '1'; }, j => { j.revision = -1; },
        j => { j.settings.configured.api_key = 'true'; }, j => { j.settings.configured.extra = false; },
        j => { j.settings.provider = 'unknown'; }, j => { j.settings.model = null; },
        j => { delete j.settings.endpoint_policy; }, j => { j.settings.token_limit_field = 'unknown'; },
        j => { j.settings.model_digest = ''; }, j => { j.runtime.state = 'connected'; },
        j => { j.runtime.applied = 1; }, j => { j.runtime.secret = 'bad'; },
      ];
      for(const mutate of mutations) {
        const receipt = JSON.parse(produce({stored:state.stored}).wire); mutate(receipt);
        getHook = route => route.fulfill({contentType:'application/json', body:JSON.stringify(receipt)});
        await page.locator('#loadAISettings').click();
        await expect(page.locator('#aiSettingsStatus')).toContainText('Load failed');
        await expect(page.locator('#saveAISettings')).toBeDisabled();
        await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      }
      getHook = null;
      for(const mutate of [
        j => { j.settings.model = 'foreign-valid-model'; }, j => { j.revision += 1; },
        j => { j.warnings = ['not_a_warning']; }, j => { j.warnings = ['ai_provider_unsettled','ai_provider_unsettled']; },
        j => { j.settings.configured.api_key = false; }, j => { delete j.status; }
      ]) {
        await page.locator('#loadAISettings').click();
        await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
        postHook = async (route, data) => {
          const j = JSON.parse(produce({stored:state.stored, revision:state.revision, patch:data.settings}).wire);
          mutate(j);
          await route.fulfill({contentType:'application/json', body:JSON.stringify(j)});
        };
        await page.locator('#saveAISettings').click();
        await expect(page.locator('#aiSettingsStatus')).toContainText('outcome unknown');
        await expect(page.locator('#saveAISettings')).toBeDisabled();
        await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      }
    } else if(['read-later','read-order'].includes(scenario)) {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      let release, entered = false;
      const gate = new Promise(resolve => { release = resolve; });
      const oldWire = produce({stored:{...remote, model:'old-read'}, revision:1}).wire;
      getHook = async route => { entered = true; await gate; await route.fulfill({contentType:'application/json', body:oldWire}); };
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#loadAISettings').click();
      await expect.poll(() => entered).toBe(true);
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      await expect(page.locator('#saveAISettings')).toBeDisabled();
      if(scenario === 'read-later') {
        await page.locator('#aiModel').fill('later-read-draft');
        await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-B');
        release();
        await expect(page.locator('#aiSettingsStatus')).toContainText('Later draft retained');
        await expect(page.locator('#aiModel')).toHaveValue('later-read-draft');
        await expect(page.locator('#aiApiKey')).toHaveValue('SYNTHETIC-UI-KEY-B');
        await expect(page.locator('#saveAISettings')).toBeDisabled();
      } else {
        const aborted = page.waitForEvent('requestfailed', {predicate:r => r.url().endsWith('/ai/settings')});
        getHook = route => route.fulfill({contentType:'application/json', body:produce({stored:{...remote, model:'new-read'}, revision:2}).wire});
        await page.locator('#loadAISettings').click();
        await aborted;
        release();
        await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
        await expect(page.locator('#aiModel')).toHaveValue('new-read');
        await expect(page.locator('#saveAISettings')).toBeEnabled();
      }
    } else if(scenario.startsWith('retire-')) {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      let release;
      const gate = new Promise(resolve => { release = resolve; });
      postHook = async (route, data) => {
        const wire = produce({stored:state.stored, revision:state.revision, patch:data.settings}).wire;
        await gate;
        await route.fulfill({contentType:'application/json', body:wire});
      };
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#saveAISettings').click();
      await expect.poll(() => posts.length).toBe(1);
      await expect(page.locator('#loadAISettings')).toBeDisabled();
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-B');
      if(scenario === 'retire-hide') await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
      else {
        getHook = route => route.fulfill({status:403, contentType:'application/json', body:'{"error":"forbidden"}'});
        await page.evaluate(() => fetch('/ai/settings').catch(() => {}));
      }
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', true);
      release();
      await expect(page.locator('#saveAISettings')).toBeDisabled();
      await expect(page.locator('#loadAISettings')).toBeDisabled();
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow')));
      if(scenario === 'retire-hide') {
        await expect(page.locator('#loadAISettings')).toBeEnabled();
        await expect(page.locator('#saveAISettings')).toBeDisabled();
        await page.locator('#loadAISettings').click();
        await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      } else await expect(page.locator('#loadAISettings')).toBeDisabled();
    } else if(scenario === 'provider-switch') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#aiProvider').selectOption('ollama');
      await expect(page.locator('#aiApiKey')).toHaveValue('');
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('replacement');
      assert.equal(posts.length, 0);
    } else if(scenario === 'runtime-reflow') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await page.locator('#deliveryOperations > summary').click();
      await page.locator('#deliveryLocalAI').click();
      await expect(page.locator('#deliveryLocalAIPanel')).not.toBeEmpty();
      for(const mode of ['ready','disabled','draining','unsettled','unavailable','stopped']) {
        postHook = async (route, data) => {
          state = produce({stored:state.stored, revision:state.revision, patch:data.settings,
            runtime:{applied:mode !== 'unavailable', state:mode}});
          const j = JSON.parse(state.wire);
          j.warnings = mode === 'unavailable' ? ['ai_runtime_apply_failed'] : mode === 'draining' ? ['ai_previous_call_draining'] : mode === 'unsettled' ? ['ai_provider_unsettled'] : [];
          await route.fulfill({contentType:'application/json', body:JSON.stringify(j)});
        };
        await page.locator('#saveAISettings').click();
        await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
        await expect(page.locator('#aiSettingsRuntime')).toContainText(mode);
        await expect(page.locator('#aiSettingsRuntime')).toContainText('not a connection test');
        if(mode === 'unavailable') await expect(page.locator('#aiSettingsRuntime')).toContainText('ai_runtime_apply_failed');
      }
      await expect(page.locator('#deliveryLocalAIPanel')).toBeEmpty();
      assert.ok(!(await page.locator('#deliveryLocalAI').innerText()).includes('Local AI'));
      assert.ok(!(await page.locator('#decoderLocalAI').innerText()).includes('Local AI'));
      for(const lang of ['en','ko']) {
        await page.evaluate(lang => { document.documentElement.lang = lang; }, lang);
        for(const width of [1280, 390]) {
          await page.setViewportSize({width,height:900});
          for(const id of ['aiSettingsForm','aiApiKey','aiBaseURL','aiTokenLimitField','aiSettingsHelp']) {
            const geometry = await page.locator('#'+id).evaluate(el => {
              const b = el.getBoundingClientRect();
              return {fits:el.scrollWidth <= el.clientWidth + 1, left:b.left, right:b.right, viewport:innerWidth};
            });
            assert.ok(geometry.fits && geometry.left >= 0 && geometry.right <= geometry.viewport, JSON.stringify({id,lang,width,geometry}));
          }
          await expect(page.getByLabel('Replacement API key · 교체 API 키', {exact:true})).toBeVisible();
          await expect(page.getByLabel('Base URL · 기본 URL', {exact:true})).toBeVisible();
          await page.screenshot({path:process.env.AI_SETTINGS_OUTPUT + '/' + lang + '-' + width + '.png', fullPage:true});
        }
      }
    } else if(scenario === 'unrelated-drafts') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await expect.poll(() => page.evaluate(() => [configRevision,alertRevision,decoderRevision].every(v => v !== null))).toBe(true);
      await page.locator('#aiModel').fill('ai-dirty-model');
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#settingsTabDomains').click();
      await page.locator('#load').click();
      await expect(page.locator('#domainSettingsStatus')).toContainText('Loaded');
      await page.locator('#settingsTabAlerts').click();
      await page.locator('#alertIntegrationAdvanced > summary').click();
      await page.locator('#push_event_id_front').fill('77');
      await page.locator('#saveAlertSettingsBtn').click();
      await expect(page.locator('#alertSettingsStatus')).toContainText('Saved');
      const otherRevisions = await page.evaluate(() => [configRevision,alertRevision,decoderRevision]);
      assert.equal(otherRevisions[1], 1);
      state = produce({stored:remote, revision:1});
      postHook = async (route,data) => {
        assert.equal(data.revision, 0, 'unrelated save must not rebase AI');
        await route.fulfill({status:409, contentType:'application/json', body:JSON.stringify({code:'config_revision_conflict', revision:1})});
      };
      await page.locator('#settingsTabAI').click();
      await expect(page.locator('#aiModel')).toHaveValue('ai-dirty-model');
      await expect(page.locator('#aiApiKey')).toHaveValue('SYNTHETIC-UI-KEY-A');
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Conflict');
      await expect(page.locator('#aiModel')).toHaveValue('ai-dirty-model');
      await page.locator('#loadAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      postHook = null;
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.deepEqual(await page.evaluate(() => [configRevision,alertRevision,decoderRevision]), otherRevisions);
      await expect(page.locator('#push_event_id_front')).toHaveValue('77');
      assert.equal(gets, 2);
    } else if(scenario === 'conflict-key-aba') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      let release;
      const gate = new Promise(resolve => { release = resolve; });
      postHook = async route => { await gate; await route.fulfill({status:409, contentType:'application/json', body:'{"code":"config_revision_conflict","revision":99}'}); };
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.locator('#saveAISettings').click();
      await expect.poll(() => posts.length).toBe(1);
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-B');
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      release();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Conflict');
      await expect(page.locator('#aiApiKey')).toHaveValue('SYNTHETIC-UI-KEY-A');
      await expect(page.locator('#saveAISettings')).toBeDisabled();
    } else if(scenario.startsWith('auth-')) {
      await expect(page.locator('#settingsTabAI')).toBeHidden();
      await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', true);
      await expect(page.locator('#saveAISettings')).toBeDisabled();
      assert.equal(gets, 0); assert.equal(posts.length, 0);
    } else if(scenario === 'initial-gate') {
      await expect.poll(() => initialEntered).toBe(true);
      await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', true);
      await expect(page.locator('#aiApiKey')).toBeDisabled();
      assert.equal(posts.length, 0);
      initialRelease();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      await expect(page.locator('#aiSettingsFields')).toHaveJSProperty('disabled', false);
    } else if(scenario === 'logout') {
      await expect(page.locator('#aiModel')).toHaveValue('fixture-model');
      await page.locator('#aiApiKey').fill('SYNTHETIC-UI-KEY-A');
      await page.evaluate(() => document.addEventListener('click', event => {
        if(event.target.closest('#logout')) sessionStorage.setItem('test-logout-cleared',
          document.getElementById('aiApiKey').value === '' ? '1' : '0');
      }));
      await page.locator('#accountMenu > summary').click();
      await page.locator('#logout').click();
      await page.waitForURL('**/login.html');
      assert.equal(await page.evaluate(() => sessionStorage.getItem('test-logout-cleared')), '1');
      assert.equal(posts.length, 0);
    } else if(scenario === 'native-loaded') {
      await expect(page.locator('#aiProvider')).toHaveValue('ollama');
      await expect(page.locator('#aiModelDigest')).toHaveValue('a'.repeat(64));
      await expect(page.locator('#aiEnabled')).toBeChecked();
      await page.locator('#aiEnabled').uncheck();
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.deepEqual(posts[0].settings, {provider:'ollama', enabled:false,
        base_url:'http://127.0.0.1:11434', model:'fixture:local', model_digest:'a'.repeat(64)});
      await page.locator('#loadAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Loaded');
      await expect(page.locator('#aiModelDigest')).toHaveValue('a'.repeat(64));
    } else if(scenario === 'loopback-anonymous') {
      await expect(page.locator('#aiEndpointPolicy')).toHaveValue('loopback');
      await expect(page.locator('#aiEnabled')).toBeChecked();
      await page.locator('#saveAISettings').click();
      await expect(page.locator('#aiSettingsStatus')).toContainText('Saved');
      assert.equal(posts[0].settings.api_key, undefined);
      assert.equal(state.stored.api_key, undefined);
      await expect(page.locator('#aiKeyConfigured')).toContainText('not configured');
    } else throw new Error('unknown scenario');
    const secretSurface = await page.evaluate(() => ({
      storage:JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]),
      writes:window.secretStorageViolations, url:location.href,
      attrs:[...document.querySelectorAll('*')].flatMap(el => [...el.attributes].map(a => a.value)).join(' '),
      text:document.body.innerText,
      genericDraft:typeof settingsDraftStamp === 'function' ? settingsDraftStamp('settings') : ''
    }));
    assert.equal(secretSurface.writes, 0);
    for(const value of [secretSurface.storage, secretSurface.url, secretSurface.attrs, secretSurface.text,
      secretSurface.genericDraft, ...consoleMessages]) assert.ok(!value.includes('SYNTHETIC-UI-'), 'secret reached a public/persistent surface');
    assert.equal(requests.filter(r => r.url.includes('SYNTHETIC-UI-') || (r.method === 'GET' && (r.body || '').includes('SYNTHETIC-UI-'))).length, 0);
    assert.deepEqual(errors, []);
    assert.equal(requests.filter(r => /\/ai\/jobs|\/api\/tags|\/api\/chat|\/chat\/completions|\/models(?:\?|$)/.test(r.url)).length, 0);
    console.log(JSON.stringify({scope:'component-only', scenario, gets, posts:posts.length, pageErrors:errors.length, providerRequests:0}));
  } finally { await context.close(); await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
