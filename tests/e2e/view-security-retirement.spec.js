const {test, expect} = require('@playwright/test');
const {withViewServer, loginView} = require('./view-helpers');

async function ready(page, origin) {
  await loginView(page, origin);
  await expect.poll(() => page.evaluate(() => configRevision !== null)).toBe(true);
  await page.click('#pauseRefreshBtn');
}
async function invalidate(page) {
  await page.route('**/retirement-denied', route => route.fulfill({status:403,json:{error:'forbidden'}}));
  await page.evaluate(() => fetch('/retirement-denied').catch(() => {}));
  expect(await page.evaluate(() => TraceAuth.accessInvalidated)).toBe(true);
}
for (const entry of ['row', 'selector']) test(`Domain cache cannot reopen through ${entry} after access invalidation`, async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    await page.click('#menuDomainAnalysis');
    const row = page.locator('#domainDomainStatsTable tbody tr').filter({hasText:'target-000.test'});
    await row.getByRole('button', {name:'View',exact:true}).click();
    await page.locator('#domainAnalysisRaw > summary').click();
    // Native toggle is asynchronous: first prove the real disclosure rendered.
    await expect(page.locator('#domainAnalysisRaw pre')).toContainText('target-000.test');
    await page.evaluate(() => { window.oldDomainView = document.querySelector('#domainDomainStatsTable tbody tr button'); });
    await invalidate(page);
    await page.evaluate(entry => {
      if (entry === 'row') window.oldDomainView.click();
      else {
        const select = document.getElementById('domainAnalysisDomainSelect');
        select.value = 'target-000.test';
        select.dispatchEvent(new Event('change', {bubbles:true}));
      }
    }, entry);
    // If stale selection remounts Raw, actually await its native toggle before
    // asserting the retired payload. This makes the review's partial probe RED.
    if (await page.locator('#domainAnalysisRaw > summary').count()) {
      await page.locator('#domainAnalysisRaw > summary').click();
      await expect(page.locator('#domainAnalysisRaw pre')).toContainText('target-000.test');
    }
    await expect(page.locator('#domainAnalysisDetail')).toBeEmpty();
    expect(await page.evaluate(() => DOMAIN_ANALYSIS_CACHE.length)).toBe(0);
    expect(await page.evaluate(() => domainAnalysisPageReady)).toBe(false);
    expect(await page.evaluate(() => canManageDomainAnalysis())).toBe(false);
    await expect(page.locator('#domainAnalysisDomainSelect')).toBeDisabled();
    await page.reload();
    await expect(page.locator('#resultsTable tbody tr').first()).toBeVisible();
    await page.click('#menuDomainAnalysis');
    await row.getByRole('button', {name:'View',exact:true}).click();
    await page.locator('#domainAnalysisRaw > summary').click();
    await expect(page.locator('#domainAnalysisRaw pre')).toContainText('target-000.test');
  });
});

test('Prepared Status and IP caches retire and reject refresh while permission is unknown', async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    await page.locator('#resultsTable tbody tr').first().getByRole('button', {name:'Details',exact:true}).click();
    await page.click('#menuIPs');
    await expect(page.locator('#ipsTable tbody tr').first()).toBeVisible();
    await page.click('#menuValidIPs');
    await expect.poll(() => page.evaluate(() => preparedViews.has('validips'))).toBe(true);
    await invalidate(page);
    const requests = [];
    page.on('request', request => { if (['/results','/ips','/domain-analysis'].includes(new URL(request.url()).pathname)) requests.push(request.url()); });
    await page.evaluate(async () => {
      openTargetDetail('target-000.test', null);
      await Promise.all([refreshResults(), refreshIPs(), refreshValidIPs(), refreshDomainAnalysis()]);
    });
    await expect(page.locator('#targetDetail')).toBeEmpty();
    await expect(page.locator('#resultsTable tbody tr, #ipsTable tbody tr, #validIpsTable tbody tr')).toHaveCount(0);
    expect(await page.evaluate(() => preparedViews.size)).toBe(0);
    expect(await page.evaluate(() => statusPageRows.size)).toBe(0);
    expect(requests).toEqual([]);
  });
});

// Hold the real decoded body after the shared auth wrapper accepted headers.
async function holdBody(page, pathname, method, bodyMethod = 'json', beforeLoad = false) {
  const install = ({pathname, method, bodyMethod}) => {
    const original = window.fetch;
    window.fetch = async (input, options) => {
      const response = await original(input, options);
      if (new URL(input instanceof Request ? input.url : input, location.href).pathname !== pathname || (options?.method || 'GET') !== method) return response;
      return new Proxy(response, {get(target, key) {
        if (key === bodyMethod) return () => new Promise((resolve, reject) => {
          window.releaseRetirementBody = () => target[bodyMethod]().then(resolve, reject);
        });
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }});
    };
  };
  if (beforeLoad) await page.addInitScript(install, {pathname, method, bodyMethod});
  else await page.evaluate(install, {pathname, method, bodyMethod});
}
async function bodyReached(page) {
  await expect.poll(() => page.evaluate(() => !!window.releaseRetirementBody)).toBe(true);
}
async function releaseBody(page) {
  await page.evaluate(async () => { await window.releaseRetirementBody(); await new Promise(resolve => setTimeout(resolve, 0)); });
}

for (const [screen, endpoint] of [['account','/auth/sessions'], ['accounts','/admin/users'], ['audit','/admin/audit']]) {
  test(`Initial ${screen} JSON body cannot publish after access invalidation`, async ({page}) => {
    await withViewServer({rows:3}, async origin => {
      await ready(page, origin);
      await holdBody(page, endpoint, 'GET', 'json', true);
      await page.goto(`${origin}/${screen}.html`);
      await bodyReached(page);
      await invalidate(page);
      await releaseBody(page);
      await expect(page.locator('#sessions li, #users tr, #audit-events tr')).toHaveCount(0);
      await expect(page.locator('#current-user')).toHaveText('');
      expect(await page.locator('main button').evaluateAll(nodes => nodes.every(node => node.disabled))).toBe(true);
    });
  });
}

test('A real current-session revocation retires the page before its 401 redirect', async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    await page.goto(origin + '/audit.html');
    await expect(page.locator('#audit-events tr').first()).toBeVisible();
    await page.evaluate(() => {
      TraceAuth.onInvalidated(status => sessionStorage.setItem('retirement-observation', JSON.stringify({
        status, rows:document.querySelectorAll('#audit-events tr').length,
        disabled:document.getElementById('audit-export').disabled,
        identity:document.getElementById('current-user').textContent
      })));
    });
    // Use the actual server to revoke the session; no redirect interception.
    await page.evaluate(() => TraceAuth.json('/auth/sessions/revoke', {}));
    await page.click('#audit-apply');
    await expect(page).toHaveURL(/login\.html$/);
    expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem('retirement-observation')))).toEqual({status:401,rows:0,disabled:true,identity:''});
    await loginView(page, origin);
    await expect(page.locator('#resultsTable tbody tr').first()).toBeVisible();
  });
});

test('Login can retry a denied attempt and temporary-password users can change password and relogin', async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    await page.evaluate(() => TraceAuth.json('/admin/users', {username:'retirement-viewer',password:'temporary-fixture-password',role:'viewer'}));
    await page.locator('#accountMenu > summary').click();
    await page.click('#logout');
    await expect(page).toHaveURL(/login\.html$/);
    await expect(page.locator('#login-submit')).toBeEnabled();
    await page.fill('#username', 'retirement-viewer');
    await page.fill('#password', 'wrong-fixture-password');
    await page.click('#login-submit');
    await expect(page.locator('#page-status')).toContainText('Sign-in failed');
    await expect(page.locator('#login-submit')).toBeEnabled();
    await page.fill('#password', 'temporary-fixture-password');
    await page.click('#login-submit');
    await expect(page).toHaveURL(/account\.html$/);
    await expect(page.locator('#password-submit')).toBeEnabled();
    await expect(page.locator('#password-required')).toBeVisible();
    await page.fill('#current-password', 'temporary-fixture-password');
    await page.fill('#new-password', 'changed-fixture-password');
    await page.fill('#confirm-password', 'changed-fixture-password');
    await page.click('#password-submit');
    await expect(page).toHaveURL(/login\.html$/);
    await loginView(page, origin, 'retirement-viewer', 'changed-fixture-password');
    await page.goto(origin + '/audit.html');
    await expect(page.locator('#audit-events tr').first()).toBeVisible();
    await holdBody(page, '/auth/activity', 'GET');
    await page.click('#audit-apply');
    await bodyReached(page);
    await invalidate(page);
    await releaseBody(page);
    await expect(page.locator('#audit-events tr')).toHaveCount(0);
    await expect(page.locator('#audit-export')).toBeHidden();
    await expect(page.locator('#audit-apply')).toBeDisabled();
  });
});

for (const screen of ['account', 'accounts', 'audit']) test(`Security ${screen} retires loaded data, dialogs and a delayed JSON continuation`, async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    if (screen === 'account') {
      const other = await page.context().browser().newContext();
      try { await loginView(await other.newPage(), origin); }
      finally { await other.close(); }
    }
    await page.goto(`${origin}/${screen}.html`);
    await page.waitForLoadState('load');
    if (screen === 'account') {
      await expect(page.locator('#sessions li').first()).toBeVisible();
      await holdBody(page, '/auth/sessions/revoke', 'POST');
      await page.locator('#sessions li').filter({hasNotText:'This session'}).getByRole('button', {name:'Revoke session'}).click();
    } else if (screen === 'accounts') {
      await expect(page.locator('#users tr').first()).toBeVisible();
      await page.locator('#users tr').first().getByRole('button', {name:'Reset password',exact:true}).click();
      await page.fill('#reset-password', 'fixture-reset-not-submitted');
      await expect(page.locator('#reset-dialog')).toBeVisible();
      await page.click('#reset-cancel');
      await holdBody(page, '/admin/users', 'POST');
      await page.fill('#create-username', 'retirement-user');
      await page.fill('#create-password', 'fixture-new-user-password');
      await page.click('#create-user');
      await bodyReached(page);
      await page.locator('#users tr').first().getByRole('button', {name:'Reset password',exact:true}).click();
      await page.fill('#reset-password', 'fixture-reset-not-submitted');
    } else {
      await expect(page.locator('#audit-events tr').first()).toBeVisible();
      await holdBody(page, '/admin/audit', 'GET');
      await page.click('#audit-apply');
    }
    await bodyReached(page);
    await invalidate(page);
    await releaseBody(page);
    await expect(page.locator('#sessions li, #users tr, #audit-events tr')).toHaveCount(0);
    await expect(page.locator('dialog[open]')).toHaveCount(0);
    await expect(page.locator('#current-user')).toHaveText('');
    expect(await page.locator('main input, main textarea').evaluateAll(nodes => nodes.every(node => !node.value))).toBe(true);
    expect(await page.locator('main button').evaluateAll(nodes => nodes.every(node => node.disabled))).toBe(true);
    await expect(page.locator('#page-status')).not.toContainText(/User created|Temporary password set|downloaded/);
    await expect(page).toHaveURL(new RegExp(`/${screen}\\.html$`));
    await expect(page.locator('#logout')).toBeEnabled();
  });
});

test('Audit export cannot download or reenable its action after invalidation during blob decoding', async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    await page.goto(origin + '/audit.html');
    await expect(page.locator('#audit-events tr').first()).toBeVisible();
    await holdBody(page, '/admin/audit/export', 'POST', 'blob');
    await page.evaluate(() => {
      window.retiredDownloadClicks = 0;
      const click = HTMLAnchorElement.prototype.click;
      HTMLAnchorElement.prototype.click = function() {
        if (this.download === 'tracedns-audit.jsonl') window.retiredDownloadClicks++;
        return click.call(this);
      };
    });
    const downloads = [];
    page.on('download', download => downloads.push(download.suggestedFilename()));
    await page.click('#audit-export');
    await bodyReached(page);
    await invalidate(page);
    await releaseBody(page);
    expect(await page.evaluate(() => window.retiredDownloadClicks)).toBe(0);
    await expect(page.locator('#audit-export')).toBeDisabled();
    await expect(page.locator('#audit-events tr')).toHaveCount(0);
    await expect(page.locator('#page-status')).not.toContainText('downloaded');
    expect(downloads).toEqual([]);
    // Sign-out remains functional even though every protected action retired.
    await page.click('#logout');
    await expect(page).toHaveURL(/login\.html$/);
    await loginView(page, origin);
    await expect(page.locator('#resultsTable tbody tr').first()).toBeVisible();
  });
});

const precheck = domain => ({domain, requested_type:'A', selected_type:'A', detected_types:['A'],
  domain_object:{name:domain,type:'A'}, can_add:true, resolved_ips:['192.0.2.8'], managed_ips:['192.0.2.8'],
  by_server:[], decoder_candidates:[], ip_rows:[], notes:[]});

for (const exit of ['navigation', 'pagehide']) test(`Submitted Add retains uncertainty after ${exit} without rebasing a draft`, async ({page}) => {
  await withViewServer({rows:3}, async origin => {
    await ready(page, origin);
    await page.click('#menuSettings');
    await page.locator('#domainTable summary').first().click();
    await page.locator('.domain-name').first().fill('independent-draft.test');
    const revision = await page.evaluate(() => configRevision);
    await page.route('**/domain-precheck', route => route.fulfill({json:precheck('committed-add.test')}));
    await page.click('#menuDomainVerify');
    await page.fill('#verifyDomainName', 'committed-add.test');
    await page.click('#runDomainVerifyBtn');
    await expect(page.locator('#addVerifiedDomainBtn')).toBeEnabled();
    let release, committed = false, posts = 0;
    const gate = new Promise(resolve => { release = resolve; });
    await page.route('**/config', async route => {
      if (route.request().method() !== 'POST') return route.continue();
      posts++;
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      committed = true;
      await gate;
      await route.fulfill({response}).catch(() => {});
    });
    try {
      await page.evaluate(() => { window.pendingAdd = addVerifiedDomainToConfig(); });
      await expect.poll(() => committed).toBe(true);
      // Direct invocation is also fenced, not only the disabled button.
      await page.evaluate(() => { window.duplicateAdd = addVerifiedDomainToConfig(); });
      if (exit === 'navigation') await page.click('#menuStatus');
      else await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
      release();
      await page.evaluate(() => Promise.all([window.pendingAdd, window.duplicateAdd]));
      const saved = await page.evaluate(async () => (await TraceAuth.json('/config')).domains);
      expect(saved.filter(d => (d.name || d) === 'committed-add.test')).toHaveLength(1);
      expect(posts).toBe(1);
      await page.click('#menuDomainVerify');
      await expect(page.locator('#domainVerifyAddOutcome')).toContainText('outcome is unknown');
      await expect(page.locator('#domainVerifySummary')).toHaveText('No validation result.');
      expect(await page.evaluate(() => configRevision)).toBe(revision);
      await expect(page.locator('.domain-name').first()).toHaveValue('independent-draft.test');
      await page.click('#runDomainVerifyBtn');
      await expect(page.locator('#domainVerifyStatus')).toContainText('Validation complete');
      await expect(page.locator('#addVerifiedDomainBtn')).toBeDisabled();
      await page.click('#clearDomainVerifyBtn');
      await expect(page.locator('#domainVerifyAddOutcome')).toContainText('outcome is unknown');
      // Reload retires private evidence but must not silently erase uncertainty.
      await page.reload();
      await expect.poll(() => page.evaluate(() => configRevision !== null)).toBe(true);
      await page.click('#menuDomainVerify');
      await expect(page.locator('#domainVerifyAddOutcome')).toContainText('outcome is unknown');
      await page.click('#reconcileVerifiedDomainBtn');
      await expect(page.locator('#domainVerifySavedTargets')).toContainText('committed-add.test');
      await page.click('#acknowledgeVerifiedDomainBtn');
      await expect(page.locator('#domainVerifyAddOutcome')).toBeHidden();
      expect(posts).toBe(1);
    } finally { release(); }
  });
});
