const {test, expect} = require('@playwright/test');

test('decoder catalog revision preserves both drafts and applies committed CRUD without rereads', async ({page}) => {
  const errors = [];
  const unavailable = [];
  page.on('response', r => { if(r.status() === 503 && !r.url().endsWith('/decoders')) unavailable.push(r.url()); });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/login.html');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.evaluate(async () => {
    const config = await (await fetch('/config')).json();
    await fetch('/config', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({revision: config.revision, domains: [{name: 'saved.example', type: 'A'}]})});
  });
  await page.reload();
  await page.click('#menuSettings');
  await expect(page.locator('.domain-full-name').first()).toHaveText('saved.example');
  const loaded = await page.evaluate(async () => (await (await fetch('/decoders')).json()).revision);
  await page.locator('#domainTable summary').first().click();
  await page.locator('.domain-name').first().fill('unsaved.example');
  await page.click('#settingsTabCustom');
  const steps = '[{"op":"ascii"}]';
  await page.fill('#custom_name', 'browser_atomic');
  await page.fill('#custom_steps', steps);
  await page.evaluate(async revision => {
    await fetch('/config', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({revision, interval: 63})});
  }, loaded);
  // Tab changes must not silently rebase the decoder draft either.
  await page.click('#settingsTabDomains');
  await page.click('#settingsTabCustom');
  const staleRequest = page.waitForRequest(r => r.url().endsWith('/decoders/custom') && r.method() === 'POST');
  await page.click('#registerCustom');
  expect((await staleRequest).postDataJSON().revision).toBe(loaded);
  await expect(page.locator('#customPreviewResult')).toContainText('Conflict');
  await expect(page.locator('#custom_name')).toHaveValue('browser_atomic');
  await expect(page.locator('#custom_steps')).toHaveValue(steps);
  await page.click('#reloadCustom');
  await expect(page.locator('#customPreviewResult')).toContainText('review');
  // The committed response, not a later GET, must drive create/update/delete.
  await page.route('**/decoders', route => route.fulfill({status: 503, contentType: 'application/json', body: '{"error":"offline"}'}));
  await page.route('**/decoders/custom', async route => {
    const response = await route.fetch();
    const result = await response.json();
    await route.fulfill({response, json: {...result, warnings: ['history_cleanup_pending']}});
  });
  await page.click('#registerCustom');
  await expect(page.locator('#customPreviewResult')).toContainText('Registered: browser_atomic');
  await expect(page.locator('#customPreviewResult')).toContainText('history_cleanup_pending');
  const row = page.locator('#customList > div').filter({hasText: 'browser_atomic'});
  await expect(row).toHaveCount(1);
  await row.getByRole('button', {name: 'Edit', exact: true}).click();
  await page.fill('#custom_steps', '[{"op":"extract_ip_prefix"}]');
  await row.getByRole('button', {name: 'Update', exact: true}).click();
  await expect(page.locator('#customPreviewResult')).toContainText('Updated browser_atomic');
  page.on('dialog', dialog => dialog.accept());
  await row.getByRole('button', {name: 'Delete', exact: true}).click();
  await expect(page.locator('#customPreviewResult')).toContainText('Deleted browser_atomic');
  await expect(row).toHaveCount(0);
  await page.click('#settingsTabDomains');
  await expect(page.locator('.domain-name').first()).toHaveValue('unsaved.example');
  const staleConfig = page.waitForRequest(r => r.url().endsWith('/config') && r.method() === 'POST');
  await page.click('#save');
  expect((await staleConfig).postDataJSON().revision).toBe(loaded);
  await expect(page.locator('#domainSettingsStatus')).toContainText('Save failed');
  await expect(page.locator('.domain-name').first()).toHaveValue('unsaved.example');
  expect(errors).toEqual([]);
  expect(unavailable).toEqual([]);
});


test('committed warning stays visible without treating the settings save as rollback', async ({page}) => {
  await page.goto('/login.html');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.click('#menuSettings');
  await page.click('#settingsTabAlerts');
  // Await the startup load rather than racing a second GET against the draft.
  await expect(page.locator('#alertSettingsStatus')).toHaveText('Loaded');
  await page.route('**/settings', async route => {
    if(route.request().method() !== 'POST') return route.continue();
    // Browser fault fixture: retain a real committed response; inject only the
    // optional-adapter warning already covered by backend fault tests.
    const response = await route.fetch();
    const result = await response.json();
    await route.fulfill({response, json: {...result, warnings: ['alerts_runtime_apply_failed']}});
  });
  await page.fill('#vt_cache_ttl_days_front', '17');
  await page.click('#saveAlertSettingsBtn');
  await expect(page.locator('#alertSettingsStatus')).toContainText('Saved with warnings');
  await expect(page.locator('#alertSettingsStatus')).toContainText('alerts_runtime_apply_failed');
  await expect(page.locator('#vt_cache_ttl_days_front')).toHaveValue('17');
  await page.click('#settingsTabDomains');
  await page.evaluate(() => loadCfg());
  await page.route('**/config', async route => {
    if(route.request().method() !== 'POST') return route.continue();
    const response = await route.fetch();
    const result = await response.json();
    await route.fulfill({response, json: {...result, warnings: ['history_cleanup_pending']}});
  });
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('history_cleanup_pending');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Settings saved');
});
