// Exercise real sessions and UI across distinct users, without external APIs.
const {test, expect} = require('@playwright/test');
async function login(page, user, password) {
  await page.goto('/login.html');
  await page.fill('#username', user);
  await page.fill('#password', password);
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
}
async function api(page, path, data) {
  return page.evaluate(async ({path, data}) => {
    const me = await (await window.fetch('/auth/me')).json();
    const response = await window.fetch(path, data === undefined ? {} : {
      method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf_token},
      body:JSON.stringify(data)
    });
    return response.json();
  }, {path, data});
}

test('accounts, forced password change, simultaneous roles and audit', async ({browser}) => {
  const admin = await browser.newPage();
  const errors = [];
  admin.on('pageerror', e=>errors.push(e.message));
  await login(admin, 'admin', 'test-admin-password');
  await expect(admin.locator('#current-user')).toContainText('admin');
  await admin.goto('/accounts.html');
  for (const role of ['viewer', 'operator']) {
    await admin.fill('#create-username', role);
    await admin.fill('#create-password', 'temporary-password');
    await admin.selectOption('#create-role', role);
    await admin.click('#create-user');
    await expect(admin.locator('#users tr td:first-child').filter({hasText:new RegExp(`^${role}$`)})).toHaveCount(1);
  }
  const pages = [];
  for (const role of ['viewer','operator']) {
    const page = await browser.newPage(); pages.push(page);
    page.on('pageerror', e=>errors.push(e.message));
    await login(page, role, 'temporary-password');
    await expect(page).toHaveURL(/account\.html/);
    await page.fill('#current-password', 'temporary-password');
    await page.fill('#new-password', 'changed-password');
    await page.fill('#confirm-password', 'changed-password');
    await page.click('#password-submit');
    await expect(page).toHaveURL(/login\.html/);
    await login(page, role, 'changed-password');
    await expect(page.locator('#current-user')).toContainText(role);
  }
  const [viewer, operator] = pages;
  await expect(viewer.locator('#save')).not.toBeVisible();
  const denied = await viewer.request.get('/admin/users');
  expect(denied.status()).toBe(403);
  const cfg = await api(operator, '/config');
  const saved = await api(operator, '/config', {domains:[], revision:cfg.revision});
  expect(saved.status).toBe('ok');
  await admin.goto('/audit.html');
  await expect(admin.locator('#audit-events')).toContainText('access.denied');
  await expect(admin.locator('#audit-events')).toContainText('operator');
  const download = admin.waitForEvent('download');
  await admin.click('#audit-export');
  expect((await download).suggestedFilename()).toBe('tracedns-audit.jsonl');
  await admin.goto('/accounts.html');
  admin.on('dialog', d=>d.accept());
  const row = admin.locator('#users tr').filter({has:admin.locator('td:first-child').getByText('viewer',{exact:true})});
  await row.getByRole('button',{name:'Disable',exact:true}).click();
  await expect(row).toContainText('Disabled');
  await viewer.reload();
  await expect(viewer).toHaveURL(/login\.html/);
  expect((await operator.request.get('/results')).status()).toBe(200);
  expect(errors).toEqual([]);
  await Promise.all([admin, viewer, operator].map(p=>p.context().close()));
});