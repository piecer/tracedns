const {test, expect} = require('@playwright/test');

async function config(page, data) {
  return page.evaluate(async data => {
    const response = await fetch('/config', data ? {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
    } : {});
    return response.json();
  }, data);
}

const longName = `${'long-domain-'.repeat(5)}.${'another-label-'.repeat(4)}.example.test`;

test('settings shows full names, dates, safe editing and narrow reflow', async ({page}) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/login.html');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  const initial = await config(page);
  await config(page, {revision: initial.revision, domains: [
    {name: longName, type: 'A'},
    {name: 'node.eth', type: 'ENS', ens_text_key: 'WoAh', ens_decode: 'none',
      ens_node: '0x' + 'a'.repeat(64), ens_resolver: '0x' + 'b'.repeat(40)}
  ]});
  await page.reload();
  await page.click('#menuSettings');
  await expect(page.locator('.domain-full-name').first()).toHaveText(longName);
  await expect(page.locator('#domainSettingsSummary')).toContainText('2');
  const card = page.locator('#domainTable tbody tr').first();
  await expect(card.locator('.domain-created time')).toHaveAttribute('datetime', /\+00:00$/);
  await expect(card.locator('.domain-updated time')).toHaveAttribute('datetime', /\+00:00$/);
  await expect(page.locator('#domainTable tbody tr').nth(1).locator('.domain-created time')).toHaveAttribute('datetime', /\+00:00$/);
  const before = await config(page);
  await page.fill('#domainSettingsSearch', 'node.eth');
  await expect(page.locator('#domainSettingsSummary')).toHaveText('1 of 2 targets shown');
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toHaveText('Settings saved');
  const after = await config(page);
  expect(after.domain_metadata).toEqual(before.domain_metadata);
  expect(after.domains).toEqual(before.domains);
  await page.fill('#domainSettingsSearch', '');
  await card.locator('summary').click();
  await card.locator('.domain-type').selectOption('AAAA');
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toHaveText('Settings saved');
  const changed = await config(page);
  expect(changed.domain_metadata[longName].created_at).toBe(before.domain_metadata[longName].created_at);
  expect(changed.domain_metadata[longName].updated_at).not.toBe(before.domain_metadata[longName].updated_at);
  for (const width of [1280, 390]) {
    await page.setViewportSize({width, height: 900});
    const geometry = await page.locator('.domain-full-name').first().evaluate(el => {
      const box = el.getBoundingClientRect();
      return {scroll: el.scrollWidth, client: el.clientWidth, left: box.left, right: box.right, viewport: innerWidth};
    });
    expect(geometry.scroll <= geometry.client + 1 && geometry.left >= 0 && geometry.right <= geometry.viewport, JSON.stringify(geometry)).toBe(true);
    expect(await page.locator('#domainSettingsSection').evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
  }
  // A stale write must keep the draft and the displayed server-owned dates.
  await card.locator('summary').click();
  await card.locator('.domain-name').fill('draft.example.test');
  await config(page, {revision: changed.revision, interval: 61});
  await page.click('#save');
  await expect(page.locator('#domainSettingsStatus')).toContainText('Save failed');
  await expect(card.locator('.domain-name')).toHaveValue('draft.example.test');
  expect((await config(page)).domains).toEqual(changed.domains);
  page.on('dialog', d => d.accept());
  await card.getByRole('button', {name: 'Remove'}).click();
  await expect(page.locator('#domainSettingsStatus')).toContainText('Remove failed');
  await expect(page.locator('#domainTable tbody tr')).toHaveCount(2);
  await expect(card.locator('.domain-name')).toHaveValue('draft.example.test');
  await page.click('#load');
  await expect(card.locator('.domain-full-name')).toHaveText(longName);
  // Successful deletion must not depend on a subsequent GET succeeding.
  await page.route('**/config', route => route.request().method() === 'GET'
    ? route.fulfill({status: 503, contentType: 'application/json', body: '{"error":"unavailable"}'})
    : route.continue());
  await card.getByRole('button', {name: 'Remove'}).click();
  await expect(page.locator('#domainSettingsStatus')).toHaveText('Removed domain and saved');
  await expect(page.locator('#domainTable tbody tr')).toHaveCount(1);
  await page.unroute('**/config');
  const removed = await config(page);
  expect(removed.domains).toEqual([changed.domains[1]]);
  expect(removed.domain_metadata[longName]).toBeUndefined();
  expect(errors).toEqual([]);
});
