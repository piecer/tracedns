const {test, expect} = require('@playwright/test');

const method = 'ipv6_last4_xor_6b9e3f2a';
const domainName = 'jxk.imarapi.st';

// Isolated server, synthetic login, no monitor or external DNS/C2 traffic.
test('pseudo-IPv6 TXT decoder is selectable and survives settings save/reload', async ({page}) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/login.html');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.click('#menuDomainVerify');
  await page.selectOption('#verifyDomainType', 'TXT');
  await expect(page.locator(`#verifyTxtDecode option[value="${method}"]`)).toHaveCount(1);
  await page.selectOption('#verifyTxtDecode', method);
  await expect(page.locator('#verifyTxtDecode')).toHaveValue(method);

  await page.click('#menuSettings');
  await page.click('#addDomain');
  const row = page.locator('#domainTable tbody tr').last();
  await row.locator('.domain-name').fill(domainName);
  await row.locator('.domain-type').selectOption('TXT');
  await row.locator('.txt-decode').selectOption(method);
  const savedResponse = page.waitForResponse(response => response.url().endsWith('/config') && response.request().method() === 'POST');
  await page.click('#save');
  const response = await savedResponse;
  expect(response.status()).toBe(200);
  const saved = await response.json();
  const domain = saved.config.domains.find(entry => entry.name === domainName);
  expect(domain.type).toBe('TXT');
  expect(domain.txt_decode).toBe(method);
  await expect(page.locator('#domainSettingsStatus')).toContainText('Settings saved');
  await page.reload();
  await page.click('#menuSettings');
  const restored = page.locator('#domainTable tbody tr').filter({hasText: domainName});
  await expect(restored).toHaveCount(1);
  await restored.locator('summary').click();
  await expect(restored.locator('.domain-type')).toHaveValue('TXT');
  await expect(restored.locator('.txt-decode')).toHaveValue(method);
  expect(errors).toEqual([]);
});
