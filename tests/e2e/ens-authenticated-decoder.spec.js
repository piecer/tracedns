const {test, expect} = require('@playwright/test');
const corpus = require('../../docs/ens/sha256-hmac-xor-decoder.json');

// The server is disposable and has no monitor worker: this test never queries C2.
test('authenticated ENS decoder is selectable and its options survive UI save/reload', async ({page}) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/login.html');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'test-admin-password');
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.click('#menuDomainVerify');
  await page.selectOption('#verifyDomainType', 'ENS');
  await expect(page.locator(`#verifyEnsDecode option[value="${corpus.runtime_method_name}"]`)).toHaveCount(1);
  await page.selectOption('#verifyEnsDecode', corpus.runtime_method_name);
  await expect(page.locator('#verifyEnsDecode')).toHaveValue(corpus.runtime_method_name);

  await page.click('#menuSettings');
  await page.click('#addDomain');
  const row = page.locator('#domainTable tbody tr').last();
  await row.locator('.domain-name').fill(corpus.ens_name);
  await row.locator('.domain-type').selectOption('ENS');
  await row.locator('.ens-text-key').fill(corpus.text_key);
  await row.locator('.ens-decode').selectOption(corpus.runtime_method_name);
  await row.locator('.ens-options').fill(JSON.stringify(corpus.decoder_options));
  const savedResponse = page.waitForResponse(response => response.url().endsWith('/config') && response.request().method() === 'POST');
  await page.click('#save');
  const response = await savedResponse;
  expect(response.status()).toBe(200);
  const saved = await response.json();
  const domain = saved.config.domains.find(entry => entry.name === corpus.ens_name);
  expect(domain.ens_text_key).toBe('name');
  expect(domain.ens_decode).toBe(corpus.runtime_method_name);
  expect(domain.ens_options).toEqual(corpus.decoder_options);
  await expect(page.locator('#domainSettingsStatus')).toContainText('Settings saved');
  await page.reload();
  await page.click('#menuSettings');
  const restored = page.locator('#domainTable tbody tr').filter({hasText: corpus.ens_name});
  await expect(restored).toHaveCount(1);
  await restored.locator('summary').click();
  await expect(restored.locator('.ens-decode')).toHaveValue(corpus.runtime_method_name);
  await expect(restored.locator('.ens-text-key')).toHaveValue('name');
  expect(JSON.parse(await restored.locator('.ens-options').inputValue())).toEqual(corpus.decoder_options);
  expect(errors).toEqual([]);
});
