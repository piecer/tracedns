// Shipped admin UI -> production POST handler -> real local verified HTTPS sink.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium, expect} = require('@playwright/test');
(async () => {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const base = `http://127.0.0.1:${input.port}`;
  const browser = await chromium.launch({headless:true});
  try {
    const context = await browser.newContext({viewport:{width:1280, height:900}});
    const page = await context.newPage();
    const errors = [], posts = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', req => {
      if(new URL(req.url()).pathname.endsWith('/teams/test')) posts.push({method:req.method(), body:req.postDataJSON()});
    });
    await page.goto(base+'/login.html');
    await page.fill('#username', 'root');
    await page.fill('#password', 'test-password-123');
    await page.click('#login-submit');
    await expect(page).not.toHaveURL(/login\.html/);
    // The existing load listener selects the initial section. Wait for that
    // real startup boundary rather than racing an early navigation click.
    await page.waitForLoadState('load');
    await page.click('#menuSettings');
    await page.click('#settingsTabAlerts');
    const button = page.locator('#teamsTestBtn');
    await expect(button).toBeVisible();
    await expect(button).toBeEnabled();
    await expect(page.locator('#teamsTestHelp')).toContainText('Unsaved edits are ignored');
    assert.deepEqual(posts, [], 'loading settings must not send a test');
    await page.fill('#teams_webhook_front', 'https://draft.invalid/never-send-here');
    page.once('dialog', dialog => dialog.dismiss());
    await button.click();
    assert.deepEqual(posts, [], 'cancelled confirmation must not send');
    page.once('dialog', dialog => dialog.accept());
    await button.click();
    await expect(page.locator('#teamsTestStatus')).toContainText('accepted');
    await expect(page.locator('#teamsTestStatus')).toContainText('200');
    assert.deepEqual(posts, [{method:'POST', body:{revision:0}}]);
    const ax = await page.locator('#alertsSection').ariaSnapshot();
    assert.ok(ax.includes('Send real Teams test'));
    const screenshot = path.join(input.out, 'teams-test-browser.png');
    await page.locator('#alertsSection').screenshot({path:screenshot});
    await page.setViewportSize({width:390, height:844});
    assert.equal(await button.evaluate(el => {
      const box=el.getBoundingClientRect();
      return box.left >= 0 && box.right <= window.innerWidth;
    }), true, 'test button must fit narrow viewport');
    assert.equal(await page.locator('#teamsTestStatus').evaluate(el => el.scrollWidth <= el.clientWidth+1), true);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({browser_verified:true, screenshot, api_posts:posts.length}));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
