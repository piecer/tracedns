const {test, expect} = require('@playwright/test');
const {withViewServer, loginView} = require('./view-helpers');

for(const delivery of ['acked', 'disabled', 'degraded']) {
  for(const viewport of [{width:1366,height:768}, {width:390,height:844}]) {
    test(`results first: ${delivery} at ${viewport.width}`, async ({page}, info) => {
      await withViewServer({delivery}, async origin => {
        await page.setViewportSize(viewport);
        const requests = [], errors = [];
        page.on('request', request => requests.push({path:new URL(request.url()).pathname, method:request.method()}));
        page.on('pageerror', error => errors.push(error.message));
        await loginView(page, origin);
        await expect(page.locator('#deliveryStatus')).not.toContainText('waiting');
        await expect(page.locator('#deliveryStatus')).toContainText('Backend delivery status:');
        await page.screenshot({path:info.outputPath('viewport.png')});
        const geometry = await page.evaluate(() => ({
          rows:[...document.querySelectorAll('#resultsTable tbody tr')].slice(0,3).map(el=>el.getBoundingClientRect().toJSON()),
          header:document.querySelector('#resultsTable thead').getBoundingClientRect().toJSON(),
          elements:document.querySelectorAll('*').length,
          common:document.querySelector('#deliveryHealth').querySelectorAll('*').length,
          overflow:document.documentElement.scrollWidth > innerWidth
        }));
        await info.attach('geometry-and-requests', {body:JSON.stringify({geometry, requests}, null, 2), contentType:'application/json'});
        expect(geometry.header.bottom).toBeLessThanOrEqual(viewport.height);
        expect(geometry.rows[viewport.width > 600 ? 2 : 0].bottom).toBeLessThanOrEqual(viewport.height);
        expect(geometry.overflow).toBe(false);
        expect(geometry.common).toBeLessThanOrEqual(40);
        await expect(page.locator('#diagnosticsRead')).not.toBeVisible();
        await expect(page.locator('#deliveryDetails')).not.toBeVisible();
        expect(requests.filter(r=>r.path==='/delivery-diagnostics')).toHaveLength(0);
        expect(errors).toEqual([]);
      });
    });
  }
}

test('delivery disclosures are read-only, keyboard accessible and deep-linked', async ({page}) => {
  await withViewServer({delivery:'overflow', rows:250}, async origin => {
    await loginView(page, origin);
    const requests = [];
    page.on('request', r => requests.push({path:new URL(r.url()).pathname, method:r.method()}));
    await expect(page.locator('#deliveryWarnings')).toContainText('4 not admitted');
    const disclosure = page.locator('#deliveryDisclosure > summary');
    await disclosure.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#deliveryDetails')).toContainText('4 destination-items not admitted');
    await page.keyboard.press('Space');
    await expect(page.locator('#deliveryDetails')).not.toBeVisible();
    await expect(disclosure).toBeFocused();
    for(let i=0;i<20;i++) await disclosure.click();
    expect(requests.filter(r=>r.method==='POST' || r.path==='/delivery-diagnostics')).toHaveLength(0);
    await page.evaluate(() => { location.hash = '#deliveryDiagnostics'; });
    await expect(page.locator('#diagnosticsRead')).toBeVisible();
    await expect(page.locator('#diagnosticsHeading')).toBeFocused();
    expect(requests.filter(r=>r.path==='/delivery-diagnostics')).toHaveLength(0);
    await page.evaluate(() => { location.hash = '#deliveryHealth'; });
    await expect(page.locator('#deliveryDetails')).toBeVisible();
    await expect(page.locator('#deliveryHeading')).toBeFocused();
    expect(await page.locator('#resultsTable tbody tr').count()).toBeLessThanOrEqual(200);
    await expect(page.locator('main')).toHaveCount(1);
    await expect(page.getByRole('link', {name:'Skip to current view'})).toHaveCount(1);
  });
});
