// Real shipped forms/scripts and real session/CSRF responses, held at transport.
const {test, expect} = require('@playwright/test');

function barrier() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return {promise, release};
}

async function hold(page, pattern) {
  const reached = barrier(), gate = barrier();
  await page.route(pattern, async route => {
    reached.release();
    await gate.promise;
    await route.continue();
  });
  return {reached: reached.promise, release: gate.release};
}

for (const action of ['click', 'Enter']) {
  test(`login stays inert during real CSRF readiness: ${action}`, async ({page}, testInfo) => {
    const pending = await hold(page, '**/auth/csrf');
    const credentials = {username:'admin', password:'test-admin-password'};
    const requests = [];
    page.on('request', request => {
      const url = new URL(request.url());
      // Retain only booleans/path: never print credential-bearing URLs.
      if (request.isNavigationRequest()) requests.push({
        method:request.method(), path:url.pathname,
        usernameInURL:[...url.searchParams.values()].includes(credentials.username),
        passwordInURL:[...url.searchParams.values()].includes(credentials.password)
      });
    });
    try {
      await page.goto('/login.html');
      await pending.reached;
      await page.fill('#username', credentials.username);
      await page.fill('#password', credentials.password);
      const before = await page.locator('#login-form').evaluate(form => ({
        disabled:form.querySelector('button').disabled, handler:typeof form.onsubmit
      }));
      // Observe the actual native request on the vulnerable tree, not just markup.
      const nativeRequest = !before.disabled && before.handler !== 'function'
        ? page.waitForRequest(r => r.isNavigationRequest() && new URL(r.url()).pathname === '/login.html') : null;
      if (action === 'click') {
        const box = await page.locator('#login-submit').boundingBox();
        await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      } else await page.locator('#password').press('Enter');
      if (nativeRequest) await nativeRequest;
      await testInfo.attach('pre-ready-submission', {body:JSON.stringify({action, before, requests}), contentType:'application/json'});
      expect(requests.filter(r => r.usernameInURL || r.passwordInURL), 'no credential URL request').toEqual([]);
      expect(before.disabled, 'submit stays disabled until auth and handler are ready').toBe(true);
      await expect(page.locator('#login-submit')).toBeDisabled();
      pending.release();
      await expect(page.locator('#login-submit')).toBeEnabled();
      expect(await page.locator('#login-form').evaluate(form => typeof form.onsubmit)).toBe('function');
      const posted = page.waitForRequest(r => new URL(r.url()).pathname === '/auth/login' && r.method() === 'POST');
      if (action === 'click') await page.click('#login-submit');
      else await page.locator('#password').press('Enter');
      const request = await posted;
      expect(request.postDataJSON()).toEqual(credentials);
      expect(await request.headerValue('x-csrf-token')).toBeTruthy();
      await expect(page).toHaveURL(/dns_frontend\.html/);
      await expect(page.locator('#current-user')).toContainText('admin');
      expect(requests.some(r => r.usernameInURL || r.passwordInURL)).toBe(false);
    } finally {
      pending.release();
      await page.unrouteAll({behavior:'wait'});
    }
  });
}

const forms = [
  {path:'/login.html', id:'login-form', submit:'#login-submit', fields:{username:'admin', password:'test-admin-password'}},
  {path:'/account.html', id:'password-form', submit:'#password-submit', fields:{'current-password':'test-admin-password', 'new-password':'synthetic-new-password', 'confirm-password':'synthetic-new-password'}},
  {path:'/accounts.html', id:'create-user-form', submit:'#create-user', fields:{'create-username':'readiness-user', 'create-password':'synthetic-new-password'}},
  {path:'/accounts.html', id:'reset-password-form', submit:'#reset-password-form button[type="submit"]', fields:{'reset-password':'synthetic-new-password'}, dialog:true}
];

async function signIn(request) {
  const csrf = await (await request.get('/auth/csrf')).json();
  const response = await request.post('/auth/login', {
    headers:{'X-CSRF-Token':csrf.csrf_token, Origin:'http://127.0.0.1:18765'},
    data:{username:'admin', password:'test-admin-password'}
  });
  expect(response.status()).toBe(200);
}

async function inert(page, form) {
  if (form.dialog) {
    // Expose the shipped dormant dialog to test its own HTML fail-closed state.
    // Do not install handlers or rewrite the form/authentication sources.
    await page.locator('#reset-dialog').evaluate(dialog => dialog.showModal());
  }
  for (const [id, value] of Object.entries(form.fields)) await page.fill(`#${id}`, value);
  const submit = page.locator(form.submit);
  await expect(submit).toBeDisabled();
  expect(await page.locator(`#${form.id}`).getAttribute('method')).toBe('post');
  const outgoing = [];
  const observe = request => {
    if (request.isNavigationRequest() || request.method() === 'POST') outgoing.push({method:request.method(), path:new URL(request.url()).pathname});
  };
  page.on('request', observe);
  try {
    const box = await submit.boundingBox();
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await page.locator(`#${Object.keys(form.fields).at(-1)}`).press('Enter');
    // Both ordinary browser input actions have completed. The same form and
    // values must remain, without a native navigation or mutation request.
    for (const [id, value] of Object.entries(form.fields)) await expect(page.locator(`#${id}`)).toHaveValue(value);
    await expect(submit).toBeDisabled();
    expect(outgoing).toEqual([]);
  } finally { page.off('request', observe); }
}

for (const condition of ['auth delayed', 'security script missing', 'auth script missing', 'JavaScript disabled']) {
  test.describe(condition, () => {
    test.use({javaScriptEnabled:condition !== 'JavaScript disabled'});
    for (const form of forms) {
      test(`${form.id} blocks ordinary click and Enter before readiness`, async ({page}) => {
        if (form.path !== '/login.html') await signIn(page.request);
        let pending;
        if (condition === 'auth delayed') pending = await hold(page, form.path === '/login.html' ? '**/auth/csrf' : '**/auth/me');
        if (condition === 'security script missing') await page.route('**/security_ui.js', route => route.abort());
        if (condition === 'auth script missing') await page.route('**/auth_frontend.js', route => route.abort());
        try {
          await page.goto(form.path);
          if (pending) await pending.reached;
          await inert(page, form);
          if (pending) {
            pending.release();
            await expect(page.locator(form.submit)).toBeEnabled();
            expect(await page.locator(`#${form.id}`).evaluate(el => typeof el.onsubmit)).toBe('function');
            expect(await page.evaluate(async () => { await window.TraceAuth.ready; return true; })).toBe(true);
          }
        } finally {
          if (pending) pending.release();
          await page.unrouteAll({behavior:'wait'});
        }
      });
    }
  });
}

test('failed CSRF stays inert and the existing automatic retry recovers login', async ({page}) => {
  let attempts = 0;
  const retry = barrier(), resumed = barrier();
  await page.route('**/auth/csrf', async route => {
    if (++attempts === 1) return route.abort();
    retry.release();
    await resumed.promise;
    await route.continue();
  });
  try {
    await page.goto('/login.html');
    await expect(page.locator('#security-message')).toContainText('Authentication unavailable');
    await inert(page, forms[0]);
    await retry.promise;
    await expect(page.locator('#login-submit')).toBeDisabled();
    resumed.release();
    await expect(page.locator('#login-submit')).toBeEnabled();
    await expect(page.locator('#security-message')).toHaveText('');
    await page.click('#login-submit');
    await expect(page).toHaveURL(/dns_frontend\.html/);
    await expect(page.locator('#current-user')).toContainText('admin');
    expect(attempts).toBe(2);
  } finally {
    resumed.release();
    await page.unrouteAll({behavior:'wait'});
  }
});

test('ready admin create and reset retain real CSRF mutation and forced-password behavior', async ({page, browser}) => {
  await signIn(page.request);
  await page.goto('/accounts.html');
  await page.fill('#create-username', 'readiness-reset-user');
  await page.fill('#create-password', 'synthetic-initial-password');
  await page.click('#create-user');
  const row = page.locator('#users tr').filter({hasText:'readiness-reset-user'});
  await expect(row).toHaveCount(1);
  await row.getByRole('button', {name:'Reset password', exact:true}).click();
  await page.fill('#reset-password', 'synthetic-reset-password');
  const posted = page.waitForRequest(r => /\/admin\/users\/[^/]+\/reset$/.test(new URL(r.url()).pathname) && r.method() === 'POST');
  await page.locator('#reset-password-form button[type="submit"]').click();
  expect(await (await posted).headerValue('x-csrf-token')).toBeTruthy();
  await expect(page.locator('#reset-dialog')).not.toBeVisible();
  await expect(page.locator('#page-status')).toHaveText('Temporary password set.');
  const other = await browser.newPage();
  try {
    await other.goto('http://127.0.0.1:18765/login.html');
    await other.fill('#username', 'readiness-reset-user');
    await other.fill('#password', 'synthetic-reset-password');
    await other.click('#login-submit');
    await expect(other).toHaveURL(/account\.html/);
    await expect(other.locator('#password-submit')).toBeEnabled();
    await expect(other.locator('#password-required')).toBeVisible();
  } finally { await other.context().close(); }
});
