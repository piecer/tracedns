const {expect} = require('@playwright/test');
const {spawn} = require('node:child_process');
const {once} = require('node:events');

async function withViewServer(options, run) {
  const child = spawn(process.env.PYTHON || '.venv/bin/python', [
    'tests/e2e/view_server.py', '--delivery', options.delivery || 'acked', '--rows', String(options.rows || 12),
    ...(options.documentation ? ['--documentation'] : [])
  ], {stdio:['ignore', 'pipe', 'pipe']});
  let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  try {
    const port = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('View fixture startup timeout: ' + stderr)), 15000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); reject(new Error('View fixture exit ' + code + ': ' + stderr)); });
      let buffer = '';
      child.stdout.on('data', bytes => {
        buffer += bytes;
        if(buffer.includes('\n')) { clearTimeout(timer); resolve(JSON.parse(buffer.split('\n')[0]).port); }
      });
    });
    await run(`http://127.0.0.1:${port}`);
  } finally {
    if(child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      await exited;
      clearTimeout(timer);
    }
  }
}

async function loginView(page, origin, username = 'admin', password = 'test-admin-password', waitForRows = true) {
  await page.goto(origin + '/login.html');
  await expect(page.locator('#login-submit')).toBeEnabled();
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('#login-submit');
  await expect(page).not.toHaveURL(/login\.html/);
  await page.waitForLoadState('load');
  if(waitForRows) await expect(page.locator('#resultsTable tbody tr').first()).toContainText('target-000.test');
}

module.exports = {withViewServer, loginView};
