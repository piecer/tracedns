// Real browser contexts against an isolated Python server; never reuse production.
const {defineConfig} = require('@playwright/test');
module.exports = defineConfig({
  testDir: './tests/e2e', workers: 1, timeout: 60000,
  use: {baseURL: 'http://127.0.0.1:18765', headless: true, trace: 'retain-on-failure'},
  webServer: {
    command: `${process.env.PYTHON || '.venv/bin/python'} tests/e2e/server.py`,
    url: 'http://127.0.0.1:18765/login.html', reuseExistingServer: false, timeout: 30000
  }
});
