'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let checked = 0;
async function environment(status, security = false) {
  const calls = [], messages = [], invalidations = [];
  const context = {URL, Request, Response, Headers, AbortController, DOMException, setTimeout, clearTimeout,
    document: {getElementById() { return null; }},
    location: {href: 'http://localhost/dns_frontend.html', origin: 'http://localhost', pathname: '/dns_frontend.html', replace() {}},
    fetch: async (url, options) => {
      if (String(url).endsWith('/auth/me')) return new Response(JSON.stringify({user: {role: 'admin'}, csrf_token: 'fixture-only'}));
      calls.push({url, options});
      return new Response(JSON.stringify({error: 'provider_unsettled', code: 'provider_unsettled'}), {
        status, headers: security ? {'X-TraceDNS-Security-Error': 'security_unavailable'} : {}
      });
    }};
  context.window = context; vm.createContext(context);
  vm.runInContext(fs.readFileSync('auth_frontend.js', 'utf8'), context);
  await context.TraceAuth.ready;
  context.TraceAuth.message = (text, owner) => messages.push({text, owner});
  context.TraceAuth.onInvalidated(code => invalidations.push(code));
  return {context, calls, messages, invalidations};
}
(async () => {
  for (const prefix of ['', '/api/v1']) {
    for (const [method, suffix] of [['GET', '/ai/status'], ['POST', '/ai/jobs'],
      ['GET', '/ai/jobs/' + 'a'.repeat(32)], ['POST', '/ai/jobs/' + 'a'.repeat(32) + '/cancel']]) {
      for (const status of [400,404,409,413,422,429,502,503,504]) {
        const e = await environment(status);
        const response = await e.context.fetch(prefix + suffix, {method});
        assert.equal(response.status, status);
        assert.equal((await response.json()).code, 'provider_unsettled');
        assert.equal(e.calls.length, 1, 'no implicit retry');
        assert.equal(new Headers(e.calls[0].options.headers).get('X-CSRF-Token'), 'fixture-only');
        assert.equal(e.calls[0].options.credentials, 'same-origin');
        assert.deepEqual(e.messages, [], 'closed task failure stays local');
        checked++;
      }
      for (const status of [401,403]) {
        const e = await environment(status);
        await assert.rejects(e.context.fetch(prefix + suffix, {method}), error => error.status === status);
        assert.deepEqual(e.invalidations, [status]);
        assert(e.messages.some(message => message.owner === 'access'));
        checked++;
      }
      const e = await environment(503, true);
      await assert.rejects(e.context.fetch(prefix + suffix, {method}), error => error.code === 'security_unavailable');
      assert(e.messages.some(message => message.owner === 'security'));
      checked++;
    }
  }
  for (const [method, path] of [['POST','/ai/jobs/arbitrary/cancel'],['DELETE','/ai/jobs']]) {
    const e = await environment(503);
    await assert.rejects(e.context.fetch(path, {method}));
    assert(e.messages.some(message => message.owner === 'fallback'));
    checked++;
  }
  console.log(`PASS ${checked} real auth-wrapper AI protocol controls`);
})().catch(error => { console.error(error); process.exitCode = 1; });
