/* Install before application scripts. Tokens live only in this closure. */
(() => {
  'use strict';
  const originalFetch = window.fetch.bind(window);
  const loginPage = location.pathname === '/login.html';
  let csrf = '';
  const auth = window.TraceAuth = {user: null};
  auth.message = text => {
    let el = document.getElementById('security-message');
    if (!el && document.body) {
      el = document.createElement('p'); el.id = 'security-message';
      el.setAttribute('role', 'alert'); document.body.prepend(el);
    }
    if (el) el.textContent = text;
  };
  auth.ready = originalFetch(loginPage ? '/auth/csrf' : '/auth/me', {credentials:'same-origin',cache:'no-store'})
    .then(async response => {
      if (!response.ok) {
        if (!loginPage && response.status === 401) location.replace('/login.html');
        throw new Error('Authentication unavailable. Reload to retry.');
      }
      const data = await response.json(); csrf = data.csrf_token;
      if(data.audit_available === false) auth.message('Audit storage is unavailable. Contact the administrator.');
      auth.user = data.user || null;
      if (auth.user && auth.user.must_change_password && location.pathname !== '/account.html') location.replace('/account.html');
      return auth.user;
    });
  auth.ready.catch(error => auth.message(error.message));
  window.fetch = async (input, options = {}) => {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (url.origin !== location.origin) return originalFetch(input, options);
    await auth.ready;
    const method = String(options.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const write = !['GET','HEAD','OPTIONS'].includes(method);
    if (auth.user && auth.user.must_change_password && !['/auth/me','/auth/password','/auth/logout'].includes(url.pathname)) {
      throw new Error('Change your password before continuing.');
    }
    const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
    headers.set('X-CSRF-Token', csrf);
    if (auth.user && auth.user.role === 'viewer' && ['/ips','/domain-analysis'].includes(url.pathname)) url.searchParams.set('include_vt','0');
    const request = input instanceof Request ? new Request(url, input) : url.href;
    const response = await originalFetch(request, {...options, headers, credentials:'same-origin'});
    if (response.status === 401 && !loginPage) location.replace('/login.html');
    if (!response.ok) {
      const message = response.status === 409 ? 'Conflict: reload this page before saving again.' : response.status === 403 ? 'Permission denied for this action.' : response.status === 401 ? 'Sign-in failed or session expired.' : `Request failed (${response.status}).`;
      auth.message(message); throw new Error(message);
    }
    return response;
  };
  auth.json = async (url, data) => {
    const response = await fetch(url, data === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    return response.json();
  };
})();
