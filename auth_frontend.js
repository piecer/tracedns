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
  // One lifetime owns auth wait, transport and body decoding. Aborting the
  // controller stops real browser I/O; the race also settles uncooperative peers.
  function abortable(work, signal){
    if (signal.aborted) return Promise.reject(signal.reason || new DOMException('Request cancelled.', 'AbortError'));
    return new Promise((resolve, reject) => {
      const aborted = () => reject(signal.reason || new DOMException('Request cancelled.', 'AbortError'));
      signal.addEventListener('abort', aborted, {once:true});
      Promise.resolve().then(() => {
        if (signal.aborted) throw signal.reason;
        return work();
      }).then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
    });
  }
  async function lifetime(work, {signal, timeoutMs = 15000} = {}){
    const controller = new AbortController();
    const cancel = () => controller.abort(signal.reason || new DOMException('Request cancelled.', 'AbortError'));
    if (signal) {
      if (signal.aborted) cancel();
      else signal.addEventListener('abort', cancel, {once:true});
    }
    const duration = Number.isFinite(timeoutMs) && timeoutMs > 0 ? Math.min(timeoutMs, 15000) : 15000;
    const timer = setTimeout(() => controller.abort(new DOMException('Request timed out.', 'TimeoutError')), duration);
    try { return await abortable(() => work(controller.signal), controller.signal); }
    finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', cancel);
    }
  }
  auth.readJSON = (url, options = {}) => lifetime(async signal => {
    const response = await window.fetch(url, {...options, signal});
    return response.json();
  }, options);
  let readyPromise = null;
  let authFailed = false;
  let authBlocked = false;
  let retryAt = 0;
  let failures = 0;
  const authUnavailableMessage = 'Authentication unavailable. Will retry on the next request.';
  function ensureReady(){
    if (authBlocked) return Promise.reject(new Error('Sign-in failed or session expired.'));
    if (readyPromise && (!authFailed || authBlocked || Date.now() < retryAt)) return readyPromise;
    authFailed = false;
    readyPromise = lifetime(async signal => {
      const response = await originalFetch(loginPage ? '/auth/csrf' : '/auth/me', {credentials:'same-origin',cache:'no-store',signal});
      if (signal.aborted) throw signal.reason;
      if (!response.ok) {
        if (!loginPage && response.status === 401) {
          authBlocked = true;
          location.replace('/login.html');
        }
        throw new Error('Authentication unavailable. Reload to retry.');
      }
      return response.json();
    }).then(data => {
      csrf = data.csrf_token;
      const message = document.getElementById('security-message');
      if(message && message.textContent === authUnavailableMessage) message.textContent = '';
      if(data.audit_available === false) auth.message('Audit storage is unavailable. Contact the administrator.');
      auth.user = data.user || null;
      if (auth.user && auth.user.must_change_password && location.pathname !== '/account.html') location.replace('/account.html');
      failures = 0;
      return auth.user;
    }).catch(error => {
      csrf = ''; auth.user = null; authFailed = true;
      retryAt = Date.now() + Math.min(30000, 1000 * (2 ** Math.min(failures++, 5)));
      auth.message(authBlocked ? 'Sign-in failed or session expired.' : authUnavailableMessage);
      throw error;
    });
    // Observe eager initialization failures without poisoning later reads of ready.
    readyPromise.catch(() => {});
    return readyPromise;
  }
  Object.defineProperty(auth, 'ready', {get: ensureReady});
  Object.defineProperty(auth, 'retryDelay', {get: () => authBlocked ? null : Math.max(1000, retryAt - Date.now())});
  ensureReady();
  window.fetch = async (input, options = {}) => {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (url.origin !== location.origin) return originalFetch(input, options);
    const signal = options.signal || (input instanceof Request ? input.signal : undefined);
    if (signal) await abortable(ensureReady, signal);
    else await auth.ready;
    if (signal && signal.aborted) throw signal.reason;
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
    if (signal && signal.aborted) throw signal.reason;
    if (response.status === 401 && !loginPage) {
      authBlocked = true; csrf = ''; auth.user = null;
      location.replace('/login.html');
    }
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
