/* Install before application scripts. Tokens live only in this closure. */
(() => {
  'use strict';
  const originalFetch = window.fetch.bind(window);
  const loginPage = location.pathname === '/login.html';
  let csrf = '';
  const auth = window.TraceAuth = {user: null, accessInvalidated: false};
  const messages = new Map();
  const invalidationListeners = new Set();
  auth.onInvalidated = listener => { invalidationListeners.add(listener); return () => invalidationListeners.delete(listener); };
  function invalidate(status){
    auth.accessInvalidated = true;
    for(const listener of invalidationListeners){ try { listener(status); } catch (_) { /* Other owners still retire. */ } }
  }
  function failure(message, status, code){
    const error = new Error(message); error.status = status; error.code = code; return error;
  }
  auth.message = (text, owner = 'fallback') => {
    if(text) messages.set(owner, text); else messages.delete(owner);
    let el = document.getElementById('security-message');
    if (!el && document.body) {
      el = document.createElement('p'); el.id = 'security-message';
      el.setAttribute('role', 'alert'); document.body.prepend(el);
    }
    if (el) { el.textContent = Array.from(messages.values()).join(' '); el.hidden = !messages.size; }
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
    if (authBlocked) return Promise.reject(failure('Sign-in failed or session expired.', 401, 'unauthenticated'));
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
      auth.message('', 'authentication');
      if(data.audit_available === false) auth.message('Audit storage is unavailable. Contact the administrator.', 'security');
      auth.user = data.user || null;
      auth.accessInvalidated = false;
      if (auth.user && auth.user.must_change_password && location.pathname !== '/account.html') location.replace('/account.html');
      failures = 0;
      return auth.user;
    }).catch(error => {
      csrf = ''; auth.user = null; authFailed = true;
      retryAt = Date.now() + Math.min(30000, 1000 * (2 ** Math.min(failures++, 5)));
      auth.message(authBlocked ? 'Sign-in failed or session expired.' : authUnavailableMessage, 'authentication');
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
    const {feedback, ...transportOptions} = options;
    const feedbackAPI = window.TraceViewFeedback;
    const local = feedbackAPI && feedbackAPI.known(feedback);
    const checkOwner = () => {
      if(local && !feedbackAPI.current(feedback)) throw new DOMException('Request owner replaced.', 'AbortError');
    };
    checkOwner();
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (url.origin !== location.origin) return originalFetch(input, transportOptions);
    const signal = options.signal || (input instanceof Request ? input.signal : undefined);
    if (signal) await abortable(ensureReady, signal);
    else await auth.ready;
    if (signal && signal.aborted) throw signal.reason;
    checkOwner();
    const method = String(options.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const write = !['GET','HEAD','OPTIONS'].includes(method);
    if (auth.user && auth.user.must_change_password && !['/auth/me','/auth/password','/auth/logout'].includes(url.pathname)) {
      throw new Error('Change your password before continuing.');
    }
    const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
    headers.set('X-CSRF-Token', csrf);
    if (auth.user && auth.user.role === 'viewer' && ['/ips','/domain-analysis'].includes(url.pathname)) url.searchParams.set('include_vt','0');
    const request = input instanceof Request ? new Request(url, input) : url.href;
    const response = await originalFetch(request, {...transportOptions, headers, credentials:'same-origin'});
    if (signal && signal.aborted) throw signal.reason;
    checkOwner();
    if (response.status === 401 && !loginPage) {
      authBlocked = true; csrf = ''; auth.user = null;
      location.replace('/login.html');
    }
    if(response.headers?.get('X-TraceDNS-Security-Error') === 'security_unavailable'){
      const message = 'Security or audit storage is unavailable. Contact the administrator.';
      auth.message(message, 'security');
      throw failure(message, response.status, 'security_unavailable');
    }
    // Manual test outcomes have a closed, secret-free body even on these
    // statuses. Preserve it for the test UI; all authentication, CSRF and
    // cancellation handling above still applies, with no retry here.
    if (method === 'POST' && ['/teams/test','/api/v1/teams/test'].includes(url.pathname) &&
        [409,429,502,503].includes(response.status)) return response;
    // Only the resend widget consumes these closed refusals. Generic 401/403
    // handling above/below remains intact; never automatically repeat a POST.
    if (method === 'POST' && ['/delivery-resend/preview','/delivery-resend',
        '/api/v1/delivery-resend/preview','/api/v1/delivery-resend'].includes(url.pathname) &&
        [400,404,409,429,503].includes(response.status)) return response;
    if (!response.ok) {
      const message = response.status === 409 ? 'Conflict: reload this page before saving again.' : response.status === 403 ? 'Permission denied for this action.' : response.status === 401 ? 'Sign-in failed or session expired.' : `Request failed (${response.status}).`;
      const security = response.status === 401 || response.status === 403;
      const code = response.status === 401 ? 'unauthenticated' : response.status === 403 ? 'forbidden' : response.status === 409 ? 'conflict' : 'http_error';
      if(security) invalidate(response.status);
      if(security || !local) auth.message(message, security ? 'access' : 'fallback');
      throw failure(message, response.status, code);
    }
    return response;
  };
  auth.json = async (url, data) => {
    const response = await fetch(url, data === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    return response.json();
  };
})();
