/* Presentation-only ownership. No I/O, backend verdicts or response bodies. */
(() => {
  'use strict';
  const tokens = new WeakMap();
  const names = new Set();
  const messages = Object.freeze({
    read_failed:'Read failed. Previous data, if any, is stale. Retry this view.',
    too_large:'Prepared entry is too large (422). Previous data retained. Use the full JSON download; no automatic fallback.',
    forbidden:'Permission denied for this action. Reload to check your access.',
    unauthenticated:'Sign-in failed or session expired.',
    security_unavailable:'Security or audit storage is unavailable. Contact the administrator.',
    conflict:'Conflict: the saved revision changed. Your draft is retained; load explicitly before saving again.',
    write_failed:'Action failed. Review this form before trying again.',
    write_uncertain:'Action outcome is unknown. Check saved state before explicitly trying again; no automatic retry.',
    invalid_response:'Response could not be read. Previous data, if any, is stale.'
  });
  const known = token => !!token && typeof token === 'object' && tokens.has(token);
  const current = token => known(token) && tokens.get(token).active === token;
  function code(error, mutation = false){
    if(error?.code === 'security_unavailable') return 'security_unavailable';
    if(error?.status === 401) return 'unauthenticated';
    if(error?.status === 403) return 'forbidden';
    if(error?.status === 409) return 'conflict';
    if(error?.status === 422) return 'too_large';
    if(mutation) return !error?.status || error.status >= 500 ? 'write_uncertain' : 'write_failed';
    return error instanceof SyntaxError ? 'invalid_response' : 'read_failed';
  }
  function register(name, renderer){
    if(typeof renderer !== 'function') throw new TypeError('A local renderer is required');
    if(typeof name !== 'string' || !/^[a-z][a-z0-9:-]{0,63}$/.test(name) || names.has(name)) throw new TypeError('Unique fixed owner required');
    names.add(name);
    // One retained failure per owner, not an incident history or unbounded query cache.
    const scope = {active:null, query:null, generation:0, phase:'unknown', failure:null};
    const snapshot = () => Object.freeze({owner:name, query:scope.query, phase:scope.phase,
      error:scope.failure?.query === scope.query ? scope.failure : null});
    const publish = () => renderer(snapshot());
    return Object.freeze({
      begin(query){
        if(typeof query !== 'string') throw new TypeError('Query identity must be a string');
        const token = Object.freeze({owner:name, query, generation:++scope.generation});
        scope.query = query; scope.active = token; scope.phase = 'loading';
        tokens.set(token, scope); publish(); return token;
      },
      fail(token, errorCode){
        if(!current(token) || tokens.get(token) !== scope) return false;
        const key = Object.hasOwn(messages, errorCode) ? errorCode : 'read_failed';
        const identity = JSON.stringify([name, token.query, key]);
        const previous = scope.failure?.identity === identity ? scope.failure : null;
        const now = Date.now();
        scope.failure = Object.freeze({identity, query:token.query, code:key, message:messages[key],
          firstObservedAt:previous?.firstObservedAt ?? now, lastObservedAt:now,
          observations:(previous?.observations || 0) + 1});
        scope.phase = 'failed'; publish(); return true;
      },
      succeed(token){
        if(!current(token) || tokens.get(token) !== scope) return false;
        if(scope.failure?.query === token.query) scope.failure = null;
        scope.phase = 'ready'; publish(); return true;
      },
      invalidate(){ scope.active = null; scope.phase = 'paused'; publish(); },
      forget(){ scope.active = null; scope.failure = null; scope.query = null; scope.phase = 'unknown'; publish(); },
      snapshot
    });
  }
  const api = Object.freeze({register, known, current, code});
  if(typeof module !== 'undefined' && module.exports) module.exports = api;
  if(typeof window !== 'undefined') window.TraceViewFeedback = api;
})();
