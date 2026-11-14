/* Shared security navigation and account screens. No untrusted HTML. */
(() => {
  'use strict';
  const A = window.TraceAuth;
  const loginPage = location.pathname === '/login.html';
  let accessEpoch = 0;
  const current = epoch => epoch === accessEpoch && !A.accessInvalidated;
  const requireCurrent = epoch => {
    if(!current(epoch)) throw new DOMException('Access changed. Reload to check permissions.', 'AbortError');
  };
  // Auth checks headers; these page owners also fence body decoding and every
  // continuation using it. No stale receipt may publish or start a follow-up.
  const protectedJSON = async (url, data) => {
    const epoch = accessEpoch;
    requireCurrent(epoch);
    const result = await A.json(url, data);
    requireCurrent(epoch);
    return result;
  };
  const $ = id => document.getElementById(id);
  const node = (tag, text) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = String(text ?? ''); return el; };
  const status = text => { if ($('page-status')) $('page-status').textContent = text; };
  const act = (fn, protectedAction = true) => async event => {
    if (event) event.preventDefault();
    const epoch = accessEpoch;
    const allowed = () => !protectedAction || loginPage || current(epoch);
    if(!allowed()) return;
    const button = event && (event.submitter || event.currentTarget);
    if (button) button.disabled = true;
    try { await fn(event); } catch (error) { if(allowed()) { A.message(error.message); status(error.message); } }
    finally { if (button && allowed() && button.isConnected) button.disabled = false; }
  };
  const button = (text, fn) => { const el = node('button', text); el.type = 'button'; el.onclick = act(fn); return el; };
  // Credential forms start inert in HTML, including when scripts fail to load.
  // Call only after auth readiness; install prevention before enabling submit.
  const credentialForm = (id, fn) => {
    const form = $(id);
    form.onsubmit = act(fn);
    form.querySelectorAll('button[type="submit"]').forEach(el => { el.disabled = false; });
  };
  const signOut = async () => { await A.json('/auth/logout', {}); location.replace('/login.html'); };
  A.onInvalidated?.(() => {
    accessEpoch++;
    // Failed login must remain retryable; sign-out is outside protected data.
    if(loginPage) return;
    document.querySelectorAll('#sessions, #users, #audit-events, #audit-pagination, #current-user').forEach(el => el.replaceChildren());
    if(['/account.html', '/accounts.html', '/audit.html'].includes(location.pathname)){
      document.querySelectorAll('main dialog').forEach(el => el.close());
      document.querySelectorAll('main input, main textarea, main select, main button').forEach(el => {
        if('value' in el) el.value = '';
        el.disabled = true;
      });
      status('Access changed. Protected data retired. Reload to check permissions.');
    }
    document.querySelectorAll('[data-access]').forEach(el => {
      el.hidden = true;
      if('disabled' in el) el.disabled = true;
    });
    document.querySelectorAll('#settings input, #settings textarea, #customPreviewResult, #verifyResult').forEach(el => {
      if('value' in el) el.value = ''; else el.textContent = '';
    });
    const targets = document.querySelector('#domainTable tbody');
    if(targets) targets.replaceChildren();
  });
  function nav(user) {
    if ($('security-nav')) return;
    const el = node('nav'); el.id = 'security-nav'; el.setAttribute('aria-label','Account navigation');
    const identity = node('span', `${user.username} (${user.role})`); identity.id = 'current-user'; el.append(identity);
    const links = user.must_change_password ? [['Account','/account.html']] : [['Console','/dns_frontend.html'],['Account','/account.html'],[user.role === 'admin' ? 'Audit' : 'My activity','/audit.html']];
    if (user.role === 'admin' && !user.must_change_password) links.push(['Users','/accounts.html']);
    links.forEach(([label, href]) => { const a = node('a', label); a.href = href; el.append(a); });
    const logout = node('button', 'Sign out'); logout.type = 'button';
    logout.onclick = act(signOut, false); logout.id = 'logout'; el.append(logout);
    if ($('accountNavigation')) $('accountNavigation').append(el); else document.body.prepend(el);
  }
  async function login() {
    credentialForm('login-form', async () => {
      const result = await A.json('/auth/login', {username:$('username').value,password:$('password').value});
      $('password').value = '';
      location.replace(result.user.must_change_password ? '/account.html' : '/dns_frontend.html');
    });
  }
  async function account(user) {
    $('password-required').hidden = !user.must_change_password;
    $('session-section').hidden = !!user.must_change_password;
    credentialForm('password-form', async () => {
      if ($('new-password').value !== $('confirm-password').value) throw new Error('New passwords do not match.');
      await protectedJSON('/auth/password', {current_password:$('current-password').value,new_password:$('new-password').value});
      $('password-form').reset(); location.replace('/login.html');
    });
    if (user.must_change_password) return;
    const refresh = async () => {
      const data = await protectedJSON('/auth/sessions'); $('sessions').replaceChildren();
      for (const session of data.sessions) {
        const li = node('li', `Created ${localTime(session.created_at)} · Last seen ${localTime(session.last_seen)}${session.current ? ' · This session' : ''} `);
        li.append(button('Revoke session', async () => { await protectedJSON('/auth/sessions/revoke', {session_id:session.id}); if (session.current) location.replace('/login.html'); else await refresh(); }));
        $('sessions').append(li);
      }
    };
    $('revoke-all-sessions').onclick = act(async () => { if (!confirm('Sign out every session, including this one?')) return; await protectedJSON('/auth/sessions/revoke', {}); location.replace('/login.html'); });
    await refresh();
  }
  function localTime(value) { if (!value) return '—'; const date = new Date(typeof value === 'number' ? value * 1000 : value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(); }
  async function accounts() {
    let resetId;
    const refresh = async () => {
      const data = await protectedJSON('/admin/users'); $('users').replaceChildren();
      for (const user of data.users) {
        const tr = node('tr'); tr.dataset.userId = user.id;
        tr.append(node('td',user.username));
        const roleCell = node('td'), role = node('select'); role.setAttribute('aria-label',`Role for ${user.username}`);
        ['viewer','operator','admin'].forEach(value => { const option = node('option',value); option.value = value; role.append(option); });
        role.value = user.role; roleCell.append(role); tr.append(roleCell);
        tr.append(node('td',`${user.active ? 'Active' : 'Disabled'}${user.must_change_password ? ' · Password change required' : ''}`));
        const actions = node('td');
        const post = async (action, payload) => { await protectedJSON(`/admin/users/${encodeURIComponent(user.id)}/${action}`, payload); status('User updated.'); await refresh(); };
        actions.append(button('Save role',async () => { if(confirm('Change role and revoke sessions?')) await post('update',{role:role.value}); }));
        actions.append(button(user.active ? 'Disable' : 'Enable',async () => { if(confirm('Change account status and revoke sessions?')) await post('update',{active:!user.active}); }));
        actions.append(button('Reset password',() => { resetId = user.id; $('reset-password').value = ''; $('reset-dialog').showModal(); }));
        actions.append(button('Revoke sessions',async () => { if(confirm('Revoke all sessions for this user?')) await post('revoke',{}); }));
        tr.append(actions); $('users').append(tr);
      }
    };
    credentialForm('create-user-form', async () => {
      await protectedJSON('/admin/users',Object.fromEntries(new FormData($('create-user-form'))));
      $('create-user-form').reset(); status('User created. Password change required at next sign-in.'); await refresh();
    });
    $('reset-cancel').onclick = () => { $('reset-password').value = ''; $('reset-dialog').close(); };
    credentialForm('reset-password-form', async () => {
      await protectedJSON(`/admin/users/${encodeURIComponent(resetId)}/reset`,{password:$('reset-password').value});
      $('reset-password').value = ''; $('reset-dialog').close(); status('Temporary password set.'); await refresh();
    });
    await refresh();
  }
  async function audit(user) {
    const admin = user.role === 'admin'; let offset = 0; const limit = 50; let filters = {};
    $('actor-filter').hidden = !admin; $('audit-export').hidden = !admin;
    const refresh = async () => {
      const query = new URLSearchParams({...filters,limit,offset});
      const data = await protectedJSON(`${admin ? '/admin/audit' : '/auth/activity'}?${query}`);
      $('audit-events').replaceChildren();
      for (const event of data.events) {
        const tr = node('tr'); tr.dataset.eventId = event.id;
        [localTime(event.ts),event.actor_name || event.actor_id || 'system',event.action,event.target,event.outcome,event.source_ip,[event.request_id,event.job_id].filter(Boolean).join(' / ')].forEach(value => tr.append(node('td',value)));
        $('audit-events').append(tr);
      }
      $('audit-pagination').textContent = `${data.total} events · Offset ${offset}`;
      $('audit-prev').disabled = offset === 0; $('audit-next').disabled = offset + limit >= data.total;
      status(data.events.length ? '' : 'No events match these filters.');
    };
    $('audit-filter-form').onsubmit = act(async () => {
      filters = {};
      for (const [key, value] of new FormData($('audit-filter-form'))) if (value && (admin || key !== 'user_id')) filters[key] = ['since','until'].includes(key) ? new Date(value).getTime() / 1000 : value;
      offset = 0; await refresh();
    });
    const move = async delta => {
      const epoch = accessEpoch;
      if(!current(epoch)) return;
      offset = Math.max(0,offset+delta);
      try { await refresh(); } catch(e) { if(current(epoch)) A.message(e.message); }
    };
    $('audit-prev').onclick = () => move(-limit);
    $('audit-next').onclick = () => move(limit);
    $('audit-export').onclick = act(async () => {
      const epoch = accessEpoch;
      const response = await fetch('/admin/audit/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(filters)});
      requireCurrent(epoch);
      const blob = await response.blob();
      requireCurrent(epoch);
      const url = URL.createObjectURL(blob); const link = node('a'); link.href = url; link.download = 'tracedns-audit.jsonl'; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
      status('Audit export downloaded.');
    });
    await refresh();
  }
  function permissions(user) {
    document.body.dataset.role = user.role;
    const style = node('style');
    style.textContent = '[data-role="viewer"] [data-access="operator"],[data-role="viewer"] [data-access="admin"],[data-role="operator"] [data-access="admin"]{display:none!important}';
    document.head.append(style);
    document.querySelectorAll('[data-access]').forEach(el => {
      if (user.role !== 'admin' && (el.dataset.access === 'admin' || user.role === 'viewer')) { el.hidden = true; if ('disabled' in el) el.disabled = true; }
    });
    if (user.role === 'viewer') ['ips_include_vt','domain_analysis_include_vt'].forEach(id => { if ($(id)) { $(id).checked = false; $(id).disabled = true; } });
  }
  let startComplete = false;
  let startPending = false;
  let startRetry = null;
  async function start() {
    if(startComplete || startPending) return;
    startPending = true;
    const epoch = accessEpoch;
    let authenticationReady = false;
    if(startRetry !== null) { clearTimeout(startRetry); startRetry = null; }
    try {
      const user = await A.ready;
      authenticationReady = true;
      if (location.pathname === '/login.html') { await login(); startComplete = true; return; }
      if (!user) return;
      requireCurrent(epoch);
      nav(user); permissions(user);
      if (user.must_change_password && location.pathname !== '/account.html') return;
      if (['/accounts.html','/settings.html'].includes(location.pathname) && user.role !== 'admin') { document.querySelector('main')?.setAttribute('hidden',''); A.message('Administrator access required.'); return; }
      if (location.pathname === '/account.html') await account(user);
      if (location.pathname === '/accounts.html') await accounts();
      if (location.pathname === '/audit.html') await audit(user);
      if (location.pathname === '/settings.html') location.replace('/dns_frontend.html#settings-alerts');
      if (location.pathname === '/dns_dashboard.html') location.replace('/dns_frontend.html');
      startComplete = true;
    } catch (error) {
      // Authentication owns its transient banner and retry policy. Re-running
      // page initialization on downstream 403/503 would duplicate decoration
      // and repeatedly dispatch reads that cannot repair authentication.
      if(!authenticationReady){
        if(A.retryDelay !== null) startRetry = setTimeout(start, A.retryDelay);
      } else if(current(epoch)) { A.message(error.message); }
    } finally { startPending = false; }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',start); else start();
})();
