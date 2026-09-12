/* Shared security navigation and account screens. No untrusted HTML. */
(() => {
  'use strict';
  const A = window.TraceAuth;
  const $ = id => document.getElementById(id);
  const node = (tag, text) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = String(text ?? ''); return el; };
  const status = text => { if ($('page-status')) $('page-status').textContent = text; };
  const act = fn => async event => {
    if (event) event.preventDefault();
    const button = event && (event.submitter || event.currentTarget);
    if (button) button.disabled = true;
    try { await fn(event); } catch (error) { A.message(error.message); status(error.message); }
    finally { if (button) button.disabled = false; }
  };
  const button = (text, fn) => { const el = node('button', text); el.type = 'button'; el.onclick = act(fn); return el; };
  const signOut = async () => { await A.json('/auth/logout', {}); location.replace('/login.html'); };
  function nav(user) {
    if ($('security-nav')) return;
    const el = node('nav'); el.id = 'security-nav'; el.setAttribute('aria-label','Account navigation');
    const identity = node('span', `${user.username} (${user.role})`); identity.id = 'current-user'; el.append(identity);
    const links = user.must_change_password ? [['Account','/account.html']] : [['Console','/dns_frontend.html'],['Account','/account.html'],[user.role === 'admin' ? 'Audit' : 'My activity','/audit.html']];
    if (user.role === 'admin' && !user.must_change_password) links.push(['Users','/accounts.html']);
    links.forEach(([label, href]) => { const a = node('a', label); a.href = href; el.append(a); });
    const logout = button('Sign out', signOut); logout.id = 'logout'; el.append(logout); document.body.prepend(el);
  }
  async function login() {
    $('login-form').onsubmit = act(async () => {
      const result = await A.json('/auth/login', {username:$('username').value,password:$('password').value});
      $('password').value = '';
      location.replace(result.user.must_change_password ? '/account.html' : '/dns_frontend.html');
    });
  }
  async function account(user) {
    $('password-required').hidden = !user.must_change_password;
    $('session-section').hidden = !!user.must_change_password;
    $('password-form').onsubmit = act(async () => {
      if ($('new-password').value !== $('confirm-password').value) throw new Error('New passwords do not match.');
      await A.json('/auth/password', {current_password:$('current-password').value,new_password:$('new-password').value});
      $('password-form').reset(); location.replace('/login.html');
    });
    if (user.must_change_password) return;
    const refresh = async () => {
      const data = await A.json('/auth/sessions'); $('sessions').replaceChildren();
      for (const session of data.sessions) {
        const li = node('li', `Created ${localTime(session.created_at)} · Last seen ${localTime(session.last_seen)}${session.current ? ' · This session' : ''} `);
        li.append(button('Revoke session', async () => { await A.json('/auth/sessions/revoke', {session_id:session.id}); if (session.current) location.replace('/login.html'); else await refresh(); }));
        $('sessions').append(li);
      }
    };
    $('revoke-all-sessions').onclick = act(async () => { if (!confirm('Sign out every session, including this one?')) return; await A.json('/auth/sessions/revoke', {}); location.replace('/login.html'); });
    await refresh();
  }
  function localTime(value) { if (!value) return '—'; const date = new Date(typeof value === 'number' ? value * 1000 : value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(); }
  async function accounts() {
    let resetId;
    const refresh = async () => {
      const data = await A.json('/admin/users'); $('users').replaceChildren();
      for (const user of data.users) {
        const tr = node('tr'); tr.dataset.userId = user.id;
        tr.append(node('td',user.username));
        const roleCell = node('td'), role = node('select'); role.setAttribute('aria-label',`Role for ${user.username}`);
        ['viewer','operator','admin'].forEach(value => { const option = node('option',value); option.value = value; role.append(option); });
        role.value = user.role; roleCell.append(role); tr.append(roleCell);
        tr.append(node('td',`${user.active ? 'Active' : 'Disabled'}${user.must_change_password ? ' · Password change required' : ''}`));
        const actions = node('td');
        const post = async (action, payload) => { await A.json(`/admin/users/${encodeURIComponent(user.id)}/${action}`, payload); status('User updated.'); await refresh(); };
        actions.append(button('Save role',async () => { if(confirm('Change role and revoke sessions?')) await post('update',{role:role.value}); }));
        actions.append(button(user.active ? 'Disable' : 'Enable',async () => { if(confirm('Change account status and revoke sessions?')) await post('update',{active:!user.active}); }));
        actions.append(button('Reset password',() => { resetId = user.id; $('reset-password').value = ''; $('reset-dialog').showModal(); }));
        actions.append(button('Revoke sessions',async () => { if(confirm('Revoke all sessions for this user?')) await post('revoke',{}); }));
        tr.append(actions); $('users').append(tr);
      }
    };
    $('create-user-form').onsubmit = act(async () => {
      await A.json('/admin/users',Object.fromEntries(new FormData($('create-user-form'))));
      $('create-user-form').reset(); status('User created. Password change required at next sign-in.'); await refresh();
    });
    $('reset-cancel').onclick = () => { $('reset-password').value = ''; $('reset-dialog').close(); };
    $('reset-password-form').onsubmit = act(async () => {
      await A.json(`/admin/users/${encodeURIComponent(resetId)}/reset`,{password:$('reset-password').value});
      $('reset-password').value = ''; $('reset-dialog').close(); status('Temporary password set.'); await refresh();
    });
    await refresh();
  }
  async function audit(user) {
    const admin = user.role === 'admin'; let offset = 0; const limit = 50; let filters = {};
    $('actor-filter').hidden = !admin; $('audit-export').hidden = !admin;
    const refresh = async () => {
      const query = new URLSearchParams({...filters,limit,offset});
      const data = await A.json(`${admin ? '/admin/audit' : '/auth/activity'}?${query}`);
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
    $('audit-prev').onclick = async () => { offset = Math.max(0,offset-limit); try { await refresh(); } catch(e) { A.message(e.message); } };
    $('audit-next').onclick = async () => { offset += limit; try { await refresh(); } catch(e) { A.message(e.message); } };
    $('audit-export').onclick = act(async () => {
      const response = await fetch('/admin/audit/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(filters)});
      const url = URL.createObjectURL(await response.blob()); const link = node('a'); link.href = url; link.download = 'tracedns-audit.jsonl'; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
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
  async function start() {
    try {
      const user = await A.ready;
      if (location.pathname === '/login.html') { await login(); return; }
      if (!user) return;
      nav(user); permissions(user);
      if (user.must_change_password && location.pathname !== '/account.html') return;
      if (['/accounts.html','/settings.html'].includes(location.pathname) && user.role !== 'admin') { document.querySelector('main')?.setAttribute('hidden',''); A.message('Administrator access required.'); return; }
      if (location.pathname === '/account.html') await account(user);
      if (location.pathname === '/accounts.html') await accounts();
      if (location.pathname === '/audit.html') await audit(user);
      if (location.pathname === '/settings.html') location.replace('/dns_frontend.html#settings-alerts');
      if (location.pathname === '/dns_dashboard.html') location.replace('/dns_frontend.html');
    } catch (error) { A.message(error.message); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',start); else start();
})();
