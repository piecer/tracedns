# Security storage integration contract

`SecurityStore(path, *, create=False, idle_seconds=1800, absolute_seconds=43200, retention_days=180, clock=time.time)`.

- `login(username, password, source_ip, request_id='') -> (raw_token, principal)` **tuple, not dict**.
- `authenticate(token) -> principal | None` **direct principal, not wrapper**.
- Principal/safe user: `{id, username, role, active, must_change_password}`. No CSRF field: HTTP must derive/manage CSRF separately. Session public IDs come from `sessions(user_id)`.
- `SecurityError(message, status=400)` has `.status` and `str(error)`.
- `create=False` rejects missing/invalid/version-mismatched/insecure database. An initialized empty database is permitted by constructor for bootstrap tooling; **HTTP startup must require `has_admin()`**. Never fallback to anonymous operation.
- CLI: `.venv/bin/python -m security.cli --db PATH bootstrap USER` or `reset-password USER`; getpass confirmation, no password argument.
- Bootstrap admin has `must_change_password=False`; administrator-created and reset accounts have True. HTTP must restrict forced-change sessions to password/logout/me/CSRF. Password change revokes all sessions; client logs in again.
- `audit(actor, action, target='', outcome='success', request_id='', source_ip='', details=None, status=None, job_id=None) -> event ID`. actor is safe principal or None/system. Details have strict typed allowlist; callers must not put secrets in action/target/job/request IDs. Database write exceptions propagate: caller must stop protected work.
- `audit_list(*, user_id=None, action=None, outcome=None, target=None, since=None, until=None, limit=50, offset=0) -> {events,total}`; timestamp/since/until are UTC epoch seconds. `prune_audit()` explicitly performs configured retention (default 180 days), auditing deletion count. No automatic hidden pruning; parent should schedule/call it and expose failures.
- Remaining account/session signatures follow delegated interface exactly: bootstrap, create_user, list_users, update_user, get_user, logout, change_password, sessions, revoke_sessions, has_admin.

Implementation and tests are in progress; this contract fixes integration return shapes now.
