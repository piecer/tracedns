"""Private SQLite accounts, sessions, and transactional audit storage."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from contextlib import contextmanager


class SecurityError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class SecurityStore:
    def __init__(self, path, *, create=False, idle_seconds=1800,
                 absolute_seconds=43200, retention_days=180, clock=time.time):
        self.path = Path(path).absolute()
        self.clock = clock
        self.idle_seconds = idle_seconds
        self.absolute_seconds = absolute_seconds
        self.retention_days = retention_days
        if not self.path.exists():
            if not create:
                raise SecurityError('Security database is not initialized', 503)
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.path.parent.stat().st_mode & 0o077:
                raise SecurityError('Use a private directory for the security database', 503)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with self._db() as db:
                db.executescript('''
                CREATE TABLE schema_version(version INTEGER NOT NULL);
                INSERT INTO schema_version VALUES(1);
                CREATE TABLE audit_events(id TEXT PRIMARY KEY, timestamp REAL,
                  actor_user_id TEXT, actor_username TEXT, actor_role TEXT,
                  action TEXT, target TEXT, outcome TEXT, request_id TEXT,
                  source_ip TEXT, details TEXT, status INTEGER, job_id TEXT);
                CREATE TABLE sessions(id TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL,
                  user_id TEXT NOT NULL REFERENCES users(id), created REAL,
                  last_seen REAL, expires REAL);
                CREATE TABLE login_attempts(id INTEGER PRIMARY KEY, timestamp REAL,
                  username TEXT, source_ip TEXT);
                CREATE INDEX attempt_time ON login_attempts(timestamp);
                CREATE INDEX session_user ON sessions(user_id);
                CREATE TABLE users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL, role TEXT NOT NULL,
                  active INTEGER NOT NULL, must_change_password INTEGER NOT NULL);
                ''')
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise SecurityError('Unsafe security database path', 503)
        if self.path.stat().st_mode & 0o077 or self.path.parent.stat().st_mode & 0o077:
            raise SecurityError('Security database requires private permissions', 503)
        with self._db() as db:
            try:
                versions = db.execute('SELECT version FROM schema_version').fetchall()
                if len(versions) != 1 or versions[0][0] != 1:
                    raise SecurityError('Unsupported security schema', 503)
                db.execute('SELECT id FROM users LIMIT 1')
            except sqlite3.DatabaseError as exc:
                raise SecurityError('Invalid security schema', 503) from exc

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def has_admin(self):
        with self._db() as db:
            return bool(db.execute("SELECT 1 FROM users WHERE role='admin' AND active=1").fetchone())

    @staticmethod
    def _safe(row):
        if row is None:
            return None
        return {key: bool(row[key]) if key in ('active', 'must_change_password')
                else row[key] for key in
                ('id', 'username', 'role', 'active', 'must_change_password')}

    @staticmethod
    def _username(username):
        import re
        if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username):
            raise SecurityError('Invalid username')
        return username.lower()

    def _actor(self, db, actor, *, admin=False, user_id=None):
        row = db.execute('SELECT * FROM users WHERE id=?',
                         (actor.get('id') if isinstance(actor, dict) else actor,)).fetchone()
        if not row or not row['active'] or (admin and row['role'] != 'admin'):
            raise SecurityError('Forbidden', 403)
        if user_id and row['id'] != user_id and row['role'] != 'admin':
            raise SecurityError('Forbidden', 403)
        return self._safe(row)

    def _audit(self, db, actor, action, target='', outcome='success', request_id='',
               source_ip='', details=None, status=None, job_id=None):
        actor = actor if isinstance(actor, dict) else {'username': 'system', 'role': 'system'}
        clean = {key: value for key, value in (details or {}).items()
                 if key in ('active', 'must_change_password', 'count')
                 and isinstance(value, (bool, int))}
        if (details or {}).get('role') in ('admin', 'operator', 'viewer'):
            clean['role'] = details['role']
        event_id = secrets.token_hex(16)
        db.execute('INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (event_id, self.clock(), actor.get('id'), actor.get('username'),
                    actor.get('role'), action, str(target), outcome, request_id,
                    source_ip, json.dumps(clean), status, job_id))
        return event_id

    def get_user(self, user_id):
        with self._db() as db:
            return self._safe(db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone())

    def list_users(self):
        with self._db() as db:
            return [self._safe(row) for row in db.execute('SELECT * FROM users ORDER BY username')]

    def _insert_user(self, db, username, encoded, role, must_change):
        if role not in ('admin', 'operator', 'viewer'):
            raise SecurityError('Invalid role')
        user_id = secrets.token_hex(16)
        try:
            db.execute('INSERT INTO users VALUES(?,?,?,?,1,?)',
                       (user_id, username, encoded, role, int(must_change)))
        except sqlite3.IntegrityError as exc:
            raise SecurityError('Username already exists', 409) from exc
        return self._safe(db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone())

    def bootstrap(self, username, password):
        from .passwords import hash_password
        username = self._username(username)
        encoded = hash_password(password)
        with self._db() as db:
            if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise SecurityError('Already bootstrapped', 409)
            user = self._insert_user(db, username, encoded, 'admin', False)
            self._audit(db, user, 'account.bootstrap', user['id'])
            return user

    def create_user(self, username, password, role, *, actor, request_id='', source_ip=''):
        from .passwords import hash_password
        username = self._username(username)
        encoded = hash_password(password)
        with self._db() as db:
            principal = self._actor(db, actor, admin=True)
            user = self._insert_user(db, username, encoded, role, True)
            self._audit(db, principal, 'account.create', user['id'],
                        request_id=request_id, source_ip=source_ip, details={'role': role})
            return user

    @staticmethod
    def _digest(token):
        if not isinstance(token, str) or not 20 <= len(token) <= 128:
            return ''
        return hashlib.sha256(token.encode()).hexdigest()

    def login(self, username, password, source_ip, request_id=''):
        from .passwords import verify_password
        try:
            username = self._username(username)
        except SecurityError:
            username = '<invalid>'
        now = self.clock()
        token = None
        with self._db() as db:
            db.execute('DELETE FROM login_attempts WHERE timestamp<=?', (now - 900,))
            attempts = db.execute('SELECT COUNT(*) FROM login_attempts WHERE username=? OR source_ip=?',
                                  (username, source_ip)).fetchone()[0]
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            principal = self._safe(user)
            if attempts >= 10:
                status, action = 429, 'auth.login_limited'
            elif verify_password(user['password_hash'] if user else None, password) and user['active']:
                status, action = 200, 'auth.login'
                token = secrets.token_urlsafe(32)
                db.execute('DELETE FROM sessions WHERE expires<=? OR last_seen<=?',
                           (now, now - self.idle_seconds))
                db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)',
                           (secrets.token_hex(16), self._digest(token), user['id'],
                            now, now, now + self.absolute_seconds))
            else:
                status, action = 401, 'auth.login'
            if status != 200 and attempts < 10:
                db.execute('INSERT INTO login_attempts(timestamp,username,source_ip) VALUES(?,?,?)',
                           (now, username, source_ip))
                db.execute('DELETE FROM login_attempts WHERE id NOT IN '
                           '(SELECT id FROM login_attempts ORDER BY id DESC LIMIT 10000)')
            self._audit(db, principal, action, outcome='success' if token else 'failure',
                        request_id=request_id, source_ip=source_ip, status=status)
        if token is None:
            raise SecurityError('Invalid credentials', status)
        return token, principal

    def authenticate(self, token):
        now = self.clock()
        with self._db() as db:
            row = db.execute('SELECT users.*, sessions.id AS session_id, last_seen, expires '
                             'FROM sessions JOIN users ON users.id=sessions.user_id WHERE digest=?',
                             (self._digest(token),)).fetchone()
            if not row:
                return None
            if not row['active'] or row['expires'] <= now or row['last_seen'] + self.idle_seconds <= now:
                db.execute('DELETE FROM sessions WHERE id=?', (row['session_id'],))
                return None
            db.execute('UPDATE sessions SET last_seen=? WHERE id=?', (now, row['session_id']))
            principal = self._safe(row)
            principal['session_id'] = row['session_id']
            return principal

    def logout(self, token, request_id='', source_ip=''):
        with self._db() as db:
            row = db.execute('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id '
                             'WHERE digest=?', (self._digest(token),)).fetchone()
            db.execute('DELETE FROM sessions WHERE digest=?', (self._digest(token),))
            self._audit(db, self._safe(row), 'auth.logout', request_id=request_id, source_ip=source_ip)

    def sessions(self, user_id):
        with self._db() as db:
            return [dict(row) for row in db.execute(
                'SELECT id,created,last_seen,expires FROM sessions WHERE user_id=? '
                'AND expires>? AND last_seen>? ORDER BY created',
                (user_id, self.clock(), self.clock() - self.idle_seconds))]

    def revoke_sessions(self, user_id, *, actor, session_id=None, request_id='', source_ip=''):
        with self._db() as db:
            principal = self._actor(db, actor, user_id=user_id)
            if session_id is None:
                db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            else:
                db.execute('DELETE FROM sessions WHERE user_id=? AND id=?', (user_id, session_id))
            self._audit(db, principal, 'session.revoke', user_id,
                        request_id=request_id, source_ip=source_ip)

    def update_user(self, user_id, *, actor, role=None, active=None, password=None,
                    request_id='', source_ip=''):
        from .passwords import hash_password
        if role is not None and role not in ('admin', 'operator', 'viewer'):
            raise SecurityError('Invalid role')
        if active is not None and not isinstance(active, bool):
            raise SecurityError('Active must be boolean')
        encoded = hash_password(password) if password is not None else None
        with self._db() as db:
            principal = self._actor(db, actor, admin=True)
            row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
            if row is None:
                raise SecurityError('User not found', 404)
            new_role = role if role is not None else row['role']
            new_active = active if active is not None else bool(row['active'])
            if row['role'] == 'admin' and row['active'] and (new_role != 'admin' or not new_active):
                if db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] <= 1:
                    raise SecurityError('Cannot remove the last active administrator', 409)
            db.execute('UPDATE users SET role=?,active=?,password_hash=?,must_change_password=? WHERE id=?',
                       (new_role, int(new_active), encoded or row['password_hash'],
                        1 if encoded else row['must_change_password'], user_id))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            self._audit(db, principal, 'account.update', user_id, request_id=request_id,
                        source_ip=source_ip, details={'role': new_role, 'active': new_active,
                                                     'must_change_password': bool(encoded) or bool(row['must_change_password'])})
            return self._safe(db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone())

    def change_password(self, user_id, old_password, new_password, *, actor,
                        request_id='', source_ip=''):
        from .passwords import hash_password, verify_password
        encoded = hash_password(new_password)
        with self._db() as db:
            principal = self._actor(db, actor, user_id=user_id)
            row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
            if not row or not verify_password(row['password_hash'], old_password):
                raise SecurityError('Invalid credentials', 401)
            db.execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?',
                       (encoded, user_id))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            self._audit(db, principal, 'account.password_change', user_id,
                        request_id=request_id, source_ip=source_ip)
            return self._safe(db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone())

    def audit(self, actor, action, target='', outcome='success', request_id='', source_ip='',
              details=None, status=None, job_id=None):
        with self._db() as db:
            return self._audit(db, actor, action, target, outcome, request_id,
                               source_ip, details, status, job_id)

    def audit_list(self, *, user_id=None, action=None, outcome=None, target=None,
                   since=None, until=None, limit=50, offset=0):
        if not isinstance(limit, int) or not 1 <= limit <= 1000 or not isinstance(offset, int) or offset < 0:
            raise SecurityError('Invalid pagination')
        clauses, values = [], []
        for column, value, operator in (
            ('actor_user_id', user_id, '='), ('action', action, '='),
            ('outcome', outcome, '='), ('target', target, '='),
            ('timestamp', since, '>='), ('timestamp', until, '<='),
        ):
            if value is not None:
                clauses.append(column + operator + '?')
                values.append(value)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        with self._db() as db:
            total = db.execute('SELECT COUNT(*) FROM audit_events' + where, values).fetchone()[0]
            rows = db.execute('SELECT * FROM audit_events' + where +
                              ' ORDER BY timestamp DESC,rowid DESC LIMIT ? OFFSET ?',
                              [*values, limit, offset]).fetchall()
            events = []
            for row in rows:
                event = dict(row)
                event['details'] = json.loads(event['details'])
                events.append(event)
            return {'events': events, 'total': total}

    def reconcile_intents(self):
        """Single-instance startup: mark interrupted audited operations unknown."""
        with self._db() as db:
            rows = db.execute('''SELECT a.* FROM audit_events a WHERE a.outcome='started'
                AND NOT EXISTS (SELECT 1 FROM audit_events b WHERE b.request_id=a.request_id
                AND b.action=a.action AND b.outcome!='started' AND b.rowid>a.rowid)''').fetchall()
            for row in rows:
                actor = {'id': row['actor_user_id'], 'username': row['actor_username'], 'role': row['actor_role']}
                self._audit(db, actor, row['action'], row['target'], 'unknown', row['request_id'],
                            row['source_ip'], job_id=row['job_id'])
            return len(rows)

    def prune_audit(self):
        with self._db() as db:
            count = db.execute('DELETE FROM audit_events WHERE timestamp<?',
                               (self.clock() - self.retention_days * 86400,)).rowcount
            self._audit(db, None, 'audit.prune', details={'count': count})
            return count

    def local_reset_password(self, username, password):
        """Trusted local recovery only; never expose this method over HTTP."""
        from .passwords import hash_password
        username = self._username(username)
        encoded = hash_password(password)
        with self._db() as db:
            row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if not row:
                raise SecurityError('User not found', 404)
            db.execute('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?',
                       (encoded, row['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
            self._audit(db, None, 'account.local_reset', row['id'])
            return self._safe(db.execute('SELECT * FROM users WHERE id=?', (row['id'],)).fetchone())
