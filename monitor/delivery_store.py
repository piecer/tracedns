"""Private observation-first ledger; source calls require core coordination.

The core repository validates its original leases under config -> repository
coordination, then calls us. A cursor or caller mapping never grants a lease.
"""
from __future__ import annotations

import copy
import errno
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from .delivery_progress import counter, elapsed, finite
import uuid

from monitor.delivery_types import CHANNELS, DEFAULT_LIMITS, MAX_COUNTER, encode, size, valid_binding, provider_result as normalize_result
from monitor.delivery_types import TeamsPayloadTooLarge, encode_body, stable_reason
from monitor.delivery_types import TEAMS_BATCH_MAX_WAIT_SECONDS, TEAMS_BATCH_MAINTENANCE_LIMIT


class _DHTCancelled(Exception):
    pass


class DeliveryStore:
    @property
    def _health(self):
        return self._health_cache[0]

    @_health.setter
    def _health(self, value):
        # Every status-only update retains the exact counts/age sample.
        self._health_cache = (value, self._health_cache[1])

    def __init__(self, history_dir, *, clock=time.time, limits=None, render=None):
        self._render = render or (lambda entries, action, created: {
            "title": action + " at " + str(int(created)),
            "text": "\n".join(" | ".join(e) for e in entries),
        })
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        if any(type(v) is not int or v < 1 or v > DEFAULT_LIMITS[k]
               for k, v in self.limits.items()):
            raise ValueError("invalid delivery limits")
        self.path = Path(history_dir).absolute() / "delivery.sqlite"
        self._clock = clock
        self._monotonic = time.monotonic
        self._recovery_next = 0.0
        self._recovery_failures = 0
        self._lock = threading.RLock()
        self._db = None
        self._owner = None
        self._closed = False
        self._new_file_identity = None
        self._unresolved = None
        self._cleanup_pending = False
        self._worker_thread = False
        self._worker_active = False
        self._stopping = False
        self._claims_halted = False
        self._ready = False
        self._gap = False
        self._rebaseline = False
        self._history_failed = False
        self._pending_addition_epoch = None
        self._fault = lambda point: None
        self._process_id = uuid.uuid4().hex
        self._checkpoint = {c: 0 for c in CHANNELS}
        self._volatile = {c: 0 for c in CHANNELS}
        self._control = {
            "schema": 1, "epoch": uuid.uuid4().hex, "clean": True, "binding_key": os.urandom(32).hex(),
            "accounting_complete": True, "tracking_complete": True,
            "addition_epoch": "", "absence_pending": False,
            "missed_total": 0, "failed_total": 0, "acked_total": 0,
        }
        self._health_cache = (None, (None, None, None, None, {c: 0 for c in CHANNELS}, 0, 'unknown', 0))
        self._health = {
            "status": "disabled", "observation_policy": "continue", "storage_ok": False,
            "worker_running": False, "coverage": "covered", "accounting_complete": True,
            "missed_total": 0, "missed_unpersisted": 0, "failed_total": 0, "acked_total": 0,
            "pending": 0, "retry_wait": 0, "blocked": 0, "oldest_pending_age_seconds": None,
            "capacity": {"used_receipts": 0, "max_receipts": self.limits["receipts"],
                         "used_payload_bytes": 0, "max_payload_bytes": self.limits["payload_bytes"]},
            "channels": {c: {"enabled": False, "pending": 0, "blocked": 0,
                             "last_success_at": None, "last_error": None} for c in CHANNELS},
            "tracking_complete": True, "counts_stale": False, "last_error": None,
        }
        self._storage_error = None
        self._diagnostics = {
            'version': 1, 'observed_at': max(0, min(MAX_COUNTER, int(self._clock()))),
            'channels': {c: {'latest_result': None, 'latest_failure': None,
                             'blocked_by_reason': []} for c in CHANNELS},
            'recent_failures': [],
        }
        self._storage_stage = 'open_owner'
        try:
            self._open()
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, ImportError) as error:
            self._note_storage_error(error, self._storage_stage)
            self._release()
            self.enter_gap("delivery_storage", {})

    def _one(self, sql, args=()):
        if self._cleanup_pending:
            raise sqlite3.OperationalError('transaction cleanup pending')
        cur = self._db.execute(sql, args)
        try:
            return cur.fetchone()
        finally:
            cur.close()

    def _execute(self, sql, args=()):
        if self._cleanup_pending:
            raise sqlite3.OperationalError('transaction cleanup pending')
        cur = self._db.execute(sql, args)
        try:
            return cur.rowcount
        finally:
            cur.close()

    def _open(self):
        # Unsupported platforms degrade instead of running an unfenced owner.
        import fcntl
        if self._unresolved is not None:
            raise ValueError('unresolved ledger operation')
        self._storage_stage = 'open_owner'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        lock_path = self.path.with_name("delivery.lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self._owner = os.fdopen(fd, "a+b")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._storage_stage = 'open_db'
        sentinel = self.path.with_name("delivery.initialized")
        established = sentinel.exists()
        existed = self.path.exists()
        if established and not existed:
            raise ValueError("missing established ledger")
        if self.path.is_symlink() or sentinel.is_symlink():
            raise ValueError("unsafe ledger")
        if not existed:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            stat = os.fstat(fd)
            self._new_file_identity = (stat.st_dev, stat.st_ino)
            os.close(fd)
        elif not established:
            stat = self.path.stat()
            if stat.st_size == 0 and (stat.st_dev, stat.st_ino) == self._new_file_identity:
                existed = False  # our own uninitialized file after failed connect
        os.chmod(self.path, 0o600)
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=.05)
        self._db.row_factory = sqlite3.Row
        for pragma in ("busy_timeout=50", "page_size=4096", "journal_mode=DELETE",
                       "synchronous=FULL", "foreign_keys=ON", "temp_store=MEMORY",
                       "cache_size=-2048", "max_page_count=" + str(self.limits["pages"])):
            self._execute("PRAGMA " + pragma)
        if existed:
            self._storage_stage = 'open_validate'
            if self._one("PRAGMA quick_check")[0] != "ok":
                raise ValueError("invalid ledger")
            row = self._one("SELECT data FROM control WHERE id=1")
            self._control = json.loads(row[0])
            if self._control["schema"] != 1:
                raise ValueError("unsupported schema")
            self._control["accounting_complete"] = False
        else:
            self._db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE control (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
                CREATE TABLE cursor (target TEXT PRIMARY KEY, incarnation TEXT NOT NULL,
                  signature TEXT NOT NULL, ips TEXT NOT NULL, operation TEXT NOT NULL,
                  tracked INTEGER NOT NULL, members INTEGER NOT NULL, bytes INTEGER NOT NULL);
                CREATE TABLE recent (key TEXT PRIMARY KEY, expires REAL NOT NULL, bytes INTEGER NOT NULL);
                CREATE TABLE baseline (ip TEXT PRIMARY KEY, labels TEXT NOT NULL, bytes INTEGER NOT NULL);
                CREATE TABLE grace (ip TEXT PRIMARY KEY, labels TEXT NOT NULL, missing_since REAL NOT NULL,
                  not_before REAL NOT NULL, identity TEXT NOT NULL, bytes INTEGER NOT NULL);
                CREATE TABLE receipt (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL,
                  channel TEXT NOT NULL, binding TEXT NOT NULL, action TEXT NOT NULL, ip TEXT NOT NULL,
                  payload TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL, reserved INTEGER NOT NULL,
                  attempt INTEGER NOT NULL DEFAULT 0, token TEXT, due REAL NOT NULL DEFAULT 0,
                  progress TEXT NOT NULL DEFAULT '{}', provider_calls INTEGER NOT NULL DEFAULT 0,
                  resume INTEGER NOT NULL DEFAULT 0, hook INTEGER NOT NULL DEFAULT 0,
                  error TEXT, block_revision INTEGER NOT NULL DEFAULT -1, claim_revision INTEGER NOT NULL DEFAULT 0, batch_id INTEGER, cycle TEXT NOT NULL DEFAULT '');
                CREATE INDEX receipt_fifo ON receipt(binding,ip,id);
                CREATE TABLE batch (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE terminal (id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL,
                  state TEXT NOT NULL, reason TEXT, at REAL NOT NULL, bytes INTEGER NOT NULL);
            """).close()
            self._save_control()
            self._db.commit()
        identity = encode({"schema": 1, "epoch": self._control["epoch"]}).encode()
        if established:
            with sentinel.open("rb") as f:
                if f.read(256) != identity:
                    raise ValueError("wrong ledger epoch")
        else:
            fd = os.open(sentinel, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(identity)
                f.flush()
                os.fsync(f.fileno())
            fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

        # Additive indexes also apply to established schema-1 ledgers. Keep
        # candidate order and bounded membership lookup in SQL, not hydration.
        self._execute("CREATE INDEX IF NOT EXISTS receipt_claim ON receipt(channel,binding,id)")
        self._execute("CREATE INDEX IF NOT EXISTS receipt_members ON receipt(batch_id,id)")
        columns = self._db.execute("PRAGMA table_info(cursor)").fetchall()
        if not any(row['name'] == 'addition_epoch' for row in columns):
            self._execute("ALTER TABLE cursor ADD COLUMN addition_epoch TEXT NOT NULL DEFAULT ''")
        self._control.setdefault('addition_epoch', '')
        self._control.setdefault('absence_pending', False)
        # Additive schema-1 state: suppression is not proof of global absence.
        # Existing receipts, cursors and removal deadlines are left untouched.
        self._execute("CREATE TABLE IF NOT EXISTS reappearance (target TEXT NOT NULL, "
                      "signature TEXT NOT NULL, ip TEXT NOT NULL, expires REAL NOT NULL, "
                      "bytes INTEGER NOT NULL, PRIMARY KEY(target,signature,ip))")
        self._execute("CREATE INDEX IF NOT EXISTS reappearance_expiry ON reappearance(expires)")
        # NULL legacy context is unknown, never reconstructed from payloads.
        columns = self._db.execute("PRAGMA table_info(receipt)").fetchall()
        for name in ('source_target', 'source_incarnation', 'source_signature'):
            if not any(row['name'] == name for row in columns):
                self._execute("ALTER TABLE receipt ADD COLUMN " + name + " TEXT")
        self._execute("CREATE TABLE IF NOT EXISTS failed_addition (target TEXT NOT NULL, "
                      "incarnation TEXT NOT NULL, signature TEXT NOT NULL, ip TEXT NOT NULL, "
                      "channel TEXT NOT NULL CHECK(channel IN ('teams','misp')), binding TEXT NOT NULL, "
                      "receipt_id INTEGER NOT NULL CHECK(receipt_id>0), bytes INTEGER NOT NULL CHECK(bytes>0), "
                      "PRIMARY KEY(target,incarnation,signature,ip,channel,binding))")
        # Authoritative DHT evidence shares this ledger's application owner.
        self._execute("CREATE TABLE IF NOT EXISTS dht_state (target TEXT PRIMARY KEY, "
                      "data TEXT NOT NULL, pending TEXT, bytes INTEGER NOT NULL)")

    def load_dht_checkpoint(self, target, *, settled=False):
        with self._lock:
            if self._db is None or self._closed or self._unresolved:
                return False, None
            try:
                row = self._one("SELECT data,pending FROM dht_state WHERE target=?", (target,))
                if settled and row and row['pending'] is not None:
                    return False, None
                return True, json.loads(row[0]) if row else None
            except (sqlite3.Error, ValueError, TypeError):
                self.enter_gap("delivery_storage", {})
                return False, None

    def _put_dht_checkpoint(self, target, checkpoint, pending):
        data = encode(checkpoint)
        needed = len(data.encode()) + len(target.encode()) + 32
        old = self._one("SELECT bytes FROM dht_state WHERE target=?", (target,))
        count, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM dht_state")
        if (len(data.encode()) > self.limits['unit_bytes'] or
                used - (old[0] if old else 0) + needed > self.limits['cursor_bytes'] or
                (old is None and count >= self.limits['cursor_targets'])):
            raise ValueError('DHT state capacity')
        self._execute("INSERT OR REPLACE INTO dht_state VALUES(?,?,?,?)",
                      (target, data, pending, needed))

    def begin_dht(self, target, checkpoint, cancelled):
        """Persist a restart fence before collecting potentially newer evidence.

        A failed/uncertain final save leaves pending intact across clean shutdown
        too. Explicit target retirement can discard that unknown highwater;
        cancellation clears only its exact ticket without advancing evidence.
        """
        with self._lock:
            token = uuid.uuid4().hex
            def apply():
                row = self._one("SELECT data,pending FROM dht_state WHERE target=?", (target,))
                if row and (row['pending'] is not None or
                            json.loads(row['data']) != checkpoint):
                    return None
                self._put_dht_checkpoint(target, checkpoint, token)
                return token
            ok, result, _ = self._transaction(token, apply, cancelled=cancelled, kind='checkpoint')
            if not ok or result is None:
                if result != 'cancelled':
                    self.enter_gap("delivery_storage", {})
                return None
            return result

    def finish_dht(self, target, token, checkpoint, cancelled):
        with self._lock:
            def apply():
                row = self._one("SELECT pending FROM dht_state WHERE target=?", (target,))
                if row is None or row[0] != token:
                    return False
                self._put_dht_checkpoint(target, checkpoint, None)
                return True
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply, cancelled=cancelled, kind='checkpoint')
            if not ok and result != 'cancelled':
                self.enter_gap("delivery_storage", {})
            return bool(ok and result)

    def abort_dht(self, target, token):
        with self._lock:
            ok, _, _ = self._transaction(uuid.uuid4().hex, lambda: self._execute(
                "UPDATE dht_state SET pending=NULL WHERE target=? AND pending=?", (target, token)))
            if not ok:
                self.enter_gap("delivery_storage", {})
            return ok

    def retire_dht(self, target):
        with self._lock:
            if self._db is not None and not self._closed and self._unresolved is None and not self._one(
                    "SELECT 1 FROM dht_state WHERE target=?", (target,)):
                return True
            ok, _, _ = self._transaction(uuid.uuid4().hex, lambda: self._execute(
                "DELETE FROM dht_state WHERE target=?", (target,)))
            return ok

    def prune_dht(self, active):
        with self._lock:
            if (self._db is not None and not self._closed and self._unresolved is None
                    and not self._one("SELECT 1 FROM dht_state LIMIT 1")):
                return True
            def apply():
                last = ''
                while True:
                    cursor = self._db.execute("SELECT target FROM dht_state WHERE target>? ORDER BY target LIMIT 256", (last,))
                    try:
                        page = cursor.fetchmany(256)
                    finally:
                        cursor.close()
                    if not page:
                        break
                    last = page[-1][0]
                    for row in page:
                        if row[0] not in active:
                            self._execute("DELETE FROM dht_state WHERE target=?", (row[0],))
            ok, _, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self.enter_gap("delivery_storage", {})
            return ok

    def _release(self):
        if self._db is not None:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
            self._db = None
        if self._owner is not None:
            self._owner.close()
            self._owner = None

    def _save_control(self):
        data = encode(self._control)
        if len(data.encode()) > 65536:
            raise ValueError("control capacity")
        self._execute("INSERT OR REPLACE INTO control VALUES (1,?)", (data,))

    def _increment(self, key, count):
        total = self._control.get(key, 0) + count
        if total > MAX_COUNTER:
            self._control["accounting_complete"] = False
        self._control[key] = min(total, MAX_COUNTER)

    def _record_loss(self, reason, counts):
        # Fixed closed keys; never one row per observation or loss.
        assert reason in ("delivery_storage", "delivery_capacity", "tracking_overflow", "recovery_gap")
        totals = self._control.setdefault("missed_by_reason", {}).setdefault(reason, {c: 0 for c in CHANNELS})
        for channel in CHANNELS:
            count = max(0, counts.get(channel, 0))
            self._increment("missed_total", count)
            totals[channel] = min(MAX_COUNTER, totals[channel] + count)

    def _addition_destinations(self, observation, ip, bindings):
        """Shared admission/loss predicate; absence of proof grants no exception."""
        target, signature, now = (observation['target'], observation['projection_signature'],
                                  observation['observed_at'])
        key = encode([target, signature, ip, 'Added'])
        if self._one("SELECT 1 FROM grace WHERE ip=?", (ip,)) or self._one(
                "SELECT 1 FROM recent WHERE key=? AND expires>?", (key, now)):
            return []
        destinations = [b for b in bindings if b['enabled']]
        if not self._one("SELECT 1 FROM reappearance WHERE target=? AND signature=? AND ip=? AND expires>?",
                         (target, signature, ip, now)):
            return destinations
        if self._unresolved is not None:
            return []  # Optional failure proof cannot authorize an uncertain exception.
        cursor = self._one("SELECT incarnation FROM cursor WHERE target=? AND signature=? AND tracked=1",
                           (target, signature))
        if cursor is None:
            return []
        selected = []
        for b in destinations:
            identity = (target, cursor[0], signature, ip, b['channel'], b['binding_id'])
            if self._one("SELECT 1 FROM failed_addition WHERE target=? AND incarnation=? AND signature=? "
                         "AND ip=? AND channel=? AND binding=?", identity) and not self._one(
                    "SELECT 1 FROM receipt INDEXED BY receipt_fifo WHERE source_target=? AND source_incarnation=? "
                    "AND source_signature=? AND ip=? AND channel=? AND binding=? AND action='Added' LIMIT 1", identity):
                selected.append(b)
        return selected

    def _known_additions(self, observation, bindings):
        counts = {c: 0 for c in CHANNELS}
        if self._db is None:
            # No readable proof is unknown, not permission or an exact zero.
            return counts
        try:
            fresh = set(observation.get('fresh_positive_ips', observation['managed_ips']))
            for ip in (set(observation['managed_ips']) - set(observation.get('before_ips', []))) & fresh:
                for b in self._addition_destinations(observation, ip, bindings):
                    counts[b['channel']] += 1
            return counts
        except sqlite3.Error:
            return {c: 0 for c in CHANNELS}

    def _read_control(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=.05)
        try:
            cur = db.execute("SELECT data FROM control WHERE id=1")
            try:
                return json.loads(cur.fetchone()[0])
            finally:
                cur.close()
        finally:
            db.close()

    def binding_key(self):
        """Private registry input, never a public health field."""
        with self._lock:
            return bytes.fromhex(self._control["binding_key"]) if self._ready else None

    def _validated_control(self, epoch):
        saved = self._read_control()
        if (not isinstance(saved, dict) or type(saved.get('schema')) is not int
                or saved['schema'] != 1 or saved.get('epoch') != epoch
                or saved.get('binding_key') != self._control['binding_key']
                or not (isinstance(saved.get('last_transaction'), str)
                        or saved.get('last_transaction') is None and self._control.get('last_transaction') is None)
                or any(type(saved.get(k)) is not int or not 0 <= saved[k] <= MAX_COUNTER
                       for k in ('missed_total', 'failed_total', 'acked_total'))
                or any(type(saved.get(k)) is not bool
                       for k in ('clean', 'accounting_complete', 'tracking_complete'))
                or type(saved.get('addition_epoch', '')) is not str
                or (saved.get('addition_epoch', '') != '' and
                    (len(saved['addition_epoch']) != 32 or any(ch not in '0123456789abcdef'
                                                              for ch in saved['addition_epoch'])))
                or any(k in saved and type(saved[k]) is not bool
                       for k in ('absence_pending', 'restart_rebaseline', 'session_closed'))):
            raise ValueError('invalid recovery identity')
        return saved

    def _resolve_unresolved(self):
        if self._unresolved is None:
            return
        if self._cleanup_pending:
            self._rollback_transaction()
            if self._cleanup_pending:
                raise sqlite3.OperationalError('transaction cleanup pending')
        pending = self._unresolved
        saved = self._validated_control(pending['epoch'])
        if saved.get('last_transaction') == pending['operation']:
            if pending['checkpoint'] is not None:
                if saved.get('loss_checkpoint') != {'process': self._process_id, **pending['checkpoint']}:
                    raise ValueError('invalid loss checkpoint')
                self._adopt_checkpoint(pending['checkpoint'], pending['captured'],
                                       newer=pending['newer_losses'])
        else:
            for c in CHANNELS:
                self._volatile[c] = min(MAX_COUNTER, self._volatile[c] + pending['losses'].get(c, 0))
        # Durable identity proves the old operation, not completeness of later
        # observations. These flags are sticky within this process; preserve
        # conservative obligations on both committed and rolled-back readback.
        for key in ('accounting_complete', 'tracking_complete'):
            saved[key] = saved[key] and self._control[key]
        self._control = saved
        self._unresolved = None

    def _adopt_checkpoint(self, totals, captured, *, newer=None):
        for c in CHANNELS:
            # An unknown COMMIT may outlive new observations. Subtraction from
            # their saturated aggregate cannot recover the newer contribution.
            # Synchronous adoption still holds the store lock across capture.
            self._volatile[c] = newer[c] if newer is not None else max(0, self._volatile[c] - captured[c])
            self._checkpoint[c] = totals[c]
        self._health = {**self._health, 'missed_unpersisted': min(MAX_COUNTER, sum(self._volatile.values()))}

    def cursor_incarnation(self, target):
        with self._lock:
            if self._db is None or self._closed:
                return None
            try:
                row = self._one("SELECT incarnation FROM cursor WHERE target=?", (target,))
                return row[0] if row else None
            except sqlite3.Error:
                return None

    def _prune_cursors(self, active_projection):
        last = ""
        while True:
            cur = self._db.execute("SELECT target FROM cursor WHERE target>? ORDER BY target LIMIT 256", (last,))
            try:
                page = cur.fetchmany(256)
            finally:
                cur.close()
            if not page:
                break
            last = page[-1][0]
            for row in page:
                if row[0] not in active_projection:
                    self._execute("DELETE FROM cursor WHERE target=?", (row[0],))

    def retire_target_cursor(self, incarnation):
        with self._lock:
            def apply():
                self._execute("DELETE FROM cursor WHERE incarnation=?", (incarnation,))
                self._prune_reappearance()
            ok, _, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self.enter_gap("delivery_storage", {})
            return {"ledger_committed": ok}

    def refresh_configuration(self, authority, active_projection):
        """Commit exact source authority with its current addition cursors.

        Caller holds CONFIG -> repository; full baseline/grace and receipts are
        deliberately independent. Failed refresh never authorizes stale cursors.
        GAP recovery requires a fresh full, not this configuration-only call.
        """
        with self._lock:
            if not authority.get("valid"):
                return {"ledger_committed": False, "source_valid": False}
            if self._pending_addition_epoch is not None or not self._ready or self._unresolved or self._claims_halted:
                self.enter_gap("delivery_storage", {})
                return {"ledger_committed": False, "source_valid": True}
            def apply():
                self._prune_cursors(active_projection)
                for target, value in active_projection.items():
                    row = self._one("SELECT signature FROM cursor WHERE target=?", (target,))
                    if row is None or row["signature"] != value["signature"]:
                        self._execute("DELETE FROM cursor WHERE target=?", (target,))
                        self._put_cursor(target, sorted(set(value["ips"])), value["signature"], uuid.uuid4().hex,
                                         addition_epoch='' if self._control['absence_pending'] else None)
                self._prune_reappearance()
                self._control["revision"] = authority["revision"]
                self._control["signature"] = authority["signature"]
            ok, _, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self.enter_gap("delivery_storage", {})
            return {"ledger_committed": ok, "source_valid": True}

    def configuration_applied(self, channels=CHANNELS, *, apply_epochs=None):
        """Authorize retry only for explicitly applied channels, never discovery."""
        channels = tuple(channels)
        if len(channels) > len(CHANNELS) or not set(channels) <= set(CHANNELS):
            raise ValueError("invalid repair channels")
        if apply_epochs is not None and (set(apply_epochs) != set(channels) or any(
                type(value) is not int or value < 0 for value in apply_epochs.values())):
            raise ValueError("invalid apply epochs")
        with self._lock:
            def apply():
                for channel in set(channels):
                    if apply_epochs is not None:
                        revision = apply_epochs[channel]
                        applied_key = "applied_config_" + channel
                        if self._control.get(applied_key, -1) >= revision:
                            continue
                        self._control[applied_key] = revision
                    key = "adapter_revision_" + channel
                    self._control.setdefault(key, self._control.get("adapter_revision", 0))
                    self._increment(key, 1)
            ok, _, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self.enter_gap("delivery_storage", {})
            return {"ledger_committed": ok}

    def _rollback_transaction(self):
        # A rollback exception is not evidence of either closure or refusal.
        # Keep the writer quarantined until its native state proves closure;
        # the independent durable marker cannot establish that fact.
        self._cleanup_pending = True
        error = None
        try:
            self._db.rollback()
        except (sqlite3.Error, OSError, ValueError) as rollback_error:
            error = rollback_error
        try:
            self._cleanup_pending = self._db.in_transaction is not False
        except (sqlite3.Error, OSError, ValueError, AttributeError):
            pass
        return error

    def _change_count(self):
        try:
            value = self._db.total_changes
            return value if type(value) is int and value >= 0 else None
        except (AttributeError, sqlite3.Error, OSError, ValueError, TypeError):
            return None

    def _transaction(self, operation, fn, *, cancelled=None, kind='ledger', checkpoint=None, captured=None,
                     allow_noop=False):
        """A fixed last-transaction UUID resolves commit errors independently.

        Only one writer owned by this object exists. No subsequent write is
        permitted before this readback; unknown outcomes halt admission/claims.
        Only the post-source optional seal may elide an unchanged control write.
        Its no-write errors resolve conservatively against the prior marker;
        they never certify a new durable operation, even after a real commit.
        """
        if self._unresolved is not None:
            return False, None, True
        if self._db is None or self._closed:
            return False, None, False
        if cancelled is not None and cancelled():
            return False, 'cancelled', False
        before = copy.deepcopy(self._control)
        committed = False
        result = None
        stage = 'transaction_begin'
        try:
            self._execute("BEGIN IMMEDIATE")
            if cancelled is not None and cancelled():
                raise _DHTCancelled()
            stage = 'transaction_body'
            changes = self._change_count() if allow_noop else None
            result = fn()
            no_write = (changes is not None and self._change_count() == changes
                        and self._control == before)
            if not no_write:
                self._control["last_transaction"] = operation
                self._save_control()
            self._fault("before_commit")
            if cancelled is not None and cancelled():
                raise _DHTCancelled()
            stage = 'transaction_commit'
            self._db.commit()
            committed = True
            self._fault("after_commit")
        except (_DHTCancelled, sqlite3.Error, OSError, ValueError) as error:
            rollback_error = self._rollback_transaction()
            if isinstance(error, _DHTCancelled):
                if rollback_error is not None:
                    error = rollback_error
                elif not self._cleanup_pending:
                    self._control = before
                    return False, 'cancelled', False
            self._note_storage_error(error, stage)
            try:
                saved = self._validated_control(before['epoch'])
                if not self._cleanup_pending:
                    if saved.get("last_transaction") == operation:
                        self._control = saved
                        self._safe_refresh()
                        return True, result, False
                    self._control = before
                    return False, None, False
            except (sqlite3.Error, OSError, ValueError, TypeError) as error:
                self._note_storage_error(error, 'transaction_readback')
            self._control = before
            self._unresolved = {"operation": operation, "epoch": before['epoch'], "losses": {},
                                "kind": kind, "checkpoint": copy.deepcopy(checkpoint),
                                "captured": copy.deepcopy(captured),
                                "newer_losses": {c: 0 for c in CHANNELS}}
            self._halt_delivery()
            return False, None, True
        if committed:
            self._safe_refresh()
        return True, result, False

    def _safe_refresh(self):
        try:
            self._refresh()
        except (sqlite3.Error, OSError, ValueError) as error:
            self._note_storage_error(error, 'health_refresh')
            self._health = {**self._health, "counts_stale": True, "storage_ok": False,
                            "status": "degraded", "last_error": "delivery_storage"}

    def _refresh(self):
        health = copy.deepcopy(self._health)
        used = self._one("SELECT COUNT(*),COALESCE(SUM(reserved),0),MIN(created) FROM receipt")
        oldest = self._one("SELECT id,created FROM receipt ORDER BY created,id LIMIT 1")
        sampled = finite(self._monotonic())
        wall = finite(self._clock())
        if sampled is None or wall is None:
            # Validate the actual pair, not a preflight before potentially slow
            # SQL. Keep last-good counts, anchors and historical diagnostics.
            self._health = {**self._health, 'counts_stale': True, 'status': 'degraded'}
            return
        previous = self._health_cache[1]
        age = elapsed(wall, oldest[1]) if oldest is not None else None
        if oldest is not None and previous[0] == oldest[0] and previous[1] is not None:
            age = max(age or 0, previous[1] + (elapsed(sampled, previous[2]) or 0))
        retries = {c: self._one("SELECT COUNT(*) FROM receipt WHERE channel=? AND state='retry_wait'", (c,))[0]
                   for c in CHANNELS}
        epoch = self._pending_addition_epoch or self._control['addition_epoch']
        # Match the committed target gate in rebaseline_absence. Unrepresented
        # targets have no exact cardinality: retain bounded row counts and
        # advertise unknown, never invent a full-absence certificate.
        rebasing = self._one("SELECT COUNT(*) FROM cursor WHERE addition_epoch<>? OR tracked=0", (epoch,))[0]
        absence = ('unknown' if self._control.get('untracked_targets') else
                   'awaiting_full' if rebasing or self._control['absence_pending'] or self._pending_addition_epoch else 'ready')
        cursor_count = self._one('SELECT COUNT(*) FROM cursor')[0]
        anchors = (oldest[0] if oldest is not None else None, age, sampled, wall, retries, rebasing, absence, cursor_count)
        health["capacity"]["used_receipts"] = used[0]
        health["capacity"]["used_payload_bytes"] = used[1]
        health["pending"] = self._one("SELECT COUNT(*) FROM receipt WHERE state IN ('pending','unsealed','in_flight')")[0]
        health["blocked"] = self._one("SELECT COUNT(*) FROM receipt WHERE state='blocked_config'")[0]
        health["retry_wait"] = self._one("SELECT COUNT(*) FROM receipt WHERE state='retry_wait'")[0]
        for channel in CHANNELS:
            health["channels"][channel] = {
                "enabled": self._control.get("enabled_" + channel, False),
                "pending": self._one("SELECT COUNT(*) FROM receipt WHERE channel=? AND state IN ('pending','unsealed','in_flight')", (channel,))[0],
                "blocked": self._one("SELECT COUNT(*) FROM receipt WHERE channel=? AND state='blocked_config'", (channel,))[0],
                "last_success_at": self._control.get("success_" + channel),
                "last_error": (self._one("SELECT error FROM receipt WHERE channel=? AND state='blocked_config' AND error IS NOT NULL ORDER BY id LIMIT 1", (channel,)) or [self._control.get("error_" + channel)])[0],
            }
        health["oldest_pending_age_seconds"] = counter(age)
        for key in ("missed_total", "failed_total", "acked_total", "accounting_complete", "tracking_complete"):
            health[key] = self._control[key]
        health["storage_ok"] = True
        health["counts_stale"] = False
        health["coverage"] = "gap" if self._gap else "rebaselining" if self._rebaseline else "covered"
        health["status"] = ("degraded" if self._gap or not health["tracking_complete"] else
                            "blocked" if health["blocked"] else "ok" if used[0] or
                            any(v["enabled"] for v in health["channels"].values()) else "disabled")
        if self._gap:
            health["last_error"] = "delivery_storage"
        elif self._history_failed:
            health["last_error"] = "history_persistence"
            health["status"] = "degraded"
        self._publish_diagnostics(wall)
        self._health_cache = (health, anchors)

    def note_history_failure(self):
        """Sticky process diagnostic, not a ledger gap or raw-history receipt.

        A later single-domain save cannot prove all prior failed histories saved.
        No implicit clear on refresh, ACK, or a different domain's success.
        """
        with self._lock:
            self._history_failed = True
            if self._health["storage_ok"] and not self._gap:
                self._health = {**self._health, "last_error": "history_persistence", "status": "degraded"}

    def bootstrap(self, active_projection, legacy_grace, authority):
        with self._lock:
            if not authority.get("valid"):
                return {"ready": False, "source_valid": False}
            def apply():
                for channel in CHANNELS:
                    key = "adapter_revision_" + channel
                    if key not in self._control:
                        revision = self._control.get("adapter_revision", 0)
                        self._control[key] = revision
                        if "adapter_revision" in self._control:
                            # The legacy shared counter also counted unrelated
                            # discovery. It cannot prove an authorized repair.
                            self._execute("UPDATE receipt SET block_revision=? "
                                          "WHERE channel=? AND state='blocked_config'",
                                          (revision, channel))
                first = not self._control.get("enrolled")
                if first:
                    self._rebase(active_projection)
                    active = {}
                    for target, value in active_projection.items():
                        for ip in value["ips"]:
                            active.setdefault(ip, []).append(value.get("label", target))
                    self._install_baseline(active)
                    if isinstance(legacy_grace, dict):
                        for ip, value in legacy_grace.items():
                            try:
                                self._put_grace(ip, value["labels"], int(value["missing_since"]))
                            except (ValueError, KeyError, TypeError):
                                self._tracking_loss()
                    else:
                        self._tracking_loss()
                    self._control["grace_imported"] = True
                mismatch = (self._control.get("revision") != authority["revision"] or
                            self._control.get("signature") != authority["signature"])
                self._rebaseline = not first and (not self._control["clean"] or mismatch
                                                  or self._control['absence_pending'])
                if not first and (not self._control.get('session_closed', self._control['clean']) or mismatch):
                    self._control['addition_epoch'] = uuid.uuid4().hex
                    self._control['absence_pending'] = True
                    self._control['restart_rebaseline'] = True
                if not first and mismatch:
                    # Equal final names/definitions do not prove no intervening
                    # delete/re-add. Keep detector evidence for loss accounting,
                    # but do not attach its prior incarnation to new authority.
                    self._execute("UPDATE cursor SET incarnation=lower(hex(randomblob(16)))")
                self._prune_cursors(active_projection)
                self._prune_reappearance()
                _, self._claims_halted = self._recover_claims()
                self._control["enrolled"] = True
                self._control["clean"] = False
                self._control['session_closed'] = False
                if not self._rebaseline:
                    self._control["revision"] = authority["revision"]
                    self._control["signature"] = authority["signature"]
                return {"ready": True, "rebaseline_required": self._rebaseline}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply)
            self._ready = ok
            if not ok:
                self.enter_gap("delivery_storage", {})
                if self._db is not None:
                    self._recovery_failed()
            else:
                self.seal_cycle(None)
            return result if ok else {"ready": False}

    def _admit(self, entries, bindings, operation, action, created, force_loss=False, cycle="",
               *, selection=None, source=None):
        destinations = [b for b in bindings if b['enabled']]
        plan = [(e, b) for e in entries for b in (destinations if selection is None else selection[e[0]])]
        context = source or (None, None, None)
        context_bytes = size(context) if source is not None else 0
        needed = len(plan)
        reserved = sum(size({'entries': [e]}) + 4096 + context_bytes +
                       (self.limits['batch_bytes'] if b['channel'] == 'teams' else 0) for e, b in plan)
        used = self._one("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM receipt")
        overflow = (force_loss or len(entries) > self.limits['unit_items'] or size(entries) > self.limits['unit_bytes'] or
                    any(len(e[1].encode()) > self.limits['label_bytes'] for e in entries) or
                    needed + used[0] > self.limits['receipts'] or
                    reserved + used[1] > self.limits['payload_bytes'])
        if overflow:
            self._record_loss('delivery_capacity', {c: sum(b['channel'] == c for _, b in plan) for c in CHANNELS})
            return 0, needed
        for entry, b in plan:
            payload = encode({'entries': [entry]})
            self._execute(
                "INSERT INTO receipt(operation,channel,binding,action,ip,payload,state,created,reserved,cycle,"
                "source_target,source_incarnation,source_signature) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (operation, b['channel'], b['binding_id'], action, entry[0], payload,
                 'unsealed' if b['channel'] == 'teams' else 'pending', created,
                 len(payload.encode()) + 4096 + context_bytes +
                 (self.limits['batch_bytes'] if b['channel'] == 'teams' else 0), cycle, *context))
        return needed, 0

    def _result(self, outcome, admitted=0, missed=0, committed=False):
        return {"outcome": outcome, "admitted_receipts": admitted, "missed_receipts": missed,
                "ledger_committed": committed, "accounting_complete": self._control["accounting_complete"]}

    def _prune_reappearance(self):
        self._execute("DELETE FROM reappearance WHERE NOT EXISTS (SELECT 1 FROM cursor "
                      "WHERE cursor.target=reappearance.target AND cursor.signature=reappearance.signature)")
        self._prune_failed_additions()

    def _prune_failed_additions(self, target=None):
        scope = 'target=? AND ' if target is not None else ''
        self._execute("DELETE FROM failed_addition WHERE " + scope + "NOT EXISTS (SELECT 1 FROM cursor "
                      "WHERE cursor.target=failed_addition.target AND cursor.incarnation=failed_addition.incarnation "
                      "AND cursor.signature=failed_addition.signature AND cursor.tracked=1)",
                      (target,) if target is not None else ())

    def _remember_disappearance(self, observation, missing):
        """Retain a bounded per-target hold, never start a removal deadline."""
        now = observation["observed_at"]
        target, signature = observation["target"], observation["projection_signature"]
        self._execute("DELETE FROM reappearance WHERE expires<=?", (now,))
        self._execute("DELETE FROM reappearance WHERE target=? AND signature<>?", (target, signature))
        if not missing:
            return
        count, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM reappearance")
        expires = now + 86400
        for ip in sorted(missing):
            if self._one("SELECT 1 FROM reappearance WHERE target=? AND signature=? AND ip=?",
                         (target, signature, ip)):
                continue
            needed = size([target, signature, ip, expires])
            if count >= self.limits["reappearance_items"] or used + needed > self.limits["reappearance_bytes"]:
                self._tracking_loss()
                continue
            self._execute("INSERT INTO reappearance VALUES(?,?,?,?,?)", (target, signature, ip, expires, needed))
            count += 1
            used += needed

    def record_domain(self, observation, authority, bindings, *, cancelled=None):
        with self._lock:
            if cancelled is not None and cancelled() and self._unresolved is None:
                return self._result("stale")
            if not authority.get("valid"):
                return self._result("stale")
            if (len(bindings) > 2 or not all(valid_binding(b) for b in bindings) or
                    any(type(observation.get(k)) is not str or not observation[k]
                        for k in ('target', 'projection_signature'))):
                self.enter_gap("delivery_storage", {})
                return self._result("gap")
            if (self._unresolved is not None and self._unresolved['kind'] == 'source'
                    and self._unresolved['operation'] == observation['source_operation_id']):
                return self._result('gap')  # its speculative loss already has one owner
            pending_source = False
            if self._db is not None and not self._unresolved and not self._closed:
                try:
                    existing = self._one("SELECT operation,addition_epoch FROM cursor WHERE target=?", (observation["target"],))
                    if existing and existing[0] == observation["source_operation_id"]:
                        return self._result("consumed", committed=True)
                    pending_source = ('target_complete' in observation and self._control['absence_pending']
                                      and (existing is None or existing['addition_epoch'] != self._control['addition_epoch']))
                except sqlite3.Error:
                    pass
            # A definitely readable suppression state permits exact lower-bound
            # losses even when BEGIN IMMEDIATE cannot obtain its writer lock.
            losses = self._known_additions(observation, bindings)
            target_evidence = ('target_complete' in observation and 'fresh_positive_ips' in observation)
            gap_ready = (target_evidence and self._pending_addition_epoch is None
                         and self._control['absence_pending'])
            if (self._gap and not gap_ready) or not self._ready or self._claims_halted:
                self.enter_gap("delivery_storage", losses, invalidate_additions=not pending_source)
                return self._result("gap")
            def apply():
                row = self._one("SELECT * FROM cursor WHERE target=?", (observation["target"],))
                if row and row["operation"] == observation["source_operation_id"]:
                    return 0, 0
                if "expected_operation_id" in observation and (row["operation"] if row else None) != observation["expected_operation_id"]:
                    return "stale"
                ips = sorted(set(observation["managed_ips"]))
                pending = bool(row and row['addition_epoch'] != self._control['addition_epoch'])
                pending = pending or (row is None and self._control['absence_pending'])
                pending = pending or (target_evidence and bool(
                    row and (not row['tracked'] or row['signature'] != observation['projection_signature'])
                    or row is None and self._control.get('untracked_targets')))
                before = (set(json.loads(row["ips"])) if row and row["tracked"] and
                          row["signature"] == observation["projection_signature"]
                          else set(observation.get("before_ips", [])))
                if pending and not self._control.get('restart_rebaseline', False):
                    before = set(observation.get('before_ips', []))
                epoch = (self._control['addition_epoch'] if not pending or observation.get('target_complete', False)
                         else row['addition_epoch'] if row else '')
                if pending and not observation.get('target_complete', False) and epoch == self._control['addition_epoch']:
                    epoch = 'pending'
                fresh = set(observation.get('fresh_positive_ips', ips)) & set(ips)
                cursor_ips = ips
                if pending and not observation.get('target_complete', False) and target_evidence:
                    durable = set(json.loads(row['ips'])) if row and row['tracked'] else set()
                    cursor_ips = sorted((durable & set(ips)) | fresh)
                entries = [[ip, observation["label"], observation["source_type"]] for ip in sorted((set(ips) - before) & fresh)]
                self._execute("DELETE FROM recent WHERE expires<=?", (observation["observed_at"],))
                eligible = []
                selection = {}
                for entry in entries:
                    selected = self._addition_destinations(observation, entry[0], bindings)
                    if selected:
                        eligible.append(entry)
                        selection[entry[0]] = selected
                # Plan against the original authority before a tracking overflow
                # prunes it. Its exact selected destinations still count as loss.
                fits = self._put_cursor(observation["target"], cursor_ips, observation["projection_signature"],
                                        observation["source_operation_id"], addition_epoch=epoch)
                if (row and not row["tracked"] or not row and self._control.get("untracked_targets")) and fits:
                    before = set(ips)  # recovery enrolls current data, never a backlog
                    entries, eligible, selection = [], [], {}
                # Any actual return consumes the opportunity, including loss or
                # suppression by an independent gate. Unchanged positives do not.
                for ip in ({entry[0] for entry in entries} | (fresh if pending else set())):
                    self._execute("DELETE FROM failed_addition WHERE target=? AND signature=? AND ip=?",
                                  (observation['target'], observation['projection_signature'], ip))
                # Consume holds only after testing additions; a later disappearance
                # starts its own window rather than extending this one forever.
                for ip in fresh:
                    if target_evidence:
                        self._execute("DELETE FROM grace WHERE ip=?", (ip,))
                    self._execute("DELETE FROM reappearance WHERE target=? AND signature=? AND ip=?",
                                  (observation["target"], observation["projection_signature"], ip))
                self._remember_disappearance(observation, before - set(ips))
                recent_n, recent_bytes = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM recent")
                needed_bytes = sum(size([observation["target"], observation["projection_signature"], e[0], "Added"]) for e in eligible)
                recent_full = recent_n + len(eligible) > self.limits["recent_items"] or recent_bytes + needed_bytes > self.limits["recent_bytes"]
                if pending or not fits:
                    counts = {c: sum(b['channel'] == c for selected in selection.values() for b in selected)
                              for c in CHANNELS}
                    missed = sum(counts.values())
                    self._record_loss("recovery_gap" if pending else "tracking_overflow", counts)
                    admitted = 0
                else:
                    incarnation = self._one("SELECT incarnation FROM cursor WHERE target=?", (observation['target'],))[0]
                    admitted, missed = self._admit(eligible, bindings, observation["source_operation_id"],
                        "Added", observation["observed_at"], recent_full, observation["cycle_id"], selection=selection,
                        source=(observation['target'], incarnation, observation['projection_signature']))
                # Suppression consumes known lost transitions too, but does not ACK.
                for entry in eligible:
                    key = encode([observation["target"], observation["projection_signature"], entry[0], "Added"])
                    n, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM recent")
                    if n < self.limits["recent_items"] and used + len(key.encode()) <= self.limits["recent_bytes"]:
                        self._execute("INSERT OR REPLACE INTO recent VALUES(?,?,?)",
                                      (key, observation["observed_at"] + 60, len(key.encode())))
                return admitted, missed
            ok, result, uncertain = self._transaction(observation["source_operation_id"], apply,
                                                     cancelled=cancelled, kind='source')
            if not ok:
                if result == 'cancelled' and not uncertain:
                    return self._result("stale")
                if uncertain and self._unresolved is not None:
                    self._unresolved["losses"] = losses
                self.enter_gap("delivery_storage", {} if uncertain else losses,
                               invalidate_additions=not pending_source)
                return self._result("gap")
            if result == "stale":
                return self._result("stale")
            admitted, missed = result
            if target_evidence and self._gap:
                self._gap = False
                self._rebaseline = self._control['absence_pending']
                self._safe_refresh()
            if admitted:
                # Optional chunk sealing is a separate transaction: a renderer
                # fault cannot roll back previously admitted observations.
                self._transaction(uuid.uuid4().hex, lambda: self._seal(observation["cycle_id"], partial=False),
                                  allow_noop=True)
            return self._result("missed" if missed else ("admitted" if admitted else "consumed"),
                                admitted, missed, True)

    def _seal(self, cycle, *, partial=True, created_before=None, max_batches=None):
        count = 0
        inspected = 0
        while max_batches is None or inspected < max_batches:
            eligible = self._one("SELECT * FROM receipt WHERE state='unsealed' AND (? IS NULL OR cycle=?) "
                                 "AND (? IS NULL OR created<=?) ORDER BY id LIMIT 1",
                                 (cycle, cycle, created_before, created_before))
            if eligible is None:
                return count
            inspected += 1  # Failed oversized singletons also consume the work budget.
            cur = self._db.execute("SELECT * FROM receipt WHERE state='unsealed' AND cycle=? AND action=? AND binding=? "
                                   "ORDER BY id LIMIT ?", (eligible["cycle"], eligible["action"], eligible["binding"], self.limits["batch_items"]))
            try:
                page = cur.fetchmany(self.limits["batch_items"])
            finally:
                cur.close()
            # Any due member makes the group eligible, but clock rollback can
            # put that member behind its FIFO prefix. Render, identify and
            # terminally reject only the actual first member of that prefix.
            first = page[0]
            entries, members, body = [], [], None
            for row in page:
                candidate = entries + json.loads(row["payload"])["entries"]
                try:
                    rendered = self._render(candidate, first["action"], first["created"])
                    if type(rendered) is not dict or set(rendered) != {"title", "text"} or not all(type(v) is str for v in rendered.values()):
                        raise ValueError("invalid rendered body")
                except TeamsPayloadTooLarge:
                    break  # seal the last complete fitting prefix, not a suffix
                except Exception:
                    raise ValueError("delivery rendering unavailable") from None
                if len(encode_body(rendered)) > self.limits["batch_bytes"]:
                    break
                entries, body = candidate, rendered
                members.append(row["id"])
            if not members:
                # A known size failure of a singleton cannot be repaired by
                # splitting. Resolve it explicitly; never poison later work.
                self._terminal(first, "failed", "payload_limit", self._clock())
                continue
            if not partial and len(members) < self.limits["batch_items"] and len(members) == len(page):
                return count
            self._execute("INSERT INTO batch VALUES(?,?,?)", (first["id"], encode({"entries": entries, "body": body}), first["created"]))
            for member in members:
                self._execute("UPDATE receipt SET state='pending',batch_id=? WHERE id=?", (first["id"], member))
            count += 1
        return count

    def seal_due_batches(self, now):
        """Bounded partial flush independent of source-cycle completion.

        Age belongs to the oldest durable receipt, not the most recent append.
        Existing receipts retain their binding, FIFO and exact rendered payload.
        """
        with self._lock:
            if (self._stopping or self._claims_halted or self._closed or not self._ready
                    or self._unresolved is not None or not math.isfinite(now)):
                return {"ledger_committed": False, "sealed_batches": 0}
            cutoff = now - TEAMS_BATCH_MAX_WAIT_SECONDS
            try:
                due = self._one("SELECT 1 FROM receipt WHERE state='unsealed' AND created<=? LIMIT 1",
                                (cutoff,))
            except sqlite3.Error as error:
                self._note_storage_error(error, 'batch_due')
                self._health = {**self._health, "status": "degraded", "last_error": "delivery_storage", "counts_stale": True}
                return {"ledger_committed": False, "sealed_batches": 0}
            if due is None:
                return {"ledger_committed": True, "sealed_batches": 0}
            ok, count, _ = self._transaction(uuid.uuid4().hex,
                lambda: self._seal(None, created_before=cutoff, max_batches=TEAMS_BATCH_MAINTENANCE_LIMIT))
            if not ok:
                self._health = {**self._health, "status": "degraded", "last_error": "delivery_storage", "counts_stale": True}
            return {"ledger_committed": ok, "sealed_batches": count if ok else 0}

    def seal_cycle(self, cycle_id):
        with self._lock:
            ok, result, _ = self._transaction(uuid.uuid4().hex, lambda: self._seal(cycle_id))
            if not ok:
                # A seal fault does not invalidate source cursors or prevent
                # subsequent observation/admission. Unsealed rows retain bytes.
                self._health = {**self._health, "status": "degraded", "last_error": "delivery_storage", "counts_stale": True}
            return {"ledger_committed": ok, "sealed_batches": result if ok else 0}

    def _recover_claims(self, now=None, max_claims=8):
        if self._one("SELECT 1 FROM receipt WHERE state='in_flight' LIMIT 1") is None:
            return 0, False
        # Lazy schema-1 maintenance index: enroll only when abandoned work
        # exists, inside the resolved recovery/bootstrap transaction. Keep the
        # ordinary channel/binding FIFO claim plan unchanged.
        self._execute("CREATE INDEX IF NOT EXISTS receipt_abandoned ON receipt(id) "
                      "WHERE state='in_flight' AND (batch_id IS NULL OR id=batch_id)")
        now = self._clock() if now is None else now
        limit = min(8, max(1, int(max_claims)))
        cur = self._db.execute("SELECT * FROM receipt WHERE state='in_flight' "
                               "AND (batch_id IS NULL OR id=batch_id) ORDER BY id LIMIT ?", (limit,))
        try:
            page = cur.fetchmany(limit)
        finally:
            cur.close()
        for row in page:
            if row["attempt"] >= 8:
                self._terminal(row, "failed", "attempts_exhausted", now)
            else:
                # A reserved mutation may already have reached MISP. Preserve
                # reservations/budgets and retry from an authoritative read.
                self._execute("UPDATE receipt SET state='retry_wait',token=NULL,resume=0,"
                              "progress=CASE WHEN channel='misp' THEN '{}' ELSE progress END,"
                              "due=MAX(due,?) WHERE id=? OR batch_id=?",
                              (now + 30 * 2 ** max(0, row["attempt"] - 1), row["id"], row["id"]))
        more = self._one("SELECT 1 FROM receipt WHERE state='in_flight' "
                         "AND (batch_id IS NULL OR id=batch_id) LIMIT 1") is not None
        return len(page), more

    def _addition_outcome(self, row, state):
        context = (row['source_target'], row['source_incarnation'], row['source_signature'])
        if row['action'] != 'Added' or any(value is None for value in context):
            return
        if not self._one("SELECT 1 FROM cursor WHERE target=? AND incarnation=? AND signature=? AND tracked=1", context):
            return
        identity = (*context, row['ip'], row['channel'], row['binding'])
        old = self._one("SELECT receipt_id,bytes FROM failed_addition WHERE target=? AND incarnation=? "
                        "AND signature=? AND ip=? AND channel=? AND binding=?", identity)
        if old and old['receipt_id'] > row['id']:
            return
        if state == 'acked':
            self._execute("DELETE FROM failed_addition WHERE target=? AND incarnation=? AND signature=? "
                          "AND ip=? AND channel=? AND binding=?", identity)
            return
        needed = size([*identity, row['id']])
        count, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM failed_addition")
        if (count + (old is None) > self.limits['failed_addition_items'] or
                used - (old['bytes'] if old else 0) + needed > self.limits['failed_addition_bytes']):
            self._tracking_loss()
            return
        self._execute("INSERT OR REPLACE INTO failed_addition VALUES(?,?,?,?,?,?,?,?)", (*identity, row['id'], needed))

    def _terminal(self, row, state, reason, now, diagnostic=None):
        members = self._db.execute("SELECT * FROM receipt WHERE id=? OR batch_id=?",
                                   (row['id'], row['id']))
        try:
            for member in members:
                self._addition_outcome(member, state)
        finally:
            members.close()
        count = self._one("SELECT COUNT(*) FROM receipt WHERE id=? OR batch_id=?", (row["id"], row["id"]))[0]
        self._increment("acked_total" if state == "acked" else "failed_total", count)
        self._record_diagnostic(row, state, reason, now, diagnostic, count)
        summary_bytes = size([row["channel"], state, reason, now])
        self._execute("INSERT INTO terminal(channel,state,reason,at,bytes) VALUES(?,?,?,?,?)",
                      (row["channel"], state, reason, now, summary_bytes))
        self._execute("DELETE FROM receipt WHERE id=? OR batch_id=?", (row["id"], row["id"]))
        self._execute("DELETE FROM batch WHERE id=?", (row["id"],))
        self._execute("DELETE FROM terminal WHERE at<?", (now - 7 * 86400,))
        while True:
            count, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM terminal")
            if count <= self.limits["terminal_items"] and used <= self.limits["terminal_bytes"]:
                break
            self._execute("DELETE FROM terminal WHERE id=(SELECT MIN(id) FROM terminal)")
        if state == "acked":
            self._control["success_" + row["channel"]] = min(MAX_COUNTER, max(0, int(now)))
        self._control["error_" + row["channel"]] = reason

    def claim_next(self, bound_adapter, now):
        """Called with config ownership already held; descriptor has no secrets."""
        with self._lock:
            if self._stopping or self._claims_halted or self._closed or not self._ready:
                return None
            b = bound_adapter
            if not valid_binding(b):
                return None
            channel = b["channel"]
            def apply():
                signature = encode(b)
                self._control.setdefault("adapter_revision_" + channel, self._control.get("adapter_revision", 0))
                self._control["adapter_" + channel] = signature
                revision = self._control.get("adapter_revision_" + channel,
                                             self._control.get("adapter_revision", 0))
                self._control["enabled_" + channel] = bool(b["enabled"])
                self._execute("UPDATE receipt SET state='blocked_config',error='old_binding_blocked' "
                              "WHERE channel=? AND binding<>? AND state<>'in_flight' AND state<>'unsealed'",
                              (channel, b["binding_id"]))
                if not b["enabled"] or not b["ready"]:
                    self._execute("UPDATE receipt SET state='blocked_config',error='configuration_unavailable' "
                                  "WHERE channel=? AND state NOT IN ('in_flight','unsealed','blocked_config')", (channel,))
                    return None
                if channel == "misp" and not b["allow_removed"]:
                    self._execute("UPDATE receipt SET state='blocked_config',error='configuration_unavailable' "
                                  "WHERE channel=? AND action='Removed' AND state<>'in_flight'", (channel,))
                while True:
                    # Force the IP-selective predecessor index: absent ANALYZE,
                    # SQLite may prefer channel/binding/id and scan every older
                    # unrelated IP for each blocked candidate (quadratic again).
                    row = self._one("SELECT r.* FROM receipt r WHERE r.channel=? AND r.binding=? "
                        "AND r.state IN ('pending','retry_wait','blocked_config') AND r.due<=? "
                        "AND (r.state<>'blocked_config' OR r.block_revision<>? "
                        "OR r.error IN ('configuration_unavailable','old_binding_blocked')) "
                        "AND (? OR r.action<>'Removed') AND (r.batch_id IS NULL OR r.id=r.batch_id) "
                        "AND NOT EXISTS (SELECT 1 FROM receipt p INDEXED BY receipt_fifo WHERE p.binding=r.binding "
                        "AND p.channel=r.channel AND p.ip=r.ip AND p.id<r.id "
                        "AND (p.batch_id IS NULL OR p.batch_id<>r.id)) "
                        "AND NOT EXISTS (SELECT 1 FROM receipt m JOIN receipt p INDEXED BY receipt_fifo ON p.binding=m.binding "
                        "AND p.channel=m.channel AND p.ip=m.ip AND p.id<m.id "
                        "WHERE m.batch_id=r.id AND m.id<>r.id AND (p.batch_id IS NULL OR p.batch_id<>r.id)) "
                        "ORDER BY r.id LIMIT 1", (channel, b["binding_id"], now, revision, channel != "misp" or b["allow_removed"]))
                    if row is None:
                        return None
                    if row["provider_calls"] >= 4096 or (row["attempt"] >= 8 and not row["resume"]):
                        self._terminal(row, "failed", "provider_work_limit" if row["provider_calls"] >= 4096 else "attempts_exhausted", now)
                        continue
                    token = uuid.uuid4().hex
                    attempt = row["attempt"] + (0 if row["resume"] else 1)
                    self._execute("UPDATE receipt SET state='in_flight',token=?,attempt=?,provider_calls=provider_calls+1,error=NULL,claim_revision=? WHERE id=? OR batch_id=?",
                                  (token, attempt, revision, row["id"], row["id"]))
                    return {"claim_id": ("b:" if row["batch_id"] else "r:") + str(row["id"]), "attempt_token": token,
                            "channel": channel, "binding_id": row["binding"], "action": row["action"],
                            "attempt": attempt, "provider_calls": row["provider_calls"] + 1,
                            "progress": json.loads(row["progress"]), "payload": json.loads(
                                self._one("SELECT payload FROM batch WHERE id=?", (row["id"],))[0]
                                if row["batch_id"] else row["payload"]),
                            "observation_hook_consumed": bool(row["hook"])}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply, kind='claim')
            if not ok:
                self._halt_delivery()
            return result if ok else None

    def finish_step(self, claim, provider_result, now):
        provider_result = normalize_result(provider_result)
        with self._lock:
            if self._closed:
                return {"applied": False}
            def apply():
                if not str(claim["claim_id"]).startswith(("r:", "b:")):
                    return {"applied": False}
                row = self._one("SELECT * FROM receipt WHERE id=? AND token=? AND state='in_flight'",
                                (claim["claim_id"][2:], claim["attempt_token"]))
                if row is None or (row["batch_id"] and row["batch_id"] != row["id"]) or (
                        claim["claim_id"] != ("b:" if row["batch_id"] else "r:") + str(row["id"])):
                    return {"applied": False}
                hook = None
                first_add = row["action"] == "Added" and row["attempt"] == 1 and row["provider_calls"] == 1
                confirmed_removal = row["action"] == "Removed" and provider_result["state"] == "acked"
                if row["channel"] == "misp" and (first_add or confirmed_removal) and not row["hook"]:
                    candidate_hook = provider_result.get("observation_hook")
                    if isinstance(candidate_hook, dict) and size(candidate_hook) <= 512:
                        hook = candidate_hook
                    self._execute("UPDATE receipt SET hook=1 WHERE id=?", (row["id"],))
                state = provider_result["state"]
                reason = provider_result["reason"]
                self._control["error_" + row["channel"]] = reason
                diagnostic = provider_result.get('diagnostic')
                if state == "acked":
                    self._terminal(row, "acked", None, now, diagnostic)
                elif state == "failed" or (state == "retry" and row["attempt"] >= 8):
                    self._terminal(row, "failed", "attempts_exhausted" if state == "retry" else reason, now, diagnostic)
                else:
                    progress = encode(provider_result["progress"])
                    if len(progress.encode()) > 2048:
                        self._terminal(row, "failed", "invalid_payload", now, diagnostic)
                        return {"applied": True}
                    count = self._one("SELECT COUNT(*) FROM receipt WHERE id=? OR batch_id=?",
                                      (row['id'], row['id']))[0]
                    self._record_diagnostic(row, state, reason, now, diagnostic, count)
                    retry_after = provider_result.get("retry_after") or 0
                    delay = max(30 * 2 ** max(0, row["attempt"] - 1), min(3600, max(30, retry_after)))
                    next_state = {"continue": "pending", "retry": "retry_wait", "blocked": "blocked_config"}[state]
                    self._execute("UPDATE receipt SET state=?,token=NULL,progress=?,resume=?,due=?,error=?,"
                                  "provider_calls=provider_calls-?,block_revision=? WHERE (id=? OR batch_id=?) AND token=? AND state='in_flight'",
                                  (next_state, progress, int(state == "continue"), now + delay if state == "retry" else 0,
                                   reason, int(provider_result["provider_calls"] == 0), row["claim_revision"],
                                   row["id"], row["id"], claim["attempt_token"]))
                return {"applied": True, "observation_hook": hook}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply, kind='ack')
            if not ok:
                self._halt_delivery()
            return result if ok else {"applied": False, "storage_error": True}

    def _pages(self, table):
        # table names are internal constants, never caller-supplied SQL.
        last = ""
        while True:
            cur = self._db.execute("SELECT * FROM " + table + " WHERE ip>? ORDER BY ip LIMIT 256", (last,))
            try:
                page = cur.fetchmany(256)
            finally:
                cur.close()
            if not page:
                break
            last = page[-1]["ip"]
            yield from page

    def _tracking_loss(self):
        self._control["tracking_complete"] = False
        self._control["accounting_complete"] = False
        self._increment("tracking_overflow", 1)

    def _install_baseline(self, active):
        if len(active) > self.limits["baseline_items"] or size(active) > self.limits["baseline_bytes"]:
            self._tracking_loss()
            self._control["baseline_untracked"] = True
            return False
        self._execute("DELETE FROM baseline")
        for ip, labels in active.items():
            self._execute("INSERT INTO baseline VALUES(?,?,?)", (ip, encode(labels), size([ip, labels])))
        self._control["baseline_untracked"] = False
        return True

    def _put_grace(self, ip, labels, since):
        if self._one("SELECT 1 FROM grace WHERE ip=?", (ip,)):
            return True
        count, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM grace")
        needed = size([ip, labels, since, since + 86400, "0" * 32])
        if count >= self.limits["grace_items"] or used + needed > self.limits["grace_bytes"]:
            self._tracking_loss()
            self._control["baseline_untracked"] = True
            return False
        self._execute("INSERT INTO grace VALUES(?,?,?,?,?,?)",
                      (ip, encode(labels), since, 0, uuid.uuid4().hex, needed))
        return True

    def _reconcile(self, active, now, bindings, *, recovering=False, retain_baseline=False):
        # Cancel positives even if the complete map cannot be retained.
        for row in self._pages("grace"):
            if row["ip"] in active:
                self._execute("DELETE FROM grace WHERE ip=?", (row["ip"],))
        fits = len(active) <= self.limits["baseline_items"] and size(active) <= self.limits["baseline_bytes"]
        prior_tracked = not self._control.get("baseline_untracked", False)
        if fits and prior_tracked and (not recovering or retain_baseline):
            for row in self._pages("baseline"):
                if row["ip"] not in active:
                    self._put_grace(row["ip"], json.loads(row["labels"]), now)
        admitted = missed = 0
        for row in self._pages("grace"):
            expiry = max(row["missing_since"] + 86400, row["not_before"])
            if now >= expiry:
                labels = json.loads(row["labels"])
                entry = [row["ip"], ", ".join(labels), "A"]
                eligible = [b for b in bindings if b["channel"] != "misp" or b["allow_removed"]]
                if recovering:
                    counts = {c: sum(b["enabled"] and b["channel"] == c for b in eligible) for c in CHANNELS}
                    self._record_loss("recovery_gap", counts)
                    a, m = 0, sum(counts.values())
                else:
                    a, m = self._admit([entry], eligible, row["identity"], "Removed", now)
                admitted += a
                missed += m
                self._execute("DELETE FROM grace WHERE ip=?", (row["ip"],))
            elif recovering:
                self._execute("UPDATE grace SET not_before=? WHERE ip=?", (now + 86400, row["ip"]))
        self._install_baseline(active)
        return admitted, missed

    def reconcile_full(self, authority, active_map, completed_at, bindings):
        with self._lock:
            if not authority.get("valid"):
                return {**self._result("stale"), "source_valid": False}
            if self._gap or self._rebaseline:
                return {**self._result("gap"), "source_valid": True}
            ok, result, _ = self._transaction(uuid.uuid4().hex,
                lambda: self._reconcile(active_map, completed_at, bindings))
            if not ok:
                self.enter_gap("delivery_storage", {})
                return {**self._result("gap"), "source_valid": True}
            admitted, missed = result
            return {**self._result("missed" if missed else "consumed", admitted, missed, True), "source_valid": True}

    def cancel_force_positive(self, authority, fresh_positive_ips):
        with self._lock:
            if not authority.get("valid"):
                return {**self._result("stale"), "source_valid": False}
            def apply():
                for ip in fresh_positive_ips:
                    self._execute("DELETE FROM grace WHERE ip=?", (ip,))
            ok, _, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self.enter_gap("delivery_storage", {})
            return {**self._result("consumed" if ok else "gap", committed=ok), "source_valid": True}

    def rebaseline_absence(self, authority, active_map, completed_at, bindings):
        """Only the generation-validated complete producer may certify absence.

        Target operations remain intact. An accepted history publication during
        failed ledger admission cannot satisfy the durable target-ready gate.
        """
        with self._lock:
            if not authority.get('valid') or self._stopping or self._closed:
                return {**self._result('stale'), 'source_valid': False}
            if self._pending_addition_epoch is not None or not self._ready or self._unresolved:
                return {**self._result('gap'), 'source_valid': True}
            def apply():
                if self._one('SELECT 1 FROM cursor WHERE addition_epoch<>? OR tracked=0 LIMIT 1',
                             (self._control['addition_epoch'],)) or self._control.get('untracked_targets'):
                    return None
                result = self._reconcile(active_map, completed_at, bindings,
                    recovering=self._control['absence_pending'], retain_baseline=self._control.get('restart_rebaseline', False))
                self._control['absence_pending'] = False
                self._control['restart_rebaseline'] = False
                self._control['revision'] = authority['revision']
                self._control['signature'] = authority['signature']
                return result
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply, kind='absence',
                                             cancelled=lambda: self._stopping)
            if not ok:
                self._halt_delivery()
                return {**self._result('gap'), 'source_valid': True}
            self._rebaseline = self._control['absence_pending']
            if not self._rebaseline:
                self._gap = False
            self._safe_refresh()
            admitted, missed = result or (0, 0)
            return {**self._result('consumed' if result is not None else 'gap', admitted, missed, True),
                    'source_valid': True}

    def _put_cursor(self, target, ips, signature, operation, *, addition_epoch=None):
        epoch = self._control['addition_epoch'] if addition_epoch is None else addition_epoch
        row = self._one("SELECT * FROM cursor WHERE target=?", (target,))
        n, members, used = self._one("SELECT COUNT(*),COALESCE(SUM(members),0),COALESCE(SUM(bytes),0) FROM cursor")
        data = encode(ips)
        byte_count = len(data.encode()) + len(target.encode()) + len(signature.encode()) + len(epoch.encode())
        fits = (len(ips) <= self.limits["target_ips"] and
                members - (row["members"] if row else 0) + len(ips) <= self.limits["cursor_members"] and
                used - (row["bytes"] if row else 0) + byte_count <= self.limits["cursor_bytes"] and
                (row is not None or n < self.limits["cursor_targets"]))
        if not fits:
            self._control["tracking_complete"] = False
            self._control["accounting_complete"] = False
            self._increment("tracking_overflow", 1)
            data, byte_count = "[]", len(target.encode()) + len(signature.encode()) + len(epoch.encode()) + 2
        if (row or n < self.limits["cursor_targets"]) and used - (row["bytes"] if row else 0) + byte_count <= self.limits["cursor_bytes"]:
            self._execute("INSERT OR REPLACE INTO cursor "
                          "(target,incarnation,signature,ips,operation,tracked,members,bytes,addition_epoch) "
                          "VALUES(?,?,?,?,?,?,?,?,?)", (
                target, row["incarnation"] if row else uuid.uuid4().hex, signature,
                data, operation, int(fits), len(ips) if fits else 0, byte_count,
                epoch,
            ))
        else:
            # No unbounded side map for targets that cannot be represented.
            self._control["untracked_targets"] = True
        self._prune_failed_additions(target)
        return fits

    def _rebase(self, projection):
        self._execute("DELETE FROM cursor")
        for target, value in projection.items():
            self._put_cursor(target, sorted(set(value["ips"])), value["signature"], uuid.uuid4().hex)
            # GAP observations cannot consume holds until recovery commits.
            # These positives end their old window; still-absent IPs retain it.
            for ip in value["ips"]:
                self._execute("DELETE FROM reappearance WHERE target=? AND signature=? AND ip=?",
                              (target, value["signature"], ip))
        self._prune_reappearance()

    def recover_delivery(self, now, max_claims=8):
        """Recover durable delivery ownership, never detector evidence."""
        result = {"state": "recovering", "ledger_committed": False,
                  "recovered_claims": 0, "has_more": False}
        if not self._lock.acquire(blocking=False):
            return result
        try:
            if self._closed or self._stopping or self._worker_active:
                return {**result, "state": "stopped"}
            if self._monotonic() < self._recovery_next:
                return {**result, "state": "backoff"}
            try:
                self._resolve_unresolved()
            except (sqlite3.Error, OSError, ValueError, TypeError):
                self._recovery_failed()
                return {**result, "state": "uncertain"}
            if not self._ready:
                if self._db is None:
                    try:
                        self._open()
                    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, ImportError) as error:
                        self._note_storage_error(error, self._storage_stage)
                        self._release()
                        self._recovery_failed()
                        return {**result, "state": "failed"}
                return result  # runtime supplies current authority for bootstrap
            if (not self._claims_halted and self._pending_addition_epoch is None and self._health['storage_ok']
                    and not any(self._volatile.values())):
                return {**result, "state": "ready"}
            captured = dict(self._volatile)
            totals = {c: min(MAX_COUNTER, self._checkpoint[c] + captured[c]) for c in CHANNELS}
            def apply():
                old = self._control.get('loss_checkpoint', {})
                if self._pending_addition_epoch is not None:
                    self._control['addition_epoch'] = self._pending_addition_epoch
                    self._control['absence_pending'] = True
                    self._control['restart_rebaseline'] = False
                for c in CHANNELS:
                    prior = old.get(c, 0) if old.get('process') == self._process_id else 0
                    self._record_loss('delivery_storage', {c: max(0, totals[c] - prior)})
                self._control['loss_checkpoint'] = {'process': self._process_id, **totals}
                return self._recover_claims(now, max_claims)
            ok, page, _ = self._transaction(uuid.uuid4().hex, apply,
                                          cancelled=lambda: self._stopping, kind='recovery', checkpoint=totals, captured=captured)
            if ok:
                self._adopt_checkpoint(totals, captured)
                self._recovery_failures = 0
                self._recovery_next = 0.0
            elif not self._stopping:
                self._halt_delivery()
                self._recovery_failed()
            if ok and not self._stopping:
                self._claims_halted = page[1]
                self._pending_addition_epoch = None
                if not self._gap:
                    self._rebaseline = self._control['absence_pending']
                self._safe_refresh()
            return {**result, "state": ('recovering' if page[1] else 'ready')
                    if ok and not self._stopping else 'failed',
                    "ledger_committed": ok, "recovered_claims": page[0] if ok else 0,
                    "has_more": page[1] if ok else False}
        finally:
            self._lock.release()

    def _recovery_failed(self):
        self._recovery_next = self._monotonic() + min(30, 2 ** self._recovery_failures)
        self._recovery_failures = min(5, self._recovery_failures + 1)

    def needs_bootstrap(self):
        if not self._lock.acquire(blocking=False):
            return False
        try:
            return (self._db is not None and not self._ready and self._unresolved is None
                    and not self._closed and not self._stopping and not self._worker_active)
        finally:
            self._lock.release()

    def recover_gap(self, authority, current_projection, full_result, loss_checkpoint=None):
        with self._lock:
            if not authority.get("valid") or self._stopping or self._closed or self._worker_active:
                return {"ready": False, "source_valid": False}
            if self._db is None and not self._closed:
                try:
                    self._open()
                except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, ImportError):
                    self._release()
                    self.enter_gap("delivery_storage", {})
                    return {"ready": False, "source_valid": True}
            if (self._ready and not self._gap and not self._rebaseline and not self._unresolved
                    and not self._claims_halted and not any(self._volatile.values())):
                return {"ready": True, "source_valid": True}
            if self._unresolved is not None:
                try:
                    self._resolve_unresolved()
                except (sqlite3.Error, OSError, ValueError, TypeError):
                    return {"ready": False, "source_valid": True}
            captured = dict(self._volatile)
            totals = {c: min(MAX_COUNTER, self._checkpoint[c] + captured[c]) for c in CHANNELS}
            def apply():
                old = self._control.get("loss_checkpoint", {})
                for c in CHANNELS:
                    prior = old.get(c, 0) if old.get("process") == self._process_id else 0
                    self._record_loss("delivery_storage", {c: max(0, totals[c] - prior)})
                self._control["loss_checkpoint"] = {"process": self._process_id, **totals}
                if self._claims_halted:
                    self._recover_claims()
                self._reconcile(full_result["active_map"], full_result["completed_at"],
                                full_result.get("bindings", []), recovering=True,
                                retain_baseline=self._rebaseline)
                self._rebase(current_projection)
                self._control['absence_pending'] = False
                self._control['restart_rebaseline'] = False
                self._control["accounting_complete"] = False
                self._control["clean"] = False
                self._control["enrolled"] = True
                self._control["revision"] = authority["revision"]
                self._control["signature"] = authority["signature"]
                return {"ready": True, "source_valid": True}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply, kind='recovery', checkpoint=totals, captured=captured)
            if not ok:
                self.enter_gap("delivery_storage", {})
                return {"ready": False, "source_valid": True}
            self._adopt_checkpoint(totals, captured)
            self._gap = False
            self._rebaseline = False
            self._pending_addition_epoch = None
            self._claims_halted = self._one("SELECT 1 FROM receipt WHERE state='in_flight' LIMIT 1") is not None
            self._ready = True
            self._safe_refresh()
            self._health = {**self._health, "missed_unpersisted": 0,
                            "last_error": ("delivery_storage" if not self._health["storage_ok"] else
                                           "history_persistence" if self._history_failed else None)}
            return result

    def _halt_delivery(self):
        # Dispatch failure is not evidence of a lost source observation.
        self._claims_halted = True
        self._health = {**self._health, 'storage_ok': False, 'counts_stale': True,
                        'status': 'degraded', 'last_error': 'delivery_storage'}

    def enter_gap(self, reason, known_loss_counts, *, invalidate_additions=True):
        with self._lock:
            if self._pending_addition_epoch is None and invalidate_additions:
                self._pending_addition_epoch = uuid.uuid4().hex
            self._gap = True
            self._control["accounting_complete"] = False
            for channel in CHANNELS:
                count = max(0, int(known_loss_counts.get(channel, 0)))
                self._volatile[channel] = min(MAX_COUNTER, self._volatile[channel] + count)
                if self._unresolved is not None and self._unresolved['checkpoint'] is not None:
                    newer = self._unresolved['newer_losses']
                    newer[channel] = min(MAX_COUNTER, newer[channel] + count)
            health = copy.deepcopy(self._health)
            health.update(status="degraded", coverage="gap", storage_ok=False, counts_stale=True,
                          accounting_complete=False, last_error="delivery_storage",
                          missed_unpersisted=min(MAX_COUNTER, sum(self._volatile.values())))
            anchors = self._health_cache[1]
            if self._pending_addition_epoch is not None:
                anchors = (*anchors[:5], anchors[7], 'awaiting_full', anchors[7])
            self._health_cache = (health, anchors)

    def dispatch_available(self):
        return bool(self._ready and not self._closed and not self._stopping and not self._claims_halted)

    def worker_enter(self):
        with self._lock:
            if self._closed or self._stopping or self._worker_active:
                return False
            self._worker_active = True
            self._health = {**self._health, "worker_running": True}
            return True

    def worker_exit(self):
        with self._lock:
            self._worker_active = False
            self._health = {**self._health, "worker_running": self._worker_thread}

    def set_worker_thread_running(self, running):
        with self._lock:
            self._worker_thread = bool(running)
            self._health = {**self._health, "worker_running": bool(running or self._worker_active)}

    def fence_claims(self):
        # The Event-like assignment precedes lock acquisition: stop must not
        # wait for an in-progress fsync just to publish its admission fence.
        self._stopping = True

    def progress_health_snapshot(self):
        # Capture once: status-only publications cannot split counts and anchors.
        health, anchors = self._health_cache
        result = copy.deepcopy(health)
        _, age, sampled, _, retries, targets, absence, _ = anchors
        since = elapsed(self._monotonic(), sampled)
        result['oldest_pending_age_seconds'] = counter(age + (since or 0)) if age is not None else None
        return result, counter(since), dict(retries), targets, absence

    def health_snapshot(self):
        return self.progress_health_snapshot()[0]

    @staticmethod
    def _diagnostic_record(value):
        # Persisted control state is not a license to publish future fields.
        if type(value) is not dict:
            return None
        from monitor.delivery_diagnostics import normalize_diagnostic
        counts = ('at', 'attempt', 'items')
        if any(type(value.get(k)) is not int or not 0 <= value[k] <= MAX_COUNTER for k in counts):
            return None
        if value.get('channel') not in CHANNELS or value.get('state') not in (
                'acked', 'continue', 'retry', 'blocked', 'failed'):
            return None
        raw_reason = value.get('reason')
        reason = stable_reason(raw_reason) if raw_reason is None or (
            type(raw_reason) is str and len(raw_reason) <= 64) else 'delivery_unknown'
        return {**{k: value[k] for k in counts}, 'channel': value['channel'],
                'state': value['state'], 'reason': reason,
                'diagnostic': normalize_diagnostic(value.get('diagnostic'))}

    def _record_diagnostic(self, row, state, reason, now, detail, items):
        record = self._diagnostic_record({
            'at': max(0, min(MAX_COUNTER, int(now))), 'channel': row['channel'],
            'state': state, 'reason': reason, 'attempt': row['attempt'],
            'items': items, 'diagnostic': detail})
        if record is None:
            return
        saved = self._control.setdefault('delivery_diagnostics', {})
        saved.setdefault('latest_result', {})[row['channel']] = record
        if state == 'failed':
            saved.setdefault('latest_failure', {})[row['channel']] = record
            saved['recent_failures'] = [record, *saved.get('recent_failures', [])[:9]]

    def _publish_diagnostics(self, wall):
        saved = self._control.get('delivery_diagnostics')
        if type(saved) is not dict:
            saved = {}
        channels = {}
        for channel in CHANNELS:
            grouped = {}
            cursor = self._db.execute("SELECT error,COUNT(*) FROM receipt WHERE channel=? "
                                      "AND state='blocked_config' GROUP BY error", (channel,))
            try:
                for reason, count in cursor:
                    reason = stable_reason(reason) or 'delivery_unknown'
                    grouped[reason] = grouped.get(reason, 0) + count
            finally:
                cursor.close()
            data = {'blocked_by_reason': [{'reason': r, 'count': n} for r, n in sorted(grouped.items())]}
            for key in ('latest_result', 'latest_failure'):
                by_channel = saved.get(key)
                data[key] = self._diagnostic_record(by_channel.get(channel)) if type(by_channel) is dict else None
            channels[channel] = data
        recent = saved.get('recent_failures')
        recent = recent[:10] if type(recent) is list else []
        self._diagnostics = {
            'version': 1, 'observed_at': counter(wall),
            'channels': channels,
            'recent_failures': [r for value in recent if (r := self._diagnostic_record(value)) is not None],
        }

    def _note_storage_error(self, error, stage):
        """Fixed classes only: exception text can contain credentials and paths."""
        at = counter(self._clock())
        if at is None:
            # Error reporting must not mask a resolved COMMIT or replace a
            # historical diagnostic with a fabricated observation timestamp.
            return
        code = 'unknown'
        if stage == 'worker':
            code = 'worker_exception'
        elif isinstance(error, sqlite3.Error):
            number = getattr(error, 'sqlite_errorcode', None)
            primary = number & 255 if type(number) is int else -1
            code = {5: 'sqlite_busy', 6: 'sqlite_busy', 8: 'sqlite_readonly',
                    10: 'sqlite_io', 11: 'sqlite_corrupt', 13: 'sqlite_full',
                    26: 'sqlite_corrupt'}.get(primary, 'sqlite_error')
            # Python 3.10 has no sqlite_errorcode. Match only exact driver
            # phrases; never publish the message or interpolate any suffix.
            message = error.args[0] if len(error.args) == 1 else None
            if primary == -1 and type(message) is str and len(message) <= 128:
                code = {'database is locked': 'sqlite_busy',
                        'database table is locked': 'sqlite_busy',
                        'database or disk is full': 'sqlite_full',
                        'attempt to write a readonly database': 'sqlite_readonly',
                        'database disk image is malformed': 'sqlite_corrupt',
                        'file is not a database': 'sqlite_corrupt',
                        'disk I/O error': 'sqlite_io'}.get(message, 'sqlite_error')
        elif isinstance(error, OSError):
            if stage == 'open_owner' and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                code = 'owner_lock'
            elif error.errno in (errno.EACCES, errno.EPERM):
                code = 'permission_denied'
            elif error.errno == errno.ENOSPC:
                code = 'disk_full'
            else:
                code = 'os_error'
        elif isinstance(error, (ValueError, KeyError, TypeError, ImportError)):
            code = 'invalid_state'
        self._storage_error = {'at': at,
                               'stage': stage, 'code': code}

    def worker_failed(self, error):
        with self._lock:
            self._note_storage_error(error, 'worker')
            self.enter_gap('delivery_storage', {})
            self.fence_claims()

    def diagnostics_snapshot(self):
        """Read only published memory; never lock SQLite or contact providers."""
        health = self._health
        snapshot = copy.deepcopy(self._diagnostics)
        snapshot.update({key: health[key] for key in (
            'counts_stale', 'storage_ok', 'worker_running', 'coverage')})
        snapshot['storage_error'] = copy.deepcopy(self._storage_error)
        return snapshot

    def close(self, *, clean):
        with self._lock:
            if self._closed:
                return True
            if self._worker_active:
                return False
            self._stopping = True
            if self._db is not None:
                def apply():
                    self._control['session_closed'] = bool(clean and self._pending_addition_epoch is None)
                    self._control["clean"] = bool(clean and not self._gap and not self._rebaseline
                        and not self._control['absence_pending'] and not self._one(
                        "SELECT 1 FROM receipt WHERE state='in_flight' LIMIT 1"))
                self._transaction(uuid.uuid4().hex, apply)
            self._closed = True
            self._release()
            return True
