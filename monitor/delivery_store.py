"""Private observation-first ledger; source calls require core coordination.

The core repository validates its original leases under config -> repository
coordination, then calls us. A cursor or caller mapping never grants a lease.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from monitor.delivery_types import CHANNELS, DEFAULT_LIMITS, MAX_COUNTER, encode, size, valid_binding, provider_result as normalize_result
from monitor.delivery_types import TeamsPayloadTooLarge, encode_body


class DeliveryStore:
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
        self._lock = threading.RLock()
        self._db = None
        self._owner = None
        self._closed = False
        self._unresolved = None
        self._worker_thread = False
        self._worker_active = False
        self._stopping = False
        self._claims_halted = False
        self._ready = False
        self._gap = False
        self._rebaseline = False
        self._history_failed = False
        self._fault = lambda point: None
        self._process_id = uuid.uuid4().hex
        self._checkpoint = {c: 0 for c in CHANNELS}
        self._volatile = {c: 0 for c in CHANNELS}
        self._control = {
            "schema": 1, "epoch": uuid.uuid4().hex, "clean": True, "binding_key": os.urandom(32).hex(),
            "accounting_complete": True, "tracking_complete": True,
            "missed_total": 0, "failed_total": 0, "acked_total": 0,
        }
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
        try:
            self._open()
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, ImportError):
            self._release()
            self.enter_gap("delivery_storage", {})

    def _one(self, sql, args=()):
        cur = self._db.execute(sql, args)
        try:
            return cur.fetchone()
        finally:
            cur.close()

    def _execute(self, sql, args=()):
        cur = self._db.execute(sql, args)
        try:
            return cur.rowcount
        finally:
            cur.close()

    def _open(self):
        # Unsupported platforms degrade instead of running an unfenced owner.
        import fcntl
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        lock_path = self.path.with_name("delivery.lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self._owner = os.fdopen(fd, "a+b")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sentinel = self.path.with_name("delivery.initialized")
        established = sentinel.exists()
        existed = self.path.exists()
        if established and not existed:
            raise ValueError("missing established ledger")
        if self.path.is_symlink() or sentinel.is_symlink():
            raise ValueError("unsafe ledger")
        if not existed:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        os.chmod(self.path, 0o600)
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=.05)
        self._db.row_factory = sqlite3.Row
        for pragma in ("busy_timeout=50", "page_size=4096", "journal_mode=DELETE",
                       "synchronous=FULL", "foreign_keys=ON", "temp_store=MEMORY",
                       "cache_size=-2048", "max_page_count=" + str(self.limits["pages"])):
            self._execute("PRAGMA " + pragma)
        if existed:
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

    def _known_additions(self, observation):
        if self._db is None:
            # With no readable suppression state there is no defensible exact
            # loss count. Completeness is already false, not a fictional zero.
            return 0
        try:
            count = 0
            for ip in set(observation["managed_ips"]) - set(observation.get("before_ips", [])):
                key = encode([observation["target"], observation["projection_signature"], ip, "Added"])
                if not self._one("SELECT 1 FROM grace WHERE ip=?", (ip,)) and not self._one(
                        "SELECT 1 FROM recent WHERE key=? AND expires>?", (key, observation["observed_at"])):
                    count += 1
            return count
        except sqlite3.Error:
            return 0

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
            ok, _, _ = self._transaction(uuid.uuid4().hex,
                lambda: self._execute("DELETE FROM cursor WHERE incarnation=?", (incarnation,)))
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
            if self._gap or self._rebaseline or not self._ready:
                self.enter_gap("delivery_storage", {})
                return {"ledger_committed": False, "source_valid": True}
            def apply():
                self._prune_cursors(active_projection)
                for target, value in active_projection.items():
                    row = self._one("SELECT signature FROM cursor WHERE target=?", (target,))
                    if row is None or row["signature"] != value["signature"]:
                        self._execute("DELETE FROM cursor WHERE target=?", (target,))
                        self._put_cursor(target, sorted(set(value["ips"])), value["signature"], uuid.uuid4().hex)
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

    def _transaction(self, operation, fn):
        """A fixed last-transaction UUID resolves commit errors independently.

        Only one writer owned by this object exists. No subsequent write is
        permitted before this readback; unknown outcomes halt admission/claims.
        """
        if self._unresolved is not None:
            return False, None, True
        if self._db is None or self._closed:
            return False, None, False
        before = copy.deepcopy(self._control)
        committed = False
        result = None
        try:
            self._execute("BEGIN IMMEDIATE")
            result = fn()
            self._control["last_transaction"] = operation
            self._save_control()
            self._fault("before_commit")
            self._db.commit()
            committed = True
            self._fault("after_commit")
        except (sqlite3.Error, OSError, ValueError):
            try:
                self._db.rollback()
            except sqlite3.Error:
                pass
            try:
                saved = self._read_control()
                if saved.get("last_transaction") == operation:
                    self._control = saved
                    self._safe_refresh()
                    return True, result, False
                self._control = before
                return False, None, False
            except (sqlite3.Error, OSError, ValueError, TypeError):
                self._control = before
                self._unresolved = {"operation": operation, "losses": {}}
                self._claims_halted = True
                return False, None, True
        if committed:
            self._safe_refresh()
        return True, result, False

    def _safe_refresh(self):
        try:
            self._refresh()
        except (sqlite3.Error, OSError, ValueError):
            self._health = {**self._health, "counts_stale": True, "storage_ok": False,
                            "status": "degraded", "last_error": "delivery_storage"}

    def _refresh(self):
        health = copy.deepcopy(self._health)
        used = self._one("SELECT COUNT(*),COALESCE(SUM(reserved),0),MIN(created) FROM receipt")
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
        health["oldest_pending_age_seconds"] = min(MAX_COUNTER, max(0, int(self._clock() - used[2]))) if used[2] is not None else None
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
        self._health = health

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
                self._rebaseline = not first and (not self._control["clean"] or mismatch)
                if not first and mismatch:
                    # Equal final names/definitions do not prove no intervening
                    # delete/re-add. Keep detector evidence for loss accounting,
                    # but do not attach its prior incarnation to new authority.
                    self._execute("UPDATE cursor SET incarnation=lower(hex(randomblob(16)))")
                self._prune_cursors(active_projection)
                self._recover_claims()
                self._control["enrolled"] = True
                self._control["clean"] = False
                if not self._rebaseline:
                    self._control["revision"] = authority["revision"]
                    self._control["signature"] = authority["signature"]
                return {"ready": True, "rebaseline_required": self._rebaseline}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply)
            self._ready = ok
            if not ok:
                self.enter_gap("delivery_storage", {})
            else:
                self.seal_cycle(None)
            return result if ok else {"ready": False}

    def _admit(self, entries, bindings, operation, action, created, force_loss=False, cycle=""):
        destinations = [b for b in bindings if b["enabled"]]
        needed = len(entries) * len(destinations)
        reserved = sum(size({"entries": [e]}) + 4096 +
                       (self.limits["batch_bytes"] if b["channel"] == "teams" else 0)
                       for e in entries for b in destinations)
        used = self._one("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM receipt")
        overflow = (force_loss or len(entries) > self.limits["unit_items"] or size(entries) > self.limits["unit_bytes"] or
                    any(len(e[1].encode()) > self.limits["label_bytes"] for e in entries) or
                    needed + used[0] > self.limits["receipts"] or
                    reserved + used[1] > self.limits["payload_bytes"])
        if overflow:
            counts = {c: len(entries) * sum(b["channel"] == c for b in destinations) for c in CHANNELS}
            self._record_loss("delivery_capacity", counts)
            return 0, needed
        for entry in entries:
            payload = encode({"entries": [entry]})
            for b in destinations:
                self._execute(
                    "INSERT INTO receipt(operation,channel,binding,action,ip,payload,state,created,reserved,cycle) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (operation, b["channel"], b["binding_id"], action, entry[0], payload,
                     "unsealed" if b["channel"] == "teams" else "pending", created,
                     len(payload.encode()) + 4096 + (self.limits["batch_bytes"] if b["channel"] == "teams" else 0), cycle),
                )
        return needed, 0

    def _result(self, outcome, admitted=0, missed=0, committed=False):
        return {"outcome": outcome, "admitted_receipts": admitted, "missed_receipts": missed,
                "ledger_committed": committed, "accounting_complete": self._control["accounting_complete"]}

    def record_domain(self, observation, authority, bindings):
        with self._lock:
            if not authority.get("valid"):
                return self._result("stale")
            if len(bindings) > 2 or not all(valid_binding(b) for b in bindings):
                self.enter_gap("delivery_storage", {})
                return self._result("gap")
            if self._db is not None and not self._unresolved and not self._closed:
                try:
                    existing = self._one("SELECT operation FROM cursor WHERE target=?", (observation["target"],))
                    if existing and existing[0] == observation["source_operation_id"]:
                        return self._result("consumed", committed=True)
                except sqlite3.Error:
                    pass
            # A definitely readable suppression state permits exact lower-bound
            # losses even when BEGIN IMMEDIATE cannot obtain its writer lock.
            known = self._known_additions(observation)
            losses = {c: known * sum(b["enabled"] and b["channel"] == c for b in bindings) for c in CHANNELS}
            if self._gap or not self._ready:
                self.enter_gap("delivery_storage", losses)
                return self._result("gap")
            def apply():
                row = self._one("SELECT * FROM cursor WHERE target=?", (observation["target"],))
                if row and row["operation"] == observation["source_operation_id"]:
                    return 0, 0
                if "expected_operation_id" in observation and (row["operation"] if row else None) != observation["expected_operation_id"]:
                    return "stale"
                ips = sorted(set(observation["managed_ips"]))
                before = (set(json.loads(row["ips"])) if row and row["tracked"] and
                          row["signature"] == observation["projection_signature"]
                          else set(observation.get("before_ips", [])))
                fits = self._put_cursor(observation["target"], ips, observation["projection_signature"],
                                        observation["source_operation_id"])
                if (row and not row["tracked"] or not row and self._control.get("untracked_targets")) and fits:
                    before = set(ips)  # recovery enrolls current data, never a backlog
                entries = [[ip, observation["label"], observation["source_type"]] for ip in sorted(set(ips) - before)]
                self._execute("DELETE FROM recent WHERE expires<=?", (observation["observed_at"],))
                eligible = []
                for entry in entries:
                    key = encode([observation["target"], observation["projection_signature"], entry[0], "Added"])
                    if self._one("SELECT 1 FROM recent WHERE key=?", (key,)) or self._one(
                            "SELECT 1 FROM grace WHERE ip=?", (entry[0],)):
                        continue
                    eligible.append(entry)
                recent_n, recent_bytes = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM recent")
                needed_bytes = sum(size([observation["target"], observation["projection_signature"], e[0], "Added"]) for e in eligible)
                recent_full = recent_n + len(eligible) > self.limits["recent_items"] or recent_bytes + needed_bytes > self.limits["recent_bytes"]
                if self._rebaseline or not fits:
                    missed = len(eligible) * sum(b["enabled"] for b in bindings)
                    self._record_loss("recovery_gap" if self._rebaseline else "tracking_overflow",
                        {c: len(eligible) * sum(b["enabled"] and b["channel"] == c for b in bindings) for c in CHANNELS})
                    admitted = 0
                else:
                    admitted, missed = self._admit(eligible, bindings, observation["source_operation_id"],
                        "Added", observation["observed_at"], recent_full, observation["cycle_id"])
                # Suppression consumes known lost transitions too, but does not ACK.
                for entry in eligible:
                    key = encode([observation["target"], observation["projection_signature"], entry[0], "Added"])
                    n, used = self._one("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM recent")
                    if n < self.limits["recent_items"] and used + len(key.encode()) <= self.limits["recent_bytes"]:
                        self._execute("INSERT OR REPLACE INTO recent VALUES(?,?,?)",
                                      (key, observation["observed_at"] + 60, len(key.encode())))
                return admitted, missed
            ok, result, uncertain = self._transaction(observation["source_operation_id"], apply)
            if not ok:
                if uncertain and self._unresolved is not None:
                    self._unresolved["losses"] = losses
                self.enter_gap("delivery_storage", {} if uncertain else losses)
                return self._result("gap")
            if result == "stale":
                return self._result("stale")
            admitted, missed = result
            if admitted:
                # Optional chunk sealing is a separate transaction: a renderer
                # fault cannot roll back previously admitted observations.
                self._transaction(uuid.uuid4().hex, lambda: self._seal(observation["cycle_id"], partial=False))
            return self._result("missed" if missed else ("admitted" if admitted else "consumed"),
                                admitted, missed, True)

    def _seal(self, cycle, *, partial=True):
        count = 0
        while True:
            first = self._one("SELECT * FROM receipt WHERE state='unsealed' AND (? IS NULL OR cycle=?) ORDER BY id LIMIT 1", (cycle, cycle))
            if first is None:
                return count
            cur = self._db.execute("SELECT * FROM receipt WHERE state='unsealed' AND cycle=? AND action=? AND binding=? "
                                   "ORDER BY id LIMIT ?", (first["cycle"], first["action"], first["binding"], self.limits["batch_items"]))
            try:
                page = cur.fetchmany(self.limits["batch_items"])
            finally:
                cur.close()
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

    def seal_cycle(self, cycle_id):
        with self._lock:
            ok, result, _ = self._transaction(uuid.uuid4().hex, lambda: self._seal(cycle_id))
            if not ok:
                # A seal fault does not invalidate source cursors or prevent
                # subsequent observation/admission. Unsealed rows retain bytes.
                self._health = {**self._health, "status": "degraded", "last_error": "delivery_storage", "counts_stale": True}
            return {"ledger_committed": ok, "sealed_batches": result if ok else 0}

    def _recover_claims(self):
        last = 0
        while True:
            cur = self._db.execute("SELECT * FROM receipt WHERE state='in_flight' AND id>? "
                                   "AND (batch_id IS NULL OR id=batch_id) ORDER BY id LIMIT 256", (last,))
            try:
                page = cur.fetchmany(256)
            finally:
                cur.close()
            if not page:
                break
            last = page[-1]["id"]
            for row in page:
                if row["attempt"] >= 8:
                    self._terminal(row, "failed", "attempts_exhausted", self._clock())
                else:
                    # The reserved mutation may already have reached MISP.
                    # Recover by authoritative read, atomically with the retry
                    # state/token fence; attempts and call reservations survive.
                    self._execute("UPDATE receipt SET state='retry_wait',token=NULL,resume=0,"
                                  "progress=CASE WHEN channel='misp' THEN '{}' ELSE progress END,"
                                  "due=? WHERE id=? OR batch_id=?",
                                  (self._clock() + 30 * 2 ** max(0, row["attempt"] - 1), row["id"], row["id"]))

    def _terminal(self, row, state, reason, now):
        count = self._one("SELECT COUNT(*) FROM receipt WHERE id=? OR batch_id=?", (row["id"], row["id"]))[0]
        self._increment("acked_total" if state == "acked" else "failed_total", count)
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
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self._claims_halted = True
                self.enter_gap("delivery_storage", {})
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
                if state == "acked":
                    self._terminal(row, "acked", None, now)
                elif state == "failed" or (state == "retry" and row["attempt"] >= 8):
                    self._terminal(row, "failed", "attempts_exhausted" if state == "retry" else reason, now)
                else:
                    progress = encode(provider_result["progress"])
                    if len(progress.encode()) > 2048:
                        self._terminal(row, "failed", "invalid_payload", now)
                        return {"applied": True}
                    retry_after = provider_result.get("retry_after") or 0
                    delay = max(30 * 2 ** max(0, row["attempt"] - 1), min(3600, max(30, retry_after)))
                    next_state = {"continue": "pending", "retry": "retry_wait", "blocked": "blocked_config"}[state]
                    self._execute("UPDATE receipt SET state=?,token=NULL,progress=?,resume=?,due=?,error=?,"
                                  "provider_calls=provider_calls-?,block_revision=? WHERE (id=? OR batch_id=?) AND token=? AND state='in_flight'",
                                  (next_state, progress, int(state == "continue"), now + delay if state == "retry" else 0,
                                   reason, int(provider_result["provider_calls"] == 0), row["claim_revision"],
                                   row["id"], row["id"], claim["attempt_token"]))
                return {"applied": True, "observation_hook": hook}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self._claims_halted = True
                self.enter_gap("delivery_storage", {})
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

    def _put_cursor(self, target, ips, signature, operation):
        row = self._one("SELECT * FROM cursor WHERE target=?", (target,))
        n, members, used = self._one("SELECT COUNT(*),COALESCE(SUM(members),0),COALESCE(SUM(bytes),0) FROM cursor")
        data = encode(ips)
        byte_count = len(data.encode()) + len(target.encode()) + len(signature.encode())
        fits = (len(ips) <= self.limits["target_ips"] and
                members - (row["members"] if row else 0) + len(ips) <= self.limits["cursor_members"] and
                used - (row["bytes"] if row else 0) + byte_count <= self.limits["cursor_bytes"] and
                (row is not None or n < self.limits["cursor_targets"]))
        if not fits:
            self._control["tracking_complete"] = False
            self._control["accounting_complete"] = False
            self._increment("tracking_overflow", 1)
            data, byte_count = "[]", len(target.encode()) + len(signature.encode()) + 2
        if (row or n < self.limits["cursor_targets"]) and used - (row["bytes"] if row else 0) + byte_count <= self.limits["cursor_bytes"]:
            self._execute("INSERT OR REPLACE INTO cursor VALUES(?,?,?,?,?,?,?,?)", (
                target, row["incarnation"] if row else uuid.uuid4().hex, signature,
                data, operation, int(fits), len(ips) if fits else 0, byte_count,
            ))
        else:
            # No unbounded side map for targets that cannot be represented.
            self._control["untracked_targets"] = True
        return fits

    def _rebase(self, projection):
        self._execute("DELETE FROM cursor")
        for target, value in projection.items():
            self._put_cursor(target, sorted(set(value["ips"])), value["signature"], uuid.uuid4().hex)

    def recover_gap(self, authority, current_projection, full_result, loss_checkpoint=None):
        with self._lock:
            if not authority.get("valid"):
                return {"ready": False, "source_valid": False}
            if self._db is None and not self._closed:
                try:
                    self._open()
                except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, ImportError):
                    self._release()
                    self.enter_gap("delivery_storage", {})
                    return {"ready": False, "source_valid": True}
            if self._ready and not self._gap and not self._rebaseline and not self._unresolved and not any(self._volatile.values()):
                return {"ready": True, "source_valid": True}
            if self._unresolved is not None:
                try:
                    saved = self._read_control()
                except (sqlite3.Error, OSError, ValueError, TypeError):
                    return {"ready": False, "source_valid": True}
                if saved.get("last_transaction") != self._unresolved["operation"]:
                    for c in CHANNELS:
                        self._volatile[c] = min(MAX_COUNTER, self._volatile[c] + self._unresolved["losses"].get(c, 0))
                self._control = saved
                self._unresolved = None
            totals = {c: self._checkpoint[c] + self._volatile[c] for c in CHANNELS}
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
                self._control["accounting_complete"] = False
                self._control["clean"] = False
                self._control["enrolled"] = True
                self._control["revision"] = authority["revision"]
                self._control["signature"] = authority["signature"]
                return {"ready": True, "source_valid": True}
            ok, result, _ = self._transaction(uuid.uuid4().hex, apply)
            if not ok:
                self.enter_gap("delivery_storage", {})
                return {"ready": False, "source_valid": True}
            self._checkpoint = totals
            self._volatile = {c: 0 for c in CHANNELS}
            self._gap = False
            self._rebaseline = False
            self._claims_halted = False
            self._ready = True
            self._safe_refresh()
            self._health = {**self._health, "missed_unpersisted": 0,
                            "last_error": ("delivery_storage" if not self._health["storage_ok"] else
                                           "history_persistence" if self._history_failed else None)}
            return result

    def enter_gap(self, reason, known_loss_counts):
        with self._lock:
            self._gap = True
            self._control["accounting_complete"] = False
            for channel in CHANNELS:
                self._volatile[channel] = min(MAX_COUNTER, self._volatile[channel] +
                                              max(0, int(known_loss_counts.get(channel, 0))))
            health = copy.deepcopy(self._health)
            health.update(status="degraded", coverage="gap", storage_ok=False, counts_stale=True,
                          accounting_complete=False, last_error="delivery_storage",
                          missed_unpersisted=min(MAX_COUNTER, sum(self._volatile.values())))
            self._health = health

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

    def health_snapshot(self):
        # Copy-on-publish: no connection or store lock on the HTTP read path.
        return copy.deepcopy(self._health)

    def close(self, *, clean):
        with self._lock:
            if self._closed:
                return True
            if self._worker_active:
                return False
            self._stopping = True
            if self._db is not None:
                def apply():
                    self._control["clean"] = bool(clean and not self._gap and not self._rebaseline and not self._one(
                        "SELECT 1 FROM receipt WHERE state='in_flight' LIMIT 1"))
                self._transaction(uuid.uuid4().hex, apply)
            self._closed = True
            self._release()
            return True
