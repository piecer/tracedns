from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple


logger = logging.getLogger(__name__)

DEFAULT_IP_REMOVAL_GRACE_SECONDS = 24 * 60 * 60
IP_REMOVAL_GRACE_STATE_FILENAME = "ip_removal_grace_state"


def _labels(value: Any) -> List[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (set, list, tuple)):
        values = value
    else:
        values = []
    return sorted({str(item).strip() for item in values if str(item or "").strip()})


def load_legacy_grace(history_dir):
    """One-time bounded read; malformed/oversize import is unknown, not empty."""
    path = os.path.join(history_dir, IP_REMOVAL_GRACE_STATE_FILENAME)
    try:
        with open(path, 'rb') as source:
            raw = source.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            return None
        value = json.loads(raw)
        pending = value.get('pending') if isinstance(value, dict) else None
        if not isinstance(pending, dict) or len(pending) > 8192:
            return None
        return pending
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError):
        return None


class IpRemovalGraceTracker:
    """Track IPs that disappeared until their removal grace period expires.

    The pending state is optionally persisted so a monitor restart does not
    reset the grace timer or turn a returning IP into a new-IP alert.
    """

    def __init__(
        self,
        *,
        grace_seconds: int = DEFAULT_IP_REMOVAL_GRACE_SECONDS,
        state_path: Optional[str] = None,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.grace_seconds = max(0, int(grace_seconds))
        self.state_path = str(state_path or "").strip() or None
        self._now_fn = now_fn
        self._pending: Dict[str, Dict[str, Any]] = {}
        if self.state_path:
            self._load()

    @classmethod
    def from_history_dir(
        cls,
        history_dir: str,
        *,
        grace_seconds: int = DEFAULT_IP_REMOVAL_GRACE_SECONDS,
        now_fn: Callable[[], float] = time.time,
    ) -> "IpRemovalGraceTracker":
        return cls(
            grace_seconds=grace_seconds,
            state_path=os.path.join(history_dir, IP_REMOVAL_GRACE_STATE_FILENAME),
            now_fn=now_fn,
        )

    def pending_ips(self) -> Set[str]:
        return set(self._pending)

    def pending_snapshot(self) -> Dict[str, Dict[str, Any]]:
        return {
            ip: {
                "missing_since": int(item.get("missing_since") or 0),
                "labels": list(item.get("labels") or []),
            }
            for ip, item in self._pending.items()
        }

    def cancel_present(self, active_ips: Iterable[str]) -> Set[str]:
        """Cancel pending removals for IPs that are observable again."""
        active = {str(ip).strip() for ip in (active_ips or []) if str(ip or "").strip()}
        restored = active.intersection(self._pending)
        if not restored:
            return set()
        for ip in restored:
            self._pending.pop(ip, None)
        self._persist()
        logger.info("Cancelled removal grace for %s reappeared IP(s)", len(restored))
        return restored

    def reconcile(
        self,
        previous: Mapping[str, Any],
        current: Mapping[str, Any],
    ) -> List[Tuple[str, str, str]]:
        """Update pending removals and return entries whose grace expired."""
        previous_map = previous if isinstance(previous, Mapping) else {}
        current_map = current if isinstance(current, Mapping) else {}
        now = int(self._now_fn())
        changed = False

        active_now = {str(ip).strip() for ip in current_map if str(ip or "").strip()}
        restored = active_now.intersection(self._pending)
        for ip in restored:
            self._pending.pop(ip, None)
            changed = True

        newly_missing = {
            str(ip).strip()
            for ip in (set(previous_map) - set(current_map))
            if str(ip or "").strip()
        }
        for ip in newly_missing:
            if ip in self._pending:
                continue
            self._pending[ip] = {
                "missing_since": now,
                "labels": _labels(previous_map.get(ip)),
            }
            changed = True
            logger.info(
                "Deferring removal alert for %s until grace period expires (%ss)",
                ip,
                self.grace_seconds,
            )

        expired: List[Tuple[str, str, str]] = []
        for ip, item in list(self._pending.items()):
            if ip in active_now:
                continue
            missing_since = int(item.get("missing_since") or now)
            if (now - missing_since) < self.grace_seconds:
                continue
            labels = _labels(item.get("labels"))
            expired.append((ip, ",".join(labels) if labels else "unknown", "A"))
            self._pending.pop(ip, None)
            changed = True

        if changed:
            self._persist()
        if restored:
            logger.info("Cancelled removal grace for %s reappeared IP(s)", len(restored))
        return sorted(expired)

    def _load(self) -> None:
        try:
            with open(self.state_path, "r", encoding="utf-8") as state_file:
                data = json.load(state_file)
        except FileNotFoundError:
            return
        except Exception as exc:
            logger.warning("Cannot load IP removal grace state %s: %s", self.state_path, exc)
            return

        raw_pending = data.get("pending", {}) if isinstance(data, dict) else {}
        if not isinstance(raw_pending, dict):
            return
        for raw_ip, raw_item in raw_pending.items():
            ip = str(raw_ip or "").strip()
            if not ip or not isinstance(raw_item, dict):
                continue
            try:
                missing_since = int(raw_item.get("missing_since") or 0)
            except (TypeError, ValueError):
                continue
            if missing_since <= 0:
                continue
            self._pending[ip] = {
                "missing_since": missing_since,
                "labels": _labels(raw_item.get("labels")),
            }

    def _persist(self) -> None:
        if not self.state_path:
            return
        tmp_path = self.state_path + ".tmp"
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
            payload = {"version": 1, "pending": self.pending_snapshot()}
            with open(tmp_path, "w", encoding="utf-8") as state_file:
                json.dump(payload, state_file, ensure_ascii=False, indent=2)
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(tmp_path, self.state_path)
        except Exception as exc:
            logger.warning("Cannot persist IP removal grace state %s: %s", self.state_path, exc)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
