from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ConfigSnapshot:
    domains: List[Any]
    servers: List[str]
    interval: int
    max_workers: int
    force_req: Optional[Dict[str, Any]]


class ConfigStore:
    """Thread-safe wrapper around the shared_config dict.

    This is an incremental refactor: the HTTP layer still receives the raw
    dict+lock, but the monitor loop should use this store to avoid ad-hoc
    locking and key drift.
    """

    def __init__(self, shared_config: Dict[str, Any], lock: threading.Lock):
        self._cfg = shared_config
        self._lock = lock

    @property
    def lock(self) -> threading.Lock:
        return self._lock

    @property
    def raw(self) -> Dict[str, Any]:
        return self._cfg

    def snapshot(self) -> ConfigSnapshot:
        with self._lock:
            domains = list(self._cfg.get('domains', []) or [])
            servers = list(self._cfg.get('servers', []) or [])
            interval = int(self._cfg.get('interval') or 60)
            max_workers = int(self._cfg.get('max_workers') or 8)
            force_req = self._cfg.pop('_force_resolve', None)
        return ConfigSnapshot(
            domains=domains,
            servers=servers,
            interval=max(1, interval),
            max_workers=max(1, max_workers),
            force_req=force_req,
        )
