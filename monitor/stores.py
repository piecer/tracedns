from __future__ import annotations

import threading
from dataclasses import dataclass
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple
from config_manager import normalize_domains
from monitor.projection_authority import advance_security_projection_locked


def bounded_int(value, default, minimum, maximum):
    """Coerce an integer setting and clamp it to a safe range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


@dataclass
class ConfigSnapshot:
    domains: List[Any]
    servers: List[str]
    interval: int
    max_workers: int
    force_req: Optional[Dict[str, Any]]
    ens_rpc_url: Optional[str] = None
    sns_proxy_hosts: Optional[List[str]] = None
    target_leases: Optional[Dict[str, Any]] = None
    generation: int = 0
    registry_view: Any = None


class ConfigStore:
    """Thread-safe wrapper around the shared_config dict.

    This is an incremental refactor: the HTTP layer still receives the raw
    dict+lock, but the monitor loop should use this store to avoid ad-hoc
    locking and key drift.
    """

    def __init__(self, shared_config: Dict[str, Any], lock, state_repository=None, *, registry_snapshot=None):
        self._cfg = shared_config
        self._lock = lock
        self.state_repository = state_repository
        with lock:
            if registry_snapshot is not None:
                shared_config['_decoder_registry_snapshot'] = registry_snapshot
            self.condition = shared_config.setdefault('_monitor_condition', threading.Condition(lock))
        if state_repository is not None:
            with lock:
                state_repository.configure(shared_config)

    @property
    def lock(self) -> threading.Lock:
        return self._lock

    @property
    def raw(self) -> Dict[str, Any]:
        return self._cfg

    def dequeue_force(self):
        """Only the serial runner consumes admitted FIFO work."""
        with self._lock:
            return self._dequeue_force_locked()

    def _dequeue_force_locked(self):
        queue = self._cfg.get('_force_resolve_queue')
        if isinstance(queue, list) and queue:
            advance_security_projection_locked(self._cfg)
            job = queue.pop(0)
            if not queue:
                self._cfg.pop('_force_resolve_queue', None)
            return job
        if '_force_resolve' in self._cfg:
            advance_security_projection_locked(self._cfg)
            return self._cfg.pop('_force_resolve')
        return None

    def snapshot(self) -> ConfigSnapshot:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> ConfigSnapshot:
        domains = normalize_domains(deepcopy(self._cfg.get('domains', []) or []))
        servers = list(self._cfg.get('servers', []) or [])
        interval = bounded_int(self._cfg.get('interval'), 60, 1, 86400)
        max_workers = bounded_int(self._cfg.get('max_workers'), 8, 1, 64)
        ens_rpc_url = str(self._cfg.get('ens_rpc_url') or '').strip() or None
        sns_proxy_hosts = deepcopy(self._cfg.get('DEFAULT_SNS_PROXY_HOSTS',
                                   self._cfg.get('DEFAULT_SOLAR_PROXY_HOSTS', [])) or [])
        target_leases = None
        if self.state_repository is not None:
            self.state_repository.retry_cleanup()
            target_leases = self.state_repository.capture()
        return ConfigSnapshot(
            domains=domains, servers=servers, interval=interval, max_workers=max_workers,
            force_req=None, ens_rpc_url=ens_rpc_url, sns_proxy_hosts=sns_proxy_hosts,
            target_leases=target_leases,
            generation=self.state_repository.generation if self.state_repository is not None else 0,
            registry_view=(self._cfg['_decoder_registry_snapshot']()
                           if '_decoder_registry_snapshot' in self._cfg else None),
        )
