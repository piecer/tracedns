from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict

from http_api.request_limits import DEFAULT_MAX_BODY_BYTES


@dataclass
class HttpContext:
    frontend_html: str
    shared_config: Dict[str, Any]
    config_lock: Any
    config_path: str
    history_dir: str
    current_results: Dict[str, Any]
    history: Dict[str, Any]
    purge_removed_domains_state: Callable[..., Any]
    cache_lock: Any = None
    results_cache: Dict[str, Any] = field(default_factory=dict)
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
