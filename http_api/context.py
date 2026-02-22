from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict


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
