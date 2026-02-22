from __future__ import annotations

import json
from typing import Any, Dict


def send_json(handler, obj: Any, code: int = 200) -> None:
    """Send a JSON response with proper UTF-8 headers."""
    b = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    handler.send_response(code)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(b)))
    handler.end_headers()
    handler.wfile.write(b)


def qs_bool(qs: Dict[str, Any], name: str, default: bool = False) -> bool:
    vals = qs.get(name)
    if not vals:
        return bool(default)
    raw = str(vals[0]).strip().lower()
    if raw in ('1', 'true', 'yes', 'on', 'y'):
        return True
    if raw in ('0', 'false', 'no', 'off', 'n'):
        return False
    return bool(default)
