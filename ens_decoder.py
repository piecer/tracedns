#!/usr/bin/env python3
"""ENS text-record decoders.

This module mirrors TXT/A decoder architecture with a small registry so
ENS decoding logic can be selected per-domain and extended over time.
"""

from __future__ import annotations

import json
import ipaddress
import re
from typing import Any, Callable, Dict, List


ENS_DECODE_METHODS: Dict[str, Callable[..., List[str]]] = {}


def ens_decode_register(name: str):
    """Decorator to register ENS decode methods."""
    def deco(fn):
        ENS_DECODE_METHODS[name] = fn
        return fn

    return deco


def parse_ens_options(value: Any, legacy_xor_byte: Any = None, strict: bool = False) -> Dict[str, Any]:
    """Parse ens_options from dict/JSON text and merge legacy XOR byte if present."""
    options: Dict[str, Any] = {}
    if isinstance(value, dict):
        options = dict(value)
    elif isinstance(value, str):
        raw = value.strip()
        if raw:
            try:
                parsed = json.loads(raw)
            except Exception as exc:
                if strict:
                    raise ValueError('ens_options must be a valid JSON object') from exc
                parsed = None
            if parsed is not None:
                if not isinstance(parsed, dict):
                    if strict:
                        raise ValueError('ens_options must be a JSON object')
                else:
                    options = dict(parsed)
    elif value not in (None, '') and strict:
        raise ValueError('ens_options must be a JSON object')

    if legacy_xor_byte is not None and str(legacy_xor_byte).strip() != '':
        options.setdefault('xor_byte', str(legacy_xor_byte).strip())
    return options


def ens_options_signature(value: Any, legacy_xor_byte: Any = None) -> str:
    """Stable text form for display/logging."""
    opts = parse_ens_options(value, legacy_xor_byte=legacy_xor_byte, strict=False)
    if not opts:
        return ''
    try:
        return json.dumps(opts, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    except Exception:
        return str(opts)


def _parse_xor_byte(value, default: int = 0xA5) -> int:
    """Parse a byte value from int/decimal/hex-like input."""
    if value in (None, ''):
        return int(default) & 0xFF
    if isinstance(value, int):
        return int(value) & 0xFF
    s = str(value).strip()
    if not s:
        return int(default) & 0xFF
    if re.fullmatch(r'[0-9]+', s):
        try:
            return int(s, 10) & 0xFF
        except Exception:
            return int(default) & 0xFF
    sl = s.lower()
    if sl.startswith('0x'):
        sl = sl[2:]
    sl = re.sub(r'[^0-9a-f]', '', sl)
    if not sl:
        return int(default) & 0xFF
    try:
        return int(sl, 16) & 0xFF
    except Exception:
        return int(default) & 0xFF


def _split_tokens(record: str) -> List[str]:
    s = str(record or '').strip()
    if not s:
        return []
    if '|' in s:
        return [x.strip() for x in s.split('|') if x and x.strip()]
    if ';' in s:
        return [x.strip() for x in s.split(';') if x and x.strip()]
    return [x.strip() for x in s.split(',') if x and x.strip()]


def _ipv6_packed(token: str) -> bytes:
    return ipaddress.IPv6Address(str(token).strip()).packed


@ens_decode_register('none')
def decode_ens_none(record: str, **kwargs) -> List[str]:
    return []


@ens_decode_register('ipv6_5to8_xor')
def decode_ens_ipv6_5to8_xor(record: str, xor_byte=None, **kwargs) -> List[str]:
    """Decode by taking IPv6 bytes 5~8 (1-indexed), XOR each byte, map to IPv4.

    Example:
      - input token: any IPv6 literal
      - source bytes: packed[4:8]
      - output bytes: source ^ xor_byte (default 0xA5)
    """
    xb = _parse_xor_byte(xor_byte, default=0xA5)
    out = []
    seen = set()
    for tok in _split_tokens(record):
        try:
            packed = _ipv6_packed(tok)
            src = packed[4:8]
            if len(src) != 4:
                continue
            dec = bytes([(b ^ xb) & 0xFF for b in src])
            ip = str(ipaddress.IPv4Address(dec))
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        except Exception:
            continue
    return sorted(out)


@ens_decode_register('legacy_doc_sample')
def decode_ens_legacy_doc_sample(record: str, **kwargs) -> List[str]:
    """Legacy parser kept for compatibility with older sample format.

    Expected token format:
      2001:db8:LLLL:RRRR::1
    Output:
      each byte of LLLLRRRR XOR 0xA5 -> IPv4 octets
    """
    out = []
    seen = set()
    prefix = '2001:db8:'
    suffix = '::1'
    for tok in _split_tokens(record):
        t = str(tok).strip().lower()
        if not t.startswith(prefix) or not t.endswith(suffix):
            continue
        body = t[len(prefix): -len(suffix)]
        parts = body.split(':')
        if len(parts) != 2:
            continue
        left, right = parts
        if len(left) != 4 or len(right) != 4:
            continue
        try:
            octets = [
                str(int(left[0:2], 16) ^ 0xA5),
                str(int(left[2:4], 16) ^ 0xA5),
                str(int(right[0:2], 16) ^ 0xA5),
                str(int(right[2:4], 16) ^ 0xA5),
            ]
            ip = '.'.join(octets)
            ipaddress.IPv4Address(ip)
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        except Exception:
            continue
    return sorted(out)


def decode_ens_hidden_ips(record: str, method: str = 'ipv6_5to8_xor', ens_options=None, **kwargs) -> List[str]:
    fn = ENS_DECODE_METHODS.get(str(method or '').strip() or 'ipv6_5to8_xor')
    if not fn:
        return []
    merged_kwargs: Dict[str, Any] = {}
    try:
        merged_kwargs.update(parse_ens_options(ens_options, strict=False))
    except Exception:
        pass
    # keep backward compatibility: explicit kwargs override options.
    for k, v in (kwargs or {}).items():
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        merged_kwargs[k] = v
    try:
        return fn(record, **merged_kwargs)
    except TypeError:
        try:
            return fn(record)
        except Exception:
            return []
    except Exception:
        return []
