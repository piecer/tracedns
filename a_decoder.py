#!/usr/bin/env python3
"""
A record post-processing decoders.

This module provides optional transformations for DNS A record values.
Example use-case: malware resolves an A record, then XORs the resolved
IPv4 with a fixed 32-bit key to derive the actual C2 destination.
"""
import ipaddress
import re
import base64


A_DECODE_METHODS = {}


def a_decode_register(name):
    """Decorator to register an A-record decode/post-process method."""
    def deco(fn):
        A_DECODE_METHODS[name] = fn
        return fn
    return deco


def _parse_xor32_key(key_value, default="E7708E59"):
    """
    Parse a 32-bit XOR key from:
    - hex string: "E7708E59", "0xE7708E59", "e7 70 8e 59"
    - dotted IPv4 bytes: "231.112.142.89"
    - integer string / int
    """
    kv = key_value if key_value not in (None, "") else default
    if kv in (None, ""):
        return None

    if isinstance(kv, int):
        return kv & 0xFFFFFFFF

    s = str(kv).strip()
    if not s:
        return None

    # Dotted-byte format (also valid IPv4 literal parsing)
    try:
        return int(ipaddress.IPv4Address(s))
    except Exception:
        pass

    # Decimal integer
    if re.fullmatch(r"[0-9]+", s):
        try:
            return int(s) & 0xFFFFFFFF
        except Exception:
            return None

    # Hex format with optional 0x prefix and separators
    sl = s.lower()
    if sl.startswith("0x"):
        sl = sl[2:]
    sl = re.sub(r"[^0-9a-f]", "", sl)
    if len(sl) != 8:
        return None
    try:
        return int(sl, 16)
    except Exception:
        return None


@a_decode_register("none")
def decode_a_none(a_values, **kwargs):
    """No post-processing."""
    return []


@a_decode_register("xor32_ipv4")
def decode_a_xor32_ipv4(a_values, key_hex=None, **kwargs):
    """
    Transform each resolved IPv4 by XORing its u32 with a 32-bit key.

    Args:
        a_values (list[str]): resolved IPv4 list
        key_hex (str|int): XOR key
    """
    key = _parse_xor32_key(key_hex, default="E7708E59")
    if key is None:
        return []

    out = []
    seen = set()
    for ip in a_values or []:
        try:
            val = int(ipaddress.IPv4Address(str(ip).strip()))
        except Exception:
            continue
        dec = str(ipaddress.IPv4Address((val ^ key) & 0xFFFFFFFF))
        if dec not in seen:
            seen.add(dec)
            out.append(dec)
    return sorted(out)


# Convenience alias
A_DECODE_METHODS["xor_ipv4"] = decode_a_xor32_ipv4


def decode_a_hidden_ips(a_values, method="none", **kwargs):
    """
    Run selected A-record post-processing method.
    Returns decoded/derived IP list.
    """
    fn = A_DECODE_METHODS.get(method or "none")
    if not fn:
        return []
    try:
        return fn(a_values, **kwargs)
    except TypeError:
        try:
            return fn(a_values)
        except Exception:
            return []
    except Exception:
        return []


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(str(ip).strip())
        return True
    except Exception:
        return False


def _b64decode_pad(s: str) -> bytes:
    s = str(s or '').strip()
    if len(s) % 4:
        s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s, validate=False)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return b''
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def _extract_ip_prefix(bs: bytes) -> str:
    s = bs.decode("ascii", errors="ignore")
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", s)
    if not m:
        return ""
    ip = m.group(1)
    return ip if _is_valid_ip(ip) else ""


def register_custom_a_decoder(name: str, steps: list) -> bool:
    """Register a runtime A-record custom decoder using safe DSL steps."""
    if not isinstance(name, str) or not name.strip() or not re.match(r'^[A-Za-z0-9_\-]+$', name):
        return False
    if name in A_DECODE_METHODS:
        return False
    dec = create_custom_a_decoder(steps)
    if not dec:
        return False
    A_DECODE_METHODS[name] = dec
    return True


def create_custom_a_decoder(steps: list):
    """Create (but do not register) a custom A-record decoder from DSL steps."""
    if not isinstance(steps, list) or not steps:
        return None
    allowed_ops = {'regex', 'base64', 'urlsafe_b64', 'xor_hex', 'xor32_ipv4', 'extract_ip_prefix', 'ascii'}
    for s in steps:
        if not isinstance(s, dict) or 'op' not in s:
            return None
        if s['op'] not in allowed_ops:
            return None
        if s['op'] == 'regex' and 'pattern' not in s:
            return None
        if s['op'] == 'xor_hex' and 'key' not in s:
            return None

    def decoder(a_values, **kwargs):
        out = []
        seen = set()
        for tok in a_values or []:
            cur = str(tok or '').strip()
            if not cur:
                continue
            cur_bytes = None
            error = False
            for step in steps:
                op = step.get('op')
                try:
                    if op == 'regex':
                        pat = step.get('pattern')
                        src = cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore'))
                        m = re.search(pat, src)
                        if not m:
                            error = True
                            break
                        grp = step.get('group', 1)
                        cur = m.group(grp)
                        cur_bytes = None
                    elif op == 'base64':
                        s = cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore'))
                        cur_bytes = _b64decode_pad(s)
                        cur = None
                    elif op == 'urlsafe_b64':
                        s = cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore'))
                        cur_bytes = base64.urlsafe_b64decode(s + '=' * ((4 - len(s) % 4) % 4))
                        cur = None
                    elif op == 'xor_hex':
                        key_hex = step.get('key', '')
                        try:
                            key = bytes.fromhex(key_hex)
                        except Exception:
                            key = b''
                        source = cur_bytes if cur_bytes is not None else (cur.encode('ascii', errors='ignore') if isinstance(cur, str) else b'')
                        cur_bytes = _xor_bytes(source, key)
                        cur = None
                    elif op == 'xor32_ipv4':
                        # XOR a plain IPv4 (or 4 raw bytes) with a 32-bit key.
                        key_val = step.get('key', step.get('key_hex'))
                        key = _parse_xor32_key(key_val, default="E7708E59")
                        if key is None:
                            error = True
                            break
                        src_u32 = None
                        if isinstance(cur, str) and _is_valid_ip(cur):
                            src_u32 = int(ipaddress.IPv4Address(cur))
                        elif cur_bytes is not None and len(cur_bytes) == 4:
                            src_u32 = int.from_bytes(cur_bytes, byteorder='big', signed=False)
                        if src_u32 is None:
                            error = True
                            break
                        cur = str(ipaddress.IPv4Address((src_u32 ^ key) & 0xFFFFFFFF))
                        cur_bytes = None
                    elif op == 'extract_ip_prefix':
                        source = cur_bytes if cur_bytes is not None else (cur.encode('ascii', errors='ignore') if isinstance(cur, str) else b'')
                        ip = _extract_ip_prefix(source)
                        if not ip:
                            error = True
                            break
                        cur = ip
                        cur_bytes = None
                    elif op == 'ascii':
                        if cur_bytes is not None:
                            cur = cur_bytes.decode('ascii', errors='ignore')
                            cur_bytes = None
                        else:
                            cur = str(cur)
                    else:
                        error = True
                        break
                except Exception:
                    error = True
                    break
            if error:
                continue

            final_ip = None
            if cur_bytes is not None and len(cur_bytes) == 4:
                final_ip = '.'.join(str(b) for b in cur_bytes)
            elif isinstance(cur, str):
                cand = cur.strip().strip('"')
                if _is_valid_ip(cand):
                    final_ip = cand
            if final_ip and final_ip not in seen:
                seen.add(final_ip)
                out.append(final_ip)
        return sorted(out)

    return decoder


_BUILTIN_A_DECODE_METHODS = set(A_DECODE_METHODS.keys())


def unregister_custom_a_decoder(name: str) -> bool:
    """Unregister a custom A-record decoder. Builtins cannot be removed."""
    if not name or name in _BUILTIN_A_DECODE_METHODS:
        return False
    if name in A_DECODE_METHODS:
        try:
            del A_DECODE_METHODS[name]
            return True
        except Exception:
            return False
    return False
