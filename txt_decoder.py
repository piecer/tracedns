#!/usr/bin/env python3
"""
TXT 레코드 디코딩 기능 모듈
"""
import base64
import struct
import re


# TXT 디코딩 방식 레지스트리
TXT_DECODE_METHODS = {}


def txt_decode_register(name):
    """
    TXT 디코딩 방식을 등록하는 데코레이터입니다.

    Args:
        name (str): 디코딩 방식의 이름
    """
    def deco(fn):
        TXT_DECODE_METHODS[name] = fn
        return fn
    return deco


@txt_decode_register('cafebabe_xor_base64')
def decode_txt_cafebabe_xor_base64(txt_values):
    """
    기존 방식: base64 decode 후 0xcafebabe xor → 4byte ip
    """
    out = []
    seen = set()
    for v in txt_values or []:
        if not v:
            continue
        parts = [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]
        for part in parts:
            try:
                raw = base64.b64decode(part, validate=True)
                if len(raw) < 4:
                    continue
                val = int.from_bytes(raw[0:4], byteorder='big', signed=False)
                x = val ^ 0xcafebabe
                ip_bytes = x.to_bytes(4, byteorder='big')
                ip_str = '.'.join(str(b) for b in ip_bytes)
                if ip_str not in seen:
                    seen.add(ip_str)
                    out.append(ip_str)
            except Exception:
                continue
    return sorted(out)


@txt_decode_register('plain_base64')
def decode_txt_plain_base64(txt_values):
    """
    각 토큰을 base64 decode하여 4바이트를 바로 IP로 해석
    """
    out = []
    seen = set()
    for v in txt_values or []:
        if not v:
            continue
        parts = [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]
        for part in parts:
            try:
                raw = base64.b64decode(part, validate=True)
                if len(raw) < 4:
                    continue
                ip_bytes = raw[0:4]
                ip_str = '.'.join(str(b) for b in ip_bytes)
                if ip_str not in seen:
                    seen.add(ip_str)
                    out.append(ip_str)
            except Exception:
                continue
    return sorted(out)


def _u32(x: int) -> int:
    """32비트 정수로 마스킹"""
    return x & 0xFFFFFFFF


def _key_u32_le(key: bytes):
    """키를 리틀엔디안 32비트 정수 배열로 변환"""
    k = key[:16].ljust(16, b"\x00")
    return list(struct.unpack("<4I", k))


def _btea_decrypt_variant(buf: bytearray, k32):
    """
    변형 XXTEA 복호화 (스크립트 로직 반영)

    Args:
        buf (bytearray): 복호화할 데이터 (in-place)
        k32 (list): 4개의 32비트 정수 키
    """
    DELTA = 0x61C88647
    n = len(buf) // 4
    if n <= 1:
        return
    v = list(struct.unpack("<%dI" % n, buf))
    rounds = (0x34 // n) + 6
    s = _u32(-DELTA * rounds)
    y = v[0]
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 2, -1, -1):
            z = v[p]
            y_old = v[p+1]
            idx = ((p + 1) & 3) ^ e
            mx = (_u32((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) +
                  _u32((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ _u32((y ^ s) + (z ^ k32[idx]))
            v[p+1] = y = _u32(y_old - mx)
        z = v[n - 1]
        y0 = v[0]
        mx0 = (_u32((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) +
               _u32((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ _u32((y ^ s) + (z ^ k32[e]))
        v[0] = y = _u32(y0 - mx0)
        s = _u32(s + DELTA)
    buf[:] = struct.pack("<%dI" % n, *v)


def _b64decode_pad(s: str) -> bytes:
    """패딩을 자동 추가하여 base64 디코딩"""
    s = s.strip()
    if len(s) % 4:
        s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s, validate=False)


def decode_txt_token(token: str, key: str = "bL8U5QfWAbQN6mPX") -> bytes:
    """
    토큰을 복호화합니다.

    Args:
        token (str): base64 인코딩된 토큰
        key (str): 복호화 키 (기본값: "bL8U5QfWAbQN6mPX")

    Returns:
        bytes: 복호화된 데이터
    """
    raw = bytearray(_b64decode_pad(token))
    # C 코드처럼 4바이트 단위 데이터만 TEA 적용
    if len(raw) >= 8 and (len(raw) % 4) == 0:
        try:
            k32 = _key_u32_le(key.encode("ascii"))
            _btea_decrypt_variant(raw, k32)
        except Exception:
            pass
    # trailing NUL 제거
    while raw and raw[-1] == 0:
        raw.pop()
    return bytes(raw)


def try_parse_ipv4_ascii(b: bytes) -> str:
    """
    바이트를 ASCII IPv4 주소로 파싱합니다.
    """
    try:
        s = b.decode("ascii")
    except Exception:
        return ""
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return s
    return ""


@txt_decode_register('btea_variant')
def decode_txt_btea_variant(txt_values, key='bL8U5QfWAbQN6mPX'):
    """
    제공하신 스크립트 로직을 반영한 디코더.
    - 각 토큰을 base64->(조건부)변형-XXTEA 복호화->NUL 제거
    - plaintext가 ascii IPv4면 그대로 추가
    """
    out = []
    seen = set()
    for v in txt_values or []:
        if not v:
            continue
        parts = [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]
        for part in parts:
            s = part.strip()
            if not s:
                continue
            try:
                decoded = decode_txt_token(s, key=key)
            except Exception:
                continue

            ip = try_parse_ipv4_ascii(decoded)
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)
                continue

            try:
                txt = decoded.decode('ascii', errors='ignore')
                parts_ip = txt.split('.')
                if len(parts_ip) == 4 and all(p.isdigit() for p in parts_ip):
                    if txt not in seen:
                        seen.add(txt)
                        out.append(txt)
            except Exception:
                pass
    return sorted(out)


# ---------------------------
# NEW: fixed XOR key + Base64 + IP-string decoder
# ---------------------------

# 고정 XOR 키 (사용자 제공)
_FIXED_XOR_KEY_HEX_DEFAULT = "aeafb3dffea956373beb72638c51cc"
_IP_PREFIX_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})")

def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    return True

def _extract_ip_prefix(bs: bytes) -> str:
    """
    복호 바이트에서 '앞부분'의 IPv4 prefix만 추출
    (뒤에 부가 바이트가 붙는 케이스 대응)
    """
    s = bs.decode("ascii", errors="ignore")
    m = _IP_PREFIX_RE.match(s)
    if not m:
        return ""
    ip = m.group(1)
    return ip if _is_valid_ip(ip) else ""

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return b""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def _split_txt_tokens(v: str):
    """
    입력 TXT 한 줄에서 토큰들을 분리.
    - ';' 기반 세그먼트 우선 지원 (질문 케이스)
    - 기존 '|' / ',' 구분도 호환
    - 따옴표(") 제거
    """
    if not v:
        return []
    v = v.strip().strip('"')

    # 우선 ; 로 최대한 분리
    if ';' in v:
        toks = [t.strip() for t in v.split(';') if t.strip()]
        if toks:
            return toks

    # fallback: 기존 로직
    return [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]

@txt_decode_register('xor_ipstring_base64_fixedkey')
def decode_txt_xor_ipstring_base64_fixedkey(txt_values, key_hex=_FIXED_XOR_KEY_HEX_DEFAULT):
    """
    base64 decode된 바이너리에 대해 고정 XOR 키(key_hex)를 적용하여
    ASCII IPv4 문자열(prefix)을 추출합니다.

    Args:
        txt_values (list): TXT 레코드 값 리스트
        key_hex (str): XOR 키(hex 문자열). 기본값은 사용자 제공 키.

    Returns:
        list: 디코딩된 IP 주소 리스트
    """
    try:
        key = bytes.fromhex(key_hex)
    except Exception:
        return []

    out = []
    seen = set()

    for v in txt_values or []:
        for tok in _split_txt_tokens(v):
            try:
                cipher = _b64decode_pad(tok)
            except Exception:
                continue

            dec = _xor_bytes(cipher, key)
            ip = _extract_ip_prefix(dec)
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)

    return sorted(out)


def decode_txt_hidden_ips(txt_values, method='cafebabe_xor_base64', **kwargs):
    """
    지정된 방식으로 TXT 레코드를 디코딩하여 IP 주소를 추출합니다.

    Args:
        txt_values (list): TXT 레코드 값 리스트
        method (str): 디코딩 방식 이름
        **kwargs: 디코더별 추가 인자

    Returns:
        list: 디코딩된 IP 주소 리스트
    """
    fn = TXT_DECODE_METHODS.get(method)
    if not fn:
        return []
    return fn(txt_values, **kwargs)

