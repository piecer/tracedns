#!/usr/bin/env python3
"""
TXT record decoding utilities and decoder registry.
Provides several built-in TXT decoding methods and helpers
used by the DNS monitor and web UI.
"""
import base64
import struct
import re
import binascii
import ipaddress
from typing import Union


# TXT decode method registry
TXT_DECODE_METHODS = {}


def txt_decode_register(name):
    """
    Decorator to register a TXT decoding method.

    Args:
        name (str): name used to register the decoder
    """
    def deco(fn):
        TXT_DECODE_METHODS[name] = fn
        return fn
    return deco


@txt_decode_register('cafebabe_xor_base64')
def decode_txt_cafebabe_xor_base64(txt_values, domain=None, **kwargs):
    """
    Legacy format: base64 decode, XOR with 0xcafebabe, interpret first 4 bytes as IP
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
def decode_txt_plain_base64(txt_values, domain=None, **kwargs):
    """
    Each token is base64-decoded and its first 4 bytes are interpreted as an IPv4 address.
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


@txt_decode_register('plain_ip')
def decode_txt_plain_ip(txt_values, domain=None, **kwargs):
    """
    If TXT records contain plaintext IPv4 addresses, extract and return them.
    Token splitting accepts `;`, `|`, and `,` to handle various formats.
    """
    out = []
    seen = set()
    for v in txt_values or []:
        for tok in _split_txt_tokens(v):
            t = tok.strip().strip('"')
            if _is_valid_ip(t) and t not in seen:
                seen.add(t)
                out.append(t)
    return sorted(out)


def _u32(x: int) -> int:
    """Mask value to 32-bit unsigned integer."""
    return x & 0xFFFFFFFF


def _key_u32_le(key: bytes):
    """Convert key bytes to a list of four 32-bit little-endian integers."""
    k = key[:16].ljust(16, b"\x00")
    return list(struct.unpack("<4I", k))


def _btea_decrypt_variant(buf: bytearray, k32):
    """
    Variant of XXTEA-like decryption implemented in the original script.

    Args:
        buf (bytearray): data buffer to decrypt in-place
        k32 (list): list of four 32-bit integers as the key
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
    """Base64-decode a string after adding padding if necessary."""
    s = s.strip()
    if len(s) % 4:
        s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s, validate=False)


def decode_txt_token(token: str, key: str = "bL8U5QfWAbQN6mPX") -> bytes:
    """
    Decode a token: base64-decode and apply optional block decryption.

    Args:
        token (str): base64-encoded token
        key (str): decryption key (default provided)

    Returns:
        bytes: decoded bytes (trailing NULs removed)
    """
    raw = bytearray(_b64decode_pad(token))
    # Apply TEA only to 4-byte aligned data (like in the original C code)
    if len(raw) >= 8 and (len(raw) % 4) == 0:
        try:
            k32 = _key_u32_le(key.encode("ascii"))
            _btea_decrypt_variant(raw, k32)
        except Exception:
            pass
    # remove trailing NUL bytes
    while raw and raw[-1] == 0:
        raw.pop()
    return bytes(raw)


def try_parse_ipv4_ascii(b: bytes) -> str:
    """
    Try to parse bytes as an ASCII IPv4 address string. Returns empty string if not valid.
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
def decode_txt_btea_variant(txt_values, key='bL8U5QfWAbQN6mPX', domain=None, **kwargs):
    """
    Decoder implementing the provided script's logic:
    - base64 -> (conditional) variant-XXTEA decrypt -> strip trailing NULs
    - if plaintext is an ASCII IPv4, include it (and attempt BE/LE transform)
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
            if ip:
                # also include a BE/LE transformed variant
                parts = ip.split('.')
                if len(parts) == 4:
                    le_ip = f"{parts[2]}.{parts[3]}.{parts[0]}.{parts[1]}"
                    if le_ip not in seen:
                        seen.add(le_ip)
                        out.append(le_ip)
                        continue

    return sorted(out)


# ---------------------------
# NEW: fixed XOR key + Base64 + IP-string decoder
# ---------------------------

# Fixed XOR key (default)
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
    Extract an IPv4 prefix from decoded bytes. Handles cases where extra bytes follow the IP.
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
    Split a single TXT line into tokens.
    - Prefer ';' segments if present
    - Fall back to '|' or ',' separators
    - Strip surrounding quotes
    """
    if not v:
        return []
    v = v.strip().strip('"')

    # Prefer splitting on ';' first
    if ';' in v:
        toks = [t.strip() for t in v.split(';') if t.strip()]
        if toks:
            return toks

    # fallback: previous logic
    return [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]

@txt_decode_register('xor_ipstring_base64_fixedkey')
def decode_txt_xor_ipstring_base64_fixedkey(txt_values, key_hex=_FIXED_XOR_KEY_HEX_DEFAULT, domain=None, **kwargs):
    """
    Apply a fixed XOR key to base64-decoded bytes and extract an ASCII IPv4 prefix.

    Args:
        txt_values (list): list of TXT record strings
        key_hex (str): XOR key as a hex string (defaults provided)

    Returns:
        list: decoded IPv4 address strings
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


# ---------------------------
# Additional C2-oriented decoders (from provided script)
# ---------------------------

BASE56_ALPHABET = "ipWPeY43MhfFBt8ZCSN2KTdD6nEkmGjwx7vJR5rogzbcqHsXUQuyVA9L"
MOD_MASK = 0xFFFFFFFF
MULTIPLIER = 0x41C64E6D

def custom_base56_decode(input_str: str) -> Union[bytes, None]:
    if not isinstance(input_str, str) or len(input_str) < 2:
        return None
    try:
        first_idx = BASE56_ALPHABET.index(input_str[0])
        second_idx = BASE56_ALPHABET.index(input_str[1])
    except ValueError:
        return None
    body = input_str[2:]
    uVar2 = len(body)
    if uVar2 > 0x163:
        return None
    sbox = list(range(0x38))
    seed = first_idx * 0x38 + second_idx
    for i in range(0x37, -1, -1):
        seed = (seed * MULTIPLIER + 0x3039) & MOD_MASK
        j = seed % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inverse_sbox = [0] * 0x38
    for i, val in enumerate(sbox):
        inverse_sbox[val] = i
    if uVar2 > 0:
        decoded_body = []
        for i, ch in enumerate(body):
            try:
                idx = BASE56_ALPHABET.index(ch)
            except ValueError:
                return None
            shifted_idx = inverse_sbox[idx] - (uVar2 % 0x38)
            if shifted_idx < 0:
                shifted_idx += 0x38
            decoded_body.append(BASE56_ALPHABET[shifted_idx])
        body = ''.join(decoded_body)
    full_str = input_str[:2] + body
    if uVar2 > 0:
        new_body = []
        for ch in full_str[2:]:
            try:
                idx = BASE56_ALPHABET.index(ch)
            except ValueError:
                return None
            new_idx = (idx + ((first_idx * 0x38 + second_idx) // 0x38 * 0x38 - (first_idx * 0x38 + second_idx)) + 0x38) % 0x38
            new_body.append(BASE56_ALPHABET[new_idx])
        full_str = full_str[:2] + ''.join(new_body)
    values = []
    for ch in full_str[2:]:
        try:
            values.append(BASE56_ALPHABET.index(ch))
        except ValueError:
            return None
    leading_zeros = 0
    while leading_zeros < len(values) and values[leading_zeros] == 0:
        leading_zeros += 1
    meaningful_len = ((len(values) - leading_zeros) * 0x2d5) // 1000 + 1
    if meaningful_len > 0x104:
        return None
    output = [0] * meaningful_len
    for val in values[leading_zeros:]:
        carry = val
        for i in reversed(range(meaningful_len)):
            total = output[i] * 0x38 + carry
            output[i] = total & 0xFF
            carry = total >> 8
    non_zero_index = 0
    while non_zero_index < meaningful_len and output[non_zero_index] == 0:
        non_zero_index += 1
    final_bytes = bytes([0] * leading_zeros + output[non_zero_index:])
    return final_bytes


def is_valid_base64url(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip()
    match = re.fullmatch(r'([A-Za-z0-9\-_]*)(={0,2})', s)
    if not match:
        return False
    main_part, pad_part = match.groups()
    if len(pad_part) > 2:
        return False
    if pad_part:
        if len(s) % 4 != 0:
            return False
    else:
        if len(main_part) % 4 == 1:
            return False
    return True


def extract_ip_safeb64(encoded_str: str) -> str:
    if not is_valid_base64url(encoded_str):
        return ""
    xor_key = b"xI7ht4Uyl9rFyk0GaTt8v2Fz7HrlZVA5"
    try:
        decoded = base64.urlsafe_b64decode(encoded_str)
    except (binascii.Error, ValueError):
        return ""
    # remove first 4 bytes header if present
    payload = decoded[4:]
    if len(payload) > len(xor_key):
        return ""
    result_bytes = bytes([payload[i] ^ xor_key[i] for i in range(len(payload))])
    try:
        return result_bytes.decode('ascii')
    except Exception:
        return ""


# ---------------------------
# XOR Key Extension Decoder
# ---------------------------

def _extend_xor_key(known_key: Union[bytes, list], enc_list: list, ip_list: list) -> bytes:
    """
    데이터셋을 이용하여 알려진 XOR 키를 확장합니다.
    
    Args:
        known_key (bytes or list): 알려진 키의 초기 부분 (예: 12바이트)
        enc_list (list): base64 인코딩된 데이터 리스트
        ip_list (list): 평문 IP 주소 리스트
    
    Returns:
        bytes: 확장된 전체 키
    """
    from collections import Counter
    
    # 키를 리스트로 변환
    if isinstance(known_key, bytes):
        known_key = list(known_key)
    else:
        known_key = list(known_key)
    
    # 확장 후보 저장소 (최대 64바이트까지 지원)
    extended_key_candidates = [Counter() for _ in range(64)]
    
    matched_count = 0
    
    for enc in enc_list:
        try:
            enc_bytes = base64.b64decode(enc)
            
            # 알려진 키로 접두사 디코딩
            decoded_prefix = []
            for i in range(min(len(enc_bytes), len(known_key))):
                decoded_prefix.append(chr(enc_bytes[i] ^ known_key[i]))
            
            prefix_str = "".join(decoded_prefix)
            
            # 이 접두사로 시작하는 IP 찾기
            matched_ip = None
            for ip in ip_list:
                if ip.startswith(prefix_str):
                    matched_ip = ip
                    break
            
            if matched_ip:
                matched_count += 1
                
                # 뒷부분 키 역산 (Key = Encrypted XOR Plain)
                start_idx = len(known_key)
                
                if len(enc_bytes) > start_idx and len(matched_ip) > start_idx:
                    for i in range(start_idx, min(len(enc_bytes), len(matched_ip), 64)):
                        new_key_byte = enc_bytes[i] ^ ord(matched_ip[i])
                        extended_key_candidates[i].update([new_key_byte])
        
        except Exception:
            pass
    
    # 최종 키 구성
    final_full_key = list(known_key)
    
    for i in range(len(known_key), 64):
        if extended_key_candidates[i]:
            best_key, count = extended_key_candidates[i].most_common(1)[0]
            final_full_key.append(best_key)
        else:
            break
    
    return bytes(final_full_key)


@txt_decode_register('xor_keyextend')
def decode_txt_xor_keyextend(txt_values, known_key=None, enc_dataset=None, ip_dataset=None, domain=None, **kwargs):
    """
    데이터셋을 이용하여 키를 확장하고 XOR 디코딩을 수행합니다.
    Multi-record 처리를 지원합니다 (세미콜론 분리 포함).
    
    Args:
        txt_values (list): TXT 레코드 값 리스트 (여러 개 가능)
        known_key (bytes or str): 알려진 키 (hex 문자열 또는 바이트). 기본값: 15바이트 키
        enc_dataset (list): 암호화된 텍스트 리스트 (키 확장용)
        ip_dataset (list): 평문 IP 주소 리스트 (키 확장용)
        domain (str): 도메인 (로깅용)
    
    Returns:
        list: 디코딩된 IP 주소 리스트 (중복 제거, 정렬됨)
    """
    # 기본 알려진 키 설정 (15바이트 = 30hex chars)
    if known_key is None:
        known_key = bytes.fromhex("2ad28f0c67f549252d1ec04ccc0fcc")
    elif isinstance(known_key, str):
        try:
            # hex 문자열을 바이트로 변환
            known_key = bytes.fromhex(known_key)
        except Exception:
            # hex 변환 실패시 기본값 사용
            known_key = bytes.fromhex("2ad28f0c67f549252d1ec04ccc0fcc")
    elif isinstance(known_key, list):
        known_key = bytes(known_key)
    
    # 데이터셋이 제공된 경우 키 확장
    full_key = known_key
    if enc_dataset and ip_dataset:
        try:
            full_key = _extend_xor_key(known_key, enc_dataset, ip_dataset)
        except Exception:
            full_key = known_key
    
    out = []
    seen = set()
    
    for v in txt_values or []:
        if not v:
            continue
        
        # Multi-record 처리: 세미콜론(;)으로 분리된 세그먼트 지원
        # 세미콜론이 있으면 우선 처리, 없으면 기존 방식 사용
        if ';' in str(v):
            # 세미콜론 기준 분리 (사용자 스크립트와 동일)
            segments = str(v).split(';')
            parts = [p.strip() for segment in segments for p in segment.replace(',', '|').split('|') if p.strip()]
        else:
            # 기존 방식: 쉼표와 파이프로 분리
            parts = [p.strip() for p in str(v).replace(',', '|').split('|') if p.strip()]
        
        for part in parts:
            try:
                # 공백 제거 및 따옴표 제거
                clean_part = part.strip().replace('"', '')
                if not clean_part:
                    continue
                
                # Base64 Padding 보정 (사용자 스크립트와 동일한 방식)
                missing_padding = len(clean_part) % 4
                if missing_padding:
                    padded_part = clean_part + ('=' * (4 - missing_padding))
                else:
                    padded_part = clean_part
                
                # Base64 디코딩
                try:
                    cipher = base64.b64decode(padded_part, validate=False)
                except Exception:
                    continue
                
                # XOR 복호화 (반복 XOR 지원)
                dec = _xor_bytes(cipher, full_key)
                
                # ASCII 디코딩 (null terminator 제거)
                plaintext = dec.decode('ascii', errors='ignore').rstrip('\x00')
                
                # IP 주소 추출 방식 1: 정규식 (IPv4 패턴)
                ip = _extract_ip_prefix(plaintext.encode('ascii'))
                if ip and ip not in seen:
                    seen.add(ip)
                    out.append(ip)
                else:
                    # IP 주소 추출 방식 2: 숫자와 점만 추출 (사용자 스크립트 방식)
                    ip_fallback = ""
                    for char in plaintext:
                        if char in "0123456789.":
                            ip_fallback += char
                        else:
                            break
                    
                    # 유효한 IPv4 형식 확인
                    if ip_fallback and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_fallback) and ip_fallback not in seen:
                        seen.add(ip_fallback)
                        out.append(ip_fallback)
                
            except Exception:
                continue
    
    return sorted(out)


def is_base64(s: str):
    try:
        decoded = base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8').rstrip('\x00')
        return True, decoded
    except Exception:
        return False, s


def xor_decrypt(data: bytes, key: bytes):
    key_length = len(key)
    decrypted = bytes([data[i] ^ key[i % key_length] for i in range(len(data))])
    try:
        return decrypted.decode('utf-8', errors='ignore')
    except Exception:
        return ''


def decode_base64_to_ip(b64_str: str):
    XOR_KEY = 0xCAFEBABE
    try:
        raw = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4))
        if len(raw) != 4:
            return None
        num = int.from_bytes(raw, byteorder='big')
        xor_result = num ^ XOR_KEY
        return str(ipaddress.IPv4Address(xor_result))
    except Exception:
        return None


def base64decode_xor_febabe(label, answer_section):
    extracted_values = []
    # XOR key bytes from repeating 'febabe'
    xor_hex = "febabe" * 5
    try:
        XOR_KEY = bytes.fromhex(xor_hex)
    except Exception:
        XOR_KEY = None
    answer_section = answer_section.replace('"', '')
    parts = [p.strip() for p in answer_section.split(',') if p.strip()]
    for part in parts:
        try:
            c = base64.b64decode(part + '=' * (-len(part) % 4))
        except Exception:
            continue
        if XOR_KEY:
            try:
                decrypted_ip = bytes(ci ^ XOR_KEY[i] for i, ci in enumerate(c))
                extracted_ip = decrypted_ip.rstrip(b'\x00').decode('ascii')
                if _is_valid_ip(extracted_ip):
                    extracted_values.append(extracted_ip)
            except Exception:
                continue
    return extracted_values


def extract_ips(label, answer_section):
    # specific domain handling
    if label == "ilovementallyilltrannysandanorexicbrits.su":
        return base64decode_xor_febabe(label, answer_section)
    if label == "dvrxpert.tiananmensquare1989.su":
        answer_section = answer_section.replace('"', '')
        parts = [p.strip() for p in answer_section.split(',') if p.strip()]
        extracted_values = []
        for part in parts:
            dec_ip = decode_base64_to_ip(part)
            if dec_ip and _is_valid_ip(dec_ip):
                extracted_values.append(dec_ip)
        return extracted_values

    # unify list input
    if isinstance(answer_section, list) and len(answer_section) == 1 and isinstance(answer_section[0], str):
        answer_section = answer_section[0]
    answer_section = answer_section.replace('"', '')

    # try custom base56
    newstring = custom_base56_decode(answer_section)
    if newstring is not None:
        try:
            answer_section = newstring.decode('utf-8')
        except Exception:
            pass

    # try safe base64 xor extraction
    safeb64 = extract_ip_safeb64(answer_section)
    extracted_values = []
    if safeb64 and _is_valid_ip(safeb64):
        extracted_values.append(safeb64)

    if '|' in answer_section:
        parts = [p.strip() for p in answer_section.split('|') if p.strip()]
        for part in parts:
            dec = extract_ip_safeb64(part)
            if dec and _is_valid_ip(dec):
                extracted_values.append(dec)
                continue
            is_enc, decoded_value = is_base64(part)
            if not _is_valid_ip(decoded_value):
                best_xor_key = b'Zm6vnZ5U4mf8vAp'
                try:
                    decrypted_ip = xor_decrypt(decoded_value.encode('utf-8'), best_xor_key)
                except Exception:
                    decrypted_ip = ''
                if _is_valid_ip(decrypted_ip):
                    extracted_values.append(decrypted_ip)
                    continue
            if is_enc and _is_valid_ip(decoded_value):
                extracted_values.append(decoded_value)
    elif answer_section.startswith('<') and answer_section.endswith('>'):
        extracted_values.append(answer_section.strip('<>'))

    # final ipv4 filtering
    valid_ips = [ip.strip() for ip in extracted_values if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', ip.strip())]
    return valid_ips


@txt_decode_register('c2_multiplex')
def decode_txt_c2_multiplex(txt_values, domain=None):
    out = []
    seen = set()
    for v in txt_values or []:
        # v may be list or string
        if isinstance(v, list):
            joined = ','.join(v)
        else:
            joined = v
        ips = extract_ips(domain or '', joined)
        for ip in ips:
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)
    return sorted(out)


@txt_decode_register('base64_xor_febabe')
def decode_txt_base64_xor_febabe(txt_values, domain=None):
    """
    특정 도메인에서 쓰이는 base64 + repeating 'febabe' XOR 복호화 방식의 래퍼.
    내부의 `base64decode_xor_febabe` 헬퍼를 재사용합니다.
    """
    out = []
    seen = set()
    for v in txt_values or []:
        # normalize to string
        if isinstance(v, list):
            joined = ','.join(v)
        else:
            joined = v
        parts = [p.strip() for p in joined.replace('\"', '').split(',') if p.strip()]
        for p in parts:
            try:
                ips = base64decode_xor_febabe(domain or '', p)
            except Exception:
                ips = []
            for ip in ips:
                if ip and ip not in seen:
                    seen.add(ip)
                    out.append(ip)
    return sorted(out)


@txt_decode_register('base56')
def decode_txt_base56(txt_values, domain=None):
    """
    custom base56 디코딩을 시도하고, 결과에서 ASCII IP 문자열을 추출합니다.
    """
    out = []
    seen = set()
    for v in txt_values or []:
        toks = [t.strip() for t in (v if isinstance(v, list) else [v])]
        for t in toks:
            try:
                dec = custom_base56_decode(t)
            except Exception:
                dec = None
            if dec:
                # try ASCII IP prefix
                ip = _extract_ip_prefix(dec)
                if ip and ip not in seen:
                    seen.add(ip)
                    out.append(ip)
                else:
                    # if dec is 4 bytes, interpret as IPv4
                    if len(dec) == 4:
                        ip_str = '.'.join(str(b) for b in dec)
                        if ip_str not in seen:
                            seen.add(ip_str)
                            out.append(ip_str)
    return sorted(out)


@txt_decode_register('safeb64_xor')
def decode_txt_safeb64_xor(txt_values, domain=None):
    """
    safeb64 검사 후 고정 xor 키를 적용한 형태로 추출되는 ASCII IP를 찾습니다.
    내부의 `extract_ip_safeb64` 헬퍼를 사용합니다.
    """
    out = []
    seen = set()
    for v in txt_values or []:
        parts = [p.strip() for p in (v if isinstance(v, list) else [v])]
        for p in parts:
            try:
                ip = extract_ip_safeb64(p)
            except Exception:
                ip = ''
            if ip and _is_valid_ip(ip) and ip not in seen:
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
    # All decoders are expected to accept (txt_values, domain=None, **kwargs)
    try:
        return fn(txt_values, **kwargs)
    except TypeError:
        # fallback: call without kwargs
        try:
            return fn(txt_values)
        except Exception:
            return []
    except Exception:
        return []


def register_custom_decoder(name: str, steps: list) -> bool:
    """
    안전한 DSL 기반 커스텀 디코더를 런타임에 등록합니다.

    지원되는 steps 형식(리스트의 각 항목은 dict):
      - {'op': 'regex', 'pattern': '<pattern>', 'group': <int>} : 문자열에서 정규식 캡처 그룹 추출
      - {'op': 'base64'} : base64 디코딩 (패딩 자동)
      - {'op': 'urlsafe_b64'} : urlsafe base64 디코딩
      - {'op': 'xor_hex', 'key': '<hexstring>'} : 바이트에 대해 반복 XOR 적용
      - {'op': 'extract_ip_prefix'} : ASCII 바이트에서 IPv4 prefix 추출
      - {'op': 'ascii'} : bytes -> ASCII 문자열 디코딩 (errors='ignore')

    이 함수는 주어진 이름으로 디코더를 생성하여 `TXT_DECODE_METHODS`에 등록합니다.
    이름이 기존 디코더와 충돌하거나 steps가 잘못되면 False를 반환합니다.
    """
    # simple name validation
    if not isinstance(name, str) or not name.strip() or not re.match(r'^[A-Za-z0-9_\-]+$', name):
        return False
    if name in TXT_DECODE_METHODS:
        return False
    if not isinstance(steps, list) or not steps:
        return False

    # validate steps
    allowed_ops = {'regex', 'base64', 'urlsafe_b64', 'xor_hex', 'extract_ip_prefix', 'ascii'}
    for s in steps:
        if not isinstance(s, dict) or 'op' not in s:
            return False
        if s['op'] not in allowed_ops:
            return False
        if s['op'] == 'regex' and 'pattern' not in s:
            return False
        if s['op'] == 'xor_hex' and 'key' not in s:
            return False

    def make_decoder(steps_inner):
        def decoder(txt_values, domain=None, **kwargs):
            out = []
            seen = set()
            for v in txt_values or []:
                for tok in _split_txt_tokens(v):
                    cur = tok
                    cur_bytes = None
                    error = False
                    for step in steps_inner:
                        op = step.get('op')
                        try:
                            if op == 'regex':
                                pat = step.get('pattern')
                                m = re.search(pat, cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore')))
                                if not m:
                                    error = True
                                    break
                                grp = step.get('group', 1)
                                cur = m.group(grp)
                                cur_bytes = None
                            elif op == 'base64':
                                # ensure we operate on str
                                s = cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore'))
                                cur_bytes = _b64decode_pad(s)
                                cur = None
                            elif op == 'urlsafe_b64':
                                import base64 as _b64
                                s = cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore'))
                                try:
                                    cur_bytes = _b64.urlsafe_b64decode(s + '=' * ((4 - len(s) % 4) % 4))
                                except Exception:
                                    cur_bytes = b''
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

                    # final normalization: if bytes of length 4 => IPv4; if string matches IP pattern => accept
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

    TXT_DECODE_METHODS[name] = make_decoder(steps)
    return True


def create_custom_decoder(steps: list):
    """
    주어진 DSL `steps`로 디코더 함수를 생성하여 반환합니다. 등록하지는 않습니다.
    """
    if not isinstance(steps, list) or not steps:
        return None
    # reuse validation from register_custom_decoder
    allowed_ops = {'regex', 'base64', 'urlsafe_b64', 'xor_hex', 'extract_ip_prefix', 'ascii'}
    for s in steps:
        if not isinstance(s, dict) or 'op' not in s:
            return None
        if s['op'] not in allowed_ops:
            return None
        if s['op'] == 'regex' and 'pattern' not in s:
            return None
        if s['op'] == 'xor_hex' and 'key' not in s:
            return None

    def make_decoder(steps_inner):
        def decoder(txt_values, domain=None, **kwargs):
            out = []
            seen = set()
            for v in txt_values or []:
                for tok in _split_txt_tokens(v):
                    cur = tok
                    cur_bytes = None
                    error = False
                    for step in steps_inner:
                        op = step.get('op')
                        try:
                            if op == 'regex':
                                pat = step.get('pattern')
                                m = re.search(pat, cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore')))
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
                                import base64 as _b64
                                s = cur if isinstance(cur, str) else (cur.decode('ascii', errors='ignore'))
                                try:
                                    cur_bytes = _b64.urlsafe_b64decode(s + '=' * ((4 - len(s) % 4) % 4))
                                except Exception:
                                    cur_bytes = b''
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

    return make_decoder(steps)


# capture builtin decoder names at module load so we don't allow removing them
_BUILTIN_DECODE_METHODS = set(TXT_DECODE_METHODS.keys())


def is_builtin_decoder(name: str) -> bool:
    return name in _BUILTIN_DECODE_METHODS


def unregister_custom_decoder(name: str) -> bool:
    """
    Unregister a previously registered custom decoder. Builtin decoders cannot be unregistered.
    Returns True if removed, False otherwise.
    """
    if not name or name in _BUILTIN_DECODE_METHODS:
        return False
    if name in TXT_DECODE_METHODS:
        try:
            del TXT_DECODE_METHODS[name]
            return True
        except Exception:
            return False
    return False


def analyze_domain_decoding(domain: str, txt_record_value: str):
    """
    특정 도메인의 TXT 레코드 값을 입력받아, 등록된 모든 디코더를 시도해보고
    유효한 IPv4 주소를 반환하는 디코더를 찾아냅니다.

    Args:
        domain (str): 분석할 도메인
        txt_record_value (str): DNS TXT 레코드 조회 결과 문자열

    Returns:
        dict: { 'decoder_name': ['extracted_ip', ...], ... }
    """
    results = {}
    print(f"[*] Analyzing decoding method for: {domain}")
    short_sample = txt_record_value[:50] if isinstance(txt_record_value, str) else str(txt_record_value)
    print(f"[*] Input TXT Sample: {short_sample}...")

    for name, decode_func in TXT_DECODE_METHODS.items():
        try:
            extracted = decode_func([txt_record_value], domain=domain)
        except Exception:
            continue
        # normalize to list
        if not extracted:
            continue
        try:
            extracted_list = list(extracted) if not isinstance(extracted, str) else [extracted]
        except Exception:
            extracted_list = []

        valid_ips = [ip for ip in extracted_list if _is_valid_ip(ip)]
        raw_count = len(extracted_list)
        valid_count = len(valid_ips)
        uniq_count = len(set(valid_ips))
        valid_ratio = float(valid_count) / max(1.0, float(raw_count))

        # Improved scoring:
        # - reward high valid_ratio (primary),
        # - reward absolute number of valid IPs,
        # - reward uniqueness,
        # - penalize many non-IP tokens (noise)
        score = 0.0
        score += valid_ratio * 120.0        # primary weight for ratio
        score += valid_count * 8.0          # reward more matches
        score += min(uniq_count, 10) * 3.0   # reward uniqueness up to a cap
        score -= max(0, (raw_count - valid_count)) * 6.0  # penalize non-ip tokens

        # small heuristic tweaks based on decoder type (non-decisive)
        if 'multiplex' in name or 'c2' in name:
            score *= 0.95
        if 'base56' in name:
            score *= 1.03
        if 'safeb64' in name or 'safeb' in name:
            score *= 1.02

        if valid_count:
            results[name] = {
                'ips': sorted(valid_ips),
                'metrics': {
                    'valid_count': valid_count,
                    'raw_count': raw_count,
                    'uniq_count': uniq_count,
                    'valid_ratio': round(valid_ratio, 3)
                },
                'score': int(round(score))
            }

    out = {
        'analysis': results
    }

    if not results:
        print("[-] No suitable decoder found. It might be encrypted with a new key or algorithm.")
        out['best'] = None
        out['best_score'] = 0
    else:
        print(f"[+] Found {len(results)} working decoder(s):")
        for name, info in results.items():
            print(f"    - [{name}] score={info.get('score')} ips={info.get('ips')}")
        # recommend best by score, then prefer fewer raw tokens when tied
        best_method = max(results.keys(), key=lambda k: (results[k]['score'], -results[k]['metrics'].get('raw_count', 0)))
        out['best'] = best_method
        out['best_score'] = results[best_method]['score']
        out['best_metrics'] = results[best_method].get('metrics')
        print(f"[*] Recommendation: Use '{best_method}' (score={out['best_score']})")

    print("="*60)
    return out


if __name__ == '__main__':
    # 간단한 로컬 테스트 스니펫
    sample_mirai = "y/v7vw=="
    analyze_domain_decoding("kamru.su", sample_mirai)
    analyze_domain_decoding("ilovementallyilltrannysandanorexicbrits.su", "dummy_base64_val")

