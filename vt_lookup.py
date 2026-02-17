"""
VirusTotal IP reputation lookup with simple on-disk caching.

Usage:
- Set environment variable `VIRUSTOTAL_API_KEY` to your VT API key, OR
- Call `set_api_key(key)` to set the API key programmatically.
- Call `get_ip_report(ip)` which returns a dict with minimal fields or None if unavailable.

Notes:
- Cache TTL default: 24 hours.
- Uses stdlib `urllib.request` so no extra dependencies are required.
- For bulk lookups, use `cache_write_batch()` to flush cache file once at the end.
"""
import atexit
import os
import json
import time
import threading
import urllib.request
import urllib.error
from contextlib import contextmanager

CACHE_FILE = os.path.join(os.path.dirname(__file__), 'vt_cache.json')
CACHE_TTL = int(os.environ.get('VT_CACHE_TTL_SECONDS', str(60 * 60 * 24)))  # default 24h
API_KEY_ENV = 'VIRUSTOTAL_API_KEY'

# Global API key holder (can be set via set_api_key() or environment variable)
_GLOBAL_API_KEY = None

# load cache
try:
    with open(CACHE_FILE, 'r', encoding='utf-8') as f:
        _CACHE = json.load(f)
except Exception:
    _CACHE = {}

_CACHE_LOCK = threading.Lock()
_CACHE_DIRTY = False
_CACHE_BATCH_DEPTH = 0


def set_api_key(api_key):
    """
    설정에서 제공된 VT API Key를 설정합니다.
    
    Args:
        api_key (str): VirusTotal API 키
    """
    global _GLOBAL_API_KEY
    if api_key and isinstance(api_key, str):
        _GLOBAL_API_KEY = api_key.strip()
    else:
        _GLOBAL_API_KEY = None


def _save_cache_locked():
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(_CACHE, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def flush_cache(force=False):
    """Flush in-memory cache to disk when dirty (or always if force=True)."""
    global _CACHE_DIRTY
    with _CACHE_LOCK:
        if (not force) and (not _CACHE_DIRTY):
            return False
        _save_cache_locked()
        _CACHE_DIRTY = False
        return True


def begin_cache_batch():
    """Start a batch section to defer disk writes until end_cache_batch()."""
    global _CACHE_BATCH_DEPTH
    with _CACHE_LOCK:
        _CACHE_BATCH_DEPTH += 1
        return _CACHE_BATCH_DEPTH


def end_cache_batch(flush=True):
    """Finish a batch section and flush once when the outermost batch ends."""
    global _CACHE_BATCH_DEPTH
    should_flush = False
    with _CACHE_LOCK:
        if _CACHE_BATCH_DEPTH > 0:
            _CACHE_BATCH_DEPTH -= 1
        if flush and _CACHE_BATCH_DEPTH == 0 and _CACHE_DIRTY:
            should_flush = True
    if should_flush:
        return flush_cache(force=True)
    return False


@contextmanager
def cache_write_batch(flush=True):
    """Context manager for deferring vt_cache.json write until the block ends."""
    begin_cache_batch()
    try:
        yield
    finally:
        end_cache_batch(flush=flush)


def _fetch_from_vt(ip, api_key):
    """Query VirusTotal API v3 for an IP address. Returns parsed minimal result or None."""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    req = urllib.request.Request(url)
    req.add_header('x-apikey', api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode('utf-8'))
            # Parse essential fields
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            last_analysis_date = attrs.get('last_analysis_date')
            result = {
                'malicious': int(stats.get('malicious', 0)),
                'suspicious': int(stats.get('suspicious', 0)),
                'harmless': int(stats.get('harmless', 0)),
                'undetected': int(stats.get('undetected', 0)) if 'undetected' in stats else None,
                'last_analysis_date': last_analysis_date,
                'as_owner': attrs.get('as_owner'),
                'asn': attrs.get('asn'),
                'country': attrs.get('country'),
                'raw': data,
            }
            return result
    except urllib.error.HTTPError as e:
        # Non-200 responses
        return None
    except Exception:
        return None


def get_ip_report(ip, force=False, cache_only=False):
    """Return VT report for ip. If unavailable returns None.

    Cache entries are kept with a timestamp; TTL controlled by CACHE_TTL.
    API Key는 set_api_key()로 설정된 값 또는 환경 변수에서 읽습니다.
    cache_only=True 인 경우 네트워크 조회 없이 캐시 데이터만 반환합니다.
    """
    global _GLOBAL_API_KEY
    
    # 우선순위: set_api_key()로 설정된 값 > 환경 변수
    api_key = _GLOBAL_API_KEY or os.environ.get(API_KEY_ENV)
    
    if not api_key:
        return None

    now = int(time.time())
    with _CACHE_LOCK:
        entry = _CACHE.get(ip)
        if entry and not force:
            ts = entry.get('fetched_at', 0)
            if now - ts < CACHE_TTL:
                return entry.get('report')
            if cache_only:
                # cache-only mode returns stale cache rather than making network requests
                return entry.get('report')

    if cache_only:
        return None

    report = _fetch_from_vt(ip, api_key)
    write_now = False
    with _CACHE_LOCK:
        global _CACHE_DIRTY
        _CACHE[ip] = {'fetched_at': now, 'report': report}
        _CACHE_DIRTY = True
        write_now = (_CACHE_BATCH_DEPTH == 0)
    # best-effort save (immediate only when not in a batch)
    if write_now:
        flush_cache(force=True)
    return report


# Best-effort flush for deferred writes during graceful shutdown.
atexit.register(flush_cache)
