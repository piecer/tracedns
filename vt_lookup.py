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

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback has no cross-process flock.
    fcntl = None

CACHE_FILE = os.path.join(os.path.dirname(__file__), 'vt_cache.json')
_DEFAULT_CACHE_TTL_SECONDS = int(os.environ.get('VT_CACHE_TTL_SECONDS', str(60 * 60 * 24)))
CACHE_TTL = _DEFAULT_CACHE_TTL_SECONDS  # default 24h
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
_CACHE_INFLIGHT = {}


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


def set_cache_ttl_days(days):
    """Set VT cache TTL using day units. Returns normalized days or None."""
    global CACHE_TTL
    try:
        d = int(str(days).strip())
    except Exception:
        return None
    if d < 1:
        return None
    if d > 3650:
        d = 3650
    CACHE_TTL = int(d * 86400)
    return d


def get_cache_ttl_days():
    """Return current VT cache TTL in whole days (minimum 1)."""
    try:
        secs = int(CACHE_TTL)
    except Exception:
        secs = int(_DEFAULT_CACHE_TTL_SECONDS)
    if secs <= 0:
        return 1
    return max(1, int((secs + 86399) // 86400))


def get_runtime_config():
    """Return mutable VT settings that process workers refresh per task."""
    return {'api_key': _GLOBAL_API_KEY, 'cache_ttl': int(CACHE_TTL)}


def apply_runtime_config(config):
    """Apply a parent-process VT settings snapshot inside a worker process."""
    global CACHE_TTL
    config = config if isinstance(config, dict) else {}
    set_api_key(config.get('api_key'))
    try:
        ttl = int(config.get('cache_ttl'))
    except (TypeError, ValueError):
        return
    if ttl > 0:
        CACHE_TTL = ttl


@contextmanager
def _cache_file_lock():
    with open(f'{CACHE_FILE}.lock', 'a+b') as lock_file:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _save_cache_locked():
    tmp_path = f'{CACHE_FILE}.tmp.{os.getpid()}.{threading.get_ident()}'
    try:
        with _cache_file_lock():
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as existing_file:
                    existing = json.load(existing_file)
            except Exception:
                existing = {}
            merged = dict(existing) if isinstance(existing, dict) else {}
            for ip, entry in _CACHE.items():
                persisted = merged.get(ip)
                if not isinstance(persisted, dict) or int(entry.get('fetched_at', 0)) >= int(persisted.get('fetched_at', 0)):
                    merged[ip] = entry
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(merged, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, CACHE_FILE)
            _CACHE.clear()
            _CACHE.update(merged)
        return True
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False


def flush_cache(force=False):
    """Flush in-memory cache to disk when dirty (or always if force=True)."""
    global _CACHE_DIRTY
    with _CACHE_LOCK:
        if (not force) and (not _CACHE_DIRTY):
            return False
        if not _save_cache_locked():
            return False
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
            return None
        inflight = _CACHE_INFLIGHT.get(ip)
        if inflight is None:
            inflight = threading.Event()
            _CACHE_INFLIGHT[ip] = inflight
            fetch_owner = True
        else:
            fetch_owner = False

    if not fetch_owner:
        inflight.wait()
        with _CACHE_LOCK:
            entry = _CACHE.get(ip)
            return entry.get('report') if entry else None

    report = None
    write_now = False
    try:
        report = _fetch_from_vt(ip, api_key)
        if report is not None:
            with _CACHE_LOCK:
                global _CACHE_DIRTY
                _CACHE[ip] = {'fetched_at': now, 'report': report}
                _CACHE_DIRTY = True
                write_now = (_CACHE_BATCH_DEPTH == 0)
    finally:
        with _CACHE_LOCK:
            _CACHE_INFLIGHT.pop(ip, None)
            inflight.set()
    if report is None:
        # A missing report also represents transient network, rate-limit, and
        # server failures. Do not turn those failures into a full-TTL cache hit.
        return None
    # best-effort save (immediate only when not in a batch)
    if write_now:
        flush_cache(force=True)
    return report


# Best-effort flush for deferred writes during graceful shutdown.
atexit.register(flush_cache)
