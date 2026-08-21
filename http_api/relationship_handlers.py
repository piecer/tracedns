from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from io import BytesIO
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from http_api.misp_context import redact_misp_context_for_export

try:
    from vt_lookup import (
        apply_runtime_config as apply_vt_runtime_config,
        begin_cache_batch,
        end_cache_batch,
        get_ip_report,
        get_runtime_config as get_vt_runtime_config,
    )
except Exception:
    apply_vt_runtime_config = None
    begin_cache_batch = None
    end_cache_batch = None
    get_ip_report = None
    get_vt_runtime_config = None

logger = logging.getLogger(__name__)


def _bounded_bucket_members(bucket_key: str, ips: Any, limit: int) -> Tuple[List[str], bool]:
    """Select a deterministic, non-lexically-biased bounded bucket sample."""
    unique = sorted({str(ip) for ip in (ips or [])})
    if len(unique) <= limit:
        return unique, False
    ranked = sorted(
        unique,
        key=lambda ip: hashlib.sha256(f"{bucket_key}\0{ip}".encode("utf-8")).digest(),
    )
    return sorted(ranked[:limit]), True

_IP_REL_JOB_LOCK = threading.Lock()
_IP_REL_JOBS: Dict[str, Dict[str, Any]] = {}
_IP_REL_JOB_EXECUTOR: Optional[ProcessPoolExecutor] = None
_IP_REL_JOB_MAX_WORKERS = max(1, int(os.environ.get("TRACEDNS_IP_REL_JOB_WORKERS", "1") or "1"))
_IP_REL_JOB_MAX_PENDING = max(1, int(os.environ.get("TRACEDNS_IP_REL_JOB_MAX_PENDING", "16") or "16"))
_IP_REL_JOB_TTL_SECONDS = max(300, int(os.environ.get("TRACEDNS_IP_REL_JOB_TTL_SECONDS", "3600") or "3600"))
_IP_REL_JOB_MAX_TERMINAL = max(1, int(os.environ.get("TRACEDNS_IP_REL_JOB_MAX_TERMINAL", "32") or "32"))
_IP_REL_JOB_MAX_RESULT_BYTES = max(
    1024 * 1024,
    int(os.environ.get("TRACEDNS_IP_REL_JOB_MAX_RESULT_BYTES", str(64 * 1024 * 1024)) or str(64 * 1024 * 1024)),
)
_IP_REL_MAX_TOKENS = 20000
_IP_REL_MAX_UNIQUE_IPS = 10000
_IP_REL_LOCAL_CONTEXT_MAX_BYTES = max(
    64 * 1024,
    int(os.environ.get("TRACEDNS_IP_REL_LOCAL_CONTEXT_MAX_BYTES", str(1024 * 1024)) or str(1024 * 1024)),
)


class RelationshipJobCapacityError(RuntimeError):
    """Raised when the bounded relationship-job queue is full."""


class RelationshipRequestError(ValueError):
    """Raised when a relationship request cannot be admitted."""

    status_code = 400

    def __init__(self, message: str, **details: Any):
        super().__init__(message)
        self.payload = {"error": message, **details}


def _get_ip_rel_job_executor() -> ProcessPoolExecutor:
    global _IP_REL_JOB_EXECUTOR
    with _IP_REL_JOB_LOCK:
        if _IP_REL_JOB_EXECUTOR is None:
            _IP_REL_JOB_EXECUTOR = ProcessPoolExecutor(max_workers=_IP_REL_JOB_MAX_WORKERS)
        return _IP_REL_JOB_EXECUTOR


def _bound_terminal_jobs_locked(keep_job_id: Optional[str] = None):
    terminal = sorted(
        (
            (str(job_id), float(job.get("done_at") or 0), int(job.get("result_bytes") or 0))
            for job_id, job in _IP_REL_JOBS.items()
            if job.get("status") in ("completed", "failed", "cancelled")
        ),
        key=lambda item: (item[1], item[0]),
    )
    total_bytes = sum(item[2] for item in terminal)
    while len(terminal) > _IP_REL_JOB_MAX_TERMINAL or total_bytes > _IP_REL_JOB_MAX_RESULT_BYTES:
        evict_at = next((idx for idx, item in enumerate(terminal) if item[0] != keep_job_id), None)
        if evict_at is None:
            break
        job_id, _done_at, result_bytes = terminal.pop(evict_at)
        total_bytes -= result_bytes
        _IP_REL_JOBS.pop(job_id, None)


def _cleanup_ip_rel_jobs(now: Optional[float] = None):
    now_f = float(now if now is not None else time.time())
    with _IP_REL_JOB_LOCK:
        old_ids = []
        for job_id, job in _IP_REL_JOBS.items():
            if job.get("status") not in ("completed", "failed", "cancelled"):
                continue
            done_at = float(job.get("done_at") or 0)
            if done_at and now_f - done_at > _IP_REL_JOB_TTL_SECONDS:
                old_ids.append(job_id)
        for job_id in old_ids:
            _IP_REL_JOBS.pop(job_id, None)
        _bound_terminal_jobs_locked()


class _CapturingRelationshipHandler:
    def __init__(self, data: Dict[str, Any], shared_config: Optional[Dict[str, Any]] = None):
        raw = json.dumps(data or {}).encode("utf-8")
        self.headers = {"Content-Length": str(len(raw))}
        self.rfile = BytesIO(raw)
        self.shared_config = dict(shared_config or {})
        self.response: Dict[str, Any] = {}
        self.status_code = 200

    def _send_json(self, payload: Dict[str, Any], status: int = 200):
        self.response = payload if isinstance(payload, dict) else {"data": payload}
        self.status_code = int(status or 200)
        return {"status_code": self.status_code, "payload": self.response}


def _run_ip_relationship_analysis_payload(
    data: Dict[str, Any],
    shared_config: Optional[Dict[str, Any]] = None,
    vt_runtime_config: Optional[Dict[str, Any]] = None,
    local_dns_context: Optional[Dict[str, Dict[str, Any]]] = None,
    local_dns_context_metadata: Optional[Dict[str, Any]] = None,
    misp_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if apply_vt_runtime_config is not None and vt_runtime_config is not None:
        apply_vt_runtime_config(vt_runtime_config)
    handler = _CapturingRelationshipHandler(data, shared_config)
    result = handle_ip_relationship_analysis(
        handler,
        trusted_local_dns_context=local_dns_context,
        trusted_local_dns_context_metadata=local_dns_context_metadata,
        trusted_misp_context=misp_context,
    )
    if isinstance(result, dict) and "payload" in result:
        return result
    return {"status_code": handler.status_code, "payload": handler.response}


def _ip_rel_job_done(job_id: str, fut):
    now = time.time()
    with _IP_REL_JOB_LOCK:
        job = _IP_REL_JOBS.get(job_id)
        if not job or job.get("status") == "cancelled":
            return
        job["done_at"] = now
        if fut.cancelled():
            job["status"] = "cancelled"
            return
        try:
            result = fut.result()
            payload = result.get("payload") if isinstance(result, dict) else result
            payload_bytes = len(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            if payload_bytes > _IP_REL_JOB_MAX_RESULT_BYTES:
                job["result"] = {
                    "error": "relationship analysis result exceeded size limit",
                    "result_too_large": True,
                    "result_bytes": payload_bytes,
                    "max_result_bytes": int(_IP_REL_JOB_MAX_RESULT_BYTES),
                }
                job["result_bytes"] = len(
                    json.dumps(job["result"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                )
                job["status_code"] = 413
                job["status"] = "failed"
                job["error"] = "relationship analysis result exceeded size limit"
            else:
                job["result"] = payload
                job["result_bytes"] = payload_bytes
                job["status_code"] = int((result or {}).get("status_code") or 200) if isinstance(result, dict) else 200
                job["status"] = "completed" if int(job.get("status_code") or 200) < 400 else "failed"
        except Exception:
            logger.exception("IP relationship analysis worker failed")
            job.pop("result", None)
            job["result_bytes"] = 0
            job["status"] = "failed"
            job["status_code"] = 500
            job["error"] = "relationship analysis failed"
        _bound_terminal_jobs_locked(keep_job_id=job_id)


def ensure_ip_relationship_job_capacity() -> None:
    """Fail fast before callers perform expensive request preparation.

    Submission still repeats this check while inserting the job so concurrent
    requests cannot exceed the pending-job limit.
    """
    _cleanup_ip_rel_jobs()
    with _IP_REL_JOB_LOCK:
        active_jobs = sum(
            1 for existing in _IP_REL_JOBS.values()
            if existing.get("status") in ("queued", "running")
        )
        if active_jobs >= _IP_REL_JOB_MAX_PENDING:
            raise RelationshipJobCapacityError("relationship job queue is full")


def start_ip_relationship_job(
    data: Any,
    shared_config: Optional[Dict[str, Any]] = None,
    local_dns_context: Optional[Dict[str, Any]] = None,
    misp_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    valid_ips, _invalid = _validate_relationship_request(data)
    context_snapshot, context_metadata = _sanitize_local_dns_context(
        local_dns_context, allowed_ips=set(valid_ips), include_metadata=True
    )
    _cleanup_ip_rel_jobs()
    job_id = uuid.uuid4().hex
    now = time.time()
    job = {
        "job_id": job_id,
        "status": "queued",
        "created_at": now,
        "done_at": None,
        "status_code": None,
        "error": None,
    }
    with _IP_REL_JOB_LOCK:
        active_jobs = sum(
            1 for existing in _IP_REL_JOBS.values()
            if existing.get("status") in ("queued", "running")
        )
        if active_jobs >= _IP_REL_JOB_MAX_PENDING:
            raise RelationshipJobCapacityError("relationship job queue is full")
        _IP_REL_JOBS[job_id] = job
    try:
        fut = _get_ip_rel_job_executor().submit(
            _run_ip_relationship_analysis_payload,
            data,
            dict(shared_config or {}),
            get_vt_runtime_config() if get_vt_runtime_config is not None else None,
            context_snapshot,
            context_metadata,
            copy.deepcopy(misp_context) if isinstance(misp_context, dict) else None,
        )
    except Exception:
        with _IP_REL_JOB_LOCK:
            _IP_REL_JOBS.pop(job_id, None)
        raise
    with _IP_REL_JOB_LOCK:
        if job_id in _IP_REL_JOBS:
            _IP_REL_JOBS[job_id]["future"] = fut
            _IP_REL_JOBS[job_id]["status"] = "running"
    fut.add_done_callback(lambda f, jid=job_id: _ip_rel_job_done(jid, f))
    return {"status": "queued", "job_id": job_id}


def get_ip_relationship_job(job_id: str, *, include_result: bool = False) -> Tuple[Dict[str, Any], int]:
    _cleanup_ip_rel_jobs()
    with _IP_REL_JOB_LOCK:
        job = _IP_REL_JOBS.get(str(job_id or ""))
        if not job:
            return ({"error": "job not found"}, 404)
        out = {
            "job_id": job.get("job_id"),
            "status": job.get("status"),
            "created_at": job.get("created_at"),
            "done_at": job.get("done_at"),
            "status_code": job.get("status_code"),
            "error": job.get("error"),
        }
        if include_result and job.get("status") in ("completed", "failed"):
            out["result"] = job.get("result")
        return (out, 200)


def cancel_ip_relationship_job(job_id: str) -> Tuple[Dict[str, Any], int]:
    job_key = str(job_id or "")
    with _IP_REL_JOB_LOCK:
        job = _IP_REL_JOBS.get(job_key)
        if not job:
            return ({"error": "job not found"}, 404)
        if job.get("status") == "cancelled":
            return ({"status": "cancelled", "job_id": job_id, "cancelled": True}, 200)
        if job.get("status") in ("completed", "failed"):
            return (
                {
                    "status": job.get("status"),
                    "job_id": job_id,
                    "cancelled": False,
                    "reason": "already_finished",
                },
                409,
            )
        fut = job.get("future")

    cancelled = bool(fut.cancel()) if fut is not None else False

    with _IP_REL_JOB_LOCK:
        job = _IP_REL_JOBS.get(job_key)
        if not job:
            return ({"error": "job not found"}, 404)
        if cancelled:
            job["status"] = "cancelled"
            job["done_at"] = time.time()
            return ({"status": "cancelled", "job_id": job_id, "cancelled": True}, 200)
        reason = (
            "already_finished"
            if job.get("status") in ("completed", "failed")
            else "already_running"
        )
        return (
            {
                "status": job.get("status"),
                "job_id": job_id,
                "cancelled": False,
                "reason": reason,
            },
            409,
        )


def shutdown_ip_relationship_jobs(*, wait: bool = False) -> None:
    """Cancel queued work and release the analysis pool during server shutdown."""
    global _IP_REL_JOB_EXECUTOR
    with _IP_REL_JOB_LOCK:
        executor = _IP_REL_JOB_EXECUTOR
        _IP_REL_JOB_EXECUTOR = None
    if executor is not None:
        executor.shutdown(wait=wait, cancel_futures=True)


def _tokenize_ip_input(raw: Any) -> List[str]:
    tokens: List[str] = []
    if isinstance(raw, str):
        tokens = [x.strip() for x in re.split(r"[\s,;|]+", raw) if x and x.strip()]
    elif isinstance(raw, list):
        for item in raw:
            if item is None:
                continue
            s = str(item).strip()
            if not s:
                continue
            parts = [x.strip() for x in re.split(r"[\s,;|]+", s) if x and x.strip()]
            tokens.extend(parts)
    return tokens


def _parse_ip_tokens(raw: Any) -> Tuple[List[str], List[str]]:
    """Return (valid_ips, invalid_tokens). De-dupes while preserving order."""
    import ipaddress as _ip

    tokens = _tokenize_ip_input(raw)

    unique: List[str] = []
    seen = set()
    for t in tokens:
        if t in seen:
            continue
        seen.add(t)
        unique.append(t)

    valid: List[str] = []
    invalid: List[str] = []
    seen_valid = set()
    for tok in unique:
        try:
            if "%" in tok:
                raise ValueError("scoped IPv6 addresses are not supported")
            addr = _ip.ip_address(tok)
            if isinstance(addr, _ip.IPv6Address) and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            ip_s = str(addr)
            if ip_s not in seen_valid:
                seen_valid.add(ip_s)
                valid.append(ip_s)
        except Exception:
            invalid.append(tok)

    return (valid, invalid)


def _sanitize_local_dns_context(
    context: Any,
    *,
    allowed_ips: Optional[Set[str]] = None,
    include_metadata: bool = False,
) -> Any:
    """Bound and normalize parent-process DNS context for worker transport."""
    metadata = {
        "truncated": False,
        "byte_limit_reached": False,
        "ip_limit_reached": False,
        "ips_omitted": 0,
        "domains_omitted": 0,
        "record_types_omitted": 0,
        "decoders_omitted": 0,
        "change_timestamps_omitted": 0,
        "serialized_bytes": 2,
        "max_bytes": int(_IP_REL_LOCAL_CONTEXT_MAX_BYTES),
    }
    if not isinstance(context, dict):
        return ({}, metadata) if include_metadata else {}

    def bounded_strings(value: Any, *, limit: int, max_length: int) -> Tuple[List[str], int]:
        if not isinstance(value, (list, tuple, set)):
            return [], 0
        raw_count = len(value)
        cleaned = {
            str(item or "").strip()
            for item in value
            if str(item or "").strip() and len(str(item or "").strip()) <= max_length
        }
        bounded = sorted(cleaned)[:limit]
        return bounded, max(0, raw_count - len(bounded))

    def bounded_timestamps(value: Any, *, limit: int) -> Tuple[List[int], int]:
        if not isinstance(value, (list, tuple, set)):
            return [], 0
        raw_count = len(value)
        cleaned = set()
        for item in value:
            try:
                timestamp = int(item)
            except (TypeError, ValueError):
                continue
            if timestamp > 0:
                cleaned.add(timestamp)
        bounded = sorted(cleaned, reverse=True)[:limit]
        return bounded, max(0, raw_count - len(bounded))

    if allowed_ips is not None:
        context_items = [
            (ip, context[ip])
            for ip in sorted(allowed_ips)[:_IP_REL_MAX_UNIQUE_IPS]
            if ip in context
        ]
    else:
        context_items = list(context.items())[:_IP_REL_MAX_UNIQUE_IPS]
        if len(context) > len(context_items):
            metadata["ip_limit_reached"] = True
            metadata["ips_omitted"] = len(context) - len(context_items)

    out: Dict[str, Dict[str, Any]] = {}
    serialized_bytes = 2
    for item_index, (raw_ip, raw_entry) in enumerate(context_items):
        try:
            ip = str(ipaddress.ip_address(str(raw_ip or "").strip()))
        except Exception:
            continue
        if allowed_ips is not None and ip not in allowed_ips:
            continue
        if not isinstance(raw_entry, dict):
            continue
        try:
            count = max(0, min(int(raw_entry.get("count") or 0), 1_000_000))
        except (TypeError, ValueError):
            count = 0
        try:
            last_ts = max(0, int(raw_entry.get("last_ts") or 0))
        except (TypeError, ValueError):
            last_ts = 0
        domains, domains_omitted = bounded_strings(
            raw_entry.get("domains"), limit=32, max_length=253
        )
        record_types, record_types_omitted = bounded_strings(
            raw_entry.get("record_types"), limit=8, max_length=16
        )
        decoders, decoders_omitted = bounded_strings(
            raw_entry.get("decoders"), limit=16, max_length=160
        )
        sanitized_entry = {
            "domains": domains,
            "record_types": record_types,
            "decoders": decoders,
            "count": count,
            "last_ts": last_ts,
        }
        change_timestamps, change_timestamps_omitted = bounded_timestamps(
            raw_entry.get("change_timestamps"), limit=16
        )
        if change_timestamps:
            sanitized_entry["change_timestamps"] = change_timestamps
        encoded_entry = json.dumps(
            {ip: sanitized_entry}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        entry_bytes = max(0, len(encoded_entry) - 2) + (1 if out else 0)
        if serialized_bytes + entry_bytes > _IP_REL_LOCAL_CONTEXT_MAX_BYTES:
            metadata["byte_limit_reached"] = True
            metadata["ips_omitted"] += len(context_items) - item_index
            break
        out[ip] = sanitized_entry
        serialized_bytes += entry_bytes
        metadata["domains_omitted"] += domains_omitted
        metadata["record_types_omitted"] += record_types_omitted
        metadata["decoders_omitted"] += decoders_omitted
        metadata["change_timestamps_omitted"] += change_timestamps_omitted
    metadata["serialized_bytes"] = serialized_bytes
    metadata["truncated"] = any(
        int(metadata[key]) > 0
        for key in (
            "ips_omitted",
            "domains_omitted",
            "record_types_omitted",
            "decoders_omitted",
            "change_timestamps_omitted",
        )
    )
    return (out, metadata) if include_metadata else out


def _classify_ip_scope(ip: str) -> Tuple[str, bool]:
    """Return a stable scope label and whether an IP may be sent to VT."""
    addr = ipaddress.ip_address(ip)
    if addr.is_unspecified:
        return "unspecified", False
    if addr.is_loopback:
        return "loopback", False
    if addr.is_link_local:
        return "link_local", False
    if addr.is_multicast:
        return "multicast", False
    if addr.is_reserved:
        return "reserved", False
    if addr.is_private:
        return "private", False
    if addr.is_global:
        return "global", True
    return "non_global", False


def _validate_relationship_request(data: Any) -> Tuple[List[str], List[str]]:
    if not isinstance(data, dict):
        raise RelationshipRequestError("request body must be a JSON object")
    if "bucket_max" in data:
        try:
            int(data["bucket_max"])
        except (TypeError, ValueError):
            raise RelationshipRequestError("bucket_max must be an integer")
    raw_ips = data.get("ips")
    if not isinstance(raw_ips, (str, list)):
        raise RelationshipRequestError("ips must be a string or list")
    tokens = _tokenize_ip_input(raw_ips)
    if len(tokens) > _IP_REL_MAX_TOKENS:
        raise RelationshipRequestError(f"too many ip tokens (max {_IP_REL_MAX_TOKENS})")
    valid_ips, invalid = _parse_ip_tokens(raw_ips)
    if not valid_ips:
        raise RelationshipRequestError("no valid ips", invalid_inputs=invalid[:200])
    if len(valid_ips) > _IP_REL_MAX_UNIQUE_IPS:
        raise RelationshipRequestError(f"too many ips (max {_IP_REL_MAX_UNIQUE_IPS})")
    return valid_ips, invalid


def _classify_csp(as_owner: Any) -> Dict[str, Any]:
    """Best-effort CSP classifier (mirrors logic used in ip list analysis)."""
    owner_txt = str(as_owner or "").strip()
    ltxt = owner_txt.lower()
    if not ltxt:
        return {"csp": "other", "csp_label": "Other/Unknown", "csp_major": False}

    csp_rules = [
        ("amazon", "Amazon AWS", True, ("amazon", "amazon.com", "aws")),
        ("google", "Google Cloud", True, ("google", "gcp", "google cloud")),
        ("microsoft", "Microsoft Azure", True, ("microsoft", "azure")),
        ("cloudflare", "Cloudflare", True, ("cloudflare",)),
        ("oracle", "Oracle Cloud", True, ("oracle", "oci")),
        ("alibaba", "Alibaba Cloud", True, ("alibaba", "aliyun")),
        ("tencent", "Tencent Cloud", True, ("tencent",)),
        ("akamai", "Akamai/Linode", False, ("akamai", "linode")),
        ("digitalocean", "DigitalOcean", False, ("digitalocean",)),
        ("ovh", "OVHcloud", False, ("ovh", "ovhcloud")),
    ]
    for csp_id, label, major, needles in csp_rules:
        if any(n in ltxt for n in needles):
            return {"csp": csp_id, "csp_label": label, "csp_major": bool(major)}
    return {"csp": "other", "csp_label": "Other/Unknown", "csp_major": False}


def _normalize_owner(owner: Any) -> str:
    s = str(owner or "").strip().lower()
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s)
    # drop common legal suffixes (rough)
    s = re.sub(r"\b(inc|llc|ltd|limited|corp|corporation|co|company|gmbh|s\.a\.|sa)\b\.?", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _ipv4_prefix24(ip: str) -> Optional[str]:
    if ":" in str(ip):
        return None
    parts = str(ip).split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3]) + ".0/24"


def _load_geoip_reader(mmdb_path: Optional[str]):
    """Return geoip2 Reader or None. Optional dependency."""
    if not mmdb_path:
        return None
    try:
        import geoip2.database  # type: ignore

        return geoip2.database.Reader(mmdb_path)
    except Exception:
        return None


def _geoip_country(reader, ip: str) -> Optional[str]:
    if not reader:
        return None
    try:
        # country() is cheaper than city()
        resp = reader.country(ip)
        cc = getattr(resp.country, "iso_code", None)
        if cc:
            return str(cc).upper()
    except Exception:
        return None
    return None


def _normalize_text(value: Any) -> str:
    s = str(value or "").strip().lower()
    if not s:
        return ""
    return re.sub(r"\s+", " ", s)


def _is_missing_feature_value(value: Any, *, csp: bool = False) -> bool:
    normalized = str(value or "").strip().lower()
    if normalized in ("", "-", "n/a", "unknown", "none", "null", "other/unknown"):
        return True
    return csp and normalized in ("other", "unknown", "other/unknown")


def _normalize_hash(value: Any, *, expected_length: int) -> str:
    s = str(value or "").strip().lower()
    if len(s) != expected_length or re.fullmatch(r"[0-9a-f]+", s) is None:
        return ""
    return s


def _short_token(value: Any, *, head: int = 12, tail: int = 8) -> str:
    s = str(value or "").strip()
    if not s:
        return "-"
    if len(s) <= (head + tail + 2):
        return s
    return f"{s[:head]}..{s[-tail:]}"


def _extract_vt_attrs(report: Any) -> Dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    raw = report.get("raw")
    if not isinstance(raw, dict):
        return {}
    data = raw.get("data")
    if not isinstance(data, dict):
        return {}
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        return {}
    return attrs


def _extract_positive_vt_engines(attrs: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(attrs, dict):
        return out
    lar = attrs.get("last_analysis_results")
    if not isinstance(lar, dict):
        return out
    for eng, ent in lar.items():
        if not isinstance(ent, dict):
            continue
        cat = str(ent.get("category") or "").strip().lower()
        if cat in ("malicious", "suspicious"):
            e = str(eng or "").strip()
            if e:
                out.add(e)
    return out


def _parse_network_cidr(network_txt: Any):
    s = str(network_txt or "").strip()
    if not s:
        return None
    try:
        return ipaddress.ip_network(s, strict=False)
    except Exception:
        return None


def _network_candidate_keys(network_obj: Any) -> List[str]:
    """Return shared ancestor keys so overlapping CIDRs enter pair scoring."""
    if network_obj is None:
        return []
    try:
        version = int(network_obj.version)
        prefixlen = int(network_obj.prefixlen)
        step = 4 if version == 4 else 16
        normal_first = 8 if version == 4 else 16
        if prefixlen >= normal_first:
            first = normal_first
        elif prefixlen >= step:
            first = step
        else:
            first = 0
        prefixes = list(range(first, prefixlen + 1, step))
        if prefixlen not in prefixes:
            prefixes.append(prefixlen)
        return [
            f"v{version}:{network_obj.supernet(new_prefix=prefix)}"
            for prefix in prefixes
        ]
    except (AttributeError, TypeError, ValueError):
        return []


def _pair_gate_decision(
    score: int,
    evidence: List[Dict[str, Any]],
    min_score: int,
    *,
    enabled: bool = True,
    strong_min: int = 1,
    mid_min: int = 2,
    fallback_score: Optional[int] = None,
) -> Tuple[bool, str]:
    if not enabled:
        return True, "gate_disabled"

    strong_types = {
        "same_jarm",
        "same_cert_sha256",
        "same_network_exact",
        "shared_observed_domain",
    }
    mid_types = {
        "same_asn",
        "same_owner",
        "same_csp",
        "same_rdap_name",
        "vt_detector_overlap",
        "same_prefix24",
        "same_network_overlap",
    }
    e_types = [str((x or {}).get("type") or "").strip() for x in (evidence or [])]
    strong_n = sum(1 for t in e_types if t in strong_types)
    mid_n = sum(1 for t in e_types if t in mid_types)
    strong_min_n = max(0, int(strong_min or 0))
    mid_min_n = max(0, int(mid_min or 0))
    fallback_n = int(fallback_score if fallback_score is not None else max(int(min_score or 0), 55))

    if strong_n >= strong_min_n and strong_min_n > 0:
        return True, "strong_signal"
    if mid_n >= mid_min_n and mid_min_n > 0:
        return True, "multi_mid_signals"
    if int(score or 0) >= fallback_n:
        return True, "high_score_fallback"
    return False, "weak_pair_filtered"


def _compare_features(
    a_ip: str,
    b_ip: str,
    fa: Dict[str, Any],
    fb: Dict[str, Any],
    *,
    ca: Optional[Dict[str, Any]] = None,
    cb: Optional[Dict[str, Any]] = None,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Return (score, evidence list). Score is capped to 100."""

    ca = ca or {}
    cb = cb or {}
    score = 0
    ev: List[Dict[str, Any]] = []

    a_asn = str(fa.get("asn") or "").strip()
    b_asn = str(fb.get("asn") or "").strip()
    a_owner_n = str(fa.get("as_owner_norm") or "").strip()
    b_owner_n = str(fb.get("as_owner_norm") or "").strip()
    a_csp = str(fa.get("csp") or "").strip()
    b_csp = str(fb.get("csp") or "").strip()
    a_country = str(fa.get("country") or "").strip().upper()
    b_country = str(fb.get("country") or "").strip().upper()
    a_network = str(fa.get("network") or "").strip()
    b_network = str(fb.get("network") or "").strip()
    a_rir = str(fa.get("rir") or "").strip().upper()
    b_rir = str(fb.get("rir") or "").strip().upper()
    a_jarm = _normalize_hash(fa.get("jarm"), expected_length=62)
    b_jarm = _normalize_hash(fb.get("jarm"), expected_length=62)
    a_cert = _normalize_hash(fa.get("cert_sha256"), expected_length=64)
    b_cert = _normalize_hash(fb.get("cert_sha256"), expected_length=64)
    a_rdap_name = str(fa.get("rdap_name_norm") or "").strip()
    b_rdap_name = str(fb.get("rdap_name_norm") or "").strip()
    a_rdap_type = str(fa.get("rdap_type") or "").strip()
    b_rdap_type = str(fb.get("rdap_type") or "").strip()
    a_net_obj = ca.get("network_obj")
    b_net_obj = cb.get("network_obj")

    a_local_raw = fa.get("local_dns")
    b_local_raw = fb.get("local_dns")
    a_local: Dict[str, Any] = a_local_raw if isinstance(a_local_raw, dict) else {}
    b_local: Dict[str, Any] = b_local_raw if isinstance(b_local_raw, dict) else {}
    shared_domains = sorted(
        set(a_local.get("domains") or []).intersection(b_local.get("domains") or [])
    )
    if shared_domains:
        score += 28
        ev.append({
            "type": "shared_observed_domain",
            "value": ",".join(shared_domains[:3]),
            "weight": 28,
        })
        shared_decoders = sorted(
            set(a_local.get("decoders") or []).intersection(b_local.get("decoders") or [])
        )
        if shared_decoders:
            score += 12
            ev.append({
                "type": "shared_decoder_provenance",
                "value": ",".join(shared_decoders[:3]),
                "weight": 12,
            })
        a_changes = [int(ts) for ts in a_local.get("change_timestamps") or [] if int(ts) > 0]
        b_changes = [int(ts) for ts in b_local.get("change_timestamps") or [] if int(ts) > 0]
        if a_changes and b_changes:
            closest_change_delta = min(abs(a_ts - b_ts) for a_ts in a_changes for b_ts in b_changes)
            if closest_change_delta <= 300:
                score += 12
                ev.append({
                    "type": "coincident_dns_change",
                    "value": f"{closest_change_delta}s",
                    "weight": 12,
                })

    a_misp_raw = fa.get("misp")
    b_misp_raw = fb.get("misp")
    a_misp = a_misp_raw if isinstance(a_misp_raw, dict) else {}
    b_misp = b_misp_raw if isinstance(b_misp_raw, dict) else {}
    a_misp_event = str(a_misp.get("event_id") or "").strip()
    b_misp_event = str(b_misp.get("event_id") or "").strip()
    if a_misp_event and a_misp_event == b_misp_event:
        score += 20
        ev.append({"type": "shared_misp_event", "value": a_misp_event, "weight": 20})
        shared_campaigns = sorted(
            set(a_misp.get("campaigns") or []).intersection(
                b_misp.get("campaigns") or []
            )
        )
        if shared_campaigns:
            score += 5
            ev.append({
                "type": "shared_misp_campaign",
                "value": ",".join(shared_campaigns[:3]),
                "weight": 5,
            })

    # Infra similarity signals
    if not _is_missing_feature_value(a_asn) and not _is_missing_feature_value(b_asn) and a_asn == b_asn:
        score += 25
        ev.append({"type": "same_asn", "value": a_asn, "weight": 25})

    if not _is_missing_feature_value(a_owner_n) and not _is_missing_feature_value(b_owner_n) and a_owner_n == b_owner_n:
        score += 20
        ev.append({"type": "same_owner", "value": fa.get("as_owner") or "-", "weight": 20})

    if not _is_missing_feature_value(a_csp, csp=True) and not _is_missing_feature_value(b_csp, csp=True) and a_csp == b_csp:
        score += 15
        ev.append({"type": "same_csp", "value": fa.get("csp_label") or a_csp, "weight": 15})

    if not _is_missing_feature_value(a_country) and not _is_missing_feature_value(b_country) and a_country == b_country:
        score += 5
        ev.append({"type": "same_country", "value": a_country, "weight": 5})

    if not _is_missing_feature_value(a_network) and not _is_missing_feature_value(b_network) and a_network == b_network:
        score += 24
        ev.append({"type": "same_network_exact", "value": a_network, "weight": 24})
    elif a_net_obj is not None and b_net_obj is not None:
        try:
            if a_net_obj.version == b_net_obj.version and a_net_obj.overlaps(b_net_obj):
                w = 10 if (a_net_obj.prefixlen <= 20 or b_net_obj.prefixlen <= 20) else 7
                score += w
                ev.append({
                    "type": "same_network_overlap",
                    "value": f"{a_network or '-'}~{b_network or '-'}",
                    "weight": w,
                })
        except Exception:
            pass

    if not _is_missing_feature_value(fa.get("jarm")) and not _is_missing_feature_value(fb.get("jarm")) and a_jarm and b_jarm and a_jarm == b_jarm:
        score += 34
        ev.append({"type": "same_jarm", "value": _short_token(a_jarm), "weight": 34})

    if not _is_missing_feature_value(fa.get("cert_sha256")) and not _is_missing_feature_value(fb.get("cert_sha256")) and a_cert and b_cert and a_cert == b_cert:
        score += 36
        ev.append({"type": "same_cert_sha256", "value": _short_token(a_cert), "weight": 36})

    if not _is_missing_feature_value(a_rdap_name) and not _is_missing_feature_value(b_rdap_name) and a_rdap_name == b_rdap_name:
        score += 12
        ev.append({"type": "same_rdap_name", "value": fa.get("rdap_name") or "-", "weight": 12})

    if not _is_missing_feature_value(a_rdap_type) and not _is_missing_feature_value(b_rdap_type) and a_rdap_type == b_rdap_type:
        score += 3
        ev.append({"type": "same_rdap_type", "value": a_rdap_type, "weight": 3})

    if not _is_missing_feature_value(a_rir) and not _is_missing_feature_value(b_rir) and a_rir == b_rir:
        score += 4
        ev.append({"type": "same_rir", "value": a_rir, "weight": 4})

    # Network proximity: can be misleading for infected hosts on residential/mobile ISPs.
    # Make it strong only when the IPs look like hosted infrastructure.
    p24a = _ipv4_prefix24(a_ip)
    p24b = _ipv4_prefix24(b_ip)
    if p24a and p24b and p24a == p24b:
        hosted_hint = False
        if not _is_missing_feature_value(fa.get("csp"), csp=True) or not _is_missing_feature_value(fb.get("csp"), csp=True):
            hosted_hint = True
        if (fa.get("csp_major") or fb.get("csp_major")):
            hosted_hint = True
        if a_owner_n and b_owner_n and a_owner_n == b_owner_n:
            hosted_hint = True

        w = 15 if hosted_hint else 3
        score += w
        ev.append({"type": "same_prefix24", "value": p24a, "weight": w, "note": "strong" if hosted_hint else "weak"})

    # VT-based weak signals
    ma = int(fa.get("malicious") or 0)
    mb = int(fb.get("malicious") or 0)
    sa = int(fa.get("suspicious") or 0)
    sb = int(fb.get("suspicious") or 0)
    if ma > 0 and mb > 0:
        score += 8
        ev.append({"type": "vt_malicious_both", "value": f"{ma}/{mb}", "weight": 8})
    if sa > 0 and sb > 0:
        score += 4
        ev.append({"type": "vt_suspicious_both", "value": f"{sa}/{sb}", "weight": 4})

    a_eng = ca.get("positive_engines") or set()
    b_eng = cb.get("positive_engines") or set()
    if isinstance(a_eng, set) and isinstance(b_eng, set) and a_eng and b_eng:
        inter = a_eng.intersection(b_eng)
        if inter:
            union_n = len(a_eng.union(b_eng))
            ratio = len(inter) / max(1, union_n)
            if ratio >= 0.65:
                w = 14
            elif ratio >= 0.40:
                w = 10
            else:
                w = 6
            score += w
            sample = ",".join(sorted(inter)[:3])
            val = f"{len(inter)}/{union_n}"
            if sample:
                val += f" ({sample})"
            ev.append({"type": "vt_detector_overlap", "value": val, "weight": w})

    ta = int(fa.get("last_analysis_date") or 0)
    tb = int(fb.get("last_analysis_date") or 0)
    if ta > 0 and tb > 0:
        delta = abs(ta - tb)
        if delta <= 86400:
            score += 4
            ev.append({"type": "vt_time_proximity", "value": "<=1d", "weight": 4})
        elif delta <= (3 * 86400):
            score += 2
            ev.append({"type": "vt_time_proximity", "value": "<=3d", "weight": 2})

    if score > 100:
        score = 100

    return (score, ev)


_EVIDENCE_SEMANTICS: Dict[str, Tuple[str, str, str]] = {
    "same_asn": ("infrastructure", "virustotal", "medium"),
    "same_owner": ("infrastructure", "virustotal", "medium"),
    "same_csp": ("infrastructure", "virustotal", "low"),
    "same_country": ("infrastructure", "virustotal", "low"),
    "same_network_exact": ("infrastructure", "virustotal", "high"),
    "same_network_overlap": ("infrastructure", "virustotal", "medium"),
    "same_rdap_name": ("infrastructure", "virustotal", "medium"),
    "same_rdap_type": ("infrastructure", "virustotal", "low"),
    "same_rir": ("infrastructure", "virustotal", "low"),
    "same_prefix24": ("infrastructure", "derived_ip", "low"),
    "same_jarm": ("tls", "virustotal", "high"),
    "same_cert_sha256": ("tls", "virustotal", "high"),
    "vt_malicious_both": ("threat_intel", "virustotal", "low"),
    "vt_suspicious_both": ("threat_intel", "virustotal", "low"),
    "vt_detector_overlap": ("threat_intel", "virustotal", "medium"),
    "vt_time_proximity": ("threat_intel", "virustotal", "low"),
    "shared_observed_domain": ("local_dns", "tracedns", "high"),
    "shared_decoder_provenance": ("local_dns", "tracedns", "medium"),
    "coincident_dns_change": ("local_dns", "tracedns", "medium"),
    "shared_misp_event": ("misp_context", "misp", "medium"),
    "shared_misp_campaign": ("misp_context", "misp", "high"),
}

_EVIDENCE_FAMILY_CAPS = {
    "infrastructure": 35,
    "tls": 45,
    "threat_intel": 20,
    "local_dns": 40,
    "misp_context": 25,
    "other": 15,
}

_INDEPENDENT_EVIDENCE_SOURCES = {"virustotal", "tracedns", "misp"}
_DIRECT_BOTNET_EVIDENCE_SCORES = {
    "shared_misp_campaign": 70,
}


def _build_pair_assessment(evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a conservative botnet verdict without changing legacy pair score."""
    raw_family_scores: Dict[str, int] = defaultdict(int)
    sources: Set[str] = set()
    normalized_evidence: List[Dict[str, Any]] = []
    has_high_specificity = False
    direct_botnet_scores: Dict[str, int] = {}

    for raw_item in evidence or []:
        if not isinstance(raw_item, dict):
            continue
        evidence_type = str(raw_item.get("type") or "").strip()
        family, source, specificity = _EVIDENCE_SEMANTICS.get(
            evidence_type, ("other", "unknown", "low")
        )
        try:
            weight = max(0, int(raw_item.get("weight") or 0))
        except (TypeError, ValueError):
            weight = 0
        raw_family_scores[family] += weight
        if source in _INDEPENDENT_EVIDENCE_SOURCES:
            sources.add(source)
        has_high_specificity = has_high_specificity or specificity == "high"
        direct_score = _DIRECT_BOTNET_EVIDENCE_SCORES.get(evidence_type, 0)
        if direct_score > 0:
            direct_botnet_scores[evidence_type] = max(
                direct_botnet_scores.get(evidence_type, 0), direct_score
            )
        normalized_evidence.append({
            **raw_item,
            "family": family,
            "source": source,
            "specificity": specificity,
        })

    family_scores = {
        family: min(score, _EVIDENCE_FAMILY_CAPS.get(family, 15))
        for family, score in sorted(raw_family_scores.items())
        if score > 0
    }
    evidence_score = min(100, sum(family_scores.values()))
    botnet_evidence_score = min(100, sum(direct_botnet_scores.values()))
    independent_source_count = len(sources)
    if (
        evidence_score >= 35
        and botnet_evidence_score >= 70
        and independent_source_count >= 2
        and has_high_specificity
    ):
        verdict = "same_botnet_likely"
    elif evidence_score >= 35:
        verdict = "related_infrastructure"
    else:
        verdict = "insufficient_evidence"

    return {
        "verdict": verdict,
        "evidence_score": evidence_score,
        "botnet_evidence_score": botnet_evidence_score,
        "botnet_evidence_signals": sorted(direct_botnet_scores),
        "raw_evidence_score": sum(raw_family_scores.values()),
        "family_scores": family_scores,
        "independent_sources": sorted(sources),
        "independent_source_count": independent_source_count,
        "evidence": normalized_evidence,
    }


def _top_counter(counter: Dict[str, int]) -> Dict[str, Any]:
    items = [(str(k), int(v or 0)) for k, v in (counter or {}).items() if k and int(v or 0) > 0]
    if not items:
        return {"key": "", "count": 0}
    key, count = sorted(items, key=lambda x: (-x[1], x[0]))[0]
    return {"key": key, "count": count}


def _build_relationship_insights(payload: Dict[str, Any]) -> Dict[str, Any]:
    clusters_raw = payload.get("clusters") if isinstance(payload, dict) else []
    clusters = [c for c in (clusters_raw or []) if isinstance(c, dict) and int(c.get("size") or 0) >= 2]
    valid_count = int(payload.get("valid_count") or 0)
    pair_count = int(payload.get("pair_count") or 0)
    top_pairs_limit = int(payload.get("top_pairs") or 0)
    hints: List[Dict[str, Any]] = []

    def add_hint(level: str, title: str, detail: str, signal: str = ""):
        item = {"level": level, "title": title, "detail": detail, "source": "Cluster"}
        if signal:
            item["signal"] = signal
        hints.append(item)

    largest_cluster_size = 0
    largest_cluster_ratio = 0.0
    cohesion_sum = 0.0
    cohesion_count = 0
    high_cohesion_clusters = 0
    high_malicious_clusters = 0
    network_counter: Dict[str, int] = {}
    jarm_counter: Dict[str, int] = {}
    cert_counter: Dict[str, int] = {}

    for c in clusters:
        size = int(c.get("size") or 0)
        largest_cluster_size = max(largest_cluster_size, size)
        ratio = (size / valid_count) if valid_count > 0 else 0.0
        largest_cluster_ratio = max(largest_cluster_ratio, ratio)
        cohesion = c.get("cohesion")
        if cohesion is not None:
            try:
                cohesion_f = float(cohesion)
                cohesion_sum += cohesion_f
                cohesion_count += 1
                if cohesion_f >= 65 and size >= 3:
                    high_cohesion_clusters += 1
            except Exception:
                pass
        vt = c.get("vt_summary") if isinstance(c.get("vt_summary"), dict) else None
        mal_total = int((vt or {}).get("malicious_total") or 0)
        if size >= 3 and mal_total >= ((size + 1) // 2):
            high_malicious_clusters += 1

        for field, counter in (("top_network", network_counter), ("top_jarm", jarm_counter), ("top_cert", cert_counter)):
            top = c.get(field) if isinstance(c.get(field), list) else []
            if not top:
                continue
            ent = top[0]
            if not isinstance(ent, (list, tuple)) or len(ent) < 2:
                continue
            key = str(ent[0] or "")
            count = int(ent[1] or 0)
            if key and key != "-" and count >= 2:
                counter[key] = counter.get(key, 0) + count

    top_network = _top_counter(network_counter)
    top_jarm = _top_counter(jarm_counter)
    top_cert = _top_counter(cert_counter)
    avg_cohesion = (cohesion_sum / cohesion_count) if cohesion_count else None

    if not clusters:
        if valid_count >= 2:
            add_hint("warn", "Weak Cluster Connectivity", "No cluster with 2+ IPs met the current relationship threshold.", "cluster")
    else:
        if largest_cluster_size >= 4 and largest_cluster_ratio >= 0.55:
            add_hint("high", "Dominant Cluster", f"Largest cluster has {largest_cluster_size}/{valid_count or largest_cluster_size} IPs ({round(largest_cluster_ratio * 100)}%).", "cluster_size")
        elif len(clusters) >= 3:
            add_hint("mid", "Multi-cluster Layout", f"{len(clusters)} clusters were identified, suggesting segmented infrastructure.", "cluster_count")
        if high_cohesion_clusters > 0:
            lvl = "high" if high_cohesion_clusters >= 2 else "mid"
            add_hint(lvl, "High Cohesion Cluster", f"{high_cohesion_clusters} cluster(s) show cohesion ≥ 65.", "cohesion")
        if high_malicious_clusters > 0:
            add_hint("high", "Malicious Cluster Core", f"{high_malicious_clusters} cluster(s) have high malicious density in VT summary.", "vt_cluster")

    if top_network.get("key") and int(top_network.get("count") or 0) >= 4:
        add_hint("mid", "Cluster Network Reuse", f"Cluster footprints repeatedly include network {top_network['key']} ({top_network['count']}).", "network")
    if top_jarm.get("key") and int(top_jarm.get("count") or 0) >= 3:
        add_hint("high", "Cluster JARM Reuse", f"{top_jarm['count']} cluster-IP observations share JARM {_short_token(top_jarm['key'], head=10, tail=6)}.", "jarm")
    if top_cert.get("key") and int(top_cert.get("count") or 0) >= 2:
        lvl = "high" if int(top_cert.get("count") or 0) >= 3 else "mid"
        add_hint(lvl, "Cluster Certificate Reuse", f"{top_cert['count']} cluster-IP observations share cert {_short_token(top_cert['key'], head=10, tail=6)}.", "cert_sha256")

    pair_gate = payload.get("pair_gate") if isinstance(payload.get("pair_gate"), dict) else None
    if pair_gate and pair_gate.get("enabled"):
        kept = int(pair_gate.get("kept") or 0)
        dropped = int(pair_gate.get("dropped") or 0)
        total = kept + dropped
        if total >= 20 and dropped / max(1, total) >= 0.75:
            add_hint("info", "Pair Gate Filtering", f"{dropped}/{total} candidate edges were filtered as weak links.", "pair_gate")

    oversized = int(payload.get("bucket_oversized_count") or 0)
    truncated = int(payload.get("bucket_truncated_count") or 0)
    if oversized > 0:
        msg = f"{oversized} oversized feature buckets detected"
        if truncated > 0:
            msg += f"; {truncated} truncated"
        msg += ". Consider conservative profile or higher-quality signals for very large IP sets."
        add_hint("warn", "Bucket Overflow Applied", msg, "bucket_overflow")

    if top_pairs_limit > 0 and pair_count >= top_pairs_limit:
        add_hint("info", "Pair Result Limit Hit", f"Returned pairs reached the configured Top pairs limit ({top_pairs_limit}).", "top_pairs")

    return {
        "hints": hints,
        "characteristics": {
            "cluster_count": len(clusters),
            "pair_count": pair_count,
            "largest_cluster_size": largest_cluster_size,
            "largest_cluster_ratio": largest_cluster_ratio,
            "average_cohesion": avg_cohesion,
            "high_cohesion_clusters": high_cohesion_clusters,
            "high_malicious_clusters": high_malicious_clusters,
            "top_cluster_network": top_network,
            "top_cluster_jarm": top_jarm,
            "top_cluster_cert": top_cert,
        },
    }


def _build_relationship_graph(
    pairs: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    ip_features: Dict[str, Dict[str, Any]],
    *,
    edge_limit: int = 600,
    node_limit: int = 400,
) -> Dict[str, Any]:
    selected: List[Dict[str, Any]] = []
    nodes_seen: Set[str] = set()
    for p in pairs or []:
        a = str((p or {}).get("a") or "")
        b = str((p or {}).get("b") or "")
        if not a or not b:
            continue
        add_count = (0 if a in nodes_seen else 1) + (0 if b in nodes_seen else 1)
        if nodes_seen and len(nodes_seen) + add_count > node_limit:
            continue
        selected.append(p)
        nodes_seen.add(a)
        nodes_seen.add(b)
        if len(selected) >= edge_limit:
            break

    ip_to_cluster: Dict[str, int] = {}
    for idx, c in enumerate(clusters or []):
        for ip in c.get("ips") if isinstance(c, dict) and isinstance(c.get("ips"), list) else []:
            ip_to_cluster[str(ip)] = idx + 1

    degree: Dict[str, int] = defaultdict(int)
    for p in selected:
        a = str(p.get("a") or "")
        b = str(p.get("b") or "")
        degree[a] += 1
        degree[b] += 1

    nodes = []
    for ip in sorted(nodes_seen):
        f = ip_features.get(ip) or {}
        nodes.append({
            "id": ip,
            "label": ip,
            "country": str(f.get("country") or "-"),
            "asn": str(f.get("asn") or "-"),
            "csp": str(f.get("csp_label") or ""),
            "cluster_idx": int(ip_to_cluster.get(ip) or 0),
            "degree": int(degree.get(ip) or 0),
        })

    edges = []
    for idx, p in enumerate(selected):
        a = str(p.get("a") or "")
        b = str(p.get("b") or "")
        ca = int(ip_to_cluster.get(a) or 0)
        cb = int(ip_to_cluster.get(b) or 0)
        edges.append({
            "id": f"e{idx}",
            "source": a,
            "target": b,
            "score": int(p.get("relationship_strength") or p.get("score") or 0),
            "relationship_strength": int(p.get("relationship_strength") or p.get("score") or 0),
            "legacy_score": int(p.get("score") or 0),
            "evidence": p.get("evidence") or [],
            "same_cluster": bool(ca > 0 and cb > 0 and ca == cb),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "total_pair_count": len(pairs or []),
        "node_limit": int(node_limit),
        "edge_limit": int(edge_limit),
    }

def handle_ip_relationship_analysis(
    handler,
    *,
    gather_ip_map_fn=None,
    trusted_local_dns_context: Optional[Dict[str, Dict[str, Any]]] = None,
    trusted_local_dns_context_metadata: Optional[Dict[str, Any]] = None,
    trusted_misp_context: Optional[Dict[str, Any]] = None,
    body: Optional[bytes] = None,
):
    """Similarity analysis among a user-supplied infected-host IP list.

    IMPORTANT: This endpoint used to be "shared domain" relationships.
    It is now repurposed for botnet infected-host profiling.

    Input JSON:
      - ips: string or list
      - min_score: int (default 40)
      - top_pairs: int (default 200)
      - max_neighbors_per_ip: int (default 30)
      - include_vt: bool (default true)
      - vt_workers: int (default 8)
      - vt_budget: int (default 2000)
      - candidate_limit: int (default 500000, clamped to 1000..2000000)

    GeoIP fallback:
      - If VT is disabled/unavailable/missing per-IP context, we can optionally
        use a MaxMind mmdb file to fill country codes.
      - Path lookup order: config.geoip_mmdb_path (if present) > env GEOIP_MMDB_PATH.

    Returns:
      - pairs: top similarity edges (a,b,score,evidence)
      - clusters: union-find clusters based on score>=min_score
      - ip_features: per-ip extracted features for UI (asn/owner/csp/country/vt)
      - country_summary: for bubble map
    """

    if body is None:
        length = int(handler.headers.get("Content-Length", "0"))
        body = handler.rfile.read(length) if length > 0 else b""
    try:
        data = json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return handler._send_json({"error": "invalid json"}, 400)

    try:
        valid_ips, invalid = _validate_relationship_request(data)
    except RelationshipRequestError as exc:
        return handler._send_json(exc.payload, exc.status_code)

    try:
        lookback_days = int(data.get("lookback_days", 30))
    except Exception:
        lookback_days = 30
    lookback_days = min(max(lookback_days, 0), 365)
    analysis_as_of = int(time.time())
    analysis_cutoff = analysis_as_of - (lookback_days * 86400) if lookback_days else 0

    local_context_raw = trusted_local_dns_context
    if gather_ip_map_fn is not None:
        try:
            local_context_raw = gather_ip_map_fn()
        except Exception:
            logger.exception("Failed to snapshot local DNS context")
            local_context_raw = {}
    local_dns_context, local_context_truncation = _sanitize_local_dns_context(
        local_context_raw, allowed_ips=set(valid_ips), include_metadata=True
    )
    if isinstance(trusted_local_dns_context_metadata, dict):
        for key in (
            "ips_omitted",
            "domains_omitted",
            "record_types_omitted",
            "decoders_omitted",
            "change_timestamps_omitted",
        ):
            local_context_truncation[key] = max(
                int(local_context_truncation.get(key) or 0),
                int(trusted_local_dns_context_metadata.get(key) or 0),
            )
        for key in ("byte_limit_reached", "ip_limit_reached", "truncated"):
            local_context_truncation[key] = bool(
                local_context_truncation.get(key)
                or trusted_local_dns_context_metadata.get(key)
            )
    for local_entry in local_dns_context.values():
        change_timestamps = [
            ts for ts in (local_entry.get("change_timestamps") or [])
            if analysis_cutoff == 0 or int(ts) >= analysis_cutoff
        ]
        if change_timestamps:
            local_entry["change_timestamps"] = change_timestamps
        else:
            local_entry.pop("change_timestamps", None)
    misp_ip_context: Dict[str, Dict[str, Any]] = {}
    if isinstance(trusted_misp_context, dict):
        raw_event = trusted_misp_context.get("event")
        event = raw_event if isinstance(raw_event, dict) else {}
        event_key = str(event.get("uuid") or event.get("id") or "").strip()[:128]
        campaign_labels = set()
        for raw_tag in event.get("tags") or []:
            tag = str(raw_tag or "").strip()[:160]
            tag_lower = tag.lower()
            if tag and any(
                marker in tag_lower
                for marker in ("botnet", "campaign", "malware", "threat-actor")
            ):
                campaign_labels.add(tag)
        for raw_galaxy in event.get("galaxies") or []:
            if not isinstance(raw_galaxy, dict):
                continue
            galaxy_kind = " ".join(
                str(raw_galaxy.get(key) or "") for key in ("name", "type")
            ).lower()
            if not any(
                marker in galaxy_kind
                for marker in ("botnet", "campaign", "malware", "threat actor")
            ):
                continue
            for raw_cluster in raw_galaxy.get("clusters") or []:
                if isinstance(raw_cluster, dict):
                    label = str(raw_cluster.get("value") or "").strip()[:160]
                else:
                    label = str(raw_cluster or "").strip()[:160]
                if label:
                    campaign_labels.add(label)
        bounded_campaign_labels = sorted(campaign_labels)[:8]
        attributes = trusted_misp_context.get("attributes")
        if event_key and isinstance(attributes, list):
            allowed_ips = set(valid_ips)
            for attribute in attributes:
                if not isinstance(attribute, dict) or attribute.get("eligible_for_scoring") is not True:
                    continue
                try:
                    attribute_ts = int(attribute.get("timestamp") or 0)
                except Exception:
                    attribute_ts = 0
                if analysis_cutoff > 0 and attribute_ts > 0 and attribute_ts < analysis_cutoff:
                    continue
                ip = str(attribute.get("ip") or "").strip()
                if ip in allowed_ips:
                    misp_ip_context[ip] = {
                        "event_id": event_key,
                        "campaigns": bounded_campaign_labels,
                    }

    def _to_int(name, default, min_v=None, max_v=None):
        raw = data.get(name, default)
        try:
            n = int(raw)
        except Exception:
            n = int(default)
        if min_v is not None and n < min_v:
            n = min_v
        if max_v is not None and n > max_v:
            n = max_v
        return n

    def _to_bool(name, default=False):
        raw = data.get(name, default)
        if isinstance(raw, bool):
            return raw
        if raw is None:
            return bool(default)
        s = str(raw).strip().lower()
        if s in ("1", "true", "t", "yes", "y", "on"):
            return True
        if s in ("0", "false", "f", "no", "n", "off", ""):
            return False
        return bool(default)

    min_score = _to_int("min_score", 40, 0, 100)
    top_pairs = _to_int("top_pairs", 200, 1, 5000)
    max_neighbors_per_ip = _to_int("max_neighbors_per_ip", 30, 1, 200)

    include_vt = _to_bool("include_vt", True)
    vt_workers = _to_int("vt_workers", 8, 1, 32)
    vt_budget = _to_int("vt_budget", 2000, 0, 5000)
    pair_gate_enabled = _to_bool("pair_gate_enabled", True)
    pair_gate_strong_min = _to_int("pair_gate_strong_min", 1, 0, 3)
    pair_gate_mid_min = _to_int("pair_gate_mid_min", 2, 0, 5)
    pair_gate_fallback_score = _to_int("pair_gate_fallback_score", max(min_score, 55), 0, 100)
    candidate_limit = _to_int("candidate_limit", 500000, 1000, 2000000)

    # GeoIP config (best-effort; optional)
    geoip_mmdb_path = None
    geoip_source = "none"
    try:
        geoip_mmdb_path = getattr(handler, "shared_config", {}).get("geoip_mmdb_path")  # type: ignore
    except Exception:
        geoip_mmdb_path = None
    if geoip_mmdb_path:
        geoip_source = "config"
    if not geoip_mmdb_path:
        geoip_mmdb_path = os.environ.get("GEOIP_MMDB_PATH")
        if geoip_mmdb_path:
            geoip_source = "environment"

    geoip_reader = _load_geoip_reader(geoip_mmdb_path)
    geoip_enabled = bool(geoip_reader)

    vt_enabled = bool(include_vt and get_ip_report)
    ip_scope_metadata = {
        ip: _classify_ip_scope(ip)
        for ip in valid_ips
    }
    vt_eligible_ips = [ip for ip in valid_ips if ip_scope_metadata[ip][1]]
    vt_eligible_count = len(vt_eligible_ips)
    vt_skipped_non_global = len(valid_ips) - vt_eligible_count

    # VT lookup
    vt_attempted = 0
    vt_reports: Dict[str, Any] = {}
    vt_live_lookup_ips: Set[str] = set()
    vt_cache_only_ips: Set[str] = set()

    batch_started = False
    if vt_enabled and begin_cache_batch and end_cache_batch:
        try:
            begin_cache_batch()
            batch_started = True
        except Exception:
            batch_started = False

    try:
        if vt_enabled and vt_budget > 0:
            lookup_ips = vt_eligible_ips[:vt_budget]
            tail_ips = vt_eligible_ips[vt_budget:]
            vt_live_lookup_ips = set(lookup_ips)
            vt_cache_only_ips = set(tail_ips)
            vt_attempted = len(lookup_ips)

            # cache-only for tail (budget limited)
            for ip in tail_ips:
                try:
                    try:
                        vt_reports[ip] = get_ip_report(ip, cache_only=True)
                    except TypeError:
                        vt_reports[ip] = None
                except Exception:
                    vt_reports[ip] = None

            if lookup_ips:
                if vt_workers <= 1 or len(lookup_ips) <= 1:
                    for ip in lookup_ips:
                        try:
                            vt_reports[ip] = get_ip_report(ip)
                        except Exception:
                            vt_reports[ip] = None
                else:
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    def _lookup(ip_str: str):
                        try:
                            return get_ip_report(ip_str)
                        except Exception:
                            return None

                    with ThreadPoolExecutor(max_workers=vt_workers) as ex:
                        futs = {ex.submit(_lookup, ip): ip for ip in lookup_ips}
                        for fut in as_completed(futs):
                            ip = futs[fut]
                            try:
                                vt_reports[ip] = fut.result()
                            except Exception:
                                vt_reports[ip] = None
    finally:
        if batch_started and end_cache_batch:
            try:
                end_cache_batch(flush=True)
            except Exception:
                pass

    # Extract per-IP features
    ip_features: Dict[str, Dict[str, Any]] = {}
    ip_similarity_context: Dict[str, Dict[str, Any]] = {}
    country_map = defaultdict(lambda: {"country": "-", "ip_count": 0, "malicious_ips": 0, "suspicious_ips": 0, "asn_count": 0, "asns": set()})

    for ip in valid_ips:
        rep = vt_reports.get(ip) if vt_enabled else None

        asn = rep.get("asn") if isinstance(rep, dict) else None
        as_owner = rep.get("as_owner") if isinstance(rep, dict) else None
        vt_country = rep.get("country") if isinstance(rep, dict) else None
        malicious = int(rep.get("malicious", 0) or 0) if isinstance(rep, dict) else 0
        suspicious = int(rep.get("suspicious", 0) or 0) if isinstance(rep, dict) else 0
        attrs = _extract_vt_attrs(rep) if isinstance(rep, dict) else {}
        network = str(attrs.get("network") or "").strip()
        network_obj = _parse_network_cidr(network)
        rir = str(attrs.get("regional_internet_registry") or "").strip().upper()
        jarm = _normalize_hash(attrs.get("jarm"), expected_length=62)
        cert_obj = attrs.get("last_https_certificate")
        cert_sha256 = ""
        if isinstance(cert_obj, dict):
            cert_sha256 = _normalize_hash(
                cert_obj.get("thumbprint_sha256"), expected_length=64
            )
        rdap = attrs.get("rdap")
        if not isinstance(rdap, dict):
            rdap = {}
        rdap_name = str(rdap.get("name") or "").strip()
        rdap_name_norm = _normalize_text(rdap_name)
        rdap_type = _normalize_text(rdap.get("type"))
        positive_engines = _extract_positive_vt_engines(attrs)
        try:
            last_analysis_date = int((rep or {}).get("last_analysis_date") or attrs.get("last_analysis_date") or 0)
        except Exception:
            last_analysis_date = 0

        # country fallback
        country = str(vt_country).upper() if vt_country else None
        country_source = "vt" if country and country != "-" else "unknown"
        if not country or country == "-":
            cc = _geoip_country(geoip_reader, ip)
            if cc:
                country = cc
                country_source = "geoip"
        if not country:
            country = "-"

        if not vt_enabled:
            vt_source = "disabled"
        elif not ip_scope_metadata[ip][1]:
            vt_source = "skipped_non_global"
        elif isinstance(rep, dict):
            vt_source = "report" if ip in vt_live_lookup_ips else "cached_report"
        elif ip in vt_live_lookup_ips:
            vt_source = "unavailable"
        elif ip in vt_cache_only_ips:
            vt_source = "cache_miss"
        else:
            vt_source = "budget_exhausted"

        owner_norm = _normalize_owner(as_owner)
        csp_info = _classify_csp(as_owner)

        feat = {
            "ip": ip,
            "scope": ip_scope_metadata[ip][0],
            "vt_eligible": ip_scope_metadata[ip][1],
            "vt_source": vt_source,
            "asn": str(asn) if asn is not None else "-",
            "as_owner": str(as_owner) if as_owner else "-",
            "as_owner_norm": owner_norm,
            "csp": csp_info.get("csp", "other"),
            "csp_label": csp_info.get("csp_label", "Other/Unknown"),
            "csp_major": bool(csp_info.get("csp_major", False)),
            "country": str(country) if country else "-",
            "country_source": country_source,
            "malicious": malicious,
            "suspicious": suspicious,
            "network": network if network else "-",
            "rir": rir if rir else "-",
            "rdap_name": rdap_name if rdap_name else "-",
            "rdap_name_norm": rdap_name_norm,
            "rdap_type": rdap_type if rdap_type else "-",
            "jarm": jarm if jarm else "",
            "cert_sha256": cert_sha256 if cert_sha256 else "",
            "last_analysis_date": last_analysis_date if last_analysis_date > 0 else None,
            "vt_engine_positive_count": len(positive_engines),
            "vt_present": bool(isinstance(rep, dict)),
            "local_dns": local_dns_context.get(ip, {
                "domains": [],
                "record_types": [],
                "decoders": [],
                "count": 0,
                "last_ts": 0,
            }),
            "misp": misp_ip_context.get(ip),
        }
        ip_features[ip] = feat
        ip_similarity_context[ip] = {
            "network_obj": network_obj,
            "positive_engines": positive_engines,
        }

        # country summary for map
        ckey = feat.get("country") or "-"
        ent = country_map[ckey]
        ent["country"] = ckey
        ent["ip_count"] += 1
        if malicious > 0:
            ent["malicious_ips"] += 1
        if suspicious > 0:
            ent["suspicious_ips"] += 1
        ent["asns"].add(feat.get("asn") or "-")

    # finalize country summary (add asn_count)
    country_summary = []
    for v in country_map.values():
        country_summary.append({
            "country": v["country"],
            "ip_count": v["ip_count"],
            "malicious_ips": v["malicious_ips"],
            "suspicious_ips": v["suspicious_ips"],
            "asn_count": len(v.get("asns") or []),
        })
    country_summary.sort(key=lambda x: (-int(x.get("ip_count") or 0), -int(x.get("malicious_ips") or 0), str(x.get("country") or "")))

    # Blocking: build buckets to generate candidate pairs efficiently
    buckets: Dict[str, List[str]] = {}

    def _add_bucket(prefix: str, key: str, ip: str):
        if _is_missing_feature_value(key, csp=(prefix == "csp")):
            return
        buckets.setdefault(f"{prefix}:{key}", []).append(ip)

    for ip, f in ip_features.items():
        local_dns = f.get("local_dns") if isinstance(f.get("local_dns"), dict) else {}
        for domain in (local_dns or {}).get("domains") or []:
            _add_bucket("local-domain", str(domain), ip)
        misp = f.get("misp") if isinstance(f.get("misp"), dict) else {}
        _add_bucket("misp-event", str((misp or {}).get("event_id") or ""), ip)
        for network_key in _network_candidate_keys(ip_similarity_context[ip].get("network_obj")):
            _add_bucket("network-overlap", network_key, ip)
        positive_engines = sorted(
            str(engine) for engine in (ip_similarity_context[ip].get("positive_engines") or [])
            if str(engine).strip()
        )
        for engine in positive_engines:
            _add_bucket("vt-engine", engine, ip)
        _add_bucket("asn", str(f.get("asn") or ""), ip)
        _add_bucket("owner", str(f.get("as_owner_norm") or ""), ip)
        _add_bucket("csp", str(f.get("csp") or ""), ip)
        _add_bucket("country", str(f.get("country") or ""), ip)
        _add_bucket("network", str(f.get("network") or ""), ip)
        _add_bucket("rir", str(f.get("rir") or ""), ip)
        _add_bucket("rdap", str(f.get("rdap_name_norm") or ""), ip)
        _add_bucket("rdap-type", str(f.get("rdap_type") or ""), ip)
        _add_bucket("jarm", str(f.get("jarm") or ""), ip)
        _add_bucket("cert", str(f.get("cert_sha256") or ""), ip)
        if int(f.get("malicious") or 0) > 0:
            _add_bucket("vt-malicious", "positive", ip)
        if int(f.get("suspicious") or 0) > 0:
            _add_bucket("vt-suspicious", "positive", ip)
        analysis_ts = int(f.get("last_analysis_date") or 0)
        if analysis_ts > 0:
            time_window = analysis_ts // (3 * 86400)
            for window_offset in (-1, 0, 1):
                _add_bucket("vt-time", str(time_window + window_offset), ip)
        p24 = _ipv4_prefix24(ip)
        if p24:
            _add_bucket("p24", p24, ip)

    # Hard cap per bucket to avoid quadratic explosion (especially country buckets)
    BUCKET_MAX = _to_int("bucket_max", 450, 50, 2000)

    bucket_overflow_mode = str(data.get("bucket_overflow_mode", "truncate") or "truncate").strip().lower()
    if bucket_overflow_mode not in ("truncate", "skip"):
        bucket_overflow_mode = "truncate"
    bucket_oversized_count = 0
    bucket_truncated_count = 0

    # Stream bucket-generated pairs through scoring. Keep only a bounded heap so
    # large buckets do not materialize every candidate edge or require a full sort.
    import heapq

    seen_pairs: Set[Tuple[str, str]] = set()
    heap_limit = max(int(top_pairs) * 8, int(top_pairs) + 1000)
    heap_limit = min(max(heap_limit, 1000), 50000)
    pair_heap: List[Tuple[int, str, str, Dict[str, Any]]] = []
    pair_gate_kept = 0
    pair_gate_dropped = 0
    candidate_count = 0
    candidate_enumeration_count = 0
    deduped_candidate_count = 0
    candidate_limit_reached = False
    candidate_work_limit = _to_int(
        "candidate_work_limit",
        min(max(candidate_limit * 8, candidate_limit), 2_000_000),
        1,
        5_000_000,
    )
    candidate_work_limit_reached = False
    pair_heap_truncated = False

    # Keep analysis topology independent from response-display limits. Every
    # accepted edge updates the component accumulator, while the bounded heap
    # below controls only which pair details are returned to the client.
    parent: Dict[str, str] = {ip: ip for ip in valid_ips}
    component_size = {ip: 1 for ip in valid_ips}
    component_score_sum = defaultdict(int)
    component_edge_count = defaultdict(int)

    def find(x: str) -> str:
        while parent.get(x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union_edge(x: str, y: str, score: int):
        rx, ry = find(x), find(y)
        if rx == ry:
            component_score_sum[rx] += score
            component_edge_count[rx] += 1
            return
        if component_size[rx] < component_size[ry]:
            rx, ry = ry, rx
        parent[ry] = rx
        component_size[rx] += component_size.pop(ry)
        component_score_sum[rx] += component_score_sum.pop(ry, 0) + score
        component_edge_count[rx] += component_edge_count.pop(ry, 0) + 1

    def _score_and_offer_pair(a: str, b: str):
        nonlocal pair_gate_kept, pair_gate_dropped
        nonlocal candidate_count, candidate_enumeration_count, deduped_candidate_count
        nonlocal candidate_limit_reached, candidate_work_limit_reached, pair_heap_truncated
        if not a or not b or a == b:
            return
        if candidate_enumeration_count >= candidate_work_limit:
            candidate_work_limit_reached = True
            return
        if a > b:
            a, b = b, a
        pair_key = (a, b)
        if pair_key in seen_pairs:
            candidate_enumeration_count += 1
            deduped_candidate_count += 1
            return
        if candidate_count >= candidate_limit:
            candidate_limit_reached = True
            return
        candidate_enumeration_count += 1
        candidate_count += 1
        seen_pairs.add(pair_key)
        fa = ip_features.get(a) or {}
        fb = ip_features.get(b) or {}
        legacy_score, ev = _compare_features(
            a,
            b,
            fa,
            fb,
            ca=ip_similarity_context.get(a),
            cb=ip_similarity_context.get(b),
        )
        assessment = _build_pair_assessment(ev)
        relationship_strength = int(assessment["evidence_score"])
        if relationship_strength < min_score:
            return
        gate_ok, gate_reason = _pair_gate_decision(
            relationship_strength,
            ev,
            min_score,
            enabled=pair_gate_enabled,
            strong_min=pair_gate_strong_min,
            mid_min=pair_gate_mid_min,
            fallback_score=pair_gate_fallback_score,
        )
        if not gate_ok:
            pair_gate_dropped += 1
            return
        pair_gate_kept += 1
        union_edge(a, b, relationship_strength)
        item = {
            "a": a,
            "b": b,
            "score": legacy_score,
            "relationship_strength": relationship_strength,
            "evidence": ev,
            "assessment": assessment,
            "gate_reason": gate_reason,
        }
        heap_key = (relationship_strength, str(a), str(b), item)
        if len(pair_heap) < heap_limit:
            heapq.heappush(pair_heap, heap_key)
        else:
            pair_heap_truncated = True
            # Keep the highest scoring bounded working set; deterministic tie
            # breakers preserve stable output for equal scores.
            if (relationship_strength, str(a), str(b)) > (
                pair_heap[0][0], pair_heap[0][1], pair_heap[0][2]
            ):
                heapq.heapreplace(pair_heap, heap_key)

    bucket_priority = {
        "local-domain": 0,
        "misp-event": 1,
        "cert": 1,
        "jarm": 2,
        "network": 3,
        "network-overlap": 4,
        "vt-engine": 5,
        "owner": 6,
        "asn": 7,
        "rdap": 8,
        "csp": 9,
        "rdap-type": 10,
        "vt-malicious": 11,
        "vt-suspicious": 12,
        "vt-time": 13,
        "rir": 14,
        "country": 15,
        "p24": 16,
    }

    def _bucket_sort_key(item):
        bucket_key = item[0]
        prefix = bucket_key.split(":", 1)[0]
        return (bucket_priority.get(prefix, 99), bucket_key)

    for k, ips in sorted(buckets.items(), key=_bucket_sort_key):
        if candidate_limit_reached or candidate_work_limit_reached:
            break
        if not ips or len(ips) < 2:
            continue
        uniq, bucket_was_truncated = _bounded_bucket_members(k, ips, BUCKET_MAX)
        if bucket_was_truncated:
            bucket_oversized_count += 1
            if bucket_overflow_mode == "skip":
                continue
            bucket_truncated_count += 1
        for i in range(len(uniq)):
            if candidate_limit_reached or candidate_work_limit_reached:
                break
            a = uniq[i]
            for j in range(i + 1, len(uniq)):
                _score_and_offer_pair(a, uniq[j])
                if candidate_limit_reached or candidate_work_limit_reached:
                    break

    ranked_pairs = [entry[3] for entry in sorted(pair_heap, key=lambda x: (-x[0], x[1], x[2]))]

    # Neighbor cap per IP (keep strongest edges per node from bounded ranked set)
    kept: List[Dict[str, Any]] = []
    neigh_count = defaultdict(int)

    for it in ranked_pairs:
        a = str(it.get("a") or "")
        b = str(it.get("b") or "")
        if not a or not b:
            continue
        if neigh_count[a] >= max_neighbors_per_ip or neigh_count[b] >= max_neighbors_per_ip:
            continue
        kept.append(it)
        neigh_count[a] += 1
        neigh_count[b] += 1
        if len(kept) >= top_pairs:
            break

    clusters: Dict[str, List[str]] = {}
    for ip in valid_ips:
        clusters.setdefault(find(ip), []).append(ip)

    def _top_k(items: List[str], k: int = 3):
        freq = defaultdict(int)
        for s in items:
            if s is None:
                continue
            ss = str(s).strip()
            if not ss or ss in ("-", "N/A"):
                continue
            freq[ss] += 1
        return sorted(freq.items(), key=lambda x: (-x[1], x[0]))[:k]

    cluster_list = []
    for root, ips in clusters.items():
        ips_sorted = sorted(ips)
        feats = [ip_features.get(ip) or {} for ip in ips_sorted]
        top_asn = _top_k([f.get("asn") for f in feats])
        top_owner = _top_k([f.get("as_owner") for f in feats])
        top_country = _top_k([f.get("country") for f in feats])
        top_csp = _top_k([f.get("csp_label") for f in feats])
        top_network = _top_k([f.get("network") for f in feats])
        top_rir = _top_k([f.get("rir") for f in feats])
        top_jarm_raw = _top_k([f.get("jarm") for f in feats])
        top_cert_raw = _top_k([f.get("cert_sha256") for f in feats])
        top_jarm = [(_short_token(x[0]), x[1]) for x in top_jarm_raw]
        top_cert = [(_short_token(x[0]), x[1]) for x in top_cert_raw]

        # VT summary per cluster
        ms = 0
        ss = 0
        for f in feats:
            if int(f.get("malicious") or 0) > 0:
                ms += 1
            if int(f.get("suspicious") or 0) > 0:
                ss += 1

        cohesion = None
        if component_edge_count.get(root):
            cohesion = component_score_sum[root] / component_edge_count[root]

        cluster_list.append({
            "cluster_id": root,
            "size": len(ips_sorted),
            "ips": ips_sorted,
            "cohesion": cohesion,
            "top_asn": top_asn,
            "top_owner": top_owner,
            "top_country": top_country,
            "top_csp": top_csp,
            "top_network": top_network,
            "top_rir": top_rir,
            "top_jarm": top_jarm,
            "top_cert": top_cert,
            "vt_summary": {
                "malicious_total": ms,
                "suspicious_total": ss,
            } if vt_enabled else None,
        })

    cluster_list.sort(key=lambda x: (-int(x.get("size") or 0), -(float(x.get("cohesion") or 0.0)), str(x.get("cluster_id") or "")))

    # cleanup geoip reader
    try:
        if geoip_reader:
            geoip_reader.close()
    except Exception:
        pass

    unique_candidate_count = len(seen_pairs)
    vt_report_count = sum(1 for report in vt_reports.values() if isinstance(report, dict))
    # No eligible addresses means the global-only VT policy covered every
    # address it was allowed to query; it is not a partial-coverage warning.
    vt_report_coverage = vt_report_count / vt_eligible_count if vt_eligible_count else 1.0
    local_context_truncated = bool(local_context_truncation.get("truncated"))
    candidate_analysis_complete = not (
        bucket_oversized_count > 0
        or candidate_limit_reached
        or candidate_work_limit_reached
        or local_context_truncated
    )
    cluster_topology_complete = candidate_analysis_complete
    pair_display_truncated = len(kept) < len(ranked_pairs)
    pair_detail_complete = not pair_heap_truncated and not pair_display_truncated
    enrichment_complete = not vt_enabled or vt_eligible_count == 0 or vt_report_coverage >= 1.0
    analysis_complete = (
        candidate_analysis_complete
        and cluster_topology_complete
        and pair_detail_complete
        and enrichment_complete
    )
    warning_codes = []
    if bucket_oversized_count > 0:
        warning_codes.append("bucket_truncated" if bucket_truncated_count > 0 else "bucket_skipped")
    if candidate_limit_reached:
        warning_codes.append("candidate_limit_reached")
    if candidate_work_limit_reached:
        warning_codes.append("candidate_work_limit_reached")
    if pair_heap_truncated:
        warning_codes.append("pair_heap_truncated")
    if pair_display_truncated and not pair_heap_truncated:
        warning_codes.append("pair_display_truncated")
    if local_context_truncated:
        warning_codes.append("local_context_truncated")
    if vt_enabled and vt_eligible_count > 0 and vt_report_coverage < 1.0:
        warning_codes.append("vt_partial_coverage")

    quality = {
        "analysis_complete": bool(analysis_complete),
        "candidate_analysis_complete": bool(candidate_analysis_complete),
        "candidate_generation_complete": bool(candidate_analysis_complete),
        "cluster_topology_complete": bool(cluster_topology_complete),
        "pair_detail_complete": bool(pair_detail_complete),
        "enrichment_complete": bool(enrichment_complete),
        "candidate_limit": int(candidate_limit),
        "candidate_limit_reached": bool(candidate_limit_reached),
        "candidate_work_limit": int(candidate_work_limit),
        "candidate_work_limit_reached": bool(candidate_work_limit_reached),
        "candidate_enumeration_count": int(candidate_enumeration_count),
        "unique_candidate_count": int(unique_candidate_count),
        "evaluated_candidate_count": int(unique_candidate_count),
        "deduped_candidate_count": int(deduped_candidate_count),
        "bucket_oversized_count": int(bucket_oversized_count),
        "bucket_truncated_count": int(bucket_truncated_count),
        "pair_heap_truncated": bool(pair_heap_truncated),
        "local_context_truncated": bool(local_context_truncated),
        "local_context_truncation": local_context_truncation,
        "vt_enabled": bool(vt_enabled),
        "vt_attempted": int(vt_attempted),
        "vt_eligible_count": int(vt_eligible_count),
        "vt_skipped_non_global": int(vt_skipped_non_global),
        "vt_report_count": int(vt_report_count),
        "vt_report_coverage": float(vt_report_coverage),
        "warning_codes": warning_codes,
    }

    for pair in kept:
        assessment = pair.get("assessment") if isinstance(pair.get("assessment"), dict) else {}
        source_count = int((assessment or {}).get("independent_source_count") or 0)
        verdict = str((assessment or {}).get("verdict") or "insufficient_evidence")
        if analysis_complete and source_count >= 2 and verdict == "same_botnet_likely":
            confidence_level = "high"
        elif candidate_analysis_complete and int((assessment or {}).get("evidence_score") or 0) >= 35:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        assessment["confidence"] = {
            "level": confidence_level,
            "analysis_complete": bool(analysis_complete),
            "limitations": list(warning_codes),
        }
        pair["assessment"] = assessment

    exported_misp_context = (
        redact_misp_context_for_export(trusted_misp_context)
        if isinstance(trusted_misp_context, dict)
        else None
    )
    restricted_misp_export = bool(
        isinstance(exported_misp_context, dict)
        and exported_misp_context.get("context_redacted")
    )
    export_pairs = kept
    export_ip_features = ip_features
    if restricted_misp_export:
        export_pairs = []
        for pair in kept:
            sanitized_pair = dict(pair)
            sanitized_evidence = []
            for item in pair.get("evidence") or []:
                sanitized_item = dict(item) if isinstance(item, dict) else item
                if (
                    isinstance(sanitized_item, dict)
                    and sanitized_item.get("type")
                    in {"shared_misp_event", "shared_misp_campaign"}
                ):
                    sanitized_item["value"] = "[restricted]"
                sanitized_evidence.append(sanitized_item)
            sanitized_pair["evidence"] = sanitized_evidence
            raw_assessment = pair.get("assessment")
            if isinstance(raw_assessment, dict):
                sanitized_assessment = dict(raw_assessment)
                assessment_evidence = []
                for item in raw_assessment.get("evidence") or []:
                    sanitized_item = dict(item) if isinstance(item, dict) else item
                    if (
                        isinstance(sanitized_item, dict)
                        and sanitized_item.get("type")
                        in {"shared_misp_event", "shared_misp_campaign"}
                    ):
                        sanitized_item["value"] = "[restricted]"
                    assessment_evidence.append(sanitized_item)
                sanitized_assessment["evidence"] = assessment_evidence
                sanitized_pair["assessment"] = sanitized_assessment
            export_pairs.append(sanitized_pair)

        export_ip_features = {}
        for ip, feature in ip_features.items():
            sanitized_feature = dict(feature)
            sanitized_feature.pop("misp", None)
            export_ip_features[ip] = sanitized_feature

    response = {
        "status": "ok",
        "submitted_count": len(valid_ips) + len(invalid),
        "valid_count": len(valid_ips),
        "invalid_count": len(invalid),
        "invalid_inputs": invalid[:200],
        "min_score": int(min_score),
        "top_pairs": int(top_pairs),
        "max_neighbors_per_ip": int(max_neighbors_per_ip),
        "bucket_max": int(BUCKET_MAX),
        "bucket_overflow_mode": bucket_overflow_mode,
        "bucket_oversized_count": int(bucket_oversized_count),
        "bucket_truncated_count": int(bucket_truncated_count),
        "pairs": export_pairs,
        "pair_count": len(kept),
        "candidate_count": int(candidate_count),
        "candidate_enumeration_count": int(candidate_enumeration_count),
        "candidate_limit": int(candidate_limit),
        "unique_candidate_count": int(unique_candidate_count),
        "candidate_limit_reached": bool(candidate_limit_reached),
        "candidate_work_limit": int(candidate_work_limit),
        "candidate_work_limit_reached": bool(candidate_work_limit_reached),
        "analysis_complete": bool(analysis_complete),
        "deduped_candidate_count": int(deduped_candidate_count),
        "pair_heap_limit": int(heap_limit),
        "pair_gate": {
            "enabled": bool(pair_gate_enabled),
            "kept": int(pair_gate_kept),
            "dropped": int(pair_gate_dropped),
            "strong_min": int(pair_gate_strong_min),
            "mid_min": int(pair_gate_mid_min),
            "fallback_score": int(pair_gate_fallback_score),
        },
        "clusters": cluster_list,
        "vt_enabled": vt_enabled,
        "vt_attempted": vt_attempted,
        "vt_eligible_count": int(vt_eligible_count),
        "vt_skipped_non_global": int(vt_skipped_non_global),
        "vt_report_count": int(vt_report_count),
        "vt_report_coverage": float(vt_report_coverage),
        "vt_budget": vt_budget,
        "vt_workers": vt_workers,
        "geoip_enabled": geoip_enabled,
        "geoip_source": geoip_source,
        "analysis_window": {
            "lookback_days": int(lookback_days),
            "as_of": int(analysis_as_of),
            "cutoff": int(analysis_cutoff) if analysis_cutoff else None,
        },
        "quality": quality,
        "score_semantics": {
            "score": "legacy_capped_similarity",
            "relationship_strength": "capped_relationship_strength",
            "assessment": "conservative_botnet_verdict",
            "botnet_evidence_score": "direct_campaign_or_family_evidence",
            "same_botnet_likely_requires_independent_sources": True,
            "model_version": 2,
        },
        "input_context": {
            "misp": exported_misp_context,
            "misp_evidence_export_policy": (
                "restricted_values_redacted_scores_preserved"
                if restricted_misp_export
                else "values_exported"
            ),
            "local_dns_ip_count": len(local_dns_context),
        },
        "ip_features": export_ip_features,
        "country_summary": country_summary,
        "note": (
            "Relationship strength combines VT/GeoIP infrastructure features with bounded, "
            "server-observed DNS provenance; it is not by itself a same-botnet verdict."
        ),
    }
    insight_payload = _build_relationship_insights(response)
    response["insights"] = insight_payload.get("hints", [])
    response["characteristics"] = insight_payload.get("characteristics", {})
    response["graph"] = _build_relationship_graph(
        export_pairs, cluster_list, export_ip_features
    )
    return handler._send_json(response)
