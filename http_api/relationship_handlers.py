from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from vt_lookup import begin_cache_batch, end_cache_batch, get_ip_report
except Exception:
    begin_cache_batch = None
    end_cache_batch = None
    get_ip_report = None

logger = logging.getLogger(__name__)


def _parse_ip_tokens(raw: Any) -> Tuple[List[str], List[str]]:
    """Return (valid_ips, invalid_tokens). De-dupes while preserving order."""
    import ipaddress as _ip

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
    else:
        return ([], [])

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
            ip_s = str(_ip.ip_address(tok))
            if ip_s not in seen_valid:
                seen_valid.add(ip_s)
                valid.append(ip_s)
        except Exception:
            invalid.append(tok)

    return (valid, invalid)


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


def _compare_features(a_ip: str, b_ip: str, fa: Dict[str, Any], fb: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    """Return (score, evidence list). Score is capped to 100."""

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

    # Infra similarity signals
    if a_asn and b_asn and a_asn == b_asn:
        score += 25
        ev.append({"type": "same_asn", "value": a_asn, "weight": 25})

    if a_owner_n and b_owner_n and a_owner_n == b_owner_n:
        score += 20
        ev.append({"type": "same_owner", "value": fa.get("as_owner") or "-", "weight": 20})

    if a_csp and b_csp and a_csp == b_csp and a_csp != "other":
        score += 15
        ev.append({"type": "same_csp", "value": fa.get("csp_label") or a_csp, "weight": 15})

    if a_country and b_country and a_country == b_country and a_country != "-":
        score += 5
        ev.append({"type": "same_country", "value": a_country, "weight": 5})

    # Network proximity: can be misleading for infected hosts on residential/mobile ISPs.
    # Make it strong only when the IPs look like hosted infrastructure.
    p24a = _ipv4_prefix24(a_ip)
    p24b = _ipv4_prefix24(b_ip)
    if p24a and p24b and p24a == p24b:
        hosted_hint = False
        if (fa.get("csp") and fa.get("csp") != "other") or (fb.get("csp") and fb.get("csp") != "other"):
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

    if score > 100:
        score = 100

    return (score, ev)


def handle_ip_relationship_analysis(handler, *, gather_ip_map_fn=None):
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

    length = int(handler.headers.get("Content-Length", "0"))
    body = handler.rfile.read(length) if length > 0 else b""
    try:
        data = json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return handler._send_json({"error": "invalid json"}, 400)

    valid_ips, invalid = _parse_ip_tokens(data.get("ips"))
    if not valid_ips:
        return handler._send_json({"error": "no valid ips", "invalid_inputs": invalid[:200]}, 400)

    max_ips = 10000
    if len(valid_ips) > max_ips:
        return handler._send_json({"error": f"too many ips (max {max_ips})"}, 400)

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

    min_score = _to_int("min_score", 40, 0, 100)
    top_pairs = _to_int("top_pairs", 200, 1, 5000)
    max_neighbors_per_ip = _to_int("max_neighbors_per_ip", 30, 1, 200)

    include_vt = bool(data.get("include_vt", True))
    vt_workers = _to_int("vt_workers", 8, 1, 32)
    vt_budget = _to_int("vt_budget", 2000, 0, 5000)

    # GeoIP config (best-effort; optional)
    geoip_mmdb_path = None
    try:
        geoip_mmdb_path = getattr(handler, "shared_config", {}).get("geoip_mmdb_path")  # type: ignore
    except Exception:
        geoip_mmdb_path = None
    if not geoip_mmdb_path:
        geoip_mmdb_path = os.environ.get("GEOIP_MMDB_PATH")

    geoip_reader = _load_geoip_reader(geoip_mmdb_path)
    geoip_enabled = bool(geoip_reader)

    vt_enabled = bool(include_vt and get_ip_report)

    # VT lookup
    vt_attempted = 0
    vt_reports: Dict[str, Any] = {}

    batch_started = False
    if vt_enabled and begin_cache_batch and end_cache_batch:
        try:
            begin_cache_batch()
            batch_started = True
        except Exception:
            batch_started = False

    try:
        if vt_enabled and vt_budget > 0:
            lookup_ips = valid_ips[:vt_budget]
            tail_ips = valid_ips[vt_budget:]
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
    country_map = defaultdict(lambda: {"country": "-", "ip_count": 0, "malicious_ips": 0, "suspicious_ips": 0, "asn_count": 0, "asns": set()})

    for ip in valid_ips:
        rep = vt_reports.get(ip) if vt_enabled else None

        asn = rep.get("asn") if isinstance(rep, dict) else None
        as_owner = rep.get("as_owner") if isinstance(rep, dict) else None
        vt_country = rep.get("country") if isinstance(rep, dict) else None
        malicious = int(rep.get("malicious", 0) or 0) if isinstance(rep, dict) else 0
        suspicious = int(rep.get("suspicious", 0) or 0) if isinstance(rep, dict) else 0

        # country fallback
        country = str(vt_country).upper() if vt_country else None
        if not country or country == "-":
            cc = _geoip_country(geoip_reader, ip)
            if cc:
                country = cc
        if not country:
            country = "-"

        owner_norm = _normalize_owner(as_owner)
        csp_info = _classify_csp(as_owner)

        feat = {
            "ip": ip,
            "asn": str(asn) if asn is not None else "-",
            "as_owner": str(as_owner) if as_owner else "-",
            "as_owner_norm": owner_norm,
            "csp": csp_info.get("csp", "other"),
            "csp_label": csp_info.get("csp_label", "Other/Unknown"),
            "csp_major": bool(csp_info.get("csp_major", False)),
            "country": str(country) if country else "-",
            "malicious": malicious,
            "suspicious": suspicious,
            "vt_present": bool(isinstance(rep, dict)),
        }
        ip_features[ip] = feat

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
        if not key or key == "-":
            return
        buckets.setdefault(f"{prefix}:{key}", []).append(ip)

    for ip, f in ip_features.items():
        _add_bucket("asn", str(f.get("asn") or ""), ip)
        _add_bucket("owner", str(f.get("as_owner_norm") or ""), ip)
        _add_bucket("csp", str(f.get("csp") or ""), ip)
        _add_bucket("country", str(f.get("country") or ""), ip)
        p24 = _ipv4_prefix24(ip)
        if p24:
            _add_bucket("p24", p24, ip)

    # Hard cap per bucket to avoid quadratic explosion (especially country buckets)
    BUCKET_MAX = int(data.get("bucket_max", 450) or 450)
    if BUCKET_MAX < 50:
        BUCKET_MAX = 50
    if BUCKET_MAX > 2000:
        BUCKET_MAX = 2000

    # Candidate pairs set: store per pair computed once
    candidates: Set[Tuple[str, str]] = set()

    for k, ips in buckets.items():
        if not ips or len(ips) < 2:
            continue
        if len(ips) > BUCKET_MAX:
            # Skip huge buckets (usually country buckets) to keep runtime bounded.
            continue
        uniq = sorted(set(ips))
        for i in range(len(uniq)):
            a = uniq[i]
            for j in range(i + 1, len(uniq)):
                b = uniq[j]
                candidates.add((a, b))

    # Compare candidates; keep top neighbors per IP
    per_ip_neighbors: Dict[str, List[Tuple[int, str, str, List[Dict[str, Any]]]]] = defaultdict(list)
    all_pairs: List[Dict[str, Any]] = []

    for (a, b) in candidates:
        fa = ip_features.get(a) or {}
        fb = ip_features.get(b) or {}
        sc, ev = _compare_features(a, b, fa, fb)
        if sc <= 0:
            continue
        # We still compute all, then filter by per-ip neighbor cap below
        item = {"a": a, "b": b, "score": sc, "evidence": ev}
        all_pairs.append(item)

    # Sort by score desc
    all_pairs.sort(key=lambda x: (-int(x.get("score") or 0), str(x.get("a") or ""), str(x.get("b") or "")))

    # Neighbor cap per IP (keep strongest edges per node)
    kept: List[Dict[str, Any]] = []
    neigh_count = defaultdict(int)

    for it in all_pairs:
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

    # Cluster using union-find on edges with score>=min_score
    parent: Dict[str, str] = {ip: ip for ip in valid_ips}

    def find(x):
        while parent.get(x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for it in kept:
        if int(it.get("score") or 0) >= min_score:
            union(str(it.get("a")), str(it.get("b")))

    clusters: Dict[str, List[str]] = {}
    for ip in valid_ips:
        clusters.setdefault(find(ip), []).append(ip)

    # Cohesion: avg score of in-cluster edges (from kept list)
    cluster_edges_score_sum = defaultdict(int)
    cluster_edges_n = defaultdict(int)
    for it in kept:
        a = str(it.get("a") or "")
        b = str(it.get("b") or "")
        sc = int(it.get("score") or 0)
        if sc < min_score:
            continue
        ra = find(a)
        rb = find(b)
        if ra != rb:
            continue
        cluster_edges_score_sum[ra] += sc
        cluster_edges_n[ra] += 1

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

        # VT summary per cluster
        ms = 0
        ss = 0
        for f in feats:
            if int(f.get("malicious") or 0) > 0:
                ms += 1
            if int(f.get("suspicious") or 0) > 0:
                ss += 1

        cohesion = None
        if cluster_edges_n.get(root):
            cohesion = cluster_edges_score_sum[root] / max(1, cluster_edges_n[root])

        cluster_list.append({
            "cluster_id": root,
            "size": len(ips_sorted),
            "ips": ips_sorted,
            "cohesion": cohesion,
            "top_asn": top_asn,
            "top_owner": top_owner,
            "top_country": top_country,
            "top_csp": top_csp,
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

    return handler._send_json({
        "status": "ok",
        "submitted_count": len(valid_ips) + len(invalid),
        "valid_count": len(valid_ips),
        "invalid_count": len(invalid),
        "invalid_inputs": invalid[:200],
        "min_score": int(min_score),
        "top_pairs": int(top_pairs),
        "max_neighbors_per_ip": int(max_neighbors_per_ip),
        "bucket_max": int(BUCKET_MAX),
        "pairs": kept,
        "pair_count": len(kept),
        "clusters": cluster_list,
        "vt_enabled": vt_enabled,
        "vt_attempted": vt_attempted,
        "vt_budget": vt_budget,
        "vt_workers": vt_workers,
        "geoip_enabled": geoip_enabled,
        "geoip_mmdb_path": geoip_mmdb_path if geoip_enabled else None,
        "ip_features": ip_features,
        "country_summary": country_summary,
        "note": "Similarity is inferred from VT/GeoIP infrastructure features (for infected-host IP lists).",
    })
