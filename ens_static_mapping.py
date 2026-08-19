#!/usr/bin/env python3
"""Traceability helpers for board-validated ENS cluster artifacts.

These helpers preserve the exact source-entry mapping and IOC set that
back the betavpn `network` full-decoder corpus without losing the
original 25-entry mapping.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, List


DOCS_DIR = Path(__file__).resolve().parent / "docs" / "ens"
BETAVPN_NETWORK_FULL_ARTIFACT = DOCS_DIR / "betavpn-network-full-decoder.json"
_IPV6_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:]{2,}")


def load_betavpn_network_full_artifact() -> Dict[str, Any]:
    with BETAVPN_NETWORK_FULL_ARTIFACT.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def extract_ipv6_tokens(value: Any) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    out: List[str] = []
    seen = set()
    for part in re.split(r"[|;,]", text):
        chunk = str(part or "").strip()
        if not chunk:
            continue
        candidates = [chunk]
        candidates.extend(match.group(0) for match in _IPV6_CANDIDATE_RE.finditer(chunk))
        for candidate in candidates:
            if candidate.count(":") < 2:
                continue
            try:
                normalized = str(ipaddress.IPv6Address(candidate))
            except Exception:
                continue
            if normalized in seen:
                break
            seen.add(normalized)
            out.append(normalized)
            break
    return out


def get_betavpn_network_full_mapping() -> Dict[str, str]:
    artifact = load_betavpn_network_full_artifact()
    return {
        str(ipaddress.IPv6Address(entry["network_value"])): entry["decoded_ipv4"]
        for entry in artifact.get("mappings", [])
        if entry.get("network_value") and entry.get("decoded_ipv4")
    }


def map_betavpn_network_full_record(record: str) -> List[Dict[str, str]]:
    mapping = get_betavpn_network_full_mapping()
    out: List[Dict[str, str]] = []
    for token in extract_ipv6_tokens(record):
        decoded_ipv4 = mapping.get(token)
        if not decoded_ipv4:
            continue
        out.append({
            "network_value": token,
            "decoded_ipv4": decoded_ipv4,
        })
    return out


def get_betavpn_network_full_iocs() -> List[str]:
    artifact = load_betavpn_network_full_artifact()
    iocs = [str(item) for item in artifact.get("ioc_ipv4s", []) if str(item).strip()]
    seen = set()
    out = []
    for ip in iocs:
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out
