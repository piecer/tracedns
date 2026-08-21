"""Bounded, JSON-safe MISP event context for botnet analysis."""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional


_MAX_ATTRIBUTES = 10_000
_MAX_SCANNED_ATTRIBUTES = 50_000
_MAX_OBJECTS = 2_000
_MAX_TAGS = 20
_MAX_ACCESS_TAGS = 100
_MAX_ACCESS_TAGS_SCANNED = 1_000
_MAX_GALAXIES = 100
_MAX_GALAXY_CLUSTERS = 20
_MAX_WARNINGLISTS = 20
_MAX_SIGHTINGS_SCANNED = 1_000
_MAX_TEXT = 1_000
_MAX_CONTEXT_BYTES = 1 * 1024 * 1024
_MAX_ATTRIBUTE_CONTEXT_BYTES = 768 * 1024


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    return str(value or "").strip()[:limit]


def _boolish(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _tags(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    seen = set()
    for item in value[:_MAX_TAGS]:
        name = _text(item.get("name") if isinstance(item, dict) else item, 255)
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _is_restricted_tlp_tag(value: Any) -> bool:
    """Fail closed for TLP markings that require recipient authorization."""
    normalized = _text(value, 255).strip().lower()
    if normalized.startswith("tlp:2.0="):
        normalized = normalized.split("=", 1)[1].strip().strip('"\'')
    return normalized.startswith(("tlp:red", "tlp:amber"))


def _access_tlp_tags(value: Any) -> List[str]:
    """Scan every tag for access control while keeping the exported list bounded."""
    if not isinstance(value, list):
        return []
    restricted: List[str] = []
    other: List[str] = []
    seen = set()
    for item in value[:_MAX_ACCESS_TAGS_SCANNED]:
        name = _text(item.get("name") if isinstance(item, dict) else item, 255)
        normalized = name.lower()
        if not normalized.startswith("tlp:") or normalized in seen:
            continue
        seen.add(normalized)
        target = restricted if _is_restricted_tlp_tag(normalized) else other
        target.append(name)
    return (restricted + other)[:_MAX_ACCESS_TAGS]


def _warninglists(value: Any) -> List[str]:
    items = value if isinstance(value, list) else [value] if isinstance(value, (dict, str)) else []
    names: List[str] = []
    for item in items[:_MAX_WARNINGLISTS]:
        name = _text(
            item.get("name") or item.get("value") if isinstance(item, dict) else item,
            255,
        )
        if name and name not in names:
            names.append(name)
    return names


def _sighting_summary(value: Any) -> Dict[str, int]:
    items = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
    summary = {"positive": 0, "false_positive": 0, "expiration": 0}
    sighting_types = {"0": "positive", "1": "false_positive", "2": "expiration"}
    for item in items[:_MAX_SIGHTINGS_SCANNED]:
        if not isinstance(item, dict):
            continue
        key = sighting_types.get(_text(item.get("type"), 8))
        if key:
            summary[key] += 1
    return summary


def _galaxies(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:_MAX_GALAXIES]:
        if not isinstance(item, dict):
            continue
        galaxy: Dict[str, Any] = {
            "name": _text(item.get("name"), 255),
            "type": _text(item.get("type"), 255),
        }
        clusters = []
        raw_clusters = item.get("GalaxyCluster")
        if isinstance(raw_clusters, list):
            for raw_cluster in raw_clusters[:_MAX_GALAXY_CLUSTERS]:
                if not isinstance(raw_cluster, dict):
                    continue
                cluster = {
                    "value": _text(raw_cluster.get("value"), 255),
                    "uuid": _text(raw_cluster.get("uuid"), 64),
                }
                if cluster["value"] or cluster["uuid"]:
                    clusters.append(cluster)
        if clusters:
            galaxy["clusters"] = clusters
        if galaxy["name"] or galaxy["type"]:
            out.append(galaxy)
    return out


def _producer(value: Any) -> Dict[str, str]:
    item = value if isinstance(value, dict) else {}
    return {
        "id": _text(item.get("id"), 64),
        "uuid": _text(item.get("uuid"), 64),
        "name": _text(item.get("name"), 255),
    }


def _extract_source_ip(attribute_type: Any, value: Any) -> Optional[str]:
    attr_type = _text(attribute_type, 64).lower()
    if attr_type not in ("ip-src", "ip-src|port"):
        return None
    raw_value = _text(value, 512)
    candidate = raw_value.rsplit("|", 1)[0] if attr_type == "ip-src|port" else raw_value
    try:
        return str(ipaddress.ip_address(candidate.strip()))
    except ValueError:
        return None


def _effective_access(attribute: Dict[str, Any], event: Dict[str, Any]) -> tuple[str, str]:
    distribution = _text(attribute.get("distribution"), 16)
    sharing_group_id = _text(attribute.get("sharing_group_id"), 64)
    if distribution in ("", "5"):
        distribution = _text(event.get("distribution"), 16)
        sharing_group_id = _text(event.get("sharing_group_id"), 64)
    return distribution, sharing_group_id


def _attribute_context(
    attribute: Dict[str, Any],
    event: Dict[str, Any],
    object_context: Optional[Dict[str, str]],
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    attr_type = _text(attribute.get("type"), 64).lower()
    raw_value = _text(attribute.get("value"), 512)
    if attr_type not in ("ip-src", "ip-src|port"):
        return None, None
    ip = _extract_source_ip(attr_type, raw_value)
    if not ip:
        return None, raw_value or None

    raw_tags = attribute.get("Tag")
    tags = _tags(raw_tags)
    tlp_tags = _access_tlp_tags(raw_tags)
    tlp_tag_scan_truncated = (
        isinstance(raw_tags, list) and len(raw_tags) > _MAX_ACCESS_TAGS_SCANNED
    )
    comment = _text(attribute.get("comment"))
    normalized_tags = {tag.lower() for tag in tags}
    generated = comment.upper().startswith(("NST-2-1", "NST-2-2")) or any(
        tag in {"source:tracedns", "tracedns:generated"} or tag.startswith("tracedns:")
        for tag in normalized_tags
    )
    explicitly_external = any(
        tag.startswith("source:") and tag != "source:tracedns"
        for tag in normalized_tags
    )
    provenance = "tracedns_generated" if generated else "external" if explicitly_external else "unknown"
    warninglists = _warninglists(attribute.get("Warninglist") or attribute.get("warnings"))
    sightings = _sighting_summary(attribute.get("Sighting"))
    to_ids = _boolish(attribute.get("to_ids"))
    suppression_reasons: List[str] = []
    if not to_ids:
        suppression_reasons.append("to_ids_false")
    if warninglists:
        suppression_reasons.append("warninglist_match")
    if sightings["false_positive"]:
        suppression_reasons.append("false_positive_sighting")
    if provenance == "tracedns_generated":
        suppression_reasons.append("tracedns_generated")
    distribution, sharing_group_id = _effective_access(attribute, event)

    return ({
        "ip": ip,
        "id": _text(attribute.get("id"), 64),
        "uuid": _text(attribute.get("uuid"), 64),
        "type": attr_type,
        "value": raw_value,
        "category": _text(attribute.get("category"), 255),
        "to_ids": to_ids,
        "timestamp": _text(attribute.get("timestamp"), 64),
        "first_seen": _text(attribute.get("first_seen"), 64),
        "last_seen": _text(attribute.get("last_seen"), 64),
        "tags": tags,
        "tlp_tags": tlp_tags,
        "tlp_tag_scan_truncated": tlp_tag_scan_truncated,
        "warninglists": warninglists,
        "sightings": sightings,
        "object": object_context,
        "provenance": provenance,
        "eligible_for_scoring": not suppression_reasons,
        "suppression_reasons": suppression_reasons,
        "effective_distribution": distribution,
        "effective_sharing_group_id": sharing_group_id,
    }, None)


def _iter_attributes(event: Dict[str, Any]) -> Iterable[tuple[Dict[str, Any], Optional[Dict[str, str]]]]:
    root_attributes = event.get("Attribute")
    if isinstance(root_attributes, list):
        for attribute in root_attributes:
            if isinstance(attribute, dict):
                yield attribute, None

    objects = event.get("Object")
    if not isinstance(objects, list):
        return
    for obj in objects[:_MAX_OBJECTS]:
        if not isinstance(obj, dict):
            continue
        object_context = {
            "id": _text(obj.get("id"), 64),
            "uuid": _text(obj.get("uuid"), 64),
            "name": _text(obj.get("name"), 255),
            "meta_category": _text(obj.get("meta-category"), 255),
        }
        attributes = obj.get("Attribute")
        if not isinstance(attributes, list):
            continue
        for attribute in attributes:
            if isinstance(attribute, dict):
                yield attribute, object_context


def normalize_misp_event(payload: Any) -> Dict[str, Any]:
    """Normalize a PyMISP event without exposing credentials or opaque objects."""
    root = payload.get("Event") if isinstance(payload, dict) else {}
    event = root if isinstance(root, dict) else {}
    raw_event_tags = event.get("Tag")
    event_tags = _tags(raw_event_tags)
    event_tlp_tags = _access_tlp_tags(raw_event_tags)
    event_tlp_tag_scan_truncated = (
        isinstance(raw_event_tags, list)
        and len(raw_event_tags) > _MAX_ACCESS_TAGS_SCANNED
    )
    event_context = {
        "id": _text(event.get("id"), 64),
        "uuid": _text(event.get("uuid"), 64),
        "info": _text(event.get("info")),
        "date": _text(event.get("date"), 64),
        "timestamp": _text(event.get("timestamp"), 64),
        "threat_level_id": _text(event.get("threat_level_id"), 16),
        "analysis": _text(event.get("analysis"), 16),
        "published": _boolish(event.get("published")),
        "distribution": _text(event.get("distribution"), 16),
        "sharing_group_id": _text(event.get("sharing_group_id"), 64),
        "producer": _producer(event.get("Orgc")),
        "tags": event_tags,
        "galaxies": _galaxies(event.get("Galaxy")),
    }

    attributes: List[Dict[str, Any]] = []
    invalid_values: List[str] = []
    tlp_tags = list(event_tlp_tags)
    contains_restricted = (
        event_context["distribution"] != "3"
        or event_tlp_tag_scan_truncated
        or any(_is_restricted_tlp_tag(tag) for tag in event_tlp_tags)
    )
    scanned_attributes = 0
    matched_attributes = 0
    scan_limit_reached = False
    attribute_limit_reached = False
    byte_limit_reached = False
    attribute_context_bytes = 0
    attribute_tlp_tag_scans_truncated = 0
    for attribute, object_context in _iter_attributes(event):
        if scanned_attributes >= _MAX_SCANNED_ATTRIBUTES:
            scan_limit_reached = True
            break
        scanned_attributes += 1
        normalized, invalid = _attribute_context(attribute, event_context, object_context)
        if invalid and len(invalid_values) < 200:
            invalid_values.append(invalid)
        if normalized is None:
            continue
        matched_attributes += 1
        if normalized["tlp_tag_scan_truncated"]:
            attribute_tlp_tag_scans_truncated += 1
            contains_restricted = True
        for tag in normalized["tlp_tags"]:
            if (
                tag.lower().startswith("tlp:")
                and tag not in tlp_tags
                and len(tlp_tags) < _MAX_ACCESS_TAGS
            ):
                tlp_tags.append(tag)
        if normalized["effective_distribution"] != "3" or any(
            _is_restricted_tlp_tag(tag) for tag in normalized["tlp_tags"]
        ):
            contains_restricted = True
        if len(attributes) >= _MAX_ATTRIBUTES:
            attribute_limit_reached = True
            continue
        normalized_bytes = len(json.dumps(normalized, separators=(",", ":")).encode("utf-8"))
        if attribute_context_bytes + normalized_bytes > _MAX_ATTRIBUTE_CONTEXT_BYTES:
            byte_limit_reached = True
            continue
        attribute_context_bytes += normalized_bytes
        attributes.append(normalized)

    objects = event.get("Object")
    objects_omitted = max(0, len(objects) - _MAX_OBJECTS) if isinstance(objects, list) else 0
    result = {
        "event": event_context,
        "ips": [],
        "attributes": attributes,
        "invalid_values": invalid_values,
        "access": {
            "event_distribution": event_context["distribution"],
            "event_sharing_group_id": event_context["sharing_group_id"],
            "tlp_tags": tlp_tags,
            "contains_restricted_attributes": contains_restricted,
        },
        "attribute_count": len(attributes),
        "context_truncated": bool(
            scan_limit_reached
            or attribute_limit_reached
            or objects_omitted > 0
            or event_tlp_tag_scan_truncated
            or attribute_tlp_tag_scans_truncated > 0
        ),
        "truncation": {
            "scanned_attributes": scanned_attributes,
            "attributes_omitted": max(0, matched_attributes - len(attributes)),
            "objects_omitted": objects_omitted,
            "scan_limit_reached": scan_limit_reached,
            "attribute_limit_reached": attribute_limit_reached,
            "byte_limit_reached": byte_limit_reached,
            "event_tlp_tag_scan_truncated": event_tlp_tag_scan_truncated,
            "attribute_tlp_tag_scans_truncated": attribute_tlp_tag_scans_truncated,
        },
    }

    def refresh_ips() -> None:
        result["ips"] = []
        seen_ips = set()
        for item in attributes:
            ip = item["ip"]
            if ip not in seen_ips:
                seen_ips.add(ip)
                result["ips"].append(ip)

    refresh_ips()
    if byte_limit_reached:
        result["context_truncated"] = True
    while len(json.dumps(result, separators=(",", ":")).encode("utf-8")) > _MAX_CONTEXT_BYTES:
        if not attributes:
            break
        drop_count = max(1, len(attributes) // 8)
        del attributes[-drop_count:]
        result["attribute_count"] = len(attributes)
        result["context_truncated"] = True
        result["truncation"]["byte_limit_reached"] = True
        result["truncation"]["attributes_omitted"] = matched_attributes - len(attributes)
        refresh_ips()

    return result


def redact_misp_context_for_export(context: Any) -> Dict[str, Any]:
    """Remove newly exposed MISP details when no requester ACL can be evaluated."""
    if not isinstance(context, dict):
        return {}
    raw_access = context.get("access")
    access: Dict[str, Any] = raw_access if isinstance(raw_access, dict) else {}
    if not access.get("contains_restricted_attributes"):
        return context
    return {
        "event": {"redacted": True},
        "access": {"contains_restricted_attributes": True},
        "context_truncated": context.get("context_truncated", False),
        "truncation": context.get("truncation", {}),
        "context_redacted": True,
        "redacted_fields": [
            "access_details",
            "attribute_count",
            "attributes",
            "event_metadata",
            "galaxies",
            "ips",
            "producer",
            "tags",
        ],
    }
