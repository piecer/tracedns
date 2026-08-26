import json

import pytest

from http_api import misp_context
from http_api.misp_context import normalize_misp_event, redact_misp_context_for_export


def test_normalize_misp_event_preserves_nested_object_and_access_context():
    event = {
        "Event": {
            "id": "42",
            "uuid": "event-uuid",
            "info": "Botnet campaign",
            "date": "2026-08-21",
            "timestamp": "1787320000",
            "threat_level_id": "1",
            "analysis": "2",
            "published": True,
            "distribution": "4",
            "sharing_group_id": "7",
            "Orgc": {"id": "9", "uuid": "org-uuid", "name": "Producer"},
            "Tag": [{"name": "tlp:amber+strict"}, {"name": "workflow:state=complete"}],
            "Galaxy": [{
                "name": "Threat Actor",
                "type": "threat-actor",
                "GalaxyCluster": [{
                    "value": "Example Campaign",
                    "uuid": "cluster-uuid",
                    "description": "must not be exported",
                }],
            }],
            "Attribute": [
                {
                    "id": "100",
                    "uuid": "attr-root",
                    "type": "ip-src",
                    "value": "203.0.113.10",
                    "category": "Network activity",
                    "to_ids": True,
                    "distribution": "5",
                    "sharing_group_id": "8",
                    "comment": "external report",
                    "Tag": [{"name": "source:osint"}],
                    "Warninglist": [{"name": "Known infrastructure"}],
                    "Sighting": [{"type": "1"}],
                }
            ],
            "Object": [
                {
                    "id": "200",
                    "uuid": "object-uuid",
                    "name": "network-connection",
                    "meta-category": "network",
                    "Attribute": [
                        {
                            "id": "201",
                            "uuid": "attr-nested",
                            "type": "ip-src|port",
                            "value": "198.51.100.7|443",
                            "category": "Network activity",
                            "to_ids": False,
                            "comment": "NST-2-1 TraceDNS alert output",
                            "Tag": [{"name": "tlp:red"}],
                            "first_seen": "2026-08-20T00:00:00Z",
                            "last_seen": "2026-08-21T00:00:00Z",
                        }
                    ],
                }
            ],
        }
    }

    result = normalize_misp_event(event)

    assert result["ips"] == ["203.0.113.10", "198.51.100.7"]
    assert result["event"] == {
        "id": "42",
        "uuid": "event-uuid",
        "info": "Botnet campaign",
        "date": "2026-08-21",
        "timestamp": "1787320000",
        "threat_level_id": "1",
        "analysis": "2",
        "published": True,
        "distribution": "4",
        "sharing_group_id": "7",
        "producer": {"id": "9", "uuid": "org-uuid", "name": "Producer"},
        "tags": ["tlp:amber+strict", "workflow:state=complete"],
        "galaxies": [{
            "name": "Threat Actor",
            "type": "threat-actor",
            "clusters": [{"value": "Example Campaign", "uuid": "cluster-uuid"}],
        }],
    }
    nested = result["attributes"][1]
    assert nested["object"] == {
        "id": "200",
        "uuid": "object-uuid",
        "name": "network-connection",
        "meta_category": "network",
    }
    assert nested["provenance"] == "tracedns_generated"
    assert nested["eligible_for_scoring"] is False
    assert nested["suppression_reasons"] == ["to_ids_false", "tracedns_generated"]
    assert "comment" not in nested
    assert nested["effective_distribution"] == "4"
    assert nested["effective_sharing_group_id"] == "7"
    assert result["access"] == {
        "event_distribution": "4",
        "event_sharing_group_id": "7",
        "tlp_tags": ["tlp:amber+strict", "tlp:red"],
        "contains_restricted_attributes": True,
    }
    root = result["attributes"][0]
    assert root["eligible_for_scoring"] is False
    assert root["suppression_reasons"] == ["warninglist_match", "false_positive_sighting"]
    assert root["warninglists"] == ["Known infrastructure"]


def test_normalize_misp_event_ignores_invalid_and_non_source_attributes():
    result = normalize_misp_event({"Event": {"published": "0", "Attribute": [
        {"type": "ip-dst", "value": "8.8.8.8"},
        {"type": "ip-src", "value": "invalid"},
        {"type": "ip-src", "value": "192.0.2.1", "to_ids": "false"},
        {"type": "ip-src", "value": "192.0.2.1"},
    ]}})

    assert result["ips"] == ["192.0.2.1"]
    assert result["invalid_values"] == ["invalid"]
    assert len(result["attributes"]) == 2
    assert result["event"]["published"] is False
    assert result["attributes"][0]["to_ids"] is False


def test_non_ip_attributes_do_not_hide_nested_source_ip_or_truncation_state():
    event = {"Event": {
        "Attribute": [
            {"type": "domain", "value": f"filler-{index}.example"}
            for index in range(misp_context._MAX_ATTRIBUTES)
        ],
        "Object": [{
            "name": "network-connection",
            "Attribute": [{"type": "ip-src", "value": "8.8.8.8", "to_ids": True}],
        }],
    }}

    result = normalize_misp_event(event)

    assert result["ips"] == ["8.8.8.8"]
    assert result["context_truncated"] is False
    assert result["truncation"]["scanned_attributes"] == misp_context._MAX_ATTRIBUTES + 1


def test_context_is_byte_bounded_and_uses_explicit_tracedns_provenance():
    attributes = [
        {
            "type": "ip-src",
            "value": f"10.0.{index // 256}.{index % 256}",
            "to_ids": True,
            "comment": "Not produced by TraceDNS",
            "Tag": [{"name": f"very-long-tag-{tag}-" + ("x" * 240)} for tag in range(40)],
        }
        for index in range(2_000)
    ]
    attributes[0]["comment"] = "NST-2-2 generated"

    result = normalize_misp_event({"Event": {"distribution": "3", "Attribute": attributes}})

    assert result["attributes"][0]["provenance"] == "tracedns_generated"
    assert all(
        item["provenance"] == "unknown"
        for item in result["attributes"][1:]
    )
    assert len(json.dumps(result, separators=(",", ":")).encode("utf-8")) <= misp_context._MAX_CONTEXT_BYTES
    assert result["context_truncated"] is True
    assert result["truncation"]["byte_limit_reached"] is True


def test_context_byte_limit_does_not_truncate_loadable_source_ips():
    assert misp_context._MAX_ATTRIBUTES == 20_000
    assert misp_context._MAX_CONTEXT_BYTES == 10 * 1024 * 1024
    assert misp_context._MAX_ATTRIBUTE_CONTEXT_BYTES == 7_680 * 1024

    attributes = [
        {
            "id": str(index),
            "uuid": f"attribute-{index}",
            "type": "ip-src",
            "value": f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}",
            "category": "Network activity",
            "to_ids": True,
            "distribution": "3",
            "comment": "external report",
            "Tag": [{"name": "source:osint"}],
            "first_seen": "2026-08-20T00:00:00Z",
            "last_seen": "2026-08-21T00:00:00Z",
        }
        for index in range(misp_context._MAX_ATTRIBUTES + 1)
    ]
    attributes[-1]["Tag"].append({"name": "tlp:red"})

    result = normalize_misp_event({"Event": {"distribution": "3", "Attribute": attributes}})

    assert result["truncation"]["byte_limit_reached"] is True
    assert result["truncation"]["attribute_limit_reached"] is True
    assert result["access"]["contains_restricted_attributes"] is True
    assert result["attribute_count"] < len(attributes)
    assert len(result["ips"]) == misp_context._MAX_ATTRIBUTES
    assert result["ips"][-1] == "10.0.78.31"
    assert len(json.dumps(result, separators=(",", ":")).encode("utf-8")) <= misp_context._MAX_CONTEXT_BYTES


def test_scan_limit_fails_closed_and_marks_omission_count_as_lower_bound():
    benign = {
        "type": "ip-src",
        "value": "8.8.8.8",
        "to_ids": True,
        "distribution": "3",
    }
    restricted = {
        "type": "ip-src",
        "value": "1.1.1.1",
        "to_ids": True,
        "distribution": "3",
        "Tag": [{"name": "tlp:red"}],
    }
    attributes = [benign] * misp_context._MAX_SCANNED_ATTRIBUTES + [restricted]

    normalized = normalize_misp_event({"Event": {"distribution": "3", "Attribute": attributes}})
    exported = redact_misp_context_for_export(normalized)

    assert normalized["truncation"]["scan_limit_reached"] is True
    assert normalized["truncation"]["attributes_omitted_is_lower_bound"] is True
    assert normalized["truncation"]["attributes_omitted"] >= 1
    assert normalized["access"]["contains_restricted_attributes"] is True
    assert exported["context_redacted"] is True


def test_object_limit_fails_closed_when_later_objects_are_unscanned():
    benign_object = {"name": "benign", "Attribute": []}
    restricted_object = {
        "name": "restricted",
        "Attribute": [{
            "type": "ip-src",
            "value": "1.1.1.1",
            "to_ids": True,
            "distribution": "3",
            "Tag": [{"name": "tlp:red"}],
        }],
    }
    objects = [benign_object] * misp_context._MAX_OBJECTS + [restricted_object]

    normalized = normalize_misp_event({"Event": {"distribution": "3", "Object": objects}})
    exported = redact_misp_context_for_export(normalized)

    assert normalized["truncation"]["objects_omitted"] == 1
    assert normalized["access"]["contains_restricted_attributes"] is True
    assert exported["context_redacted"] is True


def test_unique_attribute_tlp_tags_cannot_escape_global_byte_cap():
    attributes = [
        {
            "type": "ip-src",
            "value": f"10.1.{index // 256}.{index % 256}",
            "to_ids": True,
            "Tag": [
                {"name": f"tlp:amber-{index}-{tag}-" + ("x" * 220)}
                for tag in range(misp_context._MAX_TAGS)
            ],
        }
        for index in range(2_000)
    ]

    result = normalize_misp_event({"Event": {"distribution": "3", "Attribute": attributes}})

    assert len(result["access"]["tlp_tags"]) <= 100
    assert len(json.dumps(result, separators=(",", ":")).encode("utf-8")) <= misp_context._MAX_CONTEXT_BYTES
    assert result["context_truncated"] is True
    assert result["truncation"]["byte_limit_reached"] is True


def test_restricted_misp_context_is_redacted_for_api_export():
    normalized = normalize_misp_event({"Event": {
        "id": "42",
        "info": "Restricted event",
        "distribution": "0",
        "Orgc": {"name": "Sensitive producer"},
        "Tag": [{"name": "internal:campaign=secret"}],
        "Attribute": [{"type": "ip-src", "value": "8.8.8.8", "to_ids": True}],
    }})

    exported = redact_misp_context_for_export(normalized)

    assert exported["context_redacted"] is True
    assert "attributes" not in exported
    assert "ips" not in exported
    assert "producer" not in exported["event"]
    assert "tags" not in exported["event"]
    assert exported["event"] == {"redacted": True}
    serialized = json.dumps(exported)
    assert "42" not in serialized
    assert "Restricted event" not in serialized
    assert "Sensitive producer" not in serialized
    assert "secret" not in serialized


@pytest.mark.parametrize("restricted_location", ["event", "attribute"])
@pytest.mark.parametrize(
    "restricted_tag",
    [
        "TLP:RED",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        'tlp:2.0="TLP:RED"',
        'tlp:2.0="TLP:AMBER"',
        'tlp:2.0="TLP:AMBER+STRICT"',
    ],
)
def test_restricted_tlp_tag_after_display_cap_is_still_redacted(
    restricted_location, restricted_tag
):
    benign_tags = [{"name": f"benign:{index}"} for index in range(misp_context._MAX_TAGS)]
    restricted_tags = [*benign_tags, {"name": restricted_tag}]
    attribute = {
        "type": "ip-src",
        "value": "8.8.8.8",
        "to_ids": True,
        "Tag": restricted_tags if restricted_location == "attribute" else benign_tags,
    }
    event = {
        "id": "42",
        "distribution": "3",
        "Tag": restricted_tags if restricted_location == "event" else benign_tags,
        "Attribute": [attribute],
    }

    normalized = normalize_misp_event({"Event": event})
    exported = redact_misp_context_for_export(normalized)

    assert normalized["access"]["contains_restricted_attributes"] is True
    assert restricted_tag.lower() in [tag.lower() for tag in normalized["access"]["tlp_tags"]]
    assert exported["context_redacted"] is True
    assert "attributes" not in exported
    assert "ips" not in exported
    assert "galaxies" not in exported.get("event", {})


@pytest.mark.parametrize("restricted_location", ["event", "attribute"])
def test_tlp_access_scan_overflow_is_bounded_and_fail_closed(restricted_location):
    oversized_tags = [
        {"name": f"benign:{index}"}
        for index in range(misp_context._MAX_ACCESS_TAGS_SCANNED + 1)
    ]
    attribute = {
        "type": "ip-src",
        "value": "8.8.8.8",
        "to_ids": True,
        "Tag": oversized_tags if restricted_location == "attribute" else [],
    }
    event = {
        "distribution": "3",
        "Tag": oversized_tags if restricted_location == "event" else [],
        "Attribute": [attribute],
    }

    normalized = normalize_misp_event({"Event": event})
    exported = redact_misp_context_for_export(normalized)

    assert normalized["context_truncated"] is True
    assert normalized["access"]["contains_restricted_attributes"] is True
    assert normalized["truncation"]["event_tlp_tag_scan_truncated"] is (
        restricted_location == "event"
    )
    assert normalized["truncation"]["attribute_tlp_tag_scans_truncated"] == (
        1 if restricted_location == "attribute" else 0
    )
    assert exported["context_redacted"] is True
    assert "attributes" not in exported


def test_restricted_export_has_no_top_level_ioc_values():
    normalized = normalize_misp_event({
        "Event": {
            "id": "42",
            "distribution": "0",
            "Attribute": [{"type": "ip-src", "value": "10.0.0.7", "to_ids": True}],
        }
    })

    exported = redact_misp_context_for_export(normalized)

    assert normalized["ips"] == ["10.0.0.7"]
    assert exported.get("ips", []) == []
    assert "10.0.0.7" not in json.dumps(exported)


def test_string_warning_suppresses_scoring_and_nested_arrays_are_bounded():
    result = normalize_misp_event({"Event": {
        "distribution": "3",
        "Attribute": [{
            "type": "ip-src",
            "value": "8.8.8.8",
            "to_ids": True,
            "warnings": ["Known public resolver", *[f"warning-{i}" for i in range(100)]],
            "Sighting": [{"type": "1"}] * (misp_context._MAX_SIGHTINGS_SCANNED + 100),
        }],
    }})

    attribute = result["attributes"][0]
    assert attribute["eligible_for_scoring"] is False
    assert attribute["suppression_reasons"] == ["warninglist_match", "false_positive_sighting"]
    assert attribute["warninglists"][0] == "Known public resolver"
    assert len(attribute["warninglists"]) == misp_context._MAX_WARNINGLISTS
    assert attribute["sightings"]["false_positive"] == misp_context._MAX_SIGHTINGS_SCANNED
