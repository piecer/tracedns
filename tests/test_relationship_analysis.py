import io
import json

import pytest

from http_api import relationship_handlers as rh


class FakeHandler:
    def __init__(self, data):
        payload = json.dumps(data).encode("utf-8")
        self.headers = {"Content-Length": str(len(payload))}
        self.rfile = io.BytesIO(payload)
        self.shared_config = {}
        self.response = None
        self.code = None

    def _send_json(self, obj, code=200):
        self.response = obj
        self.code = code


def _analyze(data):
    handler = FakeHandler(data)
    rh.handle_ip_relationship_analysis(handler)
    assert handler.code == 200
    assert handler.response is not None
    return handler.response


def test_parser_rejects_scoped_ipv6_and_canonicalizes_ipv4_mapped_ipv6():
    valid, invalid = rh._parse_ip_tokens([
        "2606:4700:4700::1111%eth0",
        "::ffff:8.8.8.8",
        "8.8.8.8",
    ])

    assert valid == ["8.8.8.8"]
    assert invalid == ["2606:4700:4700::1111%eth0"]


@pytest.mark.parametrize("placeholder", ["-", "N/A", "", "unknown", "none", "null", "other/unknown"])
def test_unknown_placeholders_do_not_create_score_or_evidence(placeholder):
    features = {
        "asn": placeholder,
        "as_owner_norm": placeholder,
        "csp": placeholder,
        "country": placeholder,
        "network": placeholder,
        "rir": placeholder,
        "jarm": placeholder,
        "cert_sha256": placeholder,
        "rdap_name_norm": placeholder,
        "rdap_type": placeholder,
    }

    score, evidence = rh._compare_features(
        "1.1.1.1",
        "8.8.8.8",
        features,
        features,
    )

    assert score == 0
    assert evidence == []


@pytest.mark.parametrize("csp", ["other", "unknown"])
def test_unknown_csp_does_not_create_score_or_evidence(csp):
    features = {"csp": csp, "csp_label": "Other/Unknown"}

    score, evidence = rh._compare_features(
        "1.1.1.1",
        "8.8.8.8",
        features,
        features,
    )

    assert score == 0
    assert evidence == []


def test_vt_off_unrelated_ips_create_no_pairs_or_multi_ip_clusters():
    response = _analyze({
        "ips": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "include_vt": False,
    })

    assert response["pairs"] == []
    assert response["pair_count"] == 0
    assert all(cluster["size"] == 1 for cluster in response["clusters"])


def test_pair_gate_disabled_still_enforces_min_score(monkeypatch):
    reports = {
        "1.1.1.1": {
            "asn": 13335,
            "as_owner": "Cloudflare",
            "country": "US",
            "raw": {"data": {"attributes": {"network": "1.1.1.0/24"}}},
        },
        "8.8.8.8": {
            "asn": 15169,
            "as_owner": "Google",
            "country": "US",
            "raw": {"data": {"attributes": {"network": "8.8.8.0/24"}}},
        },
    }
    monkeypatch.setattr(rh, "get_ip_report", lambda ip: reports[ip])

    response = _analyze({
        "ips": list(reports),
        "include_vt": True,
        "vt_workers": 1,
        "min_score": 40,
        "pair_gate_enabled": False,
    })

    assert response["pair_gate"]["enabled"] is False
    assert response["pairs"] == []
    assert response["pair_count"] == 0


def test_vt_calls_only_global_ipv4_and_ipv6_in_live_and_cache_tail(monkeypatch):
    global_ips = ["8.8.8.8", "2606:4700:4700::1111", "1.1.1.1"]
    non_global_ips = [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.10.20",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "fc00::1",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
    ]
    calls = []

    def vt_spy(ip, cache_only=False):
        calls.append((ip, cache_only))
        return {"raw": {"data": {"attributes": {}}}}

    monkeypatch.setattr(rh, "get_ip_report", vt_spy)

    response = _analyze({
        "ips": [global_ips[0], *non_global_ips, *global_ips[1:]],
        "include_vt": True,
        "vt_workers": 1,
        "vt_budget": 1,
    })

    assert calls == [
        ("2606:4700:4700::1111", True),
        ("1.1.1.1", True),
        ("8.8.8.8", False),
    ]
    assert response["vt_attempted"] == 1
    assert response["vt_budget"] == 1
    assert response["vt_eligible_count"] == 3
    assert response["vt_skipped_non_global"] == len(non_global_ips)


def test_scope_and_vt_eligibility_metadata_are_present_when_vt_disabled():
    expected_scopes = {
        "8.8.8.8": "global",
        "2606:4700:4700::1111": "global",
        "10.0.0.1": "private",
        "fc00::1": "private",
        "127.0.0.1": "loopback",
        "::1": "loopback",
        "169.254.10.20": "link_local",
        "fe80::1": "link_local",
        "224.0.0.1": "multicast",
        "ff02::1": "multicast",
        "240.0.0.1": "reserved",
        "0.0.0.0": "unspecified",
        "::": "unspecified",
    }

    response = _analyze({"ips": list(expected_scopes), "include_vt": False})

    for ip, scope in expected_scopes.items():
        assert response["ip_features"][ip]["scope"] == scope
        assert response["ip_features"][ip]["vt_eligible"] is (scope == "global")
    assert response["vt_eligible_count"] == 2
    assert response["vt_skipped_non_global"] == 11
    assert response["quality"]["vt_eligible_count"] == 2
    assert response["quality"]["vt_skipped_non_global"] == 11
    assert response["quality"]["vt_report_coverage"] == 0.0
    assert response["quality"]["warning_codes"] == []


def test_vt_coverage_uses_eligible_denominator_and_warns_when_partial(monkeypatch):
    def partial_report(ip, cache_only=False):
        if ip == "8.8.8.8":
            return {"raw": {"data": {"attributes": {}}}}
        return None

    monkeypatch.setattr(rh, "get_ip_report", partial_report)

    response = _analyze({
        "ips": ["8.8.8.8", "10.0.0.1", "2606:4700:4700::1111"],
        "include_vt": True,
        "vt_workers": 1,
    })

    assert response["vt_eligible_count"] == 2
    assert response["vt_skipped_non_global"] == 1
    assert response["vt_report_count"] == 1
    assert response["vt_report_coverage"] == 0.5
    assert response["quality"]["vt_report_coverage"] == 0.5
    assert response["quality"]["candidate_analysis_complete"] is True
    assert response["quality"]["enrichment_complete"] is False
    assert response["quality"]["analysis_complete"] is False
    assert response["analysis_complete"] is False
    assert response["quality"]["warning_codes"] == ["vt_partial_coverage"]


def test_vt_enabled_with_no_eligible_ips_is_fully_covered_without_warning(monkeypatch):
    calls = []

    def vt_spy(ip, cache_only=False):
        calls.append((ip, cache_only))
        return {"raw": {"data": {"attributes": {}}}}

    monkeypatch.setattr(rh, "get_ip_report", vt_spy)

    response = _analyze({
        "ips": ["10.0.0.1", "::1", "fe80::1"],
        "include_vt": True,
    })

    assert calls == []
    assert response["vt_eligible_count"] == 0
    assert response["vt_skipped_non_global"] == 3
    assert response["vt_report_count"] == 0
    assert response["quality"]["vt_report_coverage"] == 1.0
    assert response["quality"]["warning_codes"] == []
    for feature in response["ip_features"].values():
        assert feature["vt_source"] == "skipped_non_global"


def test_candidate_limit_stops_bucket_generation_at_budget(monkeypatch):
    ips = [f"11.0.0.{idx}" for idx in range(1, 51)]
    reports = {
        ip: {
            "asn": 64500,
            "as_owner": f"Host {idx}",
            "country": f"X{idx}",
            "raw": {"data": {"attributes": {}}},
        }
        for idx, ip in enumerate(ips)
    }
    monkeypatch.setattr(rh, "get_ip_report", lambda ip: reports[ip])

    response = _analyze({
        "ips": ips,
        "include_vt": True,
        "vt_workers": 1,
        "min_score": 1,
        "pair_gate_enabled": False,
        "candidate_limit": 1000,
    })

    assert response["candidate_limit"] == 1000
    assert response["candidate_count"] == 1000
    assert response["candidate_enumeration_count"] == 1000
    assert response["unique_candidate_count"] == 1000
    assert response["candidate_limit_reached"] is True
    assert response["analysis_complete"] is False
    assert response["quality"]["candidate_limit_reached"] is True
    assert response["quality"]["evaluated_candidate_count"] == 1000
    assert response["quality"]["warning_codes"] == ["candidate_limit_reached"]


def test_cluster_membership_is_independent_of_pair_display_limit(monkeypatch):
    ips = ["11.0.0.1", "11.0.0.2", "11.0.0.3"]
    report = {
        "asn": 64500,
        "as_owner": "Example Hosting",
        "country": "US",
        "network": "11.0.0.0/24",
        "raw": {"data": {"attributes": {}}},
    }
    monkeypatch.setattr(rh, "get_ip_report", lambda ip: dict(report))

    limited = _analyze({
        "ips": ips,
        "include_vt": True,
        "vt_workers": 1,
        "top_pairs": 1,
    })
    expanded = _analyze({
        "ips": ips,
        "include_vt": True,
        "vt_workers": 1,
        "top_pairs": 3,
    })

    assert limited["pair_count"] == 1
    assert expanded["pair_count"] == 3
    assert [cluster["ips"] for cluster in limited["clusters"]] == [ips]
    assert [cluster["ips"] for cluster in expanded["clusters"]] == [ips]


def test_quality_metadata_redacts_geoip_filesystem_path(monkeypatch):
    class FakeGeoIPReader:
        def close(self):
            pass

    monkeypatch.setattr(rh, "_load_geoip_reader", lambda path: FakeGeoIPReader())
    secret_path = "/srv/private/GeoLite2-Country.mmdb"
    handler = FakeHandler({
        "ips": ["1.1.1.1", "8.8.8.8"],
        "include_vt": False,
    })
    handler.shared_config = {"geoip_mmdb_path": secret_path}

    rh.handle_ip_relationship_analysis(handler)

    assert handler.code == 200
    assert handler.response is not None
    response = handler.response
    assert response["candidate_limit"] == 500000
    assert response["candidate_limit_reached"] is False
    assert response["unique_candidate_count"] == 0
    assert response["analysis_complete"] is True
    assert "geoip_mmdb_path" not in response
    assert secret_path not in json.dumps(response)
    assert response["geoip_enabled"] is True
    assert response["geoip_source"] == "config"
    assert response["quality"] == {
        "analysis_complete": True,
        "candidate_analysis_complete": True,
        "enrichment_complete": True,
        "candidate_limit": 500000,
        "candidate_limit_reached": False,
        "unique_candidate_count": 0,
        "evaluated_candidate_count": 0,
        "deduped_candidate_count": 0,
        "bucket_oversized_count": 0,
        "bucket_truncated_count": 0,
        "pair_heap_truncated": False,
        "vt_enabled": False,
        "vt_attempted": 0,
        "vt_eligible_count": 2,
        "vt_skipped_non_global": 0,
        "vt_report_count": 0,
        "vt_report_coverage": 0.0,
        "warning_codes": [],
    }


@pytest.mark.parametrize(
    ("requested_limit", "expected_limit"),
    [(0, 1000), (999, 1000), (2000001, 2000000)],
)
def test_candidate_limit_is_clamped(requested_limit, expected_limit):
    response = _analyze({
        "ips": ["1.1.1.1", "8.8.8.8"],
        "include_vt": False,
        "candidate_limit": requested_limit,
    })

    assert response["candidate_limit"] == expected_limit
    assert response["quality"]["candidate_limit"] == expected_limit


def test_bucket_truncation_marks_analysis_incomplete(monkeypatch):
    ips = [f"11.{idx}.0.1" for idx in range(1, 52)]
    monkeypatch.setattr(
        rh,
        "get_ip_report",
        lambda ip: {
            "asn": 64500,
            "as_owner": f"Host {ip}",
            "country": ip,
            "raw": {"data": {"attributes": {}}},
        },
    )

    response = _analyze({
        "ips": ips,
        "include_vt": True,
        "vt_workers": 1,
        "bucket_max": 50,
    })

    assert response["bucket_oversized_count"] == 1
    assert response["bucket_truncated_count"] == 1
    assert response["analysis_complete"] is False
    assert response["quality"]["warning_codes"] == ["bucket_truncated"]


def test_pair_heap_truncation_marks_analysis_incomplete(monkeypatch):
    ips = [f"11.0.0.{idx}" for idx in range(1, 51)]
    monkeypatch.setattr(
        rh,
        "get_ip_report",
        lambda ip: {
            "asn": 64500,
            "as_owner": f"Host {ip}",
            "country": ip,
            "raw": {"data": {"attributes": {}}},
        },
    )

    response = _analyze({
        "ips": ips,
        "include_vt": True,
        "vt_workers": 1,
        "min_score": 1,
        "pair_gate_enabled": False,
        "top_pairs": 1,
    })

    assert response["quality"]["pair_heap_truncated"] is True
    assert response["analysis_complete"] is False
    assert response["quality"]["warning_codes"] == ["pair_heap_truncated"]


def test_parser_normalizes_deduplicates_and_reports_invalid_tokens():
    valid, invalid = rh._parse_ip_tokens([
        " 1.1.1.1,2001:0db8::1 ",
        None,
        "1.1.1.1;2001:db8:0:0:0:0:0:1|bad-ip",
        "",
    ])

    assert valid == ["1.1.1.1", "2001:db8::1"]
    assert invalid == ["bad-ip"]


def test_invalid_json_and_invalid_request_return_public_400_responses():
    invalid_json = FakeHandler({})
    rh.handle_ip_relationship_analysis(invalid_json, body=b"{")
    assert invalid_json.code == 400
    assert invalid_json.response == {"error": "invalid json"}

    invalid_request = FakeHandler({})
    rh.handle_ip_relationship_analysis(invalid_request, body=b"{}")
    assert invalid_request.code == 400
    assert invalid_request.response == {"error": "ips must be a string or list"}


def test_option_coercion_and_remaining_ip_scope_branch_are_exposed_in_response():
    response = _analyze({
        "ips": ["100.64.0.1", "8.8.8.8"],
        "include_vt": None,
        "pair_gate_enabled": "unexpected",
        "min_score": "bad",
        "top_pairs": 0,
        "max_neighbors_per_ip": 999,
        "vt_workers": 999,
        "vt_budget": -1,
        "bucket_max": 5000,
        "bucket_overflow_mode": "invalid",
    })

    assert response["ip_features"]["100.64.0.1"]["scope"] == "non_global"
    assert response["min_score"] == 40
    assert response["top_pairs"] == 1
    assert response["max_neighbors_per_ip"] == 200
    assert response["vt_workers"] == 32
    assert response["vt_budget"] == 0
    assert response["bucket_max"] == 2000
    assert response["bucket_overflow_mode"] == "truncate"


def test_rich_vt_reports_surface_feature_and_evidence_variants(monkeypatch):
    cert = "ab" * 32
    jarm = "cd" * 32

    def report(ip):
        return {
            "asn": 64500,
            "as_owner": "Example Hosting, Inc.",
            "country": "us",
            "malicious": 2,
            "suspicious": 1,
            "last_analysis_date": 1_700_000_000 if ip.endswith(".1") else 1_700_086_400,
            "raw": {"data": {"attributes": {
                "network": "11.0.0.0/24",
                "regional_internet_registry": "arin",
                "jarm": jarm,
                "last_https_certificate": {"thumbprint_sha256": cert},
                "rdap": {"name": " Example Network ", "type": "ALLOCATED"},
                "last_analysis_results": {
                    "Engine A": {"category": "malicious"},
                    "Engine B": {"category": "suspicious"},
                    "Clean": {"category": "harmless"},
                },
            }}},
        }

    monkeypatch.setattr(rh, "get_ip_report", report)
    response = _analyze({
        "ips": ["11.0.0.1", "11.0.0.2"],
        "include_vt": True,
        "vt_workers": 1,
        "min_score": 1,
    })

    assert response["pair_count"] == 1
    evidence_types = {item["type"] for item in response["pairs"][0]["evidence"]}
    assert {
        "same_asn", "same_owner", "same_country", "same_network_exact",
        "same_jarm", "same_cert_sha256", "same_rdap_name", "same_rdap_type",
        "same_rir", "same_prefix24", "vt_malicious_both", "vt_suspicious_both",
        "vt_detector_overlap", "vt_time_proximity",
    } <= evidence_types
    feature = response["ip_features"]["11.0.0.1"]
    assert feature["as_owner_norm"] == "example hosting,"
    assert feature["country"] == "US"
    assert feature["vt_engine_positive_count"] == 2
    assert response["country_summary"] == [{
        "country": "US", "ip_count": 2, "malicious_ips": 2,
        "suspicious_ips": 2, "asn_count": 1,
    }]


@pytest.mark.parametrize(
    ("left", "right", "expected_weight"),
    [
        ({"a", "b"}, {"a", "b", "c"}, 14),
        ({"a", "b"}, {"a", "b", "c", "d"}, 10),
        ({"a"}, {"a", "b", "c"}, 6),
    ],
)
def test_detector_overlap_weights_follow_public_similarity_behavior(left, right, expected_weight):
    score, evidence = rh._compare_features(
        "11.0.0.1", "12.0.0.1", {}, {},
        ca={"positive_engines": left}, cb={"positive_engines": right},
    )

    assert score == expected_weight
    assert evidence[0]["type"] == "vt_detector_overlap"
    assert evidence[0]["weight"] == expected_weight


def test_network_overlap_and_pair_gate_decisions_cover_signal_strengths():
    wide = rh._parse_network_cidr("11.0.0.0/16")
    narrow = rh._parse_network_cidr("11.0.1.0/24")
    score, evidence = rh._compare_features(
        "11.0.1.1", "11.0.2.1",
        {"network": "11.0.0.0/16"}, {"network": "11.0.1.0/24"},
        ca={"network_obj": wide}, cb={"network_obj": narrow},
    )
    assert score == 10
    assert evidence == [{
        "type": "same_network_overlap",
        "value": "11.0.0.0/16~11.0.1.0/24",
        "weight": 10,
    }]
    assert rh._pair_gate_decision(10, [{"type": "same_network_exact"}], 40) == (True, "strong_signal")
    assert rh._pair_gate_decision(20, evidence + [{"type": "same_asn"}], 40) == (True, "multi_mid_signals")
    assert rh._pair_gate_decision(60, [], 40) == (True, "high_score_fallback")
    assert rh._pair_gate_decision(20, [], 40) == (False, "weak_pair_filtered")


def test_vt_cache_tail_and_serial_failures_are_nonfatal_and_batch_is_closed(monkeypatch):
    events = []

    def lookup(ip, cache_only=False):
        events.append(("lookup", ip, cache_only))
        if cache_only:
            raise TypeError("legacy lookup has no cache-only support")
        raise RuntimeError("VT unavailable")

    monkeypatch.setattr(rh, "get_ip_report", lookup)
    monkeypatch.setattr(rh, "begin_cache_batch", lambda: events.append(("begin",)))
    monkeypatch.setattr(rh, "end_cache_batch", lambda flush=False: events.append(("end", flush)))

    response = _analyze({
        "ips": ["8.8.8.8", "1.1.1.1"],
        "include_vt": True,
        "vt_workers": 1,
        "vt_budget": 1,
    })

    assert events[0] == ("begin",)
    assert events[-1] == ("end", True)
    assert ("lookup", "1.1.1.1", True) in events
    assert response["status"] == "ok"
    assert response["vt_report_count"] == 0
    assert response["quality"]["warning_codes"] == ["vt_partial_coverage"]


def test_optional_batch_and_parallel_vt_failures_do_not_break_analysis(monkeypatch):
    events = []

    def lookup(ip):
        if ip == "8.8.8.8":
            raise RuntimeError("one lookup failed")
        return {"country": "US", "raw": {"data": {"attributes": {}}}}

    def broken_begin():
        events.append("begin")
        raise RuntimeError("batch unavailable")

    monkeypatch.setattr(rh, "get_ip_report", lookup)
    monkeypatch.setattr(rh, "begin_cache_batch", broken_begin)
    monkeypatch.setattr(rh, "end_cache_batch", lambda **_kwargs: events.append("end"))

    response = _analyze({
        "ips": ["8.8.8.8", "1.1.1.1"],
        "include_vt": True,
        "vt_workers": 2,
    })

    assert events == ["begin"]
    assert response["vt_attempted"] == 2
    assert response["vt_report_count"] == 1
    assert response["status"] == "ok"


def test_geoip_fallback_is_used_and_reader_is_closed_even_if_close_fails(monkeypatch):
    class Country:
        iso_code = "kr"

    class Response:
        country = Country()

    class Reader:
        def __init__(self):
            self.closed = False

        def country(self, ip):
            assert ip == "8.8.8.8"
            return Response()

        def close(self):
            self.closed = True
            raise RuntimeError("close failed")

    reader = Reader()
    monkeypatch.setattr(rh, "_load_geoip_reader", lambda _path: reader)
    handler = FakeHandler({"ips": ["8.8.8.8"], "include_vt": False})
    handler.shared_config = {"geoip_mmdb_path": "/tmp/fake.mmdb"}
    rh.handle_ip_relationship_analysis(handler)

    assert handler.code == 200
    assert handler.response is not None
    assert handler.response["ip_features"]["8.8.8.8"]["country"] == "KR"
    assert reader.closed is True


def test_graph_helper_honors_limits_and_exposes_cluster_membership():
    pairs = [
        {"a": "", "b": "2.2.2.2", "score": 99},
        {"a": "1.1.1.1", "b": "2.2.2.2", "score": 80, "evidence": ["x"]},
        {"a": "3.3.3.3", "b": "4.4.4.4", "score": 70},
        {"a": "1.1.1.1", "b": "3.3.3.3", "score": 60},
    ]
    graph = rh._build_relationship_graph(
        pairs,
        [{"ips": ["1.1.1.1", "2.2.2.2"]}],
        {"1.1.1.1": {"country": "US", "asn": "1", "csp_label": "Cloud"}},
        edge_limit=2,
        node_limit=3,
    )

    assert graph["edge_count"] == 2
    assert graph["node_count"] == 3
    assert graph["edges"][0]["same_cluster"] is True
    assert graph["edges"][1]["same_cluster"] is False
    assert next(node for node in graph["nodes"] if node["id"] == "1.1.1.1")["degree"] == 2


def test_insight_helper_reports_cluster_signals_filtering_and_limits():
    clusters = [
        {
            "size": 4,
            "cohesion": 80,
            "vt_summary": {"malicious_total": 3},
            "top_network": [["11.0.0.0/24", 4]],
            "top_jarm": [["a" * 40, 3]],
            "top_cert": [["b" * 64, 3]],
        },
        {"size": 3, "cohesion": "bad", "vt_summary": {}, "top_network": ["bad"]},
    ]
    insight = rh._build_relationship_insights({
        "clusters": clusters,
        "valid_count": 7,
        "pair_count": 5,
        "top_pairs": 5,
        "pair_gate": {"enabled": True, "kept": 2, "dropped": 18},
        "bucket_oversized_count": 2,
        "bucket_truncated_count": 1,
    })

    titles = {hint["title"] for hint in insight["hints"]}
    assert {
        "Dominant Cluster", "High Cohesion Cluster", "Malicious Cluster Core",
        "Cluster Network Reuse", "Cluster JARM Reuse", "Cluster Certificate Reuse",
        "Pair Gate Filtering", "Bucket Overflow Applied", "Pair Result Limit Hit",
    } <= titles
    assert insight["characteristics"]["average_cohesion"] == 80
