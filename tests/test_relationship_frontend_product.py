import colorsys
import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
HTML = (ROOT / "dns_frontend.html").read_text(encoding="utf-8")
CSS = (ROOT / "dns_frontend.css").read_text(encoding="utf-8")
JS = (ROOT / "dns_frontend.js").read_text(encoding="utf-8")


def _tag_with_id(element_id: str) -> str:
    match = re.search(rf"<[^>]+\bid=[\"']{re.escape(element_id)}[\"'][^>]*>", HTML)
    assert match, f"missing element #{element_id}"
    return match.group(0)


def _attr(tag: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}=[\"']([^\"']*)[\"']", tag)
    return match.group(1) if match else None


def _relative_luminance(rgb: tuple[float, float, float]) -> float:
    channels = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in rgb
    ]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def test_botnet_screen_has_semantic_input_workbench_and_secondary_results():
    section = _tag_with_id("ipintel")
    assert _attr(section, "aria-labelledby") == "ipIntelHeading"
    assert '<h3 id="ipIntelHeading">' in HTML
    assert '<section class="ipintel-input-panel" aria-labelledby="ipIntelInputHeading">' in HTML
    assert '<section class="iprel-workbench" aria-labelledby="ipRelWorkbenchHeading">' in HTML
    assert '<section class="ipintel-secondary-results" aria-labelledby="ipIntelSecondaryHeading">' in HTML


def test_graph_palette_keeps_white_labels_at_aa_contrast():
    match = re.search(r"return `hsl\(\$\{hue\},\s*(\d+)%,\s*(\d+)%\)`", JS)
    assert match, "cluster palette must expose fixed saturation/lightness"
    saturation, lightness = (int(value) / 100 for value in match.groups())
    contrasts = []
    for hue in range(360):
        red, green, blue = colorsys.hls_to_rgb(hue / 360, lightness, saturation)
        luminance = _relative_luminance((red, green, blue))
        contrasts.append(1.05 / (luminance + 0.05))
    assert min(contrasts) >= 4.5
    assert "'color': '#ffffff'" in JS


def test_visualizations_expose_keyboard_alternative_and_visible_map_values():
    assert "Keyboard users can inspect and activate the equivalent pair and cluster controls in Table view." in HTML
    summary = _tag_with_id("ipRelMapSummary")
    assert _attr(summary, "aria-label") == "Country risk values"
    assert "formatIpRelCountrySummary" in JS
    assert "getIpRelMapRadius(ipCount, maxCount)" in JS


def test_input_and_run_status_are_described_live_regions():
    input_tag = _tag_with_id("ipIntelInput")
    assert "ipIntelInputHelp" in (_attr(input_tag, "aria-describedby") or "").split()
    assert "ipIntelInputStats" in (_attr(input_tag, "aria-describedby") or "").split()

    stats = _tag_with_id("ipIntelInputStats")
    assert _attr(stats, "role") == "status"
    assert _attr(stats, "aria-live") == "polite"
    assert _attr(stats, "aria-atomic") == "true"

    run_status = _tag_with_id("ipRelRunStatus")
    assert _attr(run_status, "role") == "status"
    assert _attr(run_status, "aria-live") == "polite"
    assert _attr(run_status, "aria-atomic") == "true"


def test_relationship_actions_and_operations_have_product_controls():
    run = _tag_with_id("runIpRelationshipBtn")
    cancel = _tag_with_id("cancelIpRelationshipBtn")
    export = _tag_with_id("exportIpRelationshipBtn")
    result_filter = _tag_with_id("ipRelFilterInput")

    assert "button-primary" in (_attr(run, "class") or "").split()
    assert _attr(cancel, "type") == "button"
    assert _attr(cancel, "disabled") is not None
    assert _attr(export, "type") == "button"
    assert _attr(export, "disabled") is not None
    assert _attr(result_filter, "type") == "search"
    assert _attr(result_filter, "aria-label")


def test_misp_event_id_is_visible_beside_the_load_action():
    action_row = re.search(
        r'<div[^>]+class="[^"]*iprel-action-row[^"]*"[^>]*>(?P<body>.*?)</div>',
        HTML,
        re.DOTALL,
    )
    assert action_row, "missing Botnet IP action row"
    body = action_row.group("body")
    event_input = _tag_with_id("ipIntelMispEventId")

    assert 'for="ipIntelMispEventId"' in body
    assert 'id="ipIntelMispEventId"' in body
    assert 'id="loadIpIntelMispBtn"' in body
    assert body.index('id="ipIntelMispEventId"') < body.index('id="loadIpIntelMispBtn"')
    assert _attr(event_input, "type") == "number"
    assert _attr(event_input, "min") == "1"
    assert _attr(event_input, "step") == "1"
    assert HTML.count('id="ipIntelMispEventId"') == 1
    lookback_input = _tag_with_id("ipRelLookbackDays")
    assert _attr(lookback_input, "type") == "number"
    assert _attr(lookback_input, "min") == "0"
    assert _attr(lookback_input, "max") == "365"
    assert _attr(lookback_input, "value") == "30"
    assert "lookback_days: lookbackDays" in JS

    enrichment = re.search(
        r'<details[^>]+class="[^"]*ipintel-enrichment-settings[^"]*"[^>]*>(?P<body>.*?)</details>',
        HTML,
        re.DOTALL,
    )
    assert enrichment
    assert 'id="ipIntelMispEventId"' not in enrichment.group("body")


def test_relationship_summary_exposes_metrics_and_quality_status():
    expected_labels = {
        "ipRelMetricIps": "Analyzed IPs",
        "ipRelMetricPairs": "Relationships",
        "ipRelMetricClusters": "Clusters",
        "ipRelMetricCoverage": "Coverage",
    }
    for element_id, label in expected_labels.items():
        tag = _tag_with_id(element_id)
        assert _attr(tag, "data-empty-value") == "—"
        assert re.search(rf"{re.escape(label)}.*?id=[\"']{element_id}[\"']", HTML, re.DOTALL)

    quality = _tag_with_id("ipRelQualityBanner")
    assert _attr(quality, "role") == "status"
    assert _attr(quality, "aria-live") == "polite"
    assert _attr(quality, "aria-atomic") == "true"


def test_low_level_relationship_tuning_is_in_advanced_disclosure():
    details = re.search(
        r'<details[^>]+id="ipRelAdvancedSettings"[^>]*>(?P<body>.*?)</details>',
        HTML,
        re.DOTALL,
    )
    assert details, "missing advanced relationship settings disclosure"
    body = details.group("body")
    assert "<summary" in body
    for element_id in (
        "ipRelMinScore",
        "ipRelTopPairs",
        "ipRelMaxNeighbors",
        "ipRelBucketMax",
        "ipRelBucketOverflowMode",
        "ipRelPairGateEnabled",
        "ipRelGateStrongMin",
        "ipRelGateMidMin",
        "ipRelGateFallbackScore",
    ):
        assert f'id="{element_id}"' in body
    assert HTML.index('id="ipRelProfileSelect"') < HTML.index('id="ipRelAdvancedSettings"')


def test_relationship_views_have_complete_tab_relationships():
    tablist = re.search(r'<div[^>]+class="[^"]*iprel-tabs[^"]*"[^>]*>', HTML)
    assert tablist and _attr(tablist.group(0), "role") == "tablist"
    assert _attr(tablist.group(0), "aria-label") == "Relationship result views"

    relationships = (
        ("ipRelViewTableBtn", "ipRelTableView", "true", "0"),
        ("ipRelViewGraphBtn", "ipRelGraphView", "false", "-1"),
        ("ipRelViewMapBtn", "ipRelMapView", "false", "-1"),
    )
    for tab_id, panel_id, selected, tabindex in relationships:
        tab = _tag_with_id(tab_id)
        panel = _tag_with_id(panel_id)
        assert _attr(tab, "role") == "tab"
        assert _attr(tab, "aria-controls") == panel_id
        assert _attr(tab, "aria-selected") == selected
        assert _attr(tab, "tabindex") == tabindex
        assert _attr(panel, "role") == "tabpanel"
        assert _attr(panel, "aria-labelledby") == tab_id
        assert _attr(panel, "tabindex") == "0"


def test_wide_relationship_tables_have_labelled_overflow_regions():
    for wrapper_id, table_id, label in (
        ("ipRelPairsTableScroll", "ipRelPairsTable", "Top similar IP pairs table"),
        ("ipRelClustersTableScroll", "ipRelClustersTable", "Relationship clusters table"),
    ):
        wrapper = re.search(
            rf'<div[^>]+id="{wrapper_id}"[^>]*>(?P<body>.*?)</div>',
            HTML,
            re.DOTALL,
        )
        assert wrapper, f"missing overflow wrapper #{wrapper_id}"
        tag = wrapper.group(0).split(">", 1)[0] + ">"
        assert _attr(tag, "role") == "region"
        assert _attr(tag, "aria-label") == label
        assert _attr(tag, "tabindex") == "0"
        assert f'id="{table_id}"' in wrapper.group("body")


def test_product_css_covers_focus_motion_and_narrow_viewports():
    assert re.search(r":focus-visible\s*\{[^}]*outline\s*:", CSS, re.DOTALL)
    assert "@media (prefers-reduced-motion: reduce)" in CSS
    reduced = CSS.split("@media (prefers-reduced-motion: reduce)", 1)[1]
    assert "animation-duration" in reduced
    assert "transition-duration" in reduced
    assert "scroll-behavior:auto" in reduced.replace(" ", "")

    assert re.search(r"\.table-scroll\s*\{[^}]*overflow-x\s*:\s*auto", CSS, re.DOTALL)
    assert "@media(max-width:640px)" in CSS.replace(" ", "")
    assert re.search(r"\.iprel-action-row\s*button\s*\{[^}]*width\s*:\s*100%", CSS, re.DOTALL)
    assert re.search(r"#ipRelGraph\s*,\s*#ipRelMap\s*\{[^}]*min-width\s*:\s*0", CSS, re.DOTALL)


def test_quality_banner_visually_distinguishes_complete_warning_and_stale_states():
    compact = CSS.replace(" ", "")
    assert '.quality-banner[data-state="complete"]' in compact
    assert '.quality-banner[data-state="incomplete"]' in compact
    assert '.quality-banner[data-state="vt-partial"]' in compact
    assert '.quality-banner[data-state="stale"]' in compact


def test_initial_relationship_controls_and_results_have_honest_empty_states():
    cancel = _tag_with_id("cancelIpRelationshipBtn")
    result_filter = _tag_with_id("ipRelFilterInput")
    assert _attr(cancel, "disabled") is not None
    assert _attr(cancel, "hidden") is not None
    assert _attr(result_filter, "disabled") is not None
    assert re.search(
        r'id="ipRelPairsTable".*?<tbody>\s*<tr>\s*<td[^>]+colspan="4"[^>]*>Run an analysis',
        HTML,
        re.DOTALL,
    )
    assert re.search(
        r'id="ipRelClustersTable".*?<tbody>\s*<tr>\s*<td[^>]+colspan="8"[^>]*>Run an analysis',
        HTML,
        re.DOTALL,
    )
    assert re.search(
        r'id="ipRelMeta"[^>]*>Detailed job metadata appears after analysis\.',
        HTML,
    )


def test_per_ip_summary_tables_have_labelled_horizontal_scroll_regions():
    summaries = (
        ("ipIntelCspSummaryHeading", "ipIntelCspSummaryTable"),
        ("ipIntelAsSummaryHeading", "ipIntelAsSummaryTable"),
        ("ipIntelCountrySummaryHeading", "ipIntelCountrySummaryTable"),
        ("ipIntelAsCountrySummaryHeading", "ipIntelAsCountrySummaryTable"),
    )
    for heading_id, table_id in summaries:
        assert f'id="{heading_id}"' in HTML
        wrapper = re.search(
            rf'<div[^>]+class="[^"]*table-scroll[^"]*"[^>]*aria-labelledby="{heading_id}"[^>]*>(?P<body>.*?)</div>',
            HTML,
            re.DOTALL,
        )
        assert wrapper, f"missing labelled scroll region for #{table_id}"
        tag = wrapper.group(0).split(">", 1)[0] + ">"
        assert _attr(tag, "role") == "region"
        assert _attr(tag, "tabindex") == "0"
        assert f'id="{table_id}"' in wrapper.group("body")


def test_per_ip_summaries_reflow_without_section_level_clipping():
    compact = CSS.replace(" ", "")
    narrow = compact.split("@media(max-width:960px)", 1)[1]
    assert re.search(r"\.ipintel-summary-grid\{[^}]*grid-template-columns:1fr", narrow)
    assert "#ipintel{overflow-x:hidden" not in narrow


def test_focus_indicator_uses_a_high_contrast_double_ring():
    focus = re.search(r":focus-visible\s*\{(?P<body>[^}]*)\}", CSS, re.DOTALL)
    assert focus
    body = focus.group("body")
    assert re.search(r"outline\s*:\s*2px\s+solid\s+#fff", body, re.IGNORECASE)
    assert re.search(r"box-shadow\s*:\s*0\s+0\s+0\s+5px\s+#0b3a53", body, re.IGNORECASE)


def test_per_ip_results_start_as_one_intentional_empty_state():
    empty_state = _tag_with_id("ipIntelResultsEmpty")
    content = _tag_with_id("ipIntelResultsContent")
    assert _attr(empty_state, "role") == "status"
    assert "Enrich Per-IP Details" in HTML
    assert _attr(content, "hidden") is not None
    assert re.search(r"\.ipintel-hints-box:empty\s*\{[^}]*display\s*:\s*none", CSS, re.DOTALL)
