# TraceDNS

A lightweight DNS monitoring toolkit for extracting indicators from TXT records and optionally post-processing A-record IPs (for example XOR-based C2 derivation), with optional Teams/MISP alerting.

## Features

- Monitor domains' DNS TXT and A records for C2-style IP indicators.
- Multiple built-in TXT decoders (base64, xor variants, BTEA variants, plain IP extraction, etc.).
- Optional A-record post-processing method (`xor32_ipv4`) with user-supplied XOR key.
- Register, preview, edit and delete safe custom decoders from the web UI; custom decoders persist in `dns_config.json`.
- Alerts: Teams webhook and MISP integration for newly discovered IPs.
- Dashboard UI showing unique IPs and optional VirusTotal lookup (store VT API key in settings).

## Requirements

- Python 3.8+ (tested on Linux)

Install Python dependencies:

```bash
pip3 install -r requirements.txt
```

Notes:
- VirusTotal lookups (optional) are implemented via `requests` in `vt_lookup.py` (no special VT SDK required).
- MISP integration requires `PyMISP` (included in `requirements.txt`).
- GeoIP country fallback (optional) for IP similarity analysis: install `geoip2` and provide a MaxMind mmdb path via `GEOIP_MMDB_PATH` (env) or `geoip_mmdb_path` in `dns_config.json`.

## Quick Start

1. Clone or copy the repository into your workspace.
2. Edit `dns_config.json` to add domains, DNS servers, interval, alerting and any `custom_decoders` you want.

Run the monitor:

```bash
cd tracedns
python3 dns_monitor.py
```

Useful flags:

```bash
python3 dns_monitor.py --http-port 8000 --max-workers 16
```

- `--max-workers` controls per-domain parallel DNS queries across configured DNS servers (performance tuning).

## Web UI

- Open the dashboard in a browser (served by the built-in HTTP server). The UI provides:
  - **Status**: current per-domain A/TXT snapshots (managed/decoded IPs)
  - **All IPs**: aggregated IP list with pagination and optional VirusTotal enrichment
  - **Valid IPs**: syntactically valid IP subset
  - **Domain Verify / Analysis**: validate domains and decoding methods
  - **Settings**: configure domains/servers/interval + Teams/MISP/VT settings
  - **Custom decoders**: preview and register safe DSL-based decoders

## Configuration (`dns_config.json`)

Key items in `dns_config.json`:

- `domains`: list of domains to monitor
- `servers`: DNS servers to query
- `interval`: polling interval (seconds)
- `max_workers`: max worker threads for per-domain parallel DNS queries across servers
- `custom_decoders`: array of custom decoder objects persisted by the UI
- `alerts`: object containing `teams_webhook`, `misp_url`, `api_key`, `push_event_id`, `vt_api_key`, `vt_cache_ttl_days`, and optional `misp_remove_on_absent` (default `false`).

Per-domain decoder fields:

- TXT domains: `txt_decode`
- A domains: `a_decode` (e.g. `xor32_ipv4`) and optional `a_xor_key` (hex/int/dotted-byte format)

Do not rename config keys unless you know the code depends on them.

## Custom Decoder DSL (overview)

Custom decoders use a constrained, validated list of steps (no arbitrary code execution). Typical operations include `regex` capture, `base64` decode, `urlsafe_b64`, and `xor_hex` with a fixed key. Always **Preview** a decoder in the UI before registering.

## Performance Notes

- **DNS query parallelism:** Increase `max_workers` (or `--max-workers`) if you have multiple DNS servers configured and want faster polling.
- **All IPs + VirusTotal:** The Web UI paginates the All IPs view and applies VirusTotal lookups to the current page only. Use the UI controls (page size / VT budget / VT workers) to balance speed vs. API usage.

## Alerts

- Teams: provide a `teams_webhook` URL in settings to receive notifications when new IPs are discovered.
- MISP: existing helper functions integrate with MISP to add attributes/sightings; configure MISP-related fields in `alerts`.


## Contributing

Contributions are welcome. Please open issues or PRs with focused changes. When editing or translating user-facing strings, avoid renaming programmatic keys in `dns_config.json`.

## License & Authors

This repository is maintained by the project owner. Add a license file if you plan to publish publicly.
