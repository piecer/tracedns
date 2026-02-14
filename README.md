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
- Optional: `vt-py` or another VirusTotal helper if you enable VT lookups

Install Python dependencies (if any) using your environment's package manager. This project uses standard library modules where possible.

## Quick Start

1. Clone or copy the repository into your workspace.
2. Edit `dns_config.json` to add domains, DNS servers, interval, alerting and any `custom_decoders` you want.

Run the monitor:

```bash
cd tracedns
# Run the monitor (reads dns_config.json)
python3 dns_monitor.py
```

Run the built-in HTTP UI (if present) by starting the package's HTTP server entrypoint (the same monitor may start the UI depending on configuration). If you added a separate server script, run that instead.

## Web UI

- Open the dashboard in a browser (default path served by the repository's HTTP handler). The UI provides:
  - Dashboard: list of unique IPs discovered (optional VT info)
  - Settings: configure Teams webhook, MISP settings, and VirusTotal API key
  - Custom decoders: preview and register safe DSL-based decoders

## Configuration (`dns_config.json`)

Key items in `dns_config.json`:

- `domains`: list of domains to monitor
- `servers`: DNS servers to query
- `interval`: polling interval (seconds)
- `custom_decoders`: array of custom decoder objects persisted by the UI
- `alerts`: object containing `teams_webhook`, `misp_url`, `misp_api_key`, `vt_api_key`, etc.

Per-domain decoder fields:

- TXT domains: `txt_decode`
- A domains: `a_decode` (e.g. `xor32_ipv4`) and optional `a_xor_key` (hex/int/dotted-byte format)

Do not rename config keys unless you know the code depends on them.

## Custom Decoder DSL (overview)

Custom decoders use a constrained, validated list of steps (no arbitrary code execution). Typical operations include `regex` capture, `base64` decode, `urlsafe_b64`, and `xor_hex` with a fixed key. Always `Preview` a decoder in the UI before registering.

## Alerts

- Teams: provide a `teams_webhook` URL in settings to receive notifications when new IPs are discovered.
- MISP: existing helper functions integrate with MISP to add attributes/sightings; configure MISP-related fields in `alerts`.


## Contributing

Contributions are welcome. Please open issues or PRs with focused changes. When editing or translating user-facing strings, avoid renaming programmatic keys in `dns_config.json`.

## License & Authors

This repository is maintained by the project owner. Add a license file if you plan to publish publicly.
