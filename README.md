# TraceDNS

A lightweight DNS monitoring toolkit for extracting indicators from TXT records and optionally post-processing A-record IPs (for example XOR-based C2 derivation), with optional Teams/MISP alerting.

## Features

- Monitor domains' DNS TXT/A records and ENS text records for C2-style IP indicators.
- Multiple built-in TXT decoders (base64, xor variants, BTEA variants, plain IP extraction, etc.).
- Optional A-record post-processing method (`xor32_ipv4`) with user-supplied XOR key.
- ENS monitoring: set domain type to `ENS` in Settings, provide `ENS RPC URL`, and optional per-domain `ENS Key` (default `ipv6`) + `ENS Decode` method.
- Register, preview, edit and delete safe custom decoders from the web UI; custom decoders persist in `dns_config.json`.
- Alerts: Teams webhook and MISP integration for newly discovered IPs.
- Dashboard UI showing unique IPs and optional VirusTotal lookup (store VT API key in settings).

## Requirements

- Python 3.10+ (tested with Python 3.12 on Linux)

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

## Multi-user access and audit

TraceDNS now requires a local account database at startup. Create the first administrator from the server console, then run the monitor behind HTTPS:

```bash
# Create the initial local administrator; password is prompted, never an argument.
.venv/bin/python -m security.cli --db /var/lib/tracedns/security/auth.sqlite bootstrap admin
# Start behind an HTTPS reverse proxy.
.venv/bin/python dns_monitor.py --security-db /var/lib/tracedns/security/auth.sqlite --http-host 127.0.0.1 --public-origin https://tracedns.example --trusted-proxy 127.0.0.1
```

Roles are `admin`, `operator`, and `viewer`; every API is checked on the server. Admins manage accounts and audit exports, operators manage monitored domains and run analyses, and viewers can only read stored observations. Login, account/configuration changes, denied requests, and analysis/force-resolve outcomes are recorded per user. Passwords, session tokens, API keys, webhooks, and credential-bearing URLs are not returned or written to audit events.

For a strictly trusted wired LAN only, `--insecure-http --allow-insecure-remote-http --http-host 10.0.0.2 --public-origin http://10.0.0.2:8000` explicitly permits plaintext remote HTTP. Do not use it over Wi-Fi, VPN/shared networks, or the Internet: credentials and sessions are not TLS-protected.


- Open the dashboard in a browser (served by the built-in HTTP server). The UI provides:
  - **Status**: current per-domain A/TXT snapshots (managed/decoded IPs)
  - **All IPs**: aggregated IP list with pagination and optional VirusTotal enrichment
  - **Valid IPs**: syntactically valid IP subset
  - **Domain Verify / Analysis**: validate domains and decoding methods
  - **Settings**: configure domains/servers/interval + Teams/MISP/VT settings
  - **Custom decoders**: preview and register safe DSL-based decoders

Settings displays each monitoring target as a searchable card with its full,
wrapping domain name, record type, registration time, and last configuration
change. Expand **View / edit configuration** for type-specific decoder fields
and ENS node/resolver values. Filtering never removes hidden targets from a
save. Failed saves retain the draft; **Load** reloads the saved configuration.

Dates describe registration/configuration changes **in TraceDNS**, not WHOIS
registration, domain expiry, or changes to resolved DNS answers. They are stored
as UTC ISO timestamps and displayed in the browser's local timezone. Existing
entries without metadata show **Not recorded**; their original dates are never
inferred from a restart, file mtime, or first observation. New registrations via
`POST /config` record both dates; unchanged saves, list reordering, and changes
to global server/interval settings leave per-target dates unchanged. Removing
and re-adding a target starts a new registration. Renaming a target or changing
its ENS/SNS identity is likewise a new registration. Direct file edits are not
tracked and cannot be used to reconstruct historical dates.

## Configuration (`dns_config.json`)

Key items in `dns_config.json`:

- `domains`: list of domains to monitor
- `domain_metadata`: server-owned map keyed by `config_manager.domain_identity`,
  containing optional `created_at` / `updated_at` timestamps. Returned by
  `GET /config` and successful config writes, persisted with the configuration,
  and restored at startup. Client-supplied metadata is ignored.
- `servers`: DNS servers to query
- `interval`: polling interval (seconds)
- `max_workers`: max worker threads for per-domain parallel DNS queries across servers
- `custom_decoders`: array of custom decoder objects persisted by the UI
- `alerts`: object containing `teams_webhook`, `misp_url`, `api_key`, `push_event_id`, `vt_api_key`, `vt_cache_ttl_days`, and optional `misp_remove_on_absent` (default `false`).

Per-domain decoder fields:

- TXT domains: `txt_decode`
- A domains: `a_decode` (e.g. `xor32_ipv4`) and optional `a_xor_key` (hex/int/dotted-byte format)
- ENS domains: `ens_text_key`, `ens_decode`, and optional `ens_options`. Use
  `ipv4_literals` when a case-sensitive text record such as `Host` contains
  plain IPv4 infrastructure. `ROL3210_decode` accepts `segment` (`5to8`, the
  backward-compatible default, or `last4`) and `key_u32` options. Bracketed
  records with a shared `]:port` suffix expose `decoded_endpoints` alongside
  `decoded_ips` in current results and history.

Example for monitoring a plain IPv4 ENS record:

```json
{
  "ens_rpc_url": "https://<mainnet-rpc>",
  "domains": [
    {
      "name": "xorisgayilovekidsandihatemilfs.eth",
      "type": "ENS",
      "ens_text_key": "Host",
      "ens_decode": "ipv4_literals"
    }
  ]
}
```

Do not rename config keys unless you know the code depends on them.

## Custom Decoder DSL (overview)

Custom decoders use a constrained, validated list of steps (no arbitrary code execution). Typical operations include `regex` capture, `base64` decode, `urlsafe_b64`, and `xor_hex` with a fixed key. Always **Preview** a decoder in the UI before registering.

## Performance Notes

- **DNS query parallelism:** Increase `max_workers` (or `--max-workers`) if you have multiple DNS servers configured and want faster polling.
- **All IPs + VirusTotal:** The Web UI paginates the All IPs view and applies VirusTotal lookups to the current page only. Use the UI controls (page size / VT budget / VT workers) to balance speed vs. API usage.

## Alerts

- Teams: provide a `teams_webhook` URL in settings to receive notifications when new IPs are discovered.
- MISP: existing helper functions integrate with MISP to add attributes/sightings; configure MISP-related fields in `alerts`.
- Alert messages include local-time timestamps and cycle summaries (unique IP/domain counts, source-type breakdown).
- New-IP alerts are batched and sent once after each full resolve cycle across configured domains.



## ENS Text Record Decoder Helper

Use `ens_ipv6_decoder.py` to read an ENS text record (default key: `ipv6`) via an Ethereum RPC endpoint and decode values into IPv4s with selectable ENS decode methods.

```bash
python3 ens_ipv6_decoder.py --rpc https://<mainnet-rpc>
```

Optional flags:

- `ens_name` positional arg (default: `ukranianhorseriding.eth`)
- `--key <text-key>` to read another ENS text key
- `--decode-method <method>` to choose ENS decode method (default: `ipv6_5to8_xor`)
- `--ens-node <bytes32>` to query a raw ENS nodehash instead of `namehash(ens_name)`
- `--ens-resolver <address>` to query a resolver contract directly instead of looking one up in the ENS registry
- `--ens-options <json>` decoder options JSON object (ex: `{"xor_byte":"0xA5"}`)
- `--xor-byte <byte>` legacy shortcut (mapped to `ens_options.xor_byte` when `--ens-options` is not set)
- `--raw-only` to print only raw ENS text

Notable ENS methods:

- `ipv4_literals`: extract valid plain IPv4 literals from an ENS text record, including values embedded in URLs.
- `ipv6_5to8_xor`: take IPv6 bytes 5:8 and XOR each byte into an IPv4.
- `ROL3210_decode`: apply the board-supplied nibble-swap/rotate/key transform. It uses IPv6 bytes 5:8 by default for the existing betavpn `network` cluster; set `ens_options` to `{"segment":"last4","key_u32":"0x80408454"}` for Dysphoria-style `woah` records.
- `betavpn_network_full`: compatibility alias for the same transform, kept for cluster-specific traceability and older configs.

The exact 25-entry betavpn `network` source-to-IOC corpus is still preserved under `docs/ens/` for traceability and IOC extraction. For ENS records written to an off-name nodehash, configure `ens_node` (and optionally `ens_resolver`) alongside `ens_text_key` and `ens_decode` so TraceDNS calls `text(bytes32,string)` for the transaction node rather than only `namehash(name)`. Example: `ens_text_key=node`, `ens_decode=ROL3210_decode`, `ens_node=0x07ddacfa58713a8822dfda2b6cf229f38a9bb1a6261cb92abf72a36a0010559d`, `ens_resolver=0xF29100983E058B709F3D539b0c765937B804AC15`.

## Contributing

Contributions are welcome. Please open issues or PRs with focused changes. When editing or translating user-facing strings, avoid renaming programmatic keys in `dns_config.json`.

## License & Authors

This repository is maintained by the project owner. Add a license file if you plan to publish publicly.
