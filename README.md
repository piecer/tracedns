# TraceDNS

A lightweight DNS monitoring toolkit for extracting indicators from TXT records and optionally post-processing A-record IPs (for example XOR-based C2 derivation), with optional Teams/MISP alerting.

## Features

- Monitor domains' DNS TXT/A records and ENS text records for C2-style IP indicators.
- Multiple built-in TXT decoders (base64, xor variants, BTEA variants, plain IP extraction, etc.).
- Optional A-record post-processing method (`xor32_ipv4`) with user-supplied XOR key.
- ENS monitoring: set domain type to `ENS` in Settings, provide `ENS RPC URL`, and optional per-domain `ENS Key` (default `ipv6`) + `ENS Decode` method.
- DHT monitoring: verify read-only signed DNS records by public key; retain last-confirmed IPs separately from failed/stale/conflicting lookup attempts. See [DHT configuration, limits and evidence](docs/DHT_TRACKING.md).
- Register, preview, edit and delete safe custom decoders from the web UI; custom decoders persist in `dns_config.json`.
- Alerts: Teams webhook and MISP integration for newly discovered IPs.
- Dashboard UI showing unique IPs and optional VirusTotal lookup (store VT API key in settings).

## Requirements

- Python 3.11+ (Linux verification matrix: Python 3.11 and 3.12)

Install Python dependencies inside a new virtual environment (see Quick Start):

```bash
python3 -m pip install -r requirements-bootstrap.txt
python3 -m pip install -r requirements.txt
```

Notes:
- VirusTotal lookups (optional) are implemented via `requests` in `vt_lookup.py` (no special VT SDK required).
- MISP integration requires `PyMISP` (included in `requirements.txt`).
- To enable ENS alongside MISP, install `requirements-ens.txt` in the same
  environment with normal dependency resolution; do not use `--no-deps`.
- Existing Python 3.10 deployments need a separately validated Python 3.11+
  environment before switching. Preserve the old environment and consistent
  state backups; installing this candidate does not authorize a service restart.
- GeoIP country fallback (optional) for IP similarity analysis: install `geoip2` and provide a MaxMind mmdb path via `GEOIP_MMDB_PATH` (env) or `geoip_mmdb_path` in `dns_config.json`.

## Quick Start

Use a fresh checkout and virtual environment. The example has no monitored
targets, no external integrations, and only a loopback DNS server. Never
overwrite an existing deployment's configuration or account database.

```bash
cd tracedns
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-bootstrap.txt
python -m pip install -r requirements.txt
cp -n dns_config.json_example dns_config.json
# Password is prompted, never passed in an argument.
python -m security.cli --db ./local-security/auth.sqlite bootstrap admin
python dns_monitor.py --config dns_config.json --security-db ./local-security/auth.sqlite --http-host 127.0.0.1 --http-port 8000 --insecure-http
```

Open `http://127.0.0.1:8000` on the same machine and sign in. This local-only
HTTP example is not suitable for remote access; use the HTTPS setup below for
deployment. Add only targets you explicitly intend to monitor, and configure
your DNS resolver and integrations before enabling them. `--max-workers`
controls per-domain parallel queries.

Replay preserved evidence without querying live indicators:

```bash
make security-regression
```

This checks fixed corpora and state-preservation regressions, not detection
rates on unseen infrastructure. CI runs tests in a loopback-only network.

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
its ENS/SNS identity or DHT public key is likewise a new registration. Direct file edits are not
tracked and cannot be used to reconstruct historical dates.

## REST API and external AI integration

External tools can use the versioned `/api/v1` API without changing the existing UI.
It shares the same session/CSRF authentication, roles, audit trail and monitoring state.
Read observations/history, update monitored targets with revision checks, request
resolution, run asynchronous relationship analysis, and manage settings/decoders/accounts
with the appropriate role. No unauthenticated or remote shell interface is added.

- AI instructions: [`SKILL.md`](SKILL.md).
- API/authentication/workflow reference: [`docs/API.md`](docs/API.md).
- Machine-readable contract: [`docs/openapi.json`](docs/openapi.json), also served at
  `GET /api/v1/openapi.json` after login; discovery is `GET /api/v1`.
- Standalone Python client: `scripts/tracedns_api.py` (stdlib only; HTTPS remotely).

Set `TRACEDNS_BASE_URL` to the public HTTPS origin and `TRACEDNS_USERNAME` to a
dedicated account. Supply `TRACEDNS_PASSWORD` via your secret manager, or enter it
at the hidden prompt for interactive use; never put passwords in command arguments.

```bash
python3 scripts/tracedns_api.py GET /
python3 scripts/tracedns_api.py GET '/results?aggregate=1'
python3 scripts/tracedns_api.py GET '/ips?include_vt=0&limit=100'
```

The client handles login, cookies, CSRF and logout. For polling or multi-step changes,
reuse a `TraceDNSClient` session as shown in the API reference. Removing a target from
the full `domains` list also removes its history; read/merge/verify instead of blindly
overwriting configuration. Queued work is not completed work.

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

- TXT domains: `txt_decode`. For the pseudo-IPv6 list observed at
  `jxk.imarapi.st`, choose `ipv6_last4_xor_6b9e3f2a`. This built-in decodes
  each IPv6 carrier's final four bytes (big-endian) with XOR `0x6B9E3F2A`.
  It accepts the complete `[IPv6|IPv6|...]:digits` format with zero middle
  32 bits, at most 256 tokens and 16,384 characters per TXT record. The
  suffix must contain 1–5 ASCII digits; its meaning is unknown, so it is
  preserved in the raw TXT and **never promoted to a port**. Malformed or
  oversized records yield no decoded IPs (no partial-record results).
  Valid records are decoded independently and their IPv4 candidates are
  deduplicated/sorted. No domain allowlist or malware-family attribution
  is implied. Select `TXT` and this decoder in Domain Verification or
  Settings; it is also included in decoder analysis. Example domain entry:
  `{"name":"jxk.imarapi.st","type":"TXT","txt_decode":"ipv6_last4_xor_6b9e3f2a"}`.
  Integration does not modify existing targets or start monitoring this
  domain automatically. Restart the application to load the new built-in.
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
      "name": "replace-with-your-target.invalid",
      "type": "ENS",
      "ens_text_key": "Host",
      "ens_decode": "ipv4_literals"
    }
  ]
}
```

Replace the reserved placeholder with your explicitly selected ENS target.
Observed names and original records are preserved in `docs/ens/`; deployment
examples are not a target subscription. Do not rename config keys.

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
- Removed IPs have a 24-hour grace period. TraceDNS keeps the pending removal
  across restarts, sends the removal alert only if the IP remains absent for
  the full period, and suppresses a new-IP alert when it returns during that
  window.
- Reappearance suppression is also retained independently for each target and
  provider/decoder configuration: when an observed IP leaves that target's
  managed-IP set, its return is suppressed for 24 hours from that disappearance,
  even if another query fails or the observation comes from a forced subset.
  Repeated empty observations do not extend the deadline; a return followed by
  another disappearance starts a new window. This is not a 24-hour cooldown from
  the last alert. Previously unseen IPs remain eligible for normal alerts.
- Suppression is persisted in `<config-path>.history/delivery.sqlite`
  (`dns_config.json.history/delivery.sqlite` by default) and survives clean or
  unclean restart. It does not authorize
  removal: only a valid complete full scan can start or expire removal grace.
  Existing databases gain the suppression table on startup without resetting
  pending notifications or removal timers; already-lost disappearance timestamps
  cannot be reconstructed retroactively.
- Independent suppression is bounded to 8,192 target/configuration/IP entries
  and 2 MiB of encoded metadata. Overflow preserves existing entries and exposes
  incomplete tracking in delivery health; observation continues, but suppression
  cannot be guaranteed for entries that could not be retained.

## ENS Text Record Decoder Helper

Use `ens_ipv6_decoder.py` to read an ENS text record (default key: `ipv6`) via an Ethereum RPC endpoint and decode values into IPv4s with selectable ENS decode methods.

```bash
python3 ens_ipv6_decoder.py "$ENS_NAME" --rpc "$ENS_RPC_URL"
```

Set `ENS_NAME` and `ENS_RPC_URL` to an explicitly selected target and RPC URL.
Existing callers that supplied only `--rpc` must add the name or `--ens-node`;
RPC-only invocation exits with status 2 before any query. If both name and
node are supplied, the explicit node takes precedence (the name is a label).

Target and optional flags:

- `ens_name` positional arg or `--ens-node` is required; there is no default target.
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
- `ROL3210_decode`: apply the board-supplied nibble-swap/rotate/key transform. It uses IPv6 bytes 5:8 by default for the existing betavpn `network` cluster.
- `ipv6_last4_xor32`: decode the final four IPv6 bytes with a configurable 32-bit XOR key. Set `plain_ipv4=true` to include plain IPv4 literals and `suffix_is_port=false` when trailing metadata must not be promoted to endpoints.
- `sha256_hmac_xor`: authenticate an encrypted ENS record with truncated HMAC-SHA256, then recover its IPv4 and port using a SHA-256 XOR stream. Requires `ens_options.key_hex` (raw key bytes as hex); `marker` defaults to `1488:`. Failed authentication yields no managed IPs/endpoints. See [configuration, limits and preserved evidence](docs/ens/sha256-hmac-xor-decoder.md).
- `betavpn_network_full`: compatibility alias for the same transform, kept for cluster-specific traceability and older configs.

Exact decoder corpora are preserved under `docs/ens/` for traceability and regression testing. For ENS records written to an off-name nodehash, configure `ens_node` (and optionally `ens_resolver`) alongside `ens_text_key` and `ens_decode` so TraceDNS calls `text(bytes32,string)` for the transaction node rather than only `namehash(name)`. Example: `ens_text_key=node`, `ens_decode=ROL3210_decode`, `ens_node=0x07ddacfa58713a8822dfda2b6cf229f38a9bb1a6261cb92abf72a36a0010559d`, `ens_resolver=0xF29100983E058B709F3D539b0c765937B804AC15`.

## Contributing

Contributions are welcome. Please open issues or PRs with focused changes. When editing or translating user-facing strings, avoid renaming programmatic keys in `dns_config.json`.

## License & Authors

This repository is maintained by the project owner and distributed under the [MIT](LICENSE) license.
