# TraceDNS

**Follow the infrastructure behind an indicator, not just its latest IP.**

[English](README.md) · [한국어](README.ko.md)

TraceDNS is a self-hosted monitoring and investigation tool for analysts who need
to track infrastructure published through DNS, blockchain naming records and signed
DHT records. It brings record collection, address decoding, change history,
IP relationship analysis and optional notifications into one web dashboard.

A TXT record can hide an address. A naming record can change its endpoint. A list
of IPs can share infrastructure without belonging to the same campaign. TraceDNS
helps you inspect those changes and relationships while keeping the underlying
observations available for review.

**Start with:** [Local setup](#quick-start) · [Investigation workflow](#an-investigation-from-start-to-finish)
· [Supported sources](#decoders-and-advanced-target-types) · [API reference](docs/API.md)

Python backend · Browser dashboard · Optional Teams / MISP / VirusTotal · [MIT license](LICENSE)

## What you can do

| Task | How TraceDNS helps |
| --- | --- |
| Watch DNS records | Track A/TXT records and extract IPs with built-in or custom decoders. |
| Follow other discovery sources | Monitor ENS and SNS records, signed DHT records, and the supported Polygon RPC configuration profile. |
| Investigate IP relationships | Compare observed domains, infrastructure details and available threat-intelligence context in Botnet IP Analysis. |
| Review changes | Browse current results, IP lists and target history in the dashboard. |
| Enrich and notify | Optionally look up VirusTotal reports and send new-IP notifications to Teams or MISP. |
| Share access | Use local accounts, role-based permissions and per-user audit records. |

Teams, MISP and VirusTotal are optional. The starter configuration has no targets
or integrations enabled; you choose what to monitor and which external services
to use.

## Contents

- [Why TraceDNS](#why-tracedns)
- [An investigation from start to finish](#an-investigation-from-start-to-finish)
- [Inside Botnet IP Analysis](#inside-botnet-ip-analysis)
- [Scope and limits](#scope-and-limits)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Multi-user access and deployment](#multi-user-access-and-deployment)
- [Using the dashboard](#using-the-dashboard)
- [Configuration](#configuration)
- [Decoders and advanced target types](#decoders-and-advanced-target-types)
- [Alerts and delivery](#alerts-and-delivery)
- [REST API and external clients](#rest-api-and-external-clients)
- [Development and tests](#development-and-tests)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)

## Why TraceDNS

### Track a changing source, rather than maintaining a static IP list

An IP extracted today may not be the address published tomorrow. Save the source
and its decoding settings once, then use periodic observations and history to
follow its changes. The dashboard separates target configuration from lookup
results, so a configuration edit is not presented as a DNS change.

### Bring different discovery mechanisms into the same investigation

DNS A/TXT, ENS, SNS, signed DHT records and a supported Polygon RPC profile feed
the monitoring workflow. You can work with their extracted addresses in the same
dashboard while still inspecting source-specific details. DHT storage peers, for
example, are not treated as the addresses published inside a signed record.

### Decode first, then inspect the evidence

Built-in methods cover plain IP extraction and several encoded address formats.
Preview a decoder before saving it, or define a constrained custom decoder when
the format needs different extraction steps. Signed DHT records and the supported
authenticated RPC/ENS formats have signature or authentication checks; ordinary
address decoding alone provides no such guarantee and is not a malware verdict.

### Put relationship clues next to the IPs

Botnet IP Analysis combines available infrastructure context with local
observations. Inspect pairs, clusters and their evidence instead of treating
every address in a pasted list as equally related. Filter the results and export
JSON for further review or another tool.

### Keep monitoring and notification state visible

Optional Teams and MISP integration connects observations to an existing analyst
workflow. Delivery diagnostics distinguish queued work from completed delivery;
removal grace and reappearance suppression help avoid treating every temporary
disappearance as a fresh event. Local roles and audit records let a team share
access without giving every user configuration privileges.

### Where it fits

| Your task | What to do in TraceDNS | What to take away |
| --- | --- | --- |
| Follow infrastructure found during malware analysis | Register the selected record source and validate its decoder. | Current extracted addresses and a history of observed changes. |
| Triage a set of suspicious IPs | Paste the IP list into Botnet IP Analysis and review relationship evidence. | Candidate relationships to investigate, not an automatic infection verdict. |
| Track a signed or on-chain configuration source | Select the supported DHT, ENS, SNS or RPC target type and inspect its source-specific result. | Published addresses with the available source/authentication context. |
| Share new observations with a team | Configure Teams or MISP, then monitor delivery health. | Notifications with an explicit delivery state. |
| Connect a script or external analyst assistant | Use the authenticated REST API and standalone Python client. | Programmatic access under the same roles and audit rules as the UI. |

## An investigation from start to finish

1. **Choose the source.** Start with a target you have deliberately selected from
   your investigation. Choose DNS, a naming record, a DHT public key or the
   supported RPC profile; TraceDNS does not subscribe you to research targets.
2. **Verify before monitoring.** Use **Domain Verify** to inspect the returned
   record and extracted addresses. For encoded data, compare the available
   decoding results or preview a custom decoder before saving it.
3. **Save the target.** Add the verified configuration and choose the polling
   interval in **Settings**. Review **Status** and history as observations arrive.
4. **Investigate relationships.** Use **Domain Analysis** for monitored-domain
   statistics, or **Botnet IP Analysis** for an IP-list investigation. Examine the
   evidence behind a relationship and the coverage warnings before drawing a conclusion.
5. **Share or automate.** Export analysis JSON, read observations through the API,
   or enable Teams/MISP notifications. Check delivery diagnostics before retrying
   a notification whose outcome is uncertain.

For example, suppose a selected TXT record publishes one encoded address and
later publishes another. TraceDNS can retain observations of that change and let
you compare the resulting IPs with the rest of your investigation. A shared
hosting provider is a lead to inspect, not proof that the two IPs have the same
operator. This is an illustrative workflow, not a captured incident or a benchmark.

## Inside Botnet IP Analysis

The workbench is for investigating relationships among IPs whose roles may be
unknown. Its name does not mean that every input is a bot, an infected host or a
C2 server.

| Part of the workflow | What you can inspect or control |
| --- | --- |
| Prepare the input | Paste newline-, comma- or space-separated IPs. Duplicate entries are analyzed once; the input supports up to 10,000 valid unique IPs. |
| Add context | Use available VirusTotal infrastructure data, optional GeoIP country fallback, local DNS provenance and context from a selected MISP event. Availability depends on configuration and retained data. |
| Choose the analysis profile | Start with Balanced, or select Conservative, Aggressive or saved Custom settings. Advanced controls include pair-selection and neighbor limits. |
| Follow the job | Observe analysis progress and cancel a running job from the workbench. |
| Review the results | Inspect pair and cluster tables, or switch to Graph and Map. Filter results by IP, owner, country or evidence. |
| Check coverage | Read the coverage/quality indicators alongside the results. A bounded or partially enriched result is not an exhaustive search. |
| Keep a copy | Export the analysis as JSON for review or downstream processing. |

Relationships can draw on shared domains, infrastructure attributes and available
TLS or threat-intelligence context. The graph is a bounded view of the analysis,
not a map of every host or every possible relationship. A cluster is a connected
group of accepted relationships; it does not establish that every member is
directly related to every other member.

VirusTotal enrichment and MISP context are optional external inputs. Their
presence, absence or age affects what can be concluded. Review the underlying
observations before using a relationship score to prioritize follow-up work.

## Scope and limits

TraceDNS is an observation and investigation tool, not an endpoint protection
agent or a replacement for network telemetry.

- **It does not establish infection.** A decoded IP, shared ASN, certificate or
  cluster alone does not prove malware activity or common ownership.
- **It is not entirely passive.** Live monitoring sends queries to the selected
  DNS resolvers, naming-service providers, DHT peers or RPC services. Enabled
  enrichment and notifications contact their respective external services.
- **DHT and RPC observation is not payload execution.** These paths do not run
  malware or connect to the recovered C2 endpoints. DHT tracking is read-only;
  the RPC target supports a specific profile, not arbitrary contract crawling.
- **A missing result is not a clean bill of health.** Timeouts, unavailable
  enrichment and resource limits can leave gaps. In particular, a failed DHT
  attempt is kept separate from the last confirmed signed record.
- **An external AI client is not a built-in LLM detector.** The API and `SKILL.md`
  support external tooling; local LLM inference is not a shipped analysis feature.

Use only targets and services you are authorized to query. Start with the empty
example configuration, review outgoing-service settings and keep credentials out
of shared exports and repository commits.

## Requirements

- Python 3.11 or newer. The Linux verification matrix covers Python 3.11 and 3.12.
- A browser for the dashboard.
- Access to the DNS resolver or discovery service used by your selected targets.

The steps below use Python 3.12 and a new virtual environment. Python 3.11 can be
used in its place. Node.js is needed for browser tests, not to serve the dashboard.

| Optional feature | Additional setup |
| --- | --- |
| ENS | Install `requirements-ens.txt` in the same environment and set the ENS RPC URL. Use normal dependency resolution, not `--no-deps`. |
| VirusTotal | Set a VT API key in Settings. No separate VT SDK is needed. |
| Teams / MISP | Configure the destination in Settings. PyMISP is included in the base requirements. |
| GeoIP country fallback | Provide a MaxMind `.mmdb` file through `GEOIP_MMDB_PATH` or `geoip_mmdb_path` in the config. The base requirements include `geoip2`. |

If you already run TraceDNS on Python 3.10, prepare and validate a separate
Python 3.11+ environment before switching. Keep the old environment and consistent
state backups. These instructions are for a new installation, not an in-place
upgrade of a running service.

## Quick Start

### 1. Install in a fresh checkout

Run these commands from the directory containing your `tracedns` checkout:

```bash
cd tracedns
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-bootstrap.txt
python -m pip install -r requirements.txt
```

### 2. Create the local configuration and administrator

The example starts with no monitored targets, no external integrations and only
a loopback DNS server. Do not reuse an existing deployment's configuration or
account database for this walkthrough.

```bash
cp -n dns_config.json_example dns_config.json
# Password is prompted, never passed in an argument.
python -m security.cli --db ./local-security/auth.sqlite bootstrap admin
```

`cp -n` leaves an existing configuration untouched. If one already exists, stop
and use a separate checkout rather than assuming the starter settings were copied.

### 3. Start the local dashboard

```bash
python dns_monitor.py \
  --config dns_config.json \
  --security-db ./local-security/auth.sqlite \
  --http-host 127.0.0.1 --http-port 8000 --insecure-http
```

Open `http://127.0.0.1:8000` on the same machine and sign in as `admin`.
An empty dashboard is expected until you add a target. Keep the terminal running;
use Ctrl+C when you want to stop this local instance.

### 4. Add your first target

1. In **Settings**, replace the sample loopback resolver with a DNS resolver you
   intend to use, then save. Leave it unchanged only if you run a local resolver.
2. Open **Domain Verify**, enter an explicitly selected target and choose its type
   and decoder. Review the returned values before adding it to monitoring.
3. Check **Status** for the saved target and **All IPs** for its extracted addresses.
4. Enable external enrichment or notifications only after configuring the
   corresponding integration.

This walkthrough uses plaintext HTTP on loopback only. For another machine to
access the dashboard, configure HTTPS as described below; do not simply expose
this example's listener to the network.

## Multi-user access and deployment

TraceDNS requires a local account database. Create the first administrator from
the server console, then put the application behind an HTTPS reverse proxy.
The commands below are an example for a new deployment; they do not configure
the proxy or its certificate.

```bash
# Create the initial local administrator; password is prompted, never an argument.
.venv/bin/python -m security.cli --db /var/lib/tracedns/security/auth.sqlite bootstrap admin
# Start behind an HTTPS reverse proxy.
.venv/bin/python dns_monitor.py --security-db /var/lib/tracedns/security/auth.sqlite --http-host 127.0.0.1 --public-origin https://tracedns.example --trusted-proxy 127.0.0.1
```

| Role | Access |
| --- | --- |
| `admin` | Manage accounts, integrations, audit exports and monitoring. |
| `operator` | Manage monitored targets and run analyses. |
| `viewer` | Read stored observations without initiating external lookups. |

The server checks permissions on every API request. Audit records cover login,
account/configuration changes, denied requests and analysis/force-resolve outcomes.
Passwords, session tokens, API keys, webhooks and credential-bearing URLs are
excluded from responses and audit events.

See the [deployment guide](docs/security/deployment.md) for proxy configuration,
account recovery, audit failures and consistent backups.

<details>
<summary>Exception: plaintext HTTP on a strictly trusted wired LAN</summary>

For a strictly trusted wired LAN only, `--insecure-http --allow-insecure-remote-http --http-host 10.0.0.2 --public-origin http://10.0.0.2:8000` explicitly permits plaintext remote HTTP. Do not use it over Wi-Fi, VPN/shared networks, or the Internet: credentials and sessions are not TLS-protected.

</details>

## Using the dashboard

| Screen | Use it to |
| --- | --- |
| **Status** | Review current target observations and managed/decoded IPs. |
| **All IPs** | Browse aggregated IPs with pagination and optional VirusTotal enrichment. |
| **Valid IPs** | View the syntactically valid IP subset. “Valid” does not mean safe or reachable. |
| **Domain Verify** | Check a target and compare decoding results before monitoring it. |
| **Domain Analysis** | Review monitored domains' IP, ASN and country statistics for the current page, plus each domain's NXDOMAIN lifecycle status. |
| **Botnet IP Analysis** | Investigate IP relationships. Shared infrastructure or a cluster is not proof of infection. |
| **Settings** | Manage targets, resolvers, polling intervals, integrations and custom decoders. |

VirusTotal requests use the available page/budget controls. Increase VT workers
or budgets only with your API quota in mind. `max_workers` (or `--max-workers`)
controls parallel target queries; it is separate from the VT controls.

Settings displays each monitoring target as a searchable card with its full,
wrapping domain name, record type, registration time, and last configuration
change. Expand **View / edit configuration** for type-specific decoder fields
and ENS node/resolver values. Filtering never removes hidden targets from a
save. Failed saves retain the draft; **Load** reloads the saved configuration.

<details>
<summary>What the target dates mean</summary>

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

</details>

## Configuration

Most users can configure TraceDNS through **Settings**. The saved file is
`dns_config.json`; keep its programmatic keys unchanged.

| Key | Purpose |
| --- | --- |
| `domains` | Targets to monitor, including their type and decoder options. |
| `servers` | DNS resolvers to query. |
| `interval` | Polling interval in seconds. |
| `max_workers` | Parallel query worker limit. |
| `ens_rpc_url` | Ethereum RPC endpoint used for ENS lookups. |
| `custom_decoders` | Custom decoder definitions saved through the UI. |
| `alerts` | Teams, MISP and VirusTotal settings. |
| `domain_metadata` | Server-managed registration/change timestamps; client-supplied metadata is ignored. |

The `alerts` object includes `teams_webhook`, `misp_url`, `api_key`,
`push_event_id`, `vt_api_key`, `vt_cache_ttl_days` and optional
`misp_remove_on_absent` (default `false`). Treat this file as sensitive.

When updating targets, submit the complete `domains` list. Read and merge existing
settings before saving: removing a target also removes its history. Use the API's
revision checks to avoid overwriting someone else's changes.

## Decoders and advanced target types

Start with the record type and decoder that match the source you are examining.
Decoding an IP is not a reachability check or a malware-family attribution.

| Type | Setup |
| --- | --- |
| A | Optional `a_decode`, such as `xor32_ipv4`, and `a_xor_key`. |
| TXT | Select `txt_decode` from the built-in methods or preview a custom decoder. |
| ENS | Install the ENS dependencies, set the RPC URL, and choose the exact text key and decoder. |
| SNS | Select the SNS target type and its record/decoder settings. |
| DHT | Supply a public key to observe signed records. Failed, stale or conflicting attempts do not erase last-confirmed IPs. See the [DHT guide](docs/DHT_TRACKING.md). |
| RPC | Select the supported Polygon AES-128-GCM profile. C2 IP:port is kept separate from relay/download/mining roles. No ENS setup or C2 connection is used. See the [RPC guide](docs/RPC_TRACKING.md). |

Custom decoders use a constrained list of steps, such as `regex`, `base64`,
`urlsafe_b64` and `xor_hex`, rather than arbitrary code. **Preview** a decoder
before registering it. The UI can save, edit and delete these definitions.

<details>
<summary>TXT pseudo-IPv6 decoder and A-record options</summary>

- For pseudo-IPv6 TXT lists, choose `ipv6_last4_xor_6b9e3f2a`. This built-in decodes
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
  `{"name":"replace-with-your-target.invalid","type":"TXT","txt_decode":"ipv6_last4_xor_6b9e3f2a"}`.
  Replace the placeholder with a target you explicitly intend to monitor.
- A domains: `a_decode` (e.g. `xor32_ipv4`) and optional `a_xor_key` (hex/int/dotted-byte format)

</details>

<details>
<summary>ENS text keys, decoder options and a configuration example</summary>

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

</details>

<details>
<summary>Standalone ENS decoder: command-line reference</summary>

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

Exact decoder corpora are preserved under `docs/ens/` for traceability and
regression testing. For a record written to an off-name nodehash, set `ens_node`
and optionally `ens_resolver` alongside the exact text key and decoder. This
queries the transaction's node rather than assuming `namehash(name)`. See the
[preserved ENS examples](docs/ens/) for source-specific values.

</details>

## Alerts and delivery

- Configure a Teams webhook or MISP destination in **Settings** to receive new-IP
  notifications. Messages include local-time timestamps and cycle summaries.
- New-IP alerts are batched after a full resolve cycle. Queue admission is not
  delivery confirmation; use **Delivery health** and **Delivery diagnostics** to
  inspect progress and failures.
- Removed IPs have a 24-hour grace period. A return during the suppression window
  does not generate another new-IP alert; previously unseen IPs remain eligible.
- Admins can deliberately **Resend current IPs** from a saved target card: select
  Teams/MISP, preview the complete saved managed-IP list, then confirm. This does
  not perform a live lookup or clear history. After an uncertain outcome, check
  diagnostics and the destination rather than blindly retrying.

Read the [resend guide](docs/DELIVERY_RESEND.md) before using manual resend, and
the [delivery diagnostics guide](docs/DELIVERY_DIAGNOSTICS.md) when investigating failures.

<details>
<summary>Removal grace, reappearance suppression and persistence</summary>

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

</details>

## REST API and external clients

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

## Development and tests

Follow the [validation guide](docs/VALIDATION.md) to prepare separate application
and tooling environments, plus Node.js and Chromium for the frontend tests.
Node.js is required by `make test` and `make botnet-coverage`, not just `make e2e`.
The application requirements include pytest; `requirements-ci.txt` supplies Ruff.
Use the candidate Python environment and put Ruff on `PATH`, or pass its path as
`make lint RUFF=/path/to/tools/bin/ruff`.

From the project root, run test bodies through the Linux loopback-only wrapper:

```bash
bash scripts/ci/loopback_only.sh make test
make lint
bash scripts/ci/loopback_only.sh make security-regression
bash scripts/ci/loopback_only.sh make botnet-coverage
```

`make test` runs the Python suite and its frontend contract tests.
`make security-regression` replays preserved evidence without querying live
indicators. `make botnet-coverage` measures coverage with branch tracking enabled
and enforces an 80% minimum for the relationship-analysis module.

For browser tests, `make e2e` combines npm/browser installation and Playwright
execution. To keep downloads separate from test traffic, install the dependencies
first, then run `bash scripts/ci/loopback_only.sh npm run test:e2e` as shown in the
validation guide. The wrapper refuses to fall back to host networking.

Passing the fixed regression corpus does not measure detection rates on unseen
infrastructure. Keep test state separate from a running deployment's configuration,
history and account database.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| The dashboard is empty | The starter config has no targets. Add an explicitly selected target and check its latest lookup status. |
| DNS lookups fail after setup | The sample resolver is `127.0.0.1`. Set a working resolver unless you run one locally. |
| Startup refuses the account database | Bootstrap the first administrator and use the same `--security-db` path when starting the monitor. |
| Another computer cannot open the dashboard | The local example binds to loopback. Configure an HTTPS reverse proxy instead of exposing plaintext HTTP. |
| ENS support is unavailable | Install `requirements-ens.txt` in the interpreter environment that runs TraceDNS, then check the RPC URL and exact text key. |
| A notification is queued but not received | Check delivery health/diagnostics and the saved integration settings. Do not treat queued or unknown as delivered. |

## Documentation

| Guide | Contents |
| --- | --- |
| [Deployment and accounts](docs/security/deployment.md) | HTTPS, roles, audit, account recovery and backups. |
| [REST API](docs/API.md) / [OpenAPI](docs/openapi.json) | Authentication, requests, response contracts and external clients. |
| [AI client instructions](SKILL.md) | How an external agent should use the API safely. This is not an embedded LLM analysis engine. |
| [DHT tracking](docs/DHT_TRACKING.md) | Public-key targets, signed records, retained state and lookup limits. |
| [RPC tracking](docs/RPC_TRACKING.md) | Polygon configuration tracking and an offline decoder example. |
| [Delivery diagnostics](docs/DELIVERY_DIAGNOSTICS.md) / [resend](docs/DELIVERY_RESEND.md) | Notification state, failures and deliberate duplicate sends. |
| [ENS decoder evidence](docs/ens/) | Decoder-specific setup and preserved source records. |
| [Validation](docs/VALIDATION.md) | Test environments, network isolation and promotion checks. |

## Contributing

Contributions are welcome. Please open issues or PRs with focused changes. When editing or translating user-facing strings, avoid renaming programmatic keys in `dns_config.json`.

## License & Authors

This repository is maintained by the project owner and distributed under the [MIT](LICENSE) license.
