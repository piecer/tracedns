# Polygon RPC C2 configuration tracking

`RPC` is a separate target type, not DNS `A`, ENS or SNS. The built-in
`polygon_aes_gcm_v1` profile implements the contract lookup and authenticated
configuration format described in the supplied `rpc.txt` report. It does not
execute either malware sample or contact recovered C2/download/relay/pool hosts.

## Use in TraceDNS

In **Domain Verify & Add**, select **RPC (Polygon AES-GCM C2)**, enter a display
label (for example `Polygon config`), and leave **RPC profile** at
**Polygon AES-128-GCM (rpc.txt)**. Validate, inspect the C2 endpoints and separate
auxiliary roles, then select **Add RPC target**. Registration is explicit; a
precheck never saves a target. Settings also supports adding/editing RPC targets.
No ENS RPC URL, conventional DNS resolver or additional dependency is required.

A target object for the existing configuration/API is:

```json
{"name":"Polygon config","type":"RPC","rpc_profile":"polygon_aes_gcm_v1"}
```

The profile may be omitted to select this built-in default. Explicit null,
unknown or whitespace-modified profile names are rejected. Arbitrary RPC URLs,
contracts, keys and methods are not accepted as target options. Preserve other
configured targets when editing the complete `domains` list. The existing global
`interval` controls polling; the sample's 300-second refresh is not silently
imposed on other targets. For a dedicated monitor, `interval: 300` matches that
sample interval.

Identity: lowercased display label + `|RPC|polygon_aes_gcm_v1`.
History/storage name: `Polygon config [RPC:polygon_aes_gcm_v1]`.
Trailing dots in labels are literal. DNS and RPC targets with the same label
have distinct identities. Label length is checked against the encoded history
filename limit before configuration writes or precheck network I/O.

## Standalone decoder

```bash
# Read the current public contract; prints only authenticated C2 IP:port entries.
.venv/bin/python rpc_query.py

# Include source identity, raw ABI, plaintext and separately labelled roles.
.venv/bin/python rpc_query.py --json

# Strictly offline: JSON-RPC {"result":"0x..."} or captured {"raw_result":"0x..."}.
.venv/bin/python rpc_query.py --input docs/rpc/polygon-aes-gcm-observation.json --json
```

Invalid input/authentication returns a nonzero exit with a bounded reason code.
Offline output is not a new observation. No historical C2 IP is hardcoded in
production; the preserved JSON is a regression corpus, never a network fallback.

## Wire and decoding contract

The fixed call uses Polygon (chain 137), `eth_call`, target
`0x5D5abC33a4e5C602a002815d93806b204324D1a1`, selector `0x6d4ce63c`,
block `latest`, and JSON-RPC id `1`. It does not append an ENS namehash or query an
ENS registry. Public providers are tried in this order:

1. `https://1rpc.io/matic`
2. `https://polygon.gateway.tenderly.co/`
3. `https://polygon-bor.publicnode.com/`
4. `https://polygon.drpc.org/`

A failed request, bad response, authentication failure or configuration with no
valid C2 moves to the next provider. The first authenticated, nonempty C2 result
wins. This is one logical monitor provider, `RPC:polygon_aes_gcm_v1`, not four
independent votes. Failure of all providers is an error, not an empty/removed C2
set. The sample's executable-tail and `.c2` file fallbacks are deliberately not
implemented: TraceDNS never runs the sample or imports unverified local C2 data.

Response requirements:

- JSON-RPC `2.0`, exact integer id `1`, `result` present and no `error` field.
- Strict even-length `0x` hexadecimal, at most 2,048 decoded bytes.
- Canonical single dynamic ABI `bytes`: offset word exactly 32, full-width length
  integer in 29–1,428, exact padded total size, zero alignment padding.
  These checks are intentionally stricter than the malware's unchecked offset
  and 32-bit truncating length accumulator.
- Dynamic data is nonce (12 bytes), ciphertext, GCM tag (16 bytes). The public
  embedded sample key is `805c5098c496b1e3ee6b2f8a00adf088` (AES-128), with no AAD.
  `cryptography` verifies the tag before any plaintext is parsed. No unauthenticated
  plaintext recovery or permissive raw-IP extraction is attempted.
- UTF-8 plaintext is split on LF, CR and comma. Bare IPv4:port and case-insensitive
  `j` lines supply C2. IPv4 zero/broadcast and ports outside 1–65535 are excluded.
  Canonical dotted-decimal addresses only; maximum 24 distinct IP:port entries,
  in source order. The same IP on different ports remains distinct.
- `r`, `m`, `ma`, `w`, `p`, `p2` remain relay/download/download-alt/wallet/pool/pool-alt
  evidence. `l` and unknown/invalid lines are retained as ignored evidence. They
  are never used as managed C2 IPs or followed as URLs.

`decoded_ips` contains unique C2 IPs; `decoded_endpoints` retains their ports.
`values` preserves the raw ABI string, and `rpc_record` preserves authenticated
plaintext, roles, request identity and selected public provider. Existing IP
history, relationship views and configured Teams/MISP delivery receive only the
managed IP set with source type `RPC`; delivery remains IP-based, while endpoint
port changes remain in observation history. Unconfigured integrations stay off.

## Failure and resource semantics

TLS verification is always on. Environment proxies, redirects (including
Requests' implicit redirect-body prefetch) and automatic request retries are
not used. Responses must be 2xx and identity-encoded; unsupported content
encoding fails over rather than decompressing an unbounded body. Reads are
1,024-byte chunks with an 8,192-byte body cap. Each provider attempt gets at most
8 seconds cooperatively; monitor and precheck have a 35-second overall logical
budget. Every live socket read is rebound to the remaining attempt/owner time.
Cancellation or expiry is checked before/after transport and decode and cannot
start another fallback or publish a late result. Blocked native DNS/connect calls
are not forcibly terminated; the existing lookup worker retains physical ownership
until return. See [lookup runtime](LOOKUP_RUNTIME.md).

A failed lookup retains the last authenticated snapshot, including after repeated
failures. `domain_meta[storage_name].rpc_observation` reports the latest attempt
(`authenticated` or `error`, timestamp, and a sanitized failure reason). The Status
view separates that latest attempt from last-authenticated C2 endpoints and exposes
source/roles/plaintext under expandable details. Missing evidence is not displayed
as successful authentication. The configured target can be registered while RPC is
unavailable. Precheck always disables VT and decoder sweeps, irrespective of the
request's generic enrichment defaults.

AES-GCM verification establishes integrity under the embedded sample key, not
independent publisher identity, chain finality, C2 reachability or proof of current
malicious activity. `latest` is the selected provider's observation; there is no
multi-provider consensus, pinned-block verification or anti-rollback sequence.

## Preserved observation and tests

`rpc/polygon-aes-gcm-observation.json` was acquired read-only at
`2026-11-10T05:55:19.364098+00:00` from 1RPC. It contains 608 ABI bytes and decodes
to 515 plaintext bytes, matching the report's four endpoints:

- `139.170.223.9:18082`
- `98.177.81.185:18082`
- `80.87.206.91:443`
- `80.87.206.95:443`

These are historical observations and can change. No connection to these C2s was
made during implementation. Synthetic and captured-input tests cover ABI/tag
rejection, role separation, limits, fallback, configuration admission, monitor
history, source types, precheck, UI helpers and offline CLI. The browser test
`tests/e2e/rpc-tracking.spec.js` runs the actual app, API, decoder, worker and
persistence with only RPC transport replaced by the captured response; it blocks
external connections and covers add/edit/force/miss/restart. It is not a deployed
server or live-provider browser test.
