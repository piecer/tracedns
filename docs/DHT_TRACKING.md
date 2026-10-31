# Read-only signed DHT DNS tracking

TraceDNS supports `DHT` as a monitoring target alongside DNS, ENS and SNS. It queries an unsalted BEP44 mutable item identified by an Ed25519 public key, verifies its signature and parses the signed DNS value. The resulting IPv4 addresses enter the existing managed-IP, history, relationship and configured alert-delivery paths.

This is observation, not a C2 client: no malware execution, decoded-IP connection, DHT publication, `put`, announce or response to incoming queries is implemented. Outgoing DHT queries are `find_node`/`get` with `ro=1`. Public DHT storage peers are not classified as payload IPs. Ordinary DNS used to resolve configured bootstrap hostnames is separate from DHT UDP traffic.

## Register a target

Install the updated `requirements.txt` in the application's actual Python environment; Ed25519 verification uses `cryptography>=43,<51` and `PyNaCl==1.6.2` for libsodium public-key point validation. A shape-valid key can be registered, but weak/low-order keys cannot produce an authenticated observation. Existing configuration files are not migrated to include any research target automatically.

In Settings, add a target, select **DHT**, supply a display label and the complete public key. Alternatively use Domain Verify / Analysis, select DHT, validate and add the returned target. Precheck never enables VT enrichment or a decoder sweep, even if their usual checkboxes were selected. A valid configuration can be added when the lookup finds nothing; `can_add=true` is not evidence of retrieval.

Example target for the independently analyzed research key (public identifier, not a credential):

```json
{
  "name": "Signed DNS research",
  "type": "DHT",
  "dht_public_key": "154c64104a798935be5f7f54dcfe4644b062ab7618b34ab390e69e22fbc5252f",
  "dht_options": {"duration": 30, "max_queries": 128}
}
```

Supply this inside the complete `domains` list with the current config revision. Never replace another installation's entire list with this example. No DNS server, ENS RPC or SNS proxy is required; there is exactly one logical `DHT` provider regardless of DNS-server count.

The public key must be exactly 64 hexadecimal characters without prefixes or whitespace. Both hex cases are accepted; identity uses lowercase. The display label is not a DNS name: a trailing dot is literal. Registration identity includes label and public key. Changing a key creates a different target, rather than reusing the old key's sequence state. Removing/renaming targets follows existing history-purge semantics; export history first if it must be retained. Labels must fit the existing encoded history filename and cannot contain control characters.

## Bounded lookup options

`dht_options` is an optional object. Omit it or supply `{}` for defaults; explicit JSON `null` is rejected. Unknown properties and incorrect scalar types are rejected before configuration persistence, force-job admission or network work.

| Option | Default | Accepted range |
| --- | --- | --- |
| `duration` | 30 seconds | 0.05–60 |
| `max_queries` | 128 | integer 1–128 |
| `timeout` | 2.5 seconds | 0.02–5 |
| `rate` | 4 sends/second | 0.1–5 |
| `concurrency` | 4 | integer 1–4 |
| `max_nodes` | 512 | integer 1–512 |
| `bootstraps` | built-in public routers | 1–8 `host:port` strings, at most 260 characters each |

Custom bootstraps must resolve to permitted public IPv4 destinations. Private, loopback, multicast, noncanonical numeric and mixed prohibited DNS answers are refused; there is no private-peer override. Two lookup slots are shared process-wide. Bootstrap resolution uses bounded, terminated/reaped subprocesses within the same lookup deadline. Query, receive, node and retained-record limits prevent an unbounded crawl. Cancellation and target ownership fence late results. Coverage fields describe what the bounded attempt actually did, not a census of the DHT.

## Last confirmed record versus latest attempt

A snapshot stores the public key, selected signed record and raw DNS `value_hex`; `decoded_ips` alone supplies its managed IPs. Sequence numbers are canonical decimal strings across JSON and JavaScript, including values above JavaScript's exact integer range. They are ordering values, not timestamps.

`history.meta.dht_state` retains a bounded high-water/conflict state and signed evidence. `history.meta.dht_observation` describes the latest attempt and coverage independently of the retained snapshot. The application also checkpoints anti-rollback evidence in its existing delivery ledger before publication, including high-water advances with invalid DNS or conflicts. Persisted evidence is reverified; stored derived-IP claims are not trusted on restart. Optional `source_node` is a bounded public storage-node endpoint with `source_node_signed=false`: it is unsigned observation metadata, not the signer or a managed IP.

Keep the complete history directory, including its delivery ledger, when backing up this state. Best-effort history JSON alone is not the durable anti-rollback authority. An in-flight restart fence is written before lookup; a definite cancellation clears only its own fence. An interrupted process or failed/uncertain final checkpoint leaves that target blocked across restart rather than trusting an unknown sequence baseline. Storage diagnostics report the gap. After repairing storage, export evidence before any deliberate target deletion/re-registration: that existing retirement operation resets the target's anti-rollback history and is not an automatic recovery step. Do not delete the shared ledger to clear one target. Normal lookup misses do not create this persistent block.

| Latest status | Meaning |
| --- | --- |
| `initial` | First unambiguous verified and decoded record |
| `updated` | Accepted newer record |
| `unchanged` | Same confirmed signed value/sequence |
| `no_verified_record` | No usable verified record found in the attempt |
| `stale_only` | Observed records are older than the retained high-water mark |
| `same_seq_conflict` | Different signed values share the highest sequence |
| `signed_dns_invalid` | Signature is valid but the selected payload is not decodable DNS |
| `cancelled` | The lookup was cancelled |

Misses, stale records, conflicts, malformed signed DNS and cancellation retain the last confirmed addresses, even after repeated failures and restart. They do not produce authoritative empty sets or removal alerts. A newer valid signed DNS record with no usable A answers can withdraw addresses through the existing removal policy. Sequence/provenance changes are retained in history even if the decoded IP set is unchanged.

Status presents the latest attempt separately from the last-confirmed sequence/IPs. The full public key and coverage warning remain visible; signature/hash/target/coverage details can be expanded. A signed address does not by itself establish C2 activity, reachability, ownership or infection.

## API and evidence

Legacy and `/api/v1` aliases share authentication, roles, CSRF, configuration revisions and audit behavior. DHT uses the existing config, precheck, resolve, results, history and IP endpoints; it does not add a privileged network-proxy endpoint.

- Precheck: `domain` is the display label, `type="DHT"`, plus `dht_public_key` and optional `dht_options`. Response includes `domain_object`, `dht_record`, `dht_observation`, `managed_ips` and `by_server`.
- Force: pass the configured typed object in `domains`, not the A-record-only `domain` shorthand. Its options and identity remain pinned to the saved configuration.
- Results: aggregated rows include `dht_public_keys`, `dht_targets`, `dht_sequences` and selected record provenance. `domain_meta` exposes attempt status. Never-confirmed targets participate in prepared pagination, with page-scoped metadata.
- History retains signed values and sequence changes. Existing raw JSON export remains available; displayed/paginated projections do not delete source evidence.

No full packet capture or historical DHT census is promised. The parser deliberately follows the analyzed signed-DNS payload convention: at most 2048 value bytes, first 64 answer records, A records with at least four RDATA bytes, class ignored, first IPv4 bytes used without XOR. This compatibility bound is not a claim that standard storage nodes will accept values larger than the BEP44 storage limit. Salted items, IPv6 DHT transport and arbitrary BEP44 value applications are not supported.

## Verification and operational limits

`make test` and `make lint` cover protocol, HTTP, monitor, persistence and legacy regressions. `npm run test:e2e -- dht-tracking.spec.js dht-real-api.spec.js` uses Chromium: synthetic response tests cover UI states, while the real-API test runs the actual application main/worker/ledger, authenticates, registers a signed fixture, forces a miss and restarts with retained state. Only its DHT network source is replaced. Those browser tests are not live public-DHT evidence.

Live acceptance must use separate configuration/history and disabled alert/enrichment destinations. A failed bounded live lookup is a coverage result, not proof the record disappeared. Do not restart an operating service or enable recurring research lookups merely to validate this feature.

Protocol references: [BEP44 mutable items](https://www.bittorrent.org/beps/bep_0044.html) and [BEP43 read-only nodes](https://www.bittorrent.org/beps/bep_0043.html).
