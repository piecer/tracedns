# Authenticated ENS SHA-256/HMAC/XOR decoder

TraceDNS built-in method: `sha256_hmac_xor`.

This method recovers a literal IPv4 address and its authenticated TCP port from
an ENS text record. It is selectable in the existing Settings and Domain Verify
ENS decoder menus through the backend decoder catalog. No custom Python code or
new dependency is required for decryption.

## Configuration

Use the existing ENS RPC setting and this per-domain configuration:

```json
{
  "name": "chillpedophile.eth",
  "type": "ENS",
  "ens_text_key": "name",
  "ens_decode": "sha256_hmac_xor",
  "ens_options": {
    "key_hex": "6b39236d503224764c38406e5135217852372a775a345e74593126754a365f62",
    "marker": "1488:"
  }
}
```

In Settings:

1. Set the target's record type to `ENS`.
2. Set ENS record key to `name` (lowercase).
3. Select `sha256_hmac_xor` as the ENS decoder.
4. Enter the `ens_options` object above in Decoder options (JSON).
5. Keep a working Ethereum mainnet RPC URL in the existing ENS RPC setting.

The example key is configuration material extracted from the analyzed malware,
not a user account password or an Ethereum signing key. Decoder options are
ordinary persisted configuration and may appear in result provenance; do not
put account credentials in them.

There is no built-in default decryption key and no domain/IP-specific mapping.
Another sample using this scheme can supply a different `key_hex` and `marker`.
Existing RPC lookup, optional `ens_node`, and optional `ens_resolver` behavior is
unchanged; this decoder adds no alternate RPC routing or automatic fallback
resolver. Ordinarily leave node/resolver unset to follow the ENS registry.

## Algorithm

The decoder follows the observed sample's record format:

```text
record = optional_text + marker + hex(nonce[8] || ciphertext || tag[8])
K = SHA256(bytes.fromhex(key_hex))
expected_tag = HMAC-SHA256(K, nonce || ciphertext)[:8]
keystream_block(i) = SHA256(K || nonce || uint32_big_endian(i)), starting at i=0
plaintext = ciphertext XOR concatenated_keystream
```

The decoder finds the first exact marker, trims surrounding whitespace from the
remainder, and takes the hex token up to space, tab, CR, LF, or a double quote.
The HMAC is compared with `hmac.compare_digest` before decrypting or parsing an
IP. AES, ordinary DNS resolution of `.eth`, and reverse-name `name(bytes32)` are
not involved. The query remains ENS `text(node, "name")`.

## Output and rejection rules

- `decoded_ips`: validated IPv4 only, for existing managed-IP/history/alert paths.
- `decoded_endpoints`: the validated, authenticated `IPv4:port`, including the
  original decimal port spelling. A changed port is preserved in current results
  and history even when the IP does not change.
- `values`: the original fetched encrypted text, not replaced by the plaintext.
- Only literal IPv4 endpoints with a 1–5 digit decimal port in `1..65535` are
  promoted. Hostnames, IPv6, URLs, bare IPs and trailing plaintext are rejected;
  this decoder never resolves or contacts a decrypted destination.
- Missing/wrong keys, malformed hex, short records, invalid marker/options,
  failed HMAC and invalid plaintext yield no IPs and no endpoints.
- `key_hex` must contain 1–256 bytes as exact even-length hex (no `0x`, spaces,
  or newline). The value is the original key bytes, not their SHA-256 digest.
- `marker` defaults to `1488:` and must be a string of 1–64 characters.
- Raw input is limited to 4,096 characters before token parsing or hashing.
- An outer `]:port` is never used for this method, including on HMAC failure.
  The existing `suffix_is_port` option applies only to legacy bracketed formats;
  it does not suppress the new method's authenticated plaintext port.

A successful ENS query (`status=ok`) still means retrieval succeeded; it does not
independently assert decryption success. Inspect `decoded_ips` and
`decoded_endpoints`. Invalid records remain visible as raw evidence.

## Preserved evidence

`sha256-hmac-xor-decoder.json` contains a real historical record and its expected
plaintext, extracted from the analysis of:

```text
SHA-256: fa97cce05ae92289e3f5604abd290dd3e0088da843e67f78a503cac9d6f74b89
ENS: chillpedophile.eth
text key: name
Ethereum mainnet block: 26203772
observed UTC: 2026-10-16T08:03:19.519577+00:00
raw: 1488:6b7c8007f715b7fc038420de47eb42742ce8580c83589ac0d0031b61af8ba06d9ea04f
expected: 136.85.228.108:4433
```

The endpoint is an observation at that block, not a hard-coded output, a promise
that the record still has that value, or proof the server is online. Public RPC
and shared ENS registry/resolver infrastructure must not be labeled as C2 merely
because they retrieve this record.

## Verification

Offline focused regressions:

```sh
.venv/bin/python -m pytest -q tests/test_ens_sha256_hmac_xor.py tests/test_ens_authenticated_integration.py
```

Canonical backend gates and the isolated browser smoke:

```sh
make test
make lint
npm run test:e2e -- tests/e2e/ens-authenticated-decoder.spec.js
```

Coverage includes the historical record, configurable synthetic keys/endpoints,
HMAC tampering, malformed options, input bounds, outer-suffix rejection, raw
record retention, collector-managed IPs, both legacy/v1 precheck routes, catalog
registration, config persistence, port-only history changes, restart restoration,
results serialization and browser selection/save/reload. Synthetic fixtures are
explicitly test-only, not additional observed infrastructure.

The existing CLI can make a read-only live ENS query when its optional Web3
dependency is installed. Replace the example RPC with your existing public RPC;
this does not contact the decoded endpoint:

```sh
python3 ens_ipv6_decoder.py chillpedophile.eth \
  --rpc https://ethereum-rpc.publicnode.com \
  --key name --decode-method sha256_hmac_xor \
  --ens-options '{"key_hex":"6b39236d503224764c38406e5135217852372a775a345e74593126754a365f62","marker":"1488:"}'
```

The CLI retains its existing IPv4-only output. The collector and precheck API
also expose the authenticated port through `decoded_endpoints`.
