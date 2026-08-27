# `xorisgayilovekidsandihatemilfs.eth` Host tracking

## Why this target needs a plain-IPv4 decoder

The ENS Manager currently shows a case-sensitive `Host` text record containing
`94.154.43.176`. The resolver is ENS Public Resolver 3
(`0xF29100983E058B709F3D539b0c765937B804AC15`), and the ENS address is
`0x47CC560BDdFBB3a28519Fc11ebe253Ea44B33338`.

The existing TraceDNS ENS decoders handled obfuscated IPv4 material embedded in
IPv6-looking values, but did not promote a plain IPv4 text-record value into
`snapshot.decoded_ips`. The `ipv4_literals` method fills that gap so the normal
history, relationship, VirusTotal, Teams, and MISP paths can process the value.

## Observed on-chain record history

The address transaction history exposes three `setText(bytes32,string,string)`
updates for the same ENS node and the exact key `Host`:

| UTC timestamp | Transaction | Value |
| --- | --- | --- |
| 2026-05-23 14:31:47 | `0x0f56db2e41626a85f09d7add530df1f023dcbda69af17f35556688454d27dfb5` | `162.141.92.3` |
| 2026-06-16 09:10:47 | `0xf862e3c01c7fbb7340c58ae3e16719f40c65c31b5bf1ad04901e0fe27b500838` | `95.135.208.173` |
| 2026-08-20 21:24:11 | `0x8a8997c1846464edfd4535181f170831dc4b90e400251dcef163a0fb39b66f8e` | `94.154.43.176` |

Treat these as time-bounded infrastructure pivots. In particular,
`162.141.92.3:82` is published by ThreatFox as a Mirai/Katana payload-delivery
IOC, and URLhaus lists malware payload URLs hosted at `162.141.92.3`.

## TraceDNS configuration

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

`Host` must retain its capitalization because ENS text keys are case-sensitive.
After saving, Domain Verify should report the current text value as one managed
IP. Polling changes then flow through the existing TraceDNS snapshot/history and
new-IP alert machinery.

A one-shot verification command is:

```bash
python3 ens_ipv6_decoder.py xorisgayilovekidsandihatemilfs.eth \
  --rpc https://<mainnet-rpc> \
  --key Host \
  --decode-method ipv4_literals
```

## References

- ENS Manager record view: https://app.ens.domains/xorisgayilovekidsandihatemilfs.eth
- Address and transaction history: https://etherscan.io/address/0x47cc560bddfbb3a28519fc11ebe253ea44b33338
- ThreatFox IOC: https://threatfox.abuse.ch/ioc/1824871/
- URLhaus host record: https://urlhaus.abuse.ch/host/162.141.92.3/
- ENS Public Resolver profiles: https://docs.ens.domains/resolvers/public
