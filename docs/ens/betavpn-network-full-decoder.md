# Betavpn ENS `network` full decoder

## Purpose

- This project-local artifact preserves the board-validated 25-entry betavpn ENS `network` mapping for traceability and IOC extraction.
- The same board update also supplied a reusable runtime ENS decoding method, implemented in this repo as `ROL3210_decode` with a compatibility alias `betavpn_network_full`.

## Runtime decoding method

- Method names:
  - `ROL3210_decode`
  - `betavpn_network_full` (compatibility alias)
- Input:
  - Take IPv6 bytes 5:8 (1-indexed), equivalent to `packed[4:8]`.
- Transform:
  - `ip0 = rol8(XX, 3)`
  - `yy_eff = YY ^ 0x20 if XX in (0x65, 0x71) else YY`
  - `ip1 = rol8(yy_eff, 2)`
  - `base2 = rol8(ZZ, 1)`
  - `ip2 = (base2 + ((~(base2 << 1)) & 0x08)) & 0xff`
  - `ip3 = (WW + ((~(WW << 1)) & 0xa8)) & 0xff`
- Record normalization:
  - Strip any control prefix such as `network\x02%` and decode from the first IPv6 token onward.

## Project-local representation

- Runtime decoder:
  - `ens_decoder.py` (`ROL3210_decode`, alias `betavpn_network_full`)
- Machine-readable artifact:
  - `docs/ens/betavpn-network-full-decoder.json`
- Static helper module:
  - `ens_static_mapping.py`

The helper exposes:

- `load_betavpn_network_full_artifact()`
- `extract_ipv6_tokens(raw_record)`
- `map_betavpn_network_full_record(raw_record)`
- `get_betavpn_network_full_iocs()`

Expected artifact behavior:

- Strip any control prefix such as `network\x02%`.
- Parse from the first IPv6 token onward.
- Only emit exact matches present in the preserved 25-entry mapping.
- Preserve the original source-entry to IOC relationship even though a runtime decoder now exists.

## Source references

- `/home/piecer/dev/src/malware_report/analysis/samples/5b34ea2a57bea8c41c74ceac3101db89b58d9c65f70b900988b87135eb21a914/reports/2026-05-13-betavpn-ens-network-full-decoder-report.md`
- `/home/piecer/dev/src/malware_report/analysis/samples/5b34ea2a57bea8c41c74ceac3101db89b58d9c65f70b900988b87135eb21a914/reports/2026-05-13-ens-network-full-decoder.json`
