"""Execute shipped RPC UI helpers, without a browser or network."""
from test_dht_frontend import run_js


def test_rpc_identity_and_managed_ips_never_include_ciphertext():
    run_js(['normalizeDomainName', 'domainConfigIdentity', 'domainStorageName', 'managedIpsForResult'], r"""
const target = {name:'Polygon label.',type:'RPC',rpc_profile:'polygon_aes_gcm_v1'};
assert.equal(domainConfigIdentity(target), 'polygon label.|RPC|polygon_aes_gcm_v1');
assert.equal(domainStorageName(target), 'Polygon label. [RPC:polygon_aes_gcm_v1]');
assert.deepEqual(managedIpsForResult({type:'RPC',values:['0xdeadbeef'],decoded_ips:['192.0.2.10']}), ['192.0.2.10']);
""")


def test_rpc_evidence_reports_endpoints_separately_from_other_roles_and_staleness():
    run_js(['rpcEvidenceText'], r"""
const info = {rpc_profile:'polygon_aes_gcm_v1', decoded_endpoints:['192.0.2.10:18082'],
  rpc_record:{chain_id:137,contract:'0xabc',selector:'0x6d4ce63c',authentication:'aes-128-gcm',
    source_rpc:'https://public.invalid/',roles:{relay:['203.0.113.1:443']},plaintext:'raw config'}};
const text = rpcEvidenceText(info, {status:'error', reason:'rpc_auth_failed'});
assert(text.includes('192.0.2.10:18082'));
assert(text.includes('Last authenticated'));
assert(text.includes('rpc_auth_failed'));
assert(text.includes('relay') && text.includes('203.0.113.1:443'));
assert(text.includes('not C2') && text.includes('No C2 contact'));
assert(text.includes('0xabc') && text.includes('0x6d4ce63c'));
assert(rpcEvidenceText({}, {status:'error'}).includes('No authenticated C2 configuration'));
""")


def test_rpc_fallback_aggregation_preserves_record_and_endpoints():
    run_js(['aggregateResultsByDomain', 'managedIpsForResult'], r"""
const record = {profile:'polygon_aes_gcm_v1',authentication:'aes-128-gcm',roles:{relay:['203.0.113.1:443']}};
const snapshot = {type:'RPC',values:['0x1234'],decoded_ips:['192.0.2.10'],decoded_endpoints:['192.0.2.10:443'],rpc_record:record,ts:100};
const agg = aggregateResultsByDomain({label:{RPC:snapshot}}).label;
assert.deepEqual(agg.rpc_record, record);
assert.deepEqual(agg.decoded_endpoints, ['192.0.2.10:443']);
assert.deepEqual(managedIpsForResult(agg), ['192.0.2.10']);
""")
