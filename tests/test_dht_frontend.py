"""Execute shipped frontend helpers in Node; no DHT/external network traffic."""
import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_js(names, assertions):
    source = (ROOT / "dns_frontend.js").read_text()
    functions = []
    for name in names:
        match = re.search(r"^(?:async )?function " + name + r"\([^\n]*\)\{[\s\S]*?^\}", source, re.M)
        assert match, f"Missing shipped helper: {name}"
        functions.append(match.group())
    script = "const assert = require('node:assert/strict');\n" + "\n".join(functions) + "\n" + assertions
    result = subprocess.run(["node", "-e", script], cwd=ROOT, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


def test_dht_identity_and_inputs_preserve_label_and_exact_key():
    run_js(["normalizeDomainName", "domainConfigIdentity", "parseJsonObjectInput", "parseDhtInputs"], r"""
const key = 'AB'.repeat(32);
const target = {name:'Research label.', type:'DHT', dht_public_key:key};
assert.equal(domainConfigIdentity(target), 'research label.|DHT|' + key.toLowerCase());
assert.notEqual(domainConfigIdentity(target), domainConfigIdentity({...target, dht_public_key:'cd'.repeat(32)}));
assert.equal(domainConfigIdentity({name:'EXAMPLE.test.', type:'A'}), 'example.test');
assert.deepEqual(parseDhtInputs(key, ''), {ok:true, value:{dht_public_key:key}});
assert.deepEqual(parseDhtInputs(key, '{}'), {ok:true, value:{dht_public_key:key, dht_options:{}}});
for (const invalid of ['', 'aa'.repeat(31), 'aa'.repeat(33), 'G'.repeat(64), '0x'+key, ' '+key, key+'\n']) {
  assert.equal(parseDhtInputs(invalid, '').ok, false, JSON.stringify(invalid));
}
for (const invalid of ['[]', 'null', '42', '{bad}', '{"secret":"x"}', '{"__proto__":{}}']) {
  assert.equal(parseDhtInputs(key, invalid).ok, false, invalid);
}
const options = {duration:3,max_queries:12,timeout:1,rate:4,concurrency:2,max_nodes:20};
assert.deepEqual(parseDhtInputs(key, JSON.stringify(options)).value.dht_options, options);
""")


def test_dht_aggregation_preserves_decimal_strings_and_only_decoded_managed_ips():
    run_js(["aggregateResultsByDomain", "managedIpsForResult"], r"""
const seq = '9223372036854775807';
const raw = {type:'DHT', values:['signed-packet-not-an-IP'], decoded_ips:['192.0.2.9'],
  dht_public_key:'ab'.repeat(32), dht_record:{seq, target:'cd'.repeat(20), signature_valid:true}, ts:100};
const agg = aggregateResultsByDomain({label:{DHT:raw}}).label;
assert.deepEqual(agg.dht_public_keys, [raw.dht_public_key]);
assert.deepEqual(agg.dht_targets, [raw.dht_record.target]);
assert.deepEqual(agg.dht_sequences, [seq]);
assert.deepEqual(managedIpsForResult(agg), ['192.0.2.9']);
assert.deepEqual(managedIpsForResult({type:'A',values:['192.0.2.1'],decoded_ips:[]}), ['192.0.2.1']);
assert.deepEqual(managedIpsForResult({type:'TXT',values:['txt'],decoded_ips:['192.0.2.2']}), ['192.0.2.2']);
""")


def test_dht_attempt_text_keeps_last_confirmed_and_reports_unknown_coverage():
    run_js(["formatLocalDateTime", "formatUnixTsLocal", "formatDhtSequence", "dhtEvidenceText"], r"""
const seq = '9223372036854775807';
const key = 'ab'.repeat(32), target = 'cd'.repeat(20), hash = 'ef'.repeat(32);
const info = {dht_public_keys:[key], dht_targets:[target], dht_sequences:[seq], decoded_ips:['192.0.2.9'],
  dht_record:{seq,target,value_sha256:hash,signature_valid:true,source_node:['8.8.8.8',6881]}};
for (const status of ['initial','updated','unchanged','no_verified_record','stale_only','same_seq_conflict','signed_dns_invalid','cancelled']) {
  const text = dhtEvidenceText(info, {status,observed_at:1700000000,seq:'0',coverage:{complete:false,queries:2}});
  assert(text.includes('Latest lookup attempt: '+status));
  assert(text.includes('Last-confirmed sequence: '+seq));
  assert(text.includes('Observed sequence: 0'));
  assert(text.includes(key) && text.includes(target) && text.includes(hash));
  assert(text.includes('Coverage: {"complete":false,"queries":2}'));
  assert(text.includes('not proof of absence or deletion'));
  assert(text.includes('not proof of actual C2 activity'));
  assert(text.includes('Storage node (unsigned observation, not signer/C2): ["8.8.8.8",6881]'));
}
const empty = dhtEvidenceText({}, {status:'no_verified_record'}, 'label [DHT:'+key+']');
assert(empty.includes(key));
assert(empty.includes('No last-confirmed record available'));
assert(empty.includes('Coverage: unknown'));
assert.equal(formatDhtSequence(9223372036854775807), 'unknown (expected decimal string)');
assert.equal(formatDhtSequence('0'), '0');
""")


def test_dht_storage_name_removal_is_key_specific():
    run_js(["domainStorageName", "removeDomainsFromConfig"], r"""
(async()=>{
  const first = {name:'Label.',type:'DHT',dht_public_key:'AB'.repeat(32)};
  const second = {...first,dht_public_key:'CD'.repeat(32)};
  const storage = 'Label. [DHT:'+'ab'.repeat(32)+']';
  assert.equal(domainStorageName(first), storage);
  assert.equal(domainStorageName({name:'dns.test',type:'A'}), 'dns.test');
  let posted;
  global.window = {confirm:()=>true};
  global.fetch = async (_, options)=>({ok:true,json:async()=>{
    if(!options) return {domains:[first,second,'legacy.test'],revision:4};
    posted = JSON.parse(options.body); return {status:'ok'};
  }});
  global.setDomainRemoveStatus = ()=>{};
  global.getDomainAnalysisSelectionSet = ()=>new Set();
  global.refreshDomainAnalysis = global.loadCfg = global.refreshResults = global.refreshIPs = global.refreshValidIPs = async()=>{};
  assert.equal(await removeDomainsFromConfig([storage]), true);
  assert.deepEqual(posted, {domains:[second,'legacy.test'],revision:4});
})().catch(error=>{console.error(error);process.exitCode=1;});
""")
