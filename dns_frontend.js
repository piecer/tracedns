const SECTION_BUTTON_MAP = {
  settings: 'menuSettings',
  domainverify: 'menuDomainVerify',
  status: 'menuStatus',
  query: 'menuQuery',
  domainanalysis: 'menuDomainAnalysis',
  ipintel: 'menuIpIntel',
  ips: 'menuIPs',
  validips: 'menuValidIPs'
};

function getActiveSectionId(){
  const el = document.querySelector('.section.active');
  return el ? el.id : '';
}

function triggerSectionRefresh(name){
  if(name === 'domainverify'){
    initDomainVerifyUi();
    return;
  }
  if(name === 'status'){
    refreshResults();
    return;
  }
  if(name === 'ips'){
    refreshIPs();
    return;
  }
  if(name === 'validips'){
    const since = parseInt((document.getElementById('valid_since') || {}).value, 10) || 0;
    refreshValidIPs(since);
    return;
  }
  if(name === 'domainanalysis'){
    refreshDomainAnalysis();
  }
}

function showSection(name){
  ['settings','domainverify','status','query','domainanalysis','ipintel','ips','validips'].forEach(id=>document.getElementById(id).classList.remove('active'));
  document.getElementById(name).classList.add('active');
  Object.keys(SECTION_BUTTON_MAP).forEach(sec=>{
    const btn = document.getElementById(SECTION_BUTTON_MAP[sec]);
    if(!btn) return;
    btn.classList.toggle('active', sec === name);
  });
  triggerSectionRefresh(name);
}
document.getElementById('menuSettings').onclick = ()=> showSection('settings');
document.getElementById('menuDomainVerify').onclick = ()=> showSection('domainverify');
document.getElementById('menuStatus').onclick = ()=> showSection('status');
document.getElementById('menuQuery').onclick = ()=> showSection('query');
document.getElementById('menuDomainAnalysis').onclick = ()=> showSection('domainanalysis');
document.getElementById('menuIpIntel').onclick = ()=> showSection('ipintel');
document.getElementById('menuIPs').onclick = ()=> showSection('ips');
document.getElementById('menuValidIPs').onclick = ()=> showSection('validips');

function log(msg){ document.getElementById('log').textContent += msg + "\n"; }
const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
const IP_REL_PAIR_TABLE_RENDER_LIMIT = 1000;
const IP_REL_CLUSTER_TABLE_RENDER_LIMIT = 1000;
const IP_REL_GRAPH_EDGE_RENDER_LIMIT = 600;
const IP_REL_GRAPH_NODE_RENDER_LIMIT = 400;
const IP_REL_GRAPH_COSE_NODE_LIMIT = 180;
const IP_REL_GRAPH_COSE_EDGE_LIMIT = 300;
window.DOMAIN_ANALYSIS_CACHE = [];
window.DOMAIN_ANALYSIS_INCLUDE_VT = true;
window.DOMAIN_ANALYSIS_SELECTED_REMOVE = window.DOMAIN_ANALYSIS_SELECTED_REMOVE || new Set();
window.DOMAIN_VERIFY_LAST = null;
window.IP_REL_GRAPH_SIGNATURE = '';
window.IP_REL_MAP_SIGNATURE = '';
window.IP_REL_COUNTRY_CENTROIDS = null;
window.IP_REL_COUNTRY_CENTROIDS_PROMISE = null;
window.IP_REL_WORLD_GEOJSON = null;
window.IP_REL_WORLD_GEOJSON_PROMISE = null;

let ipIntelAnalyzeController = null;
let ipIntelAnalyzeSeq = 0;
let ipRelAnalyzeController = null;
let ipRelAnalyzeSeq = 0;
let ipIntelBusyCount = 0;
let refreshDomainAnalysisInFlight = false;

function setIpIntelBusy(isBusy){
  ipIntelBusyCount = Math.max(0, ipIntelBusyCount + (isBusy ? 1 : -1));
  const busy = ipIntelBusyCount > 0;
  ['runIpIntelBtn', 'runIpRelationshipBtn', 'loadIpIntelMispBtn'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.disabled = busy;
  });
}

function isAbortError(e){
  return !!(e && String(e.name || '') === 'AbortError');
}

function isIPv4(value){
  const s = String(value || '').trim();
  if(!IPV4_PATTERN.test(s)) return false;
  const parts = s.split('.').map(n=>Number(n));
  return parts.length === 4 && parts.every(n=>Number.isInteger(n) && n >= 0 && n <= 255);
}

function clamp01(v){
  const n = Number(v);
  if(!Number.isFinite(n)) return 0;
  if(n < 0) return 0;
  if(n > 1) return 1;
  return n;
}

function interpolateColorRgb(c1, c2, t){
  const r = Math.round(c1[0] + (c2[0] - c1[0]) * t);
  const g = Math.round(c1[1] + (c2[1] - c1[1]) * t);
  const b = Math.round(c1[2] + (c2[2] - c1[2]) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

function getNxdomainLifecycleAgeDays(sinceTs){
  const ts = Number(sinceTs || 0);
  if(!Number.isFinite(ts) || ts <= 0) return 0;
  const ageSec = Math.max(0, (Date.now() / 1000) - ts);
  return ageSec / 86400;
}

function formatLocalDateTime(dateObj){
  if(!(dateObj instanceof Date) || Number.isNaN(dateObj.getTime())) return '-';
  return dateObj.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

function formatUnixTsLocal(tsSec){
  const ts = Number(tsSec || 0);
  if(!Number.isFinite(ts) || ts <= 0) return '-';
  return formatLocalDateTime(new Date(ts * 1000));
}

function applyNxdomainLifecycleStyle(tdDomain, meta, domainName){
  if(!tdDomain) return;
  const active = !!(meta && meta.nxdomain_active);
  const sinceTs = Number((meta && meta.nxdomain_since) || 0);
  if(!active || !Number.isFinite(sinceTs) || sinceTs <= 0){
    return;
  }
  const ageDays = getNxdomainLifecycleAgeDays(sinceTs);
  const progress = clamp01(ageDays / 30);
  const bg = interpolateColorRgb([255, 241, 166], [216, 74, 74], progress);
  const fg = interpolateColorRgb([108, 84, 12], [255, 255, 255], progress);
  tdDomain.style.background = bg;
  tdDomain.style.color = fg;
  tdDomain.style.fontWeight = '800';
  tdDomain.style.borderRadius = '8px';
  tdDomain.style.padding = '8px 10px';
  tdDomain.title = `NXDOMAIN lifecycle: ${ageDays.toFixed(1)} days since first NXDOMAIN (${domainName})`;
}

function getDomainLifecycleStatus(domainObj){
  if(domainObj && domainObj.nxdomain_active){
    return {label: 'NXDOMAIN', cls: 'nxdomain'};
  }
  if(domainObj && domainObj.dns_error_only_active){
    return {label: 'Error-only', cls: 'error'};
  }
  return {label: 'Normal', cls: 'normal'};
}

function isDomainNonResolving(domainObj){
  if(!domainObj || typeof domainObj !== 'object') return true;
  if(domainObj.nxdomain_active) return true;
  if(domainObj.dns_error_only_active) return true;
  if(domainObj.resolving === false) return true;
  return false;
}

function getDomainAnalysisSelectionSet(){
  if(!(window.DOMAIN_ANALYSIS_SELECTED_REMOVE instanceof Set)){
    window.DOMAIN_ANALYSIS_SELECTED_REMOVE = new Set();
  }
  return window.DOMAIN_ANALYSIS_SELECTED_REMOVE;
}

function setDomainRemoveStatus(message, kind){
  const el = document.getElementById('domainRemoveStatus');
  if(!el) return;
  el.textContent = message || '';
  el.classList.remove('ok', 'err');
  if(kind === 'ok') el.classList.add('ok');
  if(kind === 'err') el.classList.add('err');
  if(message){
    setTimeout(()=>{
      el.textContent = '';
      el.classList.remove('ok', 'err');
    }, 3200);
  }
}

function openQueryForValue(value){
  const v = String(value || '').trim();
  if(!v) return;
  const q = document.getElementById('queryValue');
  if(q) q.value = v;
  showSection('query');
  runQuery(v);
}

function setDomainVerifyStatus(message, kind){
  const el = document.getElementById('domainVerifyStatus');
  if(!el) return;
  el.textContent = message || '';
  el.classList.remove('ok', 'err');
  if(kind === 'ok') el.classList.add('ok');
  if(kind === 'err') el.classList.add('err');
}

function normalizeDomainName(domain){
  return String(domain || '').trim().replace(/\.$/, '').toLowerCase();
}

function buildDecoderNameList(baseList, customList, includeNoneFirst){
  const out = [];
  const seen = new Set();
  if(includeNoneFirst){
    out.push('none');
    seen.add('none');
  }
  const pushName = (name)=>{
    const n = String(name || '').trim();
    if(!n || seen.has(n)) return;
    seen.add(n);
    out.push(n);
  };
  (Array.isArray(baseList) ? baseList : []).forEach(pushName);
  (Array.isArray(customList) ? customList : []).forEach(item=>{
    const n = (item && item.name) ? String(item.name).trim() : '';
    pushName(n);
  });
  return out;
}

function fillSelectWithOptions(selectEl, options, selectedValue, placeholderLabel){
  if(!selectEl) return;
  const prev = String(selectedValue || selectEl.value || '').trim();
  selectEl.innerHTML = '';
  if(placeholderLabel){
    const p = document.createElement('option');
    p.value = '';
    p.textContent = placeholderLabel;
    selectEl.appendChild(p);
  }
  (Array.isArray(options) ? options : []).forEach(opt=>{
    const value = String(opt || '').trim();
    if(!value) return;
    const o = document.createElement('option');
    o.value = value;
    o.textContent = value === 'none' ? 'None' : value;
    selectEl.appendChild(o);
  });
  if(prev){
    const hasPrev = Array.from(selectEl.options).some(o=>o.value === prev);
    if(hasPrev){
      selectEl.value = prev;
      return;
    }
  }
  if(includeOption(selectEl, 'none')) selectEl.value = 'none';
}

function includeOption(selectEl, value){
  return !!Array.from((selectEl && selectEl.options) || []).find(o=>o.value === value);
}

function parseJsonObjectInput(rawText, fieldName){
  const raw = String(rawText || '').trim();
  if(!raw) return {ok: true, value: null};
  try{
    const parsed = JSON.parse(raw);
    if(!parsed || typeof parsed !== 'object' || Array.isArray(parsed)){
      return {ok: false, error: `${fieldName} must be a JSON object`};
    }
    return {ok: true, value: parsed};
  }catch(e){
    return {ok: false, error: `${fieldName} must be valid JSON (${e})`};
  }
}

function formatJsonObjectCompact(value){
  if(!value || typeof value !== 'object' || Array.isArray(value)) return '';
  try{
    return JSON.stringify(value);
  }catch(e){
    return '';
  }
}

function syncDomainVerifyDecoderOptions(){
  const txtFallback = ['cafebabe_xor_base64','plain_base64','btea_variant','xor_ipstring_base64_fixedkey'];
  const aFallback = ['none','xor32_ipv4'];
  const ensFallback = ['ipv6_5to8_xor'];
  const txtNames = buildDecoderNameList(
    (window.DECODERS && window.DECODERS.length) ? window.DECODERS : txtFallback,
    (window.CUSTOM_DECODERS || []).filter(c => String((c && c.decoder_type) || 'TXT').toUpperCase() === 'TXT'),
    false
  );
  const aNamesRaw = buildDecoderNameList(
    (window.A_DECODERS && window.A_DECODERS.length) ? window.A_DECODERS : aFallback,
    (window.CUSTOM_A_DECODERS || []).filter(c => String((c && c.decoder_type) || 'A').toUpperCase() === 'A'),
    false
  );
  const aNames = ['none'].concat(aNamesRaw.filter(x=>x !== 'none'));
  const ensNames = buildDecoderNameList(
    (window.ENS_DECODERS && window.ENS_DECODERS.length) ? window.ENS_DECODERS : ensFallback,
    [],
    false
  );

  const txtSel = document.getElementById('verifyTxtDecode');
  const aSel = document.getElementById('verifyADecode');
  const ensSel = document.getElementById('verifyEnsDecode');
  fillSelectWithOptions(txtSel, txtNames, (txtSel || {}).value || 'cafebabe_xor_base64');
  fillSelectWithOptions(aSel, aNames, (aSel || {}).value || 'none');
  fillSelectWithOptions(ensSel, ensNames, (ensSel || {}).value || 'ipv6_5to8_xor');
  if(aSel && !aSel.value) aSel.value = 'none';
  if(ensSel && !ensSel.value) ensSel.value = 'ipv6_5to8_xor';
}

function updateDomainVerifyInputMode(){
  const typeEl = document.getElementById('verifyDomainType');
  const txtEl = document.getElementById('verifyTxtDecode');
  const aEl = document.getElementById('verifyADecode');
  const xorEl = document.getElementById('verifyAXorKey');
  const ensKeyEl = document.getElementById('verifyEnsTextKey');
  const ensDecodeEl = document.getElementById('verifyEnsDecode');
  const ensOptionsEl = document.getElementById('verifyEnsOptions');
  if(!typeEl || !txtEl || !aEl || !xorEl || !ensKeyEl || !ensDecodeEl || !ensOptionsEl) return;
  const t = String(typeEl.value || 'AUTO').toUpperCase();
  const isAOnly = t === 'A';
  const isTxtOnly = t === 'TXT';
  const isEnsOnly = t === 'ENS';
  txtEl.disabled = isAOnly || isEnsOnly;
  aEl.disabled = isTxtOnly || isEnsOnly;
  xorEl.disabled = isTxtOnly || isEnsOnly;
  ensKeyEl.disabled = !isEnsOnly;
  ensDecodeEl.disabled = !isEnsOnly;
  ensOptionsEl.disabled = !isEnsOnly;
}

function initDomainVerifyUi(){
  syncDomainVerifyDecoderOptions();
  updateDomainVerifyInputMode();
}

function toVerifyStatusClass(status){
  const s = String(status || '').toLowerCase();
  if(s === 'ok') return 'verify-status-ok';
  if(s === 'nxdomain') return 'verify-status-nxdomain';
  if(s === 'nodata') return 'verify-status-nodata';
  return 'verify-status-error';
}

function renderDomainVerifySummary(result){
  const el = document.getElementById('domainVerifySummary');
  if(!el) return;
  if(!result || result.error){
    el.textContent = result && result.error ? `Error: ${result.error}` : 'No validation result.';
    return;
  }
  const notes = Array.isArray(result.notes) ? result.notes : [];
  const detected = Array.isArray(result.detected_types) ? result.detected_types : [];
  const selectedType = String(result.selected_type || '').toUpperCase() || '-';
  const managedIps = Array.isArray(result.managed_ips) ? result.managed_ips : [];
  const resolvedIps = Array.isArray(result.resolved_ips) ? result.resolved_ips : [];
  const lines = [
    `Domain: ${result.domain || '-'}`,
    `Requested Type: ${result.requested_type || '-'}`,
    `Detected Types: ${detected.length ? detected.join(', ') : '-'}`,
    `Selected Type: ${selectedType}`,
    `Resolved IPs: ${resolvedIps.length}`,
    `Managed IPs: ${managedIps.length}`,
    `Add Payload: ${JSON.stringify(result.domain_object || {}, null, 0)}`,
  ];
  if(notes.length){
    lines.push(`Notes: ${notes.join(' | ')}`);
  }
  el.textContent = lines.join('\n');
}

function renderDomainVerifyServerTable(result){
  const body = document.querySelector('#domainVerifyServerTable tbody');
  if(!body) return;
  body.innerHTML = '';
  const rows = Array.isArray(result && result.by_server) ? result.by_server : [];
  if(!rows.length){
    setSummaryMessage(body, 6, 'No server-level result.');
    return;
  }
  rows.forEach(row=>{
    const tr = document.createElement('tr');
    const rowErr = String((row && row.error) || '').trim();
    const tdSrv = document.createElement('td');
    tdSrv.textContent = row.server || '-';
    const tdType = document.createElement('td');
    tdType.textContent = String(row.type || '-').toUpperCase();
    const tdStatus = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = `verify-status-badge ${toVerifyStatusClass(row.status)}`;
    statusBadge.textContent = String(row.status || 'error').toUpperCase();
    if(rowErr) statusBadge.title = rowErr;
    tdStatus.appendChild(statusBadge);
    const tdVals = document.createElement('td');
    tdVals.className = 'wrap-cell';
    const values = Array.isArray(row.values) ? row.values : [];
    tdVals.textContent = formatListPreview(values, 4);
    tdVals.title = values.join(', ');
    const tdManaged = document.createElement('td');
    renderCellWithClickableIps(tdManaged, Array.isArray(row.managed_ips) ? row.managed_ips : [], formatListPreview(row.managed_ips || [], 4), 6);
    const tdMethod = document.createElement('td');
    tdMethod.className = 'wrap-cell';
    if(rowErr){
      tdMethod.textContent = `${row.method || '-'} | ERROR`;
      tdMethod.title = `${row.method || '-'}\n${rowErr}`;
      tdMethod.style.color = '#8b1f1f';
      tdMethod.style.fontWeight = '700';
    } else {
      tdMethod.textContent = row.method || '-';
      tdMethod.title = row.method || '-';
    }
    tr.appendChild(tdSrv);
    tr.appendChild(tdType);
    tr.appendChild(tdStatus);
    tr.appendChild(tdVals);
    tr.appendChild(tdManaged);
    tr.appendChild(tdMethod);
    body.appendChild(tr);
  });
}

function renderDomainVerifyIpTable(result){
  const body = document.querySelector('#domainVerifyIpTable tbody');
  if(!body) return;
  body.innerHTML = '';
  const rows = Array.isArray(result && result.ip_rows) ? result.ip_rows : [];
  if(!rows.length){
    setSummaryMessage(body, 6, 'No IP rows.');
    return;
  }
  rows.forEach(row=>{
    const tr = document.createElement('tr');
    const tdIp = document.createElement('td');
    tdIp.textContent = row.ip || '-';
    if(isIPv4(row.ip)){
      tdIp.style.cursor = 'pointer';
      tdIp.title = 'Open in Query';
      tdIp.onclick = ()=> openQueryForValue(row.ip);
    }
    const tdRole = document.createElement('td');
    tdRole.textContent = row.role || '-';
    const tdVt = document.createElement('td');
    const tdAsn = document.createElement('td');
    const tdOwner = document.createElement('td');
    const tdCountry = document.createElement('td');
    const vt = row.vt || null;
    if(vt){
      const m = Number(vt.malicious || 0);
      const s = Number(vt.suspicious || 0);
      const badge = document.createElement('span');
      badge.className = 'vt-badge';
      if(m > 0) badge.classList.add('high');
      else if(s > 0) badge.classList.add('mid');
      badge.textContent = `${m}/${s}`;
      tdVt.appendChild(badge);
      tdAsn.textContent = String(vt.asn || '-');
      tdOwner.textContent = String(vt.as_owner || '-');
      tdCountry.textContent = String(vt.country || '-');
    } else {
      tdVt.textContent = (result && result.include_vt) ? '-' : 'VT off';
      tdAsn.textContent = '-';
      tdOwner.textContent = '-';
      tdCountry.textContent = '-';
    }
    tr.appendChild(tdIp);
    tr.appendChild(tdRole);
    tr.appendChild(tdVt);
    tr.appendChild(tdAsn);
    tr.appendChild(tdOwner);
    tr.appendChild(tdCountry);
    body.appendChild(tr);
  });
}

function renderDomainVerifyDecoderTable(result){
  const body = document.querySelector('#domainVerifyDecoderTable tbody');
  if(!body) return;
  body.innerHTML = '';
  const rows = Array.isArray(result && result.decoder_candidates) ? result.decoder_candidates : [];
  if(!rows.length){
    setSummaryMessage(body, 8, 'No decoder analysis (disable "Try all decoders" or no TXT/A values)');
    return;
  }
  rows.forEach(row=>{
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.title = 'Click to apply this decoder and re-run validation';

    const tdT = document.createElement('td'); tdT.textContent = String(row.decoder_type || '-');
    const tdN = document.createElement('td'); tdN.textContent = String(row.name || '-');
    const tdS = document.createElement('td'); tdS.textContent = String(row.score != null ? row.score : '-');
    const tdC = document.createElement('td'); tdC.textContent = String(row.ip_count || 0);

    const tdAn = document.createElement('td');
    const an = Number(row.anomaly_score || 0);
    tdAn.textContent = String(an || 0);
    tdAn.title = 'Composite anomaly score (higher = more suspicious signals)';

    const tdVT = document.createElement('td');
    if(row.vt_summary){
      const m = Number(row.vt_summary.malicious_total || 0);
      const s = Number(row.vt_summary.suspicious_total || 0);
      const badge = document.createElement('span');
      badge.className = 'vt-badge';
      if(m > 0) badge.classList.add('high');
      else if(s > 0) badge.classList.add('mid');
      badge.textContent = `${m}/${s}`;
      tdVT.appendChild(badge);
      // more context in title
      const mr = (row.vt_summary.malicious_ratio != null) ? String(row.vt_summary.malicious_ratio) : '-';
      const sr = (row.vt_summary.suspicious_ratio != null) ? String(row.vt_summary.suspicious_ratio) : '-';
      tdVT.title = `malicious_ratio=${mr} suspicious_ratio=${sr} unique_asn=${row.vt_summary.unique_asn || 0} unique_country=${row.vt_summary.unique_country || 0}`;
    } else {
      tdVT.textContent = (result && result.include_vt) ? '-' : 'VT off';
    }

    const tdAs = document.createElement('td'); tdAs.textContent = Array.isArray(row.vt_summary && row.vt_summary.top_asn) ? row.vt_summary.top_asn.map(x=>x[0]+'('+x[1]+')').join(', ') : '-';
    const tdCo = document.createElement('td'); tdCo.textContent = Array.isArray(row.vt_summary && row.vt_summary.top_country) ? row.vt_summary.top_country.map(x=>x[0]+'('+x[1]+')').join(', ') : '-';
    const tdSm = document.createElement('td');
    tdSm.className = 'wrap-cell';
    const sample = Array.isArray(row.sample_ips) ? row.sample_ips : [];
    tdSm.textContent = sample.join(' | ') || '-';
    tdSm.title = sample.join(' | ');

    tr.onclick = async ()=>{
      // Apply decoder choice to UI
      if(String(row.decoder_type).toUpperCase() === 'TXT'){
        const sel = document.getElementById('verifyTxtDecode');
        if(sel){
          // ensure option exists
          const name = String(row.name || '').trim();
          if(name && !Array.from(sel.options).some(o=>o.value === name)){
            const o = document.createElement('option');
            o.value = name; o.textContent = name;
            sel.appendChild(o);
          }
          if(name) sel.value = name;
        }
        const typ = document.getElementById('verifyDomainType');
        if(typ && typ.value === 'AUTO') typ.value = 'TXT';
      }
      if(String(row.decoder_type).toUpperCase() === 'A'){
        const sel = document.getElementById('verifyADecode');
        if(sel){
          const name = String(row.name || '').trim();
          if(name && !Array.from(sel.options).some(o=>o.value === name)){
            const o = document.createElement('option');
            o.value = name; o.textContent = name;
            sel.appendChild(o);
          }
          if(name) sel.value = name;
        }
        const typ = document.getElementById('verifyDomainType');
        if(typ && typ.value === 'AUTO') typ.value = 'A';
      }
      // re-run
      await runDomainVerify();
    };

    tr.appendChild(tdT);
    tr.appendChild(tdN);
    tr.appendChild(tdS);
    tr.appendChild(tdC);
    tr.appendChild(tdAn);
    tr.appendChild(tdVT);
    tr.appendChild(tdAs);
    tr.appendChild(tdCo);
    tr.appendChild(tdSm);
    body.appendChild(tr);
  });
}

function clearDomainVerifyResult(){
  window.DOMAIN_VERIFY_LAST = null;
  setDomainVerifyStatus('', '');
  renderDomainVerifySummary(null);
  renderDomainVerifyDecoderTable({decoder_candidates: []});
  renderDomainVerifyServerTable({by_server: []});
  renderDomainVerifyIpTable({ip_rows: []});
}

async function runDomainVerify(){
  const domain = String((document.getElementById('verifyDomainName') || {}).value || '').trim();
  if(!domain){
    setDomainVerifyStatus('Domain is required', 'err');
    return;
  }
  initDomainVerifyUi();
  const type = String((document.getElementById('verifyDomainType') || {}).value || 'AUTO').toUpperCase();
  const txtDecode = String((document.getElementById('verifyTxtDecode') || {}).value || '').trim();
  const aDecode = String((document.getElementById('verifyADecode') || {}).value || 'none').trim();
  const aXorKey = String((document.getElementById('verifyAXorKey') || {}).value || '').trim();
  const ensTextKey = String((document.getElementById('verifyEnsTextKey') || {}).value || '').trim();
  const ensDecode = String((document.getElementById('verifyEnsDecode') || {}).value || 'ipv6_5to8_xor').trim();
  const ensOptionsRaw = String((document.getElementById('verifyEnsOptions') || {}).value || '').trim();
  let ensOptions = null;
  if(type === 'ENS'){
    const parsedEnsOptions = parseJsonObjectInput(ensOptionsRaw, 'ENS options');
    if(!parsedEnsOptions.ok){
      setDomainVerifyStatus(parsedEnsOptions.error, 'err');
      return;
    }
    ensOptions = parsedEnsOptions.value;
  }
  const includeVt = !!((document.getElementById('verifyIncludeVt') || {}).checked);
  const analyzeDecoders = !!((document.getElementById('verifyAnalyzeDecoders') || {}).checked);
  const decoderTopN = parseBoundedInt((document.getElementById('verifyDecoderTopN') || {}).value, 8, 1, 50);
  const vtBudget = parseBoundedInt((document.getElementById('verifyVtBudget') || {}).value, 200, 0, 5000);
  const vtWorkers = parseBoundedInt((document.getElementById('verifyVtWorkers') || {}).value, 8, 1, 32);

  setDomainVerifyStatus('Validating...', '');
  try{
    const r = await fetch('/domain-precheck', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        domain: domain,
        type: type,
        txt_decode: txtDecode,
        a_decode: aDecode,
        a_xor_key: aXorKey,
        ens_text_key: ensTextKey,
        ens_decode: ensDecode,
        ens_options: ensOptions,
        include_vt: includeVt,
        analyze_decoders: analyzeDecoders,
        decoder_top_n: decoderTopN,
        vt_lookup_budget: vtBudget,
        vt_workers: vtWorkers
      })
    });
    const j = await r.json();
    if(!r.ok || !j || j.error){
      const msg = (j && j.error) ? j.error : `Validation failed (${r.status})`;
      setDomainVerifyStatus(msg, 'err');
      window.DOMAIN_VERIFY_LAST = null;
      renderDomainVerifySummary({error: msg});
      renderDomainVerifyDecoderTable({decoder_candidates: []});
      renderDomainVerifyServerTable({by_server: []});
      renderDomainVerifyIpTable({ip_rows: []});
      return;
    }
    window.DOMAIN_VERIFY_LAST = j;
    renderDomainVerifySummary(j);
    renderDomainVerifyDecoderTable(j);
    renderDomainVerifyServerTable(j);
    renderDomainVerifyIpTable(j);
    setDomainVerifyStatus(j.can_add === false ? 'Validation complete (no addable IP)' : 'Validation complete', j.can_add === false ? 'err' : 'ok');
  }catch(e){
    const msg = `Validation error: ${e}`;
    setDomainVerifyStatus(msg, 'err');
    window.DOMAIN_VERIFY_LAST = null;
    renderDomainVerifySummary({error: msg});
    renderDomainVerifyDecoderTable({decoder_candidates: []});
    renderDomainVerifyServerTable({by_server: []});
    renderDomainVerifyIpTable({ip_rows: []});
  }
}

async function addVerifiedDomainToConfig(){
  const state = window.DOMAIN_VERIFY_LAST || {};
  const domainObj = state.domain_object;
  if(!domainObj || !domainObj.name){
    setDomainVerifyStatus('Validate first, then add', 'err');
    return;
  }
  if(state.can_add === false){
    setDomainVerifyStatus('Validation has no resolvable result to add', 'err');
    return;
  }
  try{
    const cfgResp = await fetch('/config');
    const cfgJson = await cfgResp.json();
    if(!cfgResp.ok || !cfgJson){
      setDomainVerifyStatus('Failed to load config', 'err');
      return;
    }
    const existing = Array.isArray(cfgJson.domains) ? cfgJson.domains : [];
    const normTarget = normalizeDomainName(domainObj.name);
    const normalizedDomains = existing.map(item=>{
      if(typeof item === 'string'){
        return {name: item, type: 'A'};
      }
      return (item && typeof item === 'object') ? {...item} : null;
    }).filter(Boolean);

    const idx = normalizedDomains.findIndex(d=> normalizeDomainName(d.name) === normTarget);
    if(idx >= 0){
      normalizedDomains[idx] = {...domainObj};
    } else {
      normalizedDomains.push({...domainObj});
    }
    const payload = {
      domains: normalizedDomains,
      servers: Array.isArray(cfgJson.servers) ? cfgJson.servers : [],
      interval: Number(cfgJson.interval || 60)
    };
    const saveResp = await fetch('/config', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const saveJson = await saveResp.json();
    if(!saveResp.ok || !saveJson || saveJson.error){
      throw new Error((saveJson && saveJson.error) ? saveJson.error : `save failed (${saveResp.status})`);
    }
    setDomainVerifyStatus(idx >= 0 ? 'Updated existing domain' : 'Added domain', 'ok');
    loadCfg();
    uiOverview.configured = normalizedDomains.length;
    updateOverviewPanel();
  }catch(e){
    setDomainVerifyStatus(`Add failed: ${e}`, 'err');
  }
}

function renderQueryLocalResult(value, payload){
  const box = document.getElementById('queryResult');
  if(!box) return;
  box.innerHTML = '';

  if(payload && payload.error){
    box.textContent = payload.error;
    return;
  }

  if(isIPv4(value)){
    const info = payload || {};
    const rows = [
      ['IP', info.ip || value],
      ['Domains', Array.isArray(info.domains) ? info.domains.join(', ') : '-'],
      ['Count', info.count != null ? String(info.count) : '-'],
      ['Last Seen', info.last_ts ? formatUnixTsLocal(info.last_ts) : '-'],
      ['VT', info.vt ? `M:${(info.vt.malicious||0)} S:${(info.vt.suspicious||0)}` : '-']
    ];
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Field</th><th>Value</th></tr></thead>';
    const tb = document.createElement('tbody');
    rows.forEach(r=>{
      const tr = document.createElement('tr');
      const td1 = document.createElement('td'); td1.textContent = r[0];
      const td2 = document.createElement('td'); td2.textContent = r[1];
      tr.appendChild(td1); tr.appendChild(td2); tb.appendChild(tr);
    });
    table.appendChild(tb);
    box.appendChild(table);
    return;
  }

  const current = (payload && payload.current) || [];
  const history = (payload && payload.history) || [];

  const mkTitle = (txt)=>{ const h = document.createElement('h5'); h.textContent = txt; h.style.margin = '10px 0 6px'; return h; };

  const curTable = document.createElement('table');
  curTable.innerHTML = '<thead><tr><th>Domain</th><th>Type</th><th>Values</th><th>Decoded IPs</th><th>Servers</th><th>Last Seen</th></tr></thead>';
  const curBody = document.createElement('tbody');
  if(!current.length){
    setSummaryMessage(curBody, 6, 'No current matches');
  } else {
    current.forEach(it=>{
      const tr = document.createElement('tr');
      const tdD = document.createElement('td'); tdD.textContent = it.domain || '-';
      const tdT = document.createElement('td'); tdT.textContent = it.type || '-';
      const tdV = document.createElement('td'); tdV.textContent = formatListPreview(it.values || [], 4);
      const tdI = document.createElement('td'); tdI.textContent = formatListPreview(it.decoded_ips || [], 4);
      const tdS = document.createElement('td'); tdS.textContent = formatListPreview(it.servers || [], 3);
      const tdTs = document.createElement('td'); tdTs.textContent = it.ts ? formatUnixTsLocal(it.ts) : '-';
      tr.appendChild(tdD); tr.appendChild(tdT); tr.appendChild(tdV); tr.appendChild(tdI); tr.appendChild(tdS); tr.appendChild(tdTs);
      curBody.appendChild(tr);
    });
  }
  curTable.appendChild(curBody);

  const histTable = document.createElement('table');
  histTable.innerHTML = '<thead><tr><th>Domain</th><th>Server</th><th>Timestamp</th><th>Values</th></tr></thead>';
  const histBody = document.createElement('tbody');
  if(!history.length){
    setSummaryMessage(histBody, 4, 'No history matches');
  } else {
    history.forEach(it=>{
      const tr = document.createElement('tr');
      const tdD = document.createElement('td'); tdD.textContent = it.domain || '-';
      const tdS = document.createElement('td'); tdS.textContent = it.server || '-';
      const tdT = document.createElement('td'); tdT.textContent = it.ts ? formatUnixTsLocal(it.ts) : '-';
      const vals = (it.new && it.new.values) ? it.new.values : (it.values || []);
      const tdV = document.createElement('td'); tdV.textContent = formatListPreview(vals, 4);
      tr.appendChild(tdD); tr.appendChild(tdS); tr.appendChild(tdT); tr.appendChild(tdV);
      histBody.appendChild(tr);
    });
  }
  histTable.appendChild(histBody);

  box.appendChild(mkTitle('Current')); box.appendChild(curTable);
  box.appendChild(mkTitle('History')); box.appendChild(histTable);
}

function renderQueryMispResult(payload){
  const box = document.getElementById('queryMispResult');
  if(!box) return;
  box.innerHTML = '';

  if(!payload || payload.error){
    box.textContent = payload && payload.error ? payload.error : '-';
    return;
  }

  const attrs = Array.isArray(payload.attributes) ? payload.attributes : [];
  const meta = document.createElement('div');
  meta.style.fontSize = '.85rem';
  meta.style.color = '#5b6a77';
  meta.style.marginBottom = '6px';
  meta.textContent = `matches: ${payload.count || 0} (type ${payload.type_attribute || 'any'})`;
  box.appendChild(meta);

  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Value</th><th>Type</th><th>Category</th><th>Event</th><th>Comment</th><th>TS</th><th>to_ids</th></tr></thead>';
  const tbody = document.createElement('tbody');
  if(!attrs.length){
    setSummaryMessage(tbody, 7, 'No MISP matches');
  } else {
    attrs.forEach(a=>{
      const tr = document.createElement('tr');
      const tdV = document.createElement('td'); tdV.textContent = a.value || '-';
      const tdT = document.createElement('td'); tdT.textContent = a.type || '-';
      const tdC = document.createElement('td'); tdC.textContent = a.category || '-';
      const tdE = document.createElement('td'); tdE.textContent = a.event_id || '-';
      const tdCom = document.createElement('td'); tdCom.textContent = a.comment || '-';
      const tdTs = document.createElement('td'); tdTs.textContent = a.timestamp ? formatUnixTsLocal(a.timestamp) : '-';
      const tdIds = document.createElement('td'); tdIds.textContent = (a.to_ids === true) ? 'yes' : (a.to_ids === false ? 'no' : '-');
      tr.appendChild(tdV); tr.appendChild(tdT); tr.appendChild(tdC); tr.appendChild(tdE); tr.appendChild(tdCom); tr.appendChild(tdTs); tr.appendChild(tdIds);
      tbody.appendChild(tr);
    });
  }
  table.appendChild(tbody);
  box.appendChild(table);
}

async function runQuery(v){
  const value = String(v || '').trim();
  if(!value){ alert('Enter search value'); return; }
  const mispBox = document.getElementById('queryMispResult');
  if(mispBox) mispBox.textContent = 'Loading MISP...';

  if(isIPv4(value)){
    const r = await fetch('/ip?ip='+encodeURIComponent(value));
    const j = await r.json();
    renderQueryLocalResult(value, j);
  } else {
    // search value across history/current by fetching aggregated results + /history client-side
    const r1 = await fetch('/results?aggregate=1'); const res = await r1.json();
    const agg = (res && res.results_agg && typeof res.results_agg === 'object')
      ? res.results_agg
      : {};
    const matches = [];
    for(const d of Object.keys(agg || {})){
      const info = agg[d] || {};
      const vals = Array.isArray(info.values) ? info.values : [];
      const dec = Array.isArray(info.decoded_ips) ? info.decoded_ips : [];
      if(vals.some(x=>String(x || '').includes(value)) || dec.some(x=>String(x || '').includes(value))){
        matches.push({
          domain: d,
          type: info.type || 'A',
          ts: info.ts || 0,
          servers: info.servers || [],
          values: vals,
          decoded_ips: dec
        });
      }
    }
    // fallback: fetch history per domain from results list
    const histMatches = [];
    for(const d of Object.keys(agg || {})){
      const hresp = await fetch('/history?domain='+encodeURIComponent(d));
      const hj = await hresp.json();
      const histObj = hj && hj.history ? hj.history : {};
      const events = Array.isArray(histObj) ? histObj : (Array.isArray(histObj.events) ? histObj.events : []);
      events.forEach(ev=>{
        const newHit = !!(ev.new && (ev.new.values||[]).some(x=>x.includes(value)));
        const oldHit = !!(ev.old && (ev.old.values||[]).some(x=>x.includes(value)));
        if(newHit || oldHit){
          histMatches.push({domain:d, server:ev.server, ts:ev.ts, old:ev.old, new:ev.new});
        } else if(ev.values && (ev.values||[]).some(x=>x.includes(value))){
          histMatches.push({domain:d, server:ev.server, ts:ev.ts, values:ev.values});
        }
      });
    }
    renderQueryLocalResult(value, {current:matches, history:histMatches});
  }

  if(mispBox){
    try{
      const r = await fetch('/misp/search?value='+encodeURIComponent(value));
      const text = await r.text();
      let j = null;
      if(text && text.trim()){
        try{ j = JSON.parse(text); }catch(e){ j = null; }
      }
      if(!r.ok){
        if(j && j.error){
          renderQueryMispResult({error: `MISP error: ${j.error}`});
        } else {
          renderQueryMispResult({error: `MISP error (${r.status}): ${text || 'empty response'}`});
        }
      } else if(!j){
        renderQueryMispResult({error: `MISP error: invalid JSON response (${text || 'empty response'})`});
      } else if(j.status !== 'ok'){
        renderQueryMispResult({error: j.error ? `MISP error: ${j.error}` : 'MISP error: unknown response'});
      } else {
        renderQueryMispResult(j);
      }
    }catch(e){
      renderQueryMispResult({error: `MISP error: ${e}`});
    }
  }
}

function setSummaryMessage(tbody, colSpan, message){
  if(!tbody) return;
  tbody.innerHTML = '';
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = colSpan;
  td.textContent = message;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

function appendSummaryRow(tbody, colSpan, message){
  if(!tbody) return;
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = colSpan;
  td.textContent = message;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

function formatListPreview(values, maxItems){
  const maxN = Math.max(1, Number(maxItems || 3));
  const arr = Array.from(new Set((values || []).map(v=>String(v || '').trim()).filter(Boolean)));
  if(!arr.length) return '-';
  if(arr.length <= maxN) return arr.join(', ');
  return `${arr.slice(0, maxN).join(', ')} +${arr.length - maxN}`;
}

function parseBoundedInt(raw, fallbackValue, minValue, maxValue){
  const n = Number.parseInt(String(raw == null ? '' : raw), 10);
  if(!Number.isFinite(n)) return fallbackValue;
  if(n < minValue) return minValue;
  if(n > maxValue) return maxValue;
  return n;
}

function normalizeCspKey(raw){
  const s = String(raw || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
  return s || 'other';
}

function createCspBadge(cspKeyRaw, cspLabelRaw, isMajor){
  const cspKey = normalizeCspKey(cspKeyRaw);
  const label = String(cspLabelRaw || '').trim() || 'Other/Unknown';
  const span = document.createElement('span');
  span.className = `csp-badge csp-${cspKey}`;
  if(isMajor) span.classList.add('major');
  span.textContent = label;
  if(isMajor){
    span.title = 'Major CSP - blocking should be scoped carefully';
  }
  return span;
}

function getDomainStatsEntry(domainObj){
  const rows = Array.isArray(domainObj && domainObj.ip_rows) ? domainObj.ip_rows : [];
  const resolved = new Set();
  const decoded = new Set();
  const asFreq = new Map();
  const countryFreq = new Map();
  rows.forEach(row=>{
    const ip = String((row && row.ip) || '').trim();
    if(!isIPv4(ip)) return;
    const role = String((row && row.role) || '').toLowerCase();
    if(role === 'resolved') resolved.add(ip);
    if(role === 'decoded') decoded.add(ip);
    const vt = (row && row.vt) || {};
    const asn = (vt && vt.asn != null) ? String(vt.asn) : '';
    const country = (vt && vt.country) ? String(vt.country) : '';
    if(asn) asFreq.set(asn, (asFreq.get(asn) || 0) + 1);
    if(country) countryFreq.set(country, (countryFreq.get(country) || 0) + 1);
  });
  const topAs = Array.from(asFreq.entries()).sort((a,b)=>b[1]-a[1])[0] || null;
  const topCountry = Array.from(countryFreq.entries()).sort((a,b)=>b[1]-a[1])[0] || null;
  return {
    resolvedCount: resolved.size,
    decodedCount: decoded.size,
    asCount: asFreq.size,
    countryCount: countryFreq.size,
    topAs: topAs ? `${topAs[0]} (${topAs[1]})` : '-',
    topCountry: topCountry ? `${topCountry[0]} (${topCountry[1]})` : '-',
  };
}

function populateDomainAnalysisFilter(domains){
  const sel = document.getElementById('domainAnalysisDomainSelect');
  if(!sel) return '';
  const prev = String(sel.value || '');
  const names = Array.from(new Set((domains || []).map(d=>String((d && d.domain) || '').trim()).filter(Boolean))).sort();
  sel.innerHTML = '';
  const allOpt = document.createElement('option');
  allOpt.value = '';
  allOpt.textContent = 'All domains';
  sel.appendChild(allOpt);
  names.forEach(name=>{
    const o = document.createElement('option');
    o.value = name;
    o.textContent = name;
    sel.appendChild(o);
  });
  sel.value = names.includes(prev) ? prev : '';
  return sel.value;
}

function renderDomainStatsTable(allDomains, selectedDomain){
  const tbody = document.querySelector('#domainDomainStatsTable tbody');
  if(!tbody) return;
  tbody.innerHTML = '';
  const arr = Array.isArray(allDomains) ? allDomains.slice() : [];
  const selectedSet = getDomainAnalysisSelectionSet();
  if(!arr.length){
    setSummaryMessage(tbody, 11, 'No domains available');
    return;
  }
  arr.sort((a,b)=>String((a && a.domain) || '').localeCompare(String((b && b.domain) || '')));
  arr.forEach(d=>{
    const name = String((d && d.domain) || '');
    const nonResolving = isDomainNonResolving(d || {});
    const statusObj = getDomainLifecycleStatus(d || {});
    const statusLabel = statusObj.label === 'Normal' && nonResolving ? 'No-data' : statusObj.label;
    const statusCls = statusObj.label === 'Normal' && nonResolving ? 'error' : statusObj.cls;
    const tsText = formatUnixTsLocal(d && d.last_ts);
    const st = getDomainStatsEntry(d);
    const tr = document.createElement('tr');
    if(selectedDomain && name === selectedDomain){
      tr.style.background = '#eef8ff';
    }
    const c1 = document.createElement('td'); c1.textContent = name;
    applyNxdomainLifecycleStyle(c1, d || {}, name);
    if(d && d.dns_error_only_active){
      c1.title = `All DNS servers failed in last cycle (${name})`;
    }
    const c2 = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = `domain-state-badge ${statusCls}`;
    statusBadge.textContent = statusLabel;
    c2.appendChild(statusBadge);

    const c3 = document.createElement('td'); c3.textContent = String(st.resolvedCount);
    const c4 = document.createElement('td'); c4.textContent = String(st.decodedCount);
    const c5 = document.createElement('td'); c5.textContent = String(st.asCount);
    const c6 = document.createElement('td'); c6.textContent = String(st.countryCount);
    const c7 = document.createElement('td'); c7.textContent = st.topAs;
    const c8 = document.createElement('td'); c8.textContent = st.topCountry;
    const c9 = document.createElement('td'); c9.textContent = tsText;

    const c10 = document.createElement('td');
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.style.width = 'auto';
    chk.style.margin = '0';
    chk.disabled = !nonResolving;
    chk.checked = nonResolving && selectedSet.has(name);
    chk.title = nonResolving ? 'Select for bulk remove' : 'Only non-resolving domains can be selected';
    chk.onchange = ()=>{
      if(chk.checked) selectedSet.add(name);
      else selectedSet.delete(name);
      applyDomainAnalysisFilter();
    };
    c10.appendChild(chk);

    const c11 = document.createElement('td');
    const btnView = document.createElement('button');
    btnView.style.margin = '0';
    btnView.textContent = (selectedDomain && name === selectedDomain) ? 'Viewing' : 'View';
    btnView.onclick = ()=>{
      const sel = document.getElementById('domainAnalysisDomainSelect');
      if(sel){
        sel.value = name;
      }
      applyDomainAnalysisFilter();
    };
    c11.appendChild(btnView);

    const btnRemove = document.createElement('button');
    btnRemove.style.margin = '0 0 0 6px';
    btnRemove.textContent = d && d.nxdomain_active ? 'Remove NX' : 'Remove';
    btnRemove.disabled = !nonResolving;
    btnRemove.title = nonResolving ? `Remove ${name} from monitoring config` : 'Only non-resolving domains can be removed here';
    btnRemove.onclick = async ()=>{
      await removeDomainsFromConfig([name], `${name} removed`);
    };
    c11.appendChild(btnRemove);

    tr.appendChild(c1);
    tr.appendChild(c2);
    tr.appendChild(c3);
    tr.appendChild(c4);
    tr.appendChild(c5);
    tr.appendChild(c6);
    tr.appendChild(c7);
    tr.appendChild(c8);
    tr.appendChild(c9);
    tr.appendChild(c10);
    tr.appendChild(c11);
    tbody.appendChild(tr);
  });
}

function renderDomainAnalysisSummaries(domains, includeVT){
  const asBody = document.querySelector('#domainAsSummaryTable tbody');
  const countryBody = document.querySelector('#domainCountrySummaryTable tbody');
  const crossBody = document.querySelector('#domainAsCountrySummaryTable tbody');
  if(!asBody || !countryBody || !crossBody){
    return {asGroups: 0, countries: 0, intersections: 0};
  }

  if(!includeVT){
    setSummaryMessage(asBody, 5, 'VT context is disabled');
    setSummaryMessage(countryBody, 4, 'VT context is disabled');
    setSummaryMessage(crossBody, 5, 'VT context is disabled');
    return {asGroups: 0, countries: 0, intersections: 0};
  }

  const asMap = new Map();
  const countryMap = new Map();
  const crossMap = new Map();
  const seenDomainIp = new Set();
  const seenAsRole = new Set();
  const seenCrossRole = new Set();

  (domains || []).forEach(d=>{
    const domainName = String((d && d.domain) || '').trim();
    const rows = Array.isArray(d && d.ip_rows) ? d.ip_rows : [];
    rows.forEach(row=>{
      const ip = String((row && row.ip) || '').trim();
      if(!isIPv4(ip)) return;
      const role = String((row && row.role) || '-').toLowerCase();
      const vt = (row && row.vt) || {};
      const asn = (vt && vt.asn != null) ? String(vt.asn) : 'N/A';
      const asOwner = (vt && vt.as_owner) ? String(vt.as_owner) : '-';
      const country = (vt && vt.country) ? String(vt.country) : 'N/A';
      const domainIpKey = `${domainName}|${ip}`;
      const isNewDomainIp = !seenDomainIp.has(domainIpKey);
      if(isNewDomainIp) seenDomainIp.add(domainIpKey);

      const asKey = `${asn}|${asOwner}`;
      const asEntry = asMap.get(asKey) || {
        asn: asn,
        as_owner: asOwner,
        ip_count: 0,
        domains: new Set(),
        countries: new Set(),
        resolved: 0,
        decoded: 0
      };
      asEntry.countries.add(country);
      if(isNewDomainIp){
        asEntry.ip_count += 1;
        if(domainName) asEntry.domains.add(domainName);
      }
      const asRoleKey = `${asKey}|${domainName}|${role}|${ip}`;
      if(!seenAsRole.has(asRoleKey)){
        seenAsRole.add(asRoleKey);
        if(role === 'resolved') asEntry.resolved += 1;
        if(role === 'decoded') asEntry.decoded += 1;
      }
      asMap.set(asKey, asEntry);

      const countryEntry = countryMap.get(country) || {
        country: country,
        ip_count: 0,
        domains: new Set(),
        asns: new Set()
      };
      countryEntry.asns.add(asn);
      if(isNewDomainIp){
        countryEntry.ip_count += 1;
        if(domainName) countryEntry.domains.add(domainName);
      }
      countryMap.set(country, countryEntry);

      const crossKey = `${asn}|${country}|${asOwner}`;
      const crossEntry = crossMap.get(crossKey) || {
        asn: asn,
        country: country,
        as_owner: asOwner,
        ip_count: 0,
        domains: new Set(),
        resolved: 0,
        decoded: 0
      };
      if(isNewDomainIp){
        crossEntry.ip_count += 1;
        if(domainName) crossEntry.domains.add(domainName);
      }
      const crossRoleKey = `${crossKey}|${domainName}|${role}|${ip}`;
      if(!seenCrossRole.has(crossRoleKey)){
        seenCrossRole.add(crossRoleKey);
        if(role === 'resolved') crossEntry.resolved += 1;
        if(role === 'decoded') crossEntry.decoded += 1;
      }
      crossMap.set(crossKey, crossEntry);
    });
  });

  const asRows = Array.from(asMap.values()).map(e=>({
    asn: e.asn,
    as_owner: e.as_owner,
    ip_count: e.ip_count,
    domain_count: e.domains.size,
    countries: Array.from(e.countries),
    resolved: e.resolved,
    decoded: e.decoded
  })).sort((a,b)=>(b.ip_count - a.ip_count) || (b.domain_count - a.domain_count));

  const countryRows = Array.from(countryMap.values()).map(e=>({
    country: e.country,
    ip_count: e.ip_count,
    domain_count: e.domains.size,
    asn_count: e.asns.size
  })).sort((a,b)=>(b.ip_count - a.ip_count) || (b.domain_count - a.domain_count));

  const crossRows = Array.from(crossMap.values()).map(e=>({
    asn: e.asn,
    country: e.country,
    as_owner: e.as_owner,
    ip_count: e.ip_count,
    domain_count: e.domains.size,
    resolved: e.resolved,
    decoded: e.decoded
  })).sort((a,b)=>(b.ip_count - a.ip_count) || (b.domain_count - a.domain_count));

  asBody.innerHTML = '';
  countryBody.innerHTML = '';
  crossBody.innerHTML = '';

  if(!asRows.length){
    setSummaryMessage(asBody, 5, 'No AS context data');
  } else {
    asRows.forEach(e=>{
      const tr = document.createElement('tr');
      const c1 = document.createElement('td'); c1.textContent = e.asn;
      const c2 = document.createElement('td'); c2.textContent = e.as_owner || '-';
      const c3 = document.createElement('td'); c3.textContent = String(e.ip_count);
      c3.title = `resolved ${e.resolved} / decoded ${e.decoded}`;
      const c4 = document.createElement('td'); c4.textContent = String(e.domain_count);
      const c5 = document.createElement('td'); c5.textContent = formatListPreview(e.countries, 3);
      c5.title = (e.countries || []).join(', ');
      tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5);
      asBody.appendChild(tr);
    });
  }

  if(!countryRows.length){
    setSummaryMessage(countryBody, 4, 'No country data');
  } else {
    countryRows.forEach(e=>{
      const tr = document.createElement('tr');
      const c1 = document.createElement('td'); c1.textContent = e.country;
      const c2 = document.createElement('td'); c2.textContent = String(e.ip_count);
      const c3 = document.createElement('td'); c3.textContent = String(e.domain_count);
      const c4 = document.createElement('td'); c4.textContent = String(e.asn_count);
      tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4);
      countryBody.appendChild(tr);
    });
  }

  if(!crossRows.length){
    setSummaryMessage(crossBody, 5, 'No AS×Country intersection data');
  } else {
    crossRows.forEach(e=>{
      const tr = document.createElement('tr');
      const c1 = document.createElement('td'); c1.textContent = e.asn;
      const c2 = document.createElement('td'); c2.textContent = e.country;
      const c3 = document.createElement('td'); c3.textContent = e.as_owner || '-';
      const c4 = document.createElement('td'); c4.textContent = String(e.ip_count);
      c4.title = `resolved ${e.resolved} / decoded ${e.decoded}`;
      const c5 = document.createElement('td'); c5.textContent = String(e.domain_count);
      tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5);
      crossBody.appendChild(tr);
    });
  }

  return {
    asGroups: asRows.length,
    countries: countryRows.length,
    intersections: crossRows.length
  };
}

function renderDomainAnalysisTable(domains, includeVT, totalDomainsCount){
  const tbody = document.querySelector('#domainAnalysisTable tbody');
  const meta = document.getElementById('domainAnalysisMeta');
  if(!tbody) return;
  tbody.innerHTML = '';

  const arr = Array.isArray(domains) ? domains : [];
  let ipRowsCount = 0;
  let nxdomainActiveCount = 0;
  let errorOnlyCount = 0;
  arr.forEach(d=>{
    const domainName = String((d && d.domain) || '');
    if(d && d.nxdomain_active) nxdomainActiveCount += 1;
    if(d && d.dns_error_only_active) errorOnlyCount += 1;
    const statusObj = getDomainLifecycleStatus(d || {});
    const types = Array.isArray(d && d.record_types) ? d.record_types.join(', ') : '-';
    const tsText = formatUnixTsLocal(d && d.last_ts);
    const rows = Array.isArray(d && d.ip_rows) ? d.ip_rows : [];
    if(!rows.length){
      const tr = document.createElement('tr');
      const c1 = document.createElement('td'); c1.textContent = domainName;
      applyNxdomainLifecycleStyle(c1, d || {}, domainName);
      if(d && d.dns_error_only_active){
        c1.title = `All DNS servers failed in last cycle (${domainName})`;
      }
      const c2 = document.createElement('td');
      const statusBadge = document.createElement('span');
      statusBadge.className = `domain-state-badge ${statusObj.cls}`;
      statusBadge.textContent = statusObj.label;
      c2.appendChild(statusBadge);
      const c3 = document.createElement('td'); c3.textContent = types;
      const c4 = document.createElement('td'); c4.textContent = '-';
      const c5 = document.createElement('td'); c5.textContent = '-';
      const c6 = document.createElement('td'); c6.textContent = '-';
      const c7 = document.createElement('td'); c7.textContent = '-';
      const c8 = document.createElement('td'); c8.textContent = '-';
      const c9 = document.createElement('td'); c9.textContent = includeVT ? '-' : 'off';
      const c10 = document.createElement('td'); c10.textContent = tsText;
      tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6); tr.appendChild(c7); tr.appendChild(c8); tr.appendChild(c9); tr.appendChild(c10);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(row=>{
      ipRowsCount += 1;
      const tr = document.createElement('tr');
      const vt = (row && row.vt) || null;
      const m = Number((vt && vt.malicious) || 0);
      const s = Number((vt && vt.suspicious) || 0);

      const c1 = document.createElement('td'); c1.textContent = domainName;
      applyNxdomainLifecycleStyle(c1, d || {}, domainName);
      if(d && d.dns_error_only_active){
        c1.title = `All DNS servers failed in last cycle (${domainName})`;
      }
      const c2 = document.createElement('td');
      const statusBadge = document.createElement('span');
      statusBadge.className = `domain-state-badge ${statusObj.cls}`;
      statusBadge.textContent = statusObj.label;
      c2.appendChild(statusBadge);
      const c3 = document.createElement('td'); c3.textContent = types;
      const c4 = document.createElement('td'); c4.textContent = String((row && row.role) || '-');
      const c5 = document.createElement('td');
      c5.textContent = String((row && row.ip) || '-');
      if(isIPv4(row && row.ip)){
        c5.style.cursor = 'pointer';
        c5.title = 'Open in Query';
        c5.onclick = ()=> openQueryForValue(row.ip);
      }
      const c6 = document.createElement('td'); c6.textContent = vt && vt.asn != null ? String(vt.asn) : '-';
      const c7 = document.createElement('td'); c7.textContent = vt && vt.as_owner ? String(vt.as_owner) : '-';
      const c8 = document.createElement('td'); c8.textContent = vt && vt.country ? String(vt.country) : '-';
      const c9 = document.createElement('td'); c9.textContent = includeVT ? `${m}/${s}` : 'off';
      const c10 = document.createElement('td'); c10.textContent = tsText;
      tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6); tr.appendChild(c7); tr.appendChild(c8); tr.appendChild(c9); tr.appendChild(c10);
      tbody.appendChild(tr);
    });
  });

  const summary = renderDomainAnalysisSummaries(arr, includeVT);
  const selected = String((document.getElementById('domainAnalysisDomainSelect') || {}).value || '');
  const selectedRemoveCount = getDomainAnalysisSelectionSet().size;
  if(meta){
    meta.textContent = `${arr.length}/${Math.max(0, Number(totalDomainsCount || arr.length))} domains / ${ipRowsCount} IP rows / AS ${summary.asGroups} / Countries ${summary.countries} / AS×Country ${summary.intersections} / NXDOMAIN ${nxdomainActiveCount} / Error-only ${errorOnlyCount} / Selected ${selectedRemoveCount}${selected ? ` / Filter: ${selected}` : ''}`;
  }
  touchOverviewTs();
}

function applyDomainAnalysisFilter(){
  const allDomains = Array.isArray(window.DOMAIN_ANALYSIS_CACHE) ? window.DOMAIN_ANALYSIS_CACHE : [];
  const includeVT = !!window.DOMAIN_ANALYSIS_INCLUDE_VT;
  const selected = String((document.getElementById('domainAnalysisDomainSelect') || {}).value || '');
  const filtered = selected ? allDomains.filter(d=>String((d && d.domain) || '') === selected) : allDomains;
  renderDomainStatsTable(allDomains, selected);
  renderDomainAnalysisTable(filtered, includeVT, allDomains.length);
}

function pruneDomainAnalysisSelection(){
  const set = getDomainAnalysisSelectionSet();
  const validNames = new Set(
    (Array.isArray(window.DOMAIN_ANALYSIS_CACHE) ? window.DOMAIN_ANALYSIS_CACHE : [])
      .map(d=>String((d && d.domain) || '').trim())
      .filter(Boolean)
  );
  const keep = new Set();
  set.forEach(name=>{
    if(validNames.has(name)) keep.add(name);
  });
  window.DOMAIN_ANALYSIS_SELECTED_REMOVE = keep;
}

async function removeDomainsFromConfig(domainNames, successMessage){
  const names = Array.from(new Set((domainNames || []).map(v=>String(v || '').trim()).filter(Boolean)));
  if(!names.length){
    setDomainRemoveStatus('No domains selected', 'err');
    return false;
  }

  const confirmed = window.confirm(`Remove ${names.length} domain(s) from monitoring?\n\n${names.join('\n')}`);
  if(!confirmed){
    return false;
  }

  try{
    const cfgResp = await fetch('/config');
    if(!cfgResp.ok) throw new Error('config load failed');
    const cfg = await cfgResp.json();
    const currentDomains = Array.isArray(cfg.domains) ? cfg.domains : [];
    const removeSet = new Set(names);
    const nextDomains = currentDomains.filter(item=>{
      const name = typeof item === 'string'
        ? String(item || '').trim()
        : String((item && item.name) || '').trim();
      return name && !removeSet.has(name);
    });
    const removedCount = currentDomains.length - nextDomains.length;
    if(removedCount <= 0){
      setDomainRemoveStatus('No matching domains found in config', 'err');
      return false;
    }

    const saveResp = await fetch('/config', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({domains: nextDomains})
    });
    const saveJson = await saveResp.json();
    if(!(saveResp.ok && saveJson && saveJson.status === 'ok')){
      throw new Error((saveJson && saveJson.error) ? saveJson.error : 'config save failed');
    }

    const sel = getDomainAnalysisSelectionSet();
    names.forEach(n=>sel.delete(n));
    await Promise.allSettled([refreshDomainAnalysis(), loadCfg(), refreshResults(), refreshIPs(), refreshValidIPs()]);
    setDomainRemoveStatus(successMessage || `Removed ${removedCount} domain(s)`, 'ok');
    return true;
  }catch(e){
    setDomainRemoveStatus(`Remove failed: ${e}`, 'err');
    return false;
  }
}

function selectNonResolvingDomainsForBulk(){
  const set = getDomainAnalysisSelectionSet();
  const allDomains = Array.isArray(window.DOMAIN_ANALYSIS_CACHE) ? window.DOMAIN_ANALYSIS_CACHE : [];
  let added = 0;
  allDomains.forEach(d=>{
    const name = String((d && d.domain) || '').trim();
    if(!name) return;
    if(!isDomainNonResolving(d)) return;
    if(!set.has(name)){
      set.add(name);
      added += 1;
    }
  });
  applyDomainAnalysisFilter();
  setDomainRemoveStatus(added > 0 ? `Selected ${set.size} non-resolving domain(s)` : 'No non-resolving domains to select', added > 0 ? 'ok' : 'err');
}

function clearSelectedDomainsForBulk(){
  window.DOMAIN_ANALYSIS_SELECTED_REMOVE = new Set();
  applyDomainAnalysisFilter();
  setDomainRemoveStatus('Selection cleared', 'ok');
}

async function removeSelectedNonResolvingDomains(){
  const set = getDomainAnalysisSelectionSet();
  const selectedNames = Array.from(set);
  if(!selectedNames.length){
    setDomainRemoveStatus('No selected domains', 'err');
    return;
  }
  const domainMap = new Map(
    (Array.isArray(window.DOMAIN_ANALYSIS_CACHE) ? window.DOMAIN_ANALYSIS_CACHE : [])
      .map(d=>[String((d && d.domain) || '').trim(), d])
  );
  const nonResolvingSelected = selectedNames.filter(name=>isDomainNonResolving(domainMap.get(name)));
  if(!nonResolvingSelected.length){
    setDomainRemoveStatus('Selected domains are not non-resolving', 'err');
    return;
  }
  await removeDomainsFromConfig(nonResolvingSelected, `Removed ${nonResolvingSelected.length} selected non-resolving domain(s)`);
}

async function refreshDomainAnalysis(){
  if(refreshDomainAnalysisInFlight) return;
  refreshDomainAnalysisInFlight = true;
  try{
    const includeVT = !!(document.getElementById('domain_analysis_include_vt') && document.getElementById('domain_analysis_include_vt').checked);
    const r = await fetch('/domain-analysis?include_vt=' + (includeVT ? '1' : '0'));
    if(!r.ok){
      console.error('refreshDomainAnalysis: HTTP error', r.status);
      return;
    }
    const j = await r.json();
    window.DOMAIN_ANALYSIS_CACHE = Array.isArray(j.domains) ? j.domains : [];
    window.DOMAIN_ANALYSIS_INCLUDE_VT = includeVT;
    pruneDomainAnalysisSelection();
    populateDomainAnalysisFilter(window.DOMAIN_ANALYSIS_CACHE);
    applyDomainAnalysisFilter();
  }catch(e){
    console.log('refreshDomainAnalysis error', e);
  }finally{
    refreshDomainAnalysisInFlight = false;
  }
}

const IP_INTEL_HINT_LEVEL_ORDER = { high: 0, warn: 1, mid: 2, info: 3 };
window.IP_INTEL_INSIGHTS = window.IP_INTEL_INSIGHTS || {
  infra: { signature: '', hints: [], characteristics: null },
  relationship: { signature: '', hints: [], characteristics: null },
};

function normalizeIpIntelHintLevel(rawLevel){
  const level = String(rawLevel || 'info').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(IP_INTEL_HINT_LEVEL_ORDER, level) ? level : 'info';
}

function formatIpIntelSignal(rawSignal){
  const signal = String(rawSignal || '').trim();
  if(!signal) return '';
  return signal
    .replace(/_/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (m)=>m.toUpperCase());
}

function shortIpIntelToken(value, head, tail){
  const s = String(value || '').trim();
  const h = parseBoundedInt(head, 10, 4, 20);
  const t = parseBoundedInt(tail, 6, 3, 12);
  if(!s) return '-';
  if(s.length <= (h + t + 2)) return s;
  return `${s.slice(0, h)}..${s.slice(-t)}`;
}

function topIpIntelCounter(counter){
  const src = (counter && typeof counter === 'object') ? counter : {};
  let topKey = null;
  let topCount = 0;
  Object.keys(src).forEach((k)=>{
    const n = Number(src[k] || 0);
    if(n > topCount){
      topKey = k;
      topCount = n;
    }else if(n === topCount && n > 0 && topKey != null && String(k) < String(topKey)){
      topKey = k;
    }
  });
  return { key: topKey, count: topCount };
}

function computeIpIntelInputSignature(rawInput){
  const raw = String(rawInput || '').trim();
  if(!raw) return '';
  const tokens = raw.split(/[\s,;|]+/).map(x=>String(x || '').trim()).filter(Boolean);
  const uniq = Array.from(new Set(tokens)).sort();
  return uniq.join('|');
}

function getCurrentIpIntelInputSignature(){
  const raw = String((document.getElementById('ipIntelInput') || {}).value || '').trim();
  return computeIpIntelInputSignature(raw);
}

function getIpIntelInsightsState(){
  if(!window.IP_INTEL_INSIGHTS || typeof window.IP_INTEL_INSIGHTS !== 'object'){
    window.IP_INTEL_INSIGHTS = {
      infra: { signature: '', hints: [], characteristics: null },
      relationship: { signature: '', hints: [], characteristics: null },
    };
  }
  if(!window.IP_INTEL_INSIGHTS.infra || typeof window.IP_INTEL_INSIGHTS.infra !== 'object'){
    window.IP_INTEL_INSIGHTS.infra = { signature: '', hints: [], characteristics: null };
  }
  if(!window.IP_INTEL_INSIGHTS.relationship || typeof window.IP_INTEL_INSIGHTS.relationship !== 'object'){
    window.IP_INTEL_INSIGHTS.relationship = { signature: '', hints: [], characteristics: null };
  }
  return window.IP_INTEL_INSIGHTS;
}

function buildIpIntelCharacteristicsSummary(characteristics){
  if(!characteristics || typeof characteristics !== 'object'){
    return '';
  }
  const chips = [];
  const infra = (characteristics.infra && typeof characteristics.infra === 'object')
    ? characteristics.infra
    : characteristics;
  const rel = (characteristics.relationship && typeof characteristics.relationship === 'object')
    ? characteristics.relationship
    : null;

  const vtEnriched = Number((infra && infra.vt_enriched_count) || 0);
  if(vtEnriched > 0){
    chips.push(`VT-enriched ${vtEnriched}`);
  }
  const network = (infra && infra.network) || {};
  if(network.value && Number(network.count || 0) >= 2){
    chips.push(`Top network ${network.value} (${network.count})`);
  }
  const p24 = (infra && infra.prefix24) || {};
  if(p24.value && Number(p24.count || 0) >= 2){
    chips.push(`Top /24 ${p24.value} (${p24.count})`);
  }
  const jarm = (infra && infra.jarm) || {};
  if(jarm.value && Number(jarm.count || 0) >= 2){
    chips.push(`Shared JARM ${jarm.value} (${jarm.count})`);
  }
  const cert = (infra && infra.cert_sha256) || {};
  if(cert.value && Number(cert.count || 0) >= 2){
    chips.push(`Shared cert ${cert.value} (${cert.count})`);
  }
  const rdap = (infra && infra.rdap_name) || {};
  if(rdap.value && Number(rdap.count || 0) >= 2){
    chips.push(`Shared RDAP ${rdap.value} (${rdap.count})`);
  }

  if(rel){
    const clusterCount = Number(rel.cluster_count || 0);
    const largestClusterSize = Number(rel.largest_cluster_size || 0);
    const largestClusterRatio = Number(rel.largest_cluster_ratio || 0);
    const avgCohesion = (rel.avg_cohesion == null) ? null : Number(rel.avg_cohesion);
    if(clusterCount > 0){
      chips.push(`Clusters ${clusterCount}`);
    }
    if(largestClusterSize > 0){
      const ratioTxt = largestClusterRatio > 0 ? ` (${Math.round(largestClusterRatio * 100)}%)` : '';
      chips.push(`Largest ${largestClusterSize}${ratioTxt}`);
    }
    if(avgCohesion != null && Number.isFinite(avgCohesion)){
      chips.push(`Avg cohesion ${avgCohesion.toFixed(1)}`);
    }
    const relNet = (rel.top_network || {});
    if(relNet.value && Number(relNet.count || 0) >= 2){
      chips.push(`Cluster net ${relNet.value} (${relNet.count})`);
    }
    const relJarm = (rel.top_jarm || {});
    if(relJarm.value && Number(relJarm.count || 0) >= 2){
      chips.push(`Cluster JARM ${relJarm.value} (${relJarm.count})`);
    }
    const relCert = (rel.top_cert || {});
    if(relCert.value && Number(relCert.count || 0) >= 2){
      chips.push(`Cluster cert ${relCert.value} (${relCert.count})`);
    }
  }

  return chips.join(' · ');
}

function buildIpIntelRelationshipInsights(relCache){
  const payload = (relCache && typeof relCache === 'object') ? relCache : {};
  const clustersRaw = Array.isArray(payload.clusters) ? payload.clusters : [];
  const clusters = clustersRaw.filter(c=>Number((c && c.size) || 0) >= 2);
  const validCount = Number(payload.valid_count || 0);
  const pairCount = Number(payload.pair_count || 0);
  const topPairsLimit = Number(payload.top_pairs || 0);
  const hints = [];
  const addHint = (level, title, detail, signal)=>{
    const item = { level, title, detail, source: 'Cluster' };
    if(signal) item.signal = signal;
    hints.push(item);
  };

  let largestClusterSize = 0;
  let largestClusterRatio = 0;
  let cohesionSum = 0;
  let cohesionCount = 0;
  let highCohesionClusters = 0;
  let highMaliciousClusters = 0;
  const networkCounter = {};
  const jarmCounter = {};
  const certCounter = {};

  clusters.forEach((c)=>{
    const size = Number((c && c.size) || 0);
    if(size > largestClusterSize) largestClusterSize = size;
    const ratio = validCount > 0 ? size / validCount : 0;
    if(ratio > largestClusterRatio) largestClusterRatio = ratio;

    const cohesion = (c && c.cohesion != null) ? Number(c.cohesion) : null;
    if(cohesion != null && Number.isFinite(cohesion)){
      cohesionSum += cohesion;
      cohesionCount += 1;
      if(cohesion >= 65 && size >= 3){
        highCohesionClusters += 1;
      }
    }

    const vt = (c && c.vt_summary && typeof c.vt_summary === 'object') ? c.vt_summary : null;
    const malTotal = Number((vt && vt.malicious_total) || 0);
    if(size >= 3 && malTotal >= Math.ceil(size * 0.5)){
      highMaliciousClusters += 1;
    }

    const topNet = Array.isArray(c && c.top_network) ? c.top_network[0] : null;
    if(topNet && topNet[0] && topNet[0] !== '-' && Number(topNet[1] || 0) >= 2){
      const key = String(topNet[0]);
      networkCounter[key] = Number(networkCounter[key] || 0) + Number(topNet[1] || 0);
    }
    const topJarm = Array.isArray(c && c.top_jarm) ? c.top_jarm[0] : null;
    if(topJarm && topJarm[0] && topJarm[0] !== '-' && Number(topJarm[1] || 0) >= 2){
      const key = String(topJarm[0]);
      jarmCounter[key] = Number(jarmCounter[key] || 0) + Number(topJarm[1] || 0);
    }
    const topCert = Array.isArray(c && c.top_cert) ? c.top_cert[0] : null;
    if(topCert && topCert[0] && topCert[0] !== '-' && Number(topCert[1] || 0) >= 2){
      const key = String(topCert[0]);
      certCounter[key] = Number(certCounter[key] || 0) + Number(topCert[1] || 0);
    }
  });

  const topNetwork = topIpIntelCounter(networkCounter);
  const topJarm = topIpIntelCounter(jarmCounter);
  const topCert = topIpIntelCounter(certCounter);
  const avgCohesion = (cohesionCount > 0) ? (cohesionSum / cohesionCount) : null;

  if(!clusters.length){
    if(validCount >= 2){
      addHint('warn', 'Weak Cluster Connectivity', 'No cluster with 2+ IPs met the current relationship threshold.', 'cluster');
    }
  }else{
    if(largestClusterSize >= 4 && largestClusterRatio >= 0.55){
      addHint('high', 'Dominant Cluster', `Largest cluster has ${largestClusterSize}/${validCount || largestClusterSize} IPs (${Math.round(largestClusterRatio * 100)}%).`, 'cluster_size');
    }else if(clusters.length >= 3){
      addHint('mid', 'Multi-cluster Layout', `${clusters.length} clusters were identified, suggesting segmented infrastructure.`, 'cluster_count');
    }

    if(highCohesionClusters > 0){
      const lvl = highCohesionClusters >= 2 ? 'high' : 'mid';
      addHint(lvl, 'High Cohesion Cluster', `${highCohesionClusters} cluster(s) show cohesion ≥ 65.`, 'cohesion');
    }
    if(highMaliciousClusters > 0){
      addHint('high', 'Malicious Cluster Core', `${highMaliciousClusters} cluster(s) have high malicious density in VT summary.`, 'vt_cluster');
    }
  }

  if(topNetwork.key && topNetwork.count >= 4){
    addHint('mid', 'Cluster Network Reuse', `Cluster footprints repeatedly include network ${topNetwork.key} (${topNetwork.count}).`, 'network');
  }
  if(topJarm.key && topJarm.count >= 3){
    addHint('high', 'Cluster JARM Reuse', `${topJarm.count} cluster-IP observations share JARM ${shortIpIntelToken(topJarm.key, 10, 6)}.`, 'jarm');
  }
  if(topCert.key && topCert.count >= 2){
    const lvl = topCert.count >= 3 ? 'high' : 'mid';
    addHint(lvl, 'Cluster Certificate Reuse', `${topCert.count} cluster-IP observations share cert ${shortIpIntelToken(topCert.key, 10, 6)}.`, 'cert_sha256');
  }

  const pairGate = (payload.pair_gate && typeof payload.pair_gate === 'object') ? payload.pair_gate : null;
  if(pairGate && pairGate.enabled){
    const kept = Number(pairGate.kept || 0);
    const dropped = Number(pairGate.dropped || 0);
    const total = kept + dropped;
    if(total >= 20 && dropped / Math.max(1, total) >= 0.75){
      addHint('info', 'Pair Gate Filtering', `${dropped}/${total} candidate edges were filtered as weak links.`, 'pair_gate');
    }
  }

  const oversized = Number(payload.bucket_oversized_count || 0);
  const truncated = Number(payload.bucket_truncated_count || 0);
  if(oversized > 0){
    addHint('warn', 'Bucket Overflow Applied', `${oversized} oversized feature buckets detected (${truncated} truncated).`, 'bucket');
  }
  if(topPairsLimit > 0 && pairCount >= topPairsLimit){
    addHint('info', 'Pair Output Limited', `Top pair output reached configured limit (${topPairsLimit}).`, 'top_pairs');
  }

  return {
    hints,
    characteristics: {
      cluster_count: clusters.length,
      pair_count: pairCount,
      largest_cluster_size: largestClusterSize,
      largest_cluster_ratio: largestClusterRatio,
      avg_cohesion: (avgCohesion != null && Number.isFinite(avgCohesion)) ? avgCohesion : null,
      high_cohesion_clusters: highCohesionClusters,
      high_malicious_clusters: highMaliciousClusters,
      top_network: { value: topNetwork.key, count: Number(topNetwork.count || 0) },
      top_jarm: { value: topJarm.key ? shortIpIntelToken(topJarm.key, 10, 6) : null, count: Number(topJarm.count || 0) },
      top_cert: { value: topCert.key ? shortIpIntelToken(topCert.key, 10, 6) : null, count: Number(topCert.count || 0) },
    },
  };
}

function renderIpIntelHints(hintsBox, rawHints, characteristics){
  if(!hintsBox) return;
  hintsBox.innerHTML = '';
  const hints = Array.isArray(rawHints)
    ? rawHints
        .map(h=>({
          level: normalizeIpIntelHintLevel(h && h.level),
          title: String((h && h.title) || 'Hint').trim() || 'Hint',
          detail: String((h && h.detail) || '-').trim() || '-',
          source: formatIpIntelSignal(h && h.source),
          signal: formatIpIntelSignal(h && h.signal),
        }))
        .sort((a, b)=>{
          const pa = Number(IP_INTEL_HINT_LEVEL_ORDER[a.level]);
          const pb = Number(IP_INTEL_HINT_LEVEL_ORDER[b.level]);
          if(pa !== pb) return pa - pb;
          return a.title.localeCompare(b.title);
        })
    : [];

  const summary = buildIpIntelCharacteristicsSummary(characteristics);
  if(summary){
    const meta = document.createElement('div');
    meta.className = 'ipintel-hints-meta';
    meta.textContent = summary;
    hintsBox.appendChild(meta);
  }

  if(!hints.length){
    const empty = document.createElement('div');
    empty.className = 'ipintel-hint-empty';
    empty.textContent = summary ? 'No additional heuristics available' : 'No heuristics available';
    hintsBox.appendChild(empty);
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'ipintel-hints-grid';
  hints.forEach(h=>{
    const card = document.createElement('article');
    card.className = `ipintel-hint-card level-${h.level}`;

    const head = document.createElement('div');
    head.className = 'ipintel-hint-head';

    const levelBadge = document.createElement('span');
    levelBadge.className = 'ipintel-hint-level';
    levelBadge.textContent = h.level.toUpperCase();

    const title = document.createElement('span');
    title.className = 'ipintel-hint-title';
    title.textContent = h.title;

    head.appendChild(levelBadge);
    head.appendChild(title);

    if(h.source){
      const src = document.createElement('span');
      src.className = 'ipintel-hint-source';
      src.textContent = h.source;
      head.appendChild(src);
    }

    if(h.signal){
      const signal = document.createElement('span');
      signal.className = 'ipintel-hint-signal';
      signal.textContent = h.signal;
      head.appendChild(signal);
    }

    const detail = document.createElement('div');
    detail.className = 'ipintel-hint-detail';
    detail.textContent = h.detail;

    card.appendChild(head);
    card.appendChild(detail);
    grid.appendChild(card);
  });
  hintsBox.appendChild(grid);
}

function renderMergedIpIntelHints(){
  const hintsBox = document.getElementById('ipIntelHintsBox');
  if(!hintsBox) return;
  const state = getIpIntelInsightsState();
  const currentSig = getCurrentIpIntelInputSignature();
  const mergedHints = [];
  let infraCharacteristics = null;
  let relationshipCharacteristics = null;

  if(currentSig && state.infra.signature === currentSig){
    infraCharacteristics = state.infra.characteristics && typeof state.infra.characteristics === 'object'
      ? state.infra.characteristics
      : null;
    const infraHints = Array.isArray(state.infra.hints) ? state.infra.hints : [];
    infraHints.forEach((h)=>{
      if(!h || typeof h !== 'object') return;
      mergedHints.push({
        ...h,
        source: h.source || 'Infra',
      });
    });
  }

  if(currentSig && state.relationship.signature === currentSig){
    relationshipCharacteristics = state.relationship.characteristics && typeof state.relationship.characteristics === 'object'
      ? state.relationship.characteristics
      : null;
    const relHints = Array.isArray(state.relationship.hints) ? state.relationship.hints : [];
    relHints.forEach((h)=>{
      if(!h || typeof h !== 'object') return;
      mergedHints.push({
        ...h,
        source: h.source || 'Cluster',
      });
    });
  }

  renderIpIntelHints(hintsBox, mergedHints, {
    infra: infraCharacteristics,
    relationship: relationshipCharacteristics,
  });
}

function setIpIntelInfraInsights(inputSignature, rawHints, characteristics){
  const state = getIpIntelInsightsState();
  state.infra = {
    signature: String(inputSignature || ''),
    hints: Array.isArray(rawHints) ? rawHints : [],
    characteristics: (characteristics && typeof characteristics === 'object') ? characteristics : null,
  };
  renderMergedIpIntelHints();
}

function setIpIntelRelationshipInsights(inputSignature, relCache){
  const state = getIpIntelInsightsState();
  const built = buildIpIntelRelationshipInsights(relCache);
  state.relationship = {
    signature: String(inputSignature || ''),
    hints: Array.isArray(built.hints) ? built.hints : [],
    characteristics: (built.characteristics && typeof built.characteristics === 'object') ? built.characteristics : null,
  };
  renderMergedIpIntelHints();
}

function clearIpIntelRelationshipInsights(inputSignature){
  const state = getIpIntelInsightsState();
  state.relationship = {
    signature: String(inputSignature || ''),
    hints: [],
    characteristics: null,
  };
  renderMergedIpIntelHints();
}

async function analyzeIpIntel(){
  const raw = String((document.getElementById('ipIntelInput') || {}).value || '').trim();
  const inputSignature = computeIpIntelInputSignature(raw);
  const includeVT = !!(document.getElementById('ipIntelIncludeVt') && document.getElementById('ipIntelIncludeVt').checked);
  const rowLimit = parseBoundedInt((document.getElementById('ipIntelRowLimit') || {}).value, 1500, 100, 5000);
  const vtBudget = parseBoundedInt((document.getElementById('ipIntelVtBudget') || {}).value, 1200, 0, 5000);
  const vtWorkers = parseBoundedInt((document.getElementById('ipIntelVtWorkers') || {}).value, 8, 1, 32);
  const meta = document.getElementById('ipIntelMeta');
  const invalidBox = document.getElementById('ipIntelInvalidBox');
  const ipBody = document.querySelector('#ipIntelResultTable tbody');
  const asBody = document.querySelector('#ipIntelAsSummaryTable tbody');
  const cBody = document.querySelector('#ipIntelCountrySummaryTable tbody');
  const acBody = document.querySelector('#ipIntelAsCountrySummaryTable tbody');
  const cspBody = document.querySelector('#ipIntelCspSummaryTable tbody');

  if(ipIntelAnalyzeController){
    try{ ipIntelAnalyzeController.abort(); }catch(e){}
  }
  ipIntelAnalyzeSeq += 1;

  if(!raw){
    if(meta) meta.textContent = 'Input IP list first';
    renderMergedIpIntelHints();
    return;
  }

  const controller = (typeof AbortController === 'function') ? new AbortController() : null;
  ipIntelAnalyzeController = controller;
  const requestSeq = ipIntelAnalyzeSeq;
  const isStale = ()=> requestSeq !== ipIntelAnalyzeSeq || ipIntelAnalyzeController !== controller;
  setIpIntelBusy(true);

  if(meta) meta.textContent = 'Analyzing...';

  try{
    const r = await fetch('/ip-list-analysis', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      signal: controller ? controller.signal : undefined,
      body: JSON.stringify({
        ips: raw,
        include_vt: includeVT,
        row_limit: rowLimit,
        vt_lookup_budget: vtBudget,
        vt_workers: vtWorkers
      })
    });
    const j = await r.json();
    if(isStale()) return;
    if(!r.ok){
      if(meta) meta.textContent = `Analyze failed: ${(j && j.error) ? j.error : 'HTTP '+r.status}`;
      if(ipBody) setSummaryMessage(ipBody, 6, 'No data');
      if(asBody) setSummaryMessage(asBody, 6, 'No data');
      if(cBody) setSummaryMessage(cBody, 4, 'No data');
      if(acBody) setSummaryMessage(acBody, 6, 'No data');
      if(cspBody) setSummaryMessage(cspBody, 5, 'No data');
      setIpIntelInfraInsights(inputSignature, [], null);
      if(invalidBox) invalidBox.textContent = '-';
      return;
    }

    const rows = Array.isArray(j.ips) ? j.ips : [];
    const asRows = Array.isArray(j.as_summary) ? j.as_summary : [];
    const cRows = Array.isArray(j.country_summary) ? j.country_summary : [];
    const acRows = Array.isArray(j.as_country_summary) ? j.as_country_summary : [];
    const cspRows = Array.isArray(j.csp_summary) ? j.csp_summary : [];
    const hints = Array.isArray(j.hints) ? j.hints : [];
    const characteristics = (j && typeof j.characteristics === 'object' && j.characteristics) ? j.characteristics : {};
    const invalid = Array.isArray(j.invalid_inputs) ? j.invalid_inputs : [];
    const ipsTotal = Number((j && j.ips_total_count) || rows.length || 0);
    const ipsShown = Number((j && j.ips_displayed_count) || rows.length || 0);
    const ipsLimited = !!(j && j.ips_truncated);
    const vtBudgetInfo = Number((j && j.vt_lookup_budget) || vtBudget || 0);
    const vtAttemptedInfo = Number((j && j.vt_lookup_attempted) || 0);
    const vtWorkersInfo = Number((j && j.vt_workers) || vtWorkers || 1);

    if(meta){
      let txt = `submitted ${j.submitted_count || 0} / valid ${j.valid_count || 0} / invalid ${j.invalid_count || 0} / displayed ${ipsShown}/${ipsTotal}`;
      if(ipsLimited){
        txt += ' (row-limited)';
      }
      if(includeVT){
        txt += ` / VT budget ${vtBudgetInfo} (attempted ${vtAttemptedInfo}, workers ${vtWorkersInfo})`;
      }
      meta.textContent = txt;
    }

    if(ipBody){
      ipBody.innerHTML = '';
      if(!rows.length){
        setSummaryMessage(ipBody, 6, 'No valid IP results');
      } else {
        rows.forEach(it=>{
          const tr = document.createElement('tr');
          const c1 = document.createElement('td');
          c1.textContent = String((it && it.ip) || '-');
          if(isIPv4(it && it.ip)){
            c1.style.cursor = 'pointer';
            c1.title = 'Open in Query';
            c1.onclick = ()=> openQueryForValue(it.ip);
          }
          const c2 = document.createElement('td'); c2.textContent = String((it && it.asn) || '-');
          const c3 = document.createElement('td'); c3.textContent = String((it && it.as_owner) || '-');
          const c4 = document.createElement('td');
          c4.appendChild(createCspBadge((it && it.csp) || 'other', (it && it.csp_label) || 'Other/Unknown', !!(it && it.csp_major)));
          const c5 = document.createElement('td'); c5.textContent = String((it && it.country) || '-');
          const c6 = document.createElement('td');
          c6.textContent = includeVT ? `${Number((it && it.malicious) || 0)}/${Number((it && it.suspicious) || 0)}` : 'off';
          tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6);
          ipBody.appendChild(tr);
        });
      }
    }

    if(asBody){
      asBody.innerHTML = '';
      if(!asRows.length){
        setSummaryMessage(asBody, 6, 'No AS summary');
      } else {
        asRows.forEach(it=>{
          const tr = document.createElement('tr');
          const c1 = document.createElement('td'); c1.textContent = String((it && it.asn) || '-');
          const c2 = document.createElement('td'); c2.textContent = String((it && it.as_owner) || '-');
          const c3 = document.createElement('td');
          c3.appendChild(createCspBadge((it && it.csp) || 'other', (it && it.csp_label) || 'Other/Unknown', !!(it && it.csp_major)));
          const c4 = document.createElement('td'); c4.textContent = String((it && it.ip_count) || 0);
          const c5 = document.createElement('td'); c5.textContent = String((it && it.malicious_ips) || 0);
          const c6 = document.createElement('td'); c6.textContent = formatListPreview((it && it.countries) || [], 3);
          tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6);
          asBody.appendChild(tr);
        });
      }
    }

    if(cBody){
      cBody.innerHTML = '';
      if(!cRows.length){
        setSummaryMessage(cBody, 4, 'No country summary');
      } else {
        cRows.forEach(it=>{
          const tr = document.createElement('tr');
          const c1 = document.createElement('td'); c1.textContent = String((it && it.country) || '-');
          const c2 = document.createElement('td'); c2.textContent = String((it && it.ip_count) || 0);
          const c3 = document.createElement('td'); c3.textContent = String((it && it.asn_count) || 0);
          const c4 = document.createElement('td'); c4.textContent = String((it && it.malicious_ips) || 0);
          tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4);
          cBody.appendChild(tr);
        });
      }
    }

    if(acBody){
      acBody.innerHTML = '';
      if(!acRows.length){
        setSummaryMessage(acBody, 6, 'No AS×Country intersection summary');
      } else {
        acRows.forEach(it=>{
          const tr = document.createElement('tr');
          const c1 = document.createElement('td'); c1.textContent = String((it && it.asn) || '-');
          const c2 = document.createElement('td'); c2.textContent = String((it && it.country) || '-');
          const c3 = document.createElement('td'); c3.textContent = String((it && it.as_owner) || '-');
          const c4 = document.createElement('td');
          c4.appendChild(createCspBadge((it && it.csp) || 'other', (it && it.csp_label) || 'Other/Unknown', !!(it && it.csp_major)));
          const c5 = document.createElement('td'); c5.textContent = String((it && it.ip_count) || 0);
          const c6 = document.createElement('td'); c6.textContent = String((it && it.malicious_ips) || 0);
          tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6);
          acBody.appendChild(tr);
        });
      }
    }

    if(cspBody){
      cspBody.innerHTML = '';
      if(!cspRows.length){
        setSummaryMessage(cspBody, 5, 'No CSP summary');
      } else {
        cspRows.forEach(it=>{
          const tr = document.createElement('tr');
          const c1 = document.createElement('td');
          c1.appendChild(createCspBadge((it && it.csp) || 'other', (it && it.csp_label) || 'Other/Unknown', !!(it && it.csp_major)));
          const c2 = document.createElement('td'); c2.textContent = String((it && it.ip_count) || 0);
          const c3 = document.createElement('td'); c3.textContent = String((it && it.asn_count) || 0);
          const c4 = document.createElement('td'); c4.textContent = String((it && it.country_count) || 0);
          const c5 = document.createElement('td'); c5.textContent = String((it && it.malicious_ips) || 0);
          tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5);
          cspBody.appendChild(tr);
        });
      }
    }

    setIpIntelInfraInsights(inputSignature, hints, characteristics);

    if(invalidBox){
      if(!invalid.length){
        invalidBox.textContent = 'No invalid inputs';
      } else {
        invalidBox.textContent = invalid.join(', ');
      }
    }
    touchOverviewTs();
  }catch(e){
    if(isAbortError(e) || isStale()) return;
    setIpIntelInfraInsights(inputSignature, [], null);
    if(meta) meta.textContent = 'Analyze error: ' + e;
  }finally{
    if(ipIntelAnalyzeController === controller){
      ipIntelAnalyzeController = null;
    }
    setIpIntelBusy(false);
  }
}

async function loadIpIntelFromMisp(autoAnalyze){
  const eventId = String((document.getElementById('ipIntelMispEventId') || {}).value || '').trim();
  const meta = document.getElementById('ipIntelMeta');
  const invalidBox = document.getElementById('ipIntelInvalidBox');
  if(meta) meta.textContent = 'Loading MISP ip-src...';
  try{
    const payload = {};
    if(eventId) payload.event_id = eventId;
    const r = await fetch('/misp/event-ips', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json();
    if(!r.ok || !j || j.status !== 'ok'){
      if(meta) meta.textContent = `MISP load failed: ${(j && j.error) ? j.error : 'HTTP '+r.status}`;
      return;
    }

    const ips = Array.isArray(j.ips) ? j.ips : [];
    const ta = document.getElementById('ipIntelInput');
    if(ta){
      ta.value = ips.join('\n');
    }
    renderMergedIpIntelHints();
    if(!eventId){
      const eidEl = document.getElementById('ipIntelMispEventId');
      if(eidEl && j.event_id != null){
        eidEl.value = String(j.event_id);
      }
    }
    if(meta){
      const info = j.event_info ? ` (${j.event_info})` : '';
      meta.textContent = `Loaded ${ips.length} ip-src from MISP event ${j.event_id}${info}`;
    }
    const invalid = Array.isArray(j.invalid_values) ? j.invalid_values : [];
    if(invalidBox){
      invalidBox.textContent = invalid.length ? `Invalid attribute values: ${invalid.join(', ')}` : 'No invalid inputs';
    }
    if(autoAnalyze && ips.length){
      await analyzeIpIntel();
    }
  }catch(e){
    if(meta) meta.textContent = 'MISP load error: ' + e;
  }
}

function renderCellWithClickableIps(td, rawValues, fallbackText, maxDisplayItems){
  const values = Array.isArray(rawValues) ? Array.from(new Set(rawValues.map(v=>String(v || '').trim()).filter(Boolean))) : [];
  const ips = values.filter(isIPv4);
  const limit = parseBoundedInt(maxDisplayItems, 12, 3, 50);
  td.className = 'wrap-cell';
  if(!ips.length){
    const full = String(fallbackText || '');
    td.textContent = full.length > 200 ? full.slice(0,200) + '…' : full;
    td.title = full;
    return;
  }
  const shown = ips.slice(0, limit);
  td.innerHTML = '';
  td.title = ips.join(' | ');
  shown.forEach((ip, idx)=>{
    const a = document.createElement('a');
    a.href = '#';
    a.textContent = ip;
    a.onclick = (e)=>{
      e.preventDefault();
      openQueryForValue(ip);
    };
    td.appendChild(a);
    if(idx < shown.length - 1){
      td.appendChild(document.createTextNode(' | '));
    }
  });
  if(ips.length > shown.length){
    td.appendChild(document.createTextNode(` +${ips.length - shown.length}`));
  }
}

const uiOverview = {
  configured: 0,
  statusRows: 0,
  managedIps: 0,
  allIps: 0,
  validIps: 0,
  lastRefreshLocal: '-'
};
let refreshResultsInFlight = false;
let refreshIPsInFlight = false;
let refreshValidIPsInFlight = false;
let lastStatusRenderFingerprint = '';
let lastAllIpsRenderFingerprint = '';
let lastValidIpsRenderFingerprint = '';

function updateOverviewPanel(){
  const set = (id, value)=>{
    const el = document.getElementById(id);
    if(el) el.textContent = value;
  };
  set('metricConfigured', String(uiOverview.configured));
  set('metricStatusRows', String(uiOverview.statusRows));
  set('metricDecoded', String(uiOverview.managedIps));
  const validTxt = (uiOverview.validIps == null) ? '?' : String(uiOverview.validIps);
  set('metricIps', `${uiOverview.allIps} / valid ${validTxt}`);
  set('metricUpdated', uiOverview.lastRefreshLocal);
}

function touchOverviewTs(){
  uiOverview.lastRefreshLocal = formatLocalDateTime(new Date());
  updateOverviewPanel();
}

function setAlertSettingsStatus(message, kind){
  const el = document.getElementById('alertSettingsStatus');
  if(!el) return;
  el.textContent = message || '';
  el.classList.remove('ok', 'err');
  if(kind === 'ok') el.classList.add('ok');
  if(kind === 'err') el.classList.add('err');
  if(message){
    setTimeout(()=>{
      el.textContent = '';
      el.classList.remove('ok', 'err');
    }, 2800);
  }
}

async function loadAlertSettings(){
  try{
    const r = await fetch('/settings');
    if(!r.ok) throw new Error('HTTP '+r.status);
    const j = await r.json();
    const alerts = (j.settings && j.settings.alerts) ? j.settings.alerts : (j.settings || {}).alerts || {};
    document.getElementById('teams_webhook_front').value = alerts.teams_webhook || '';
    document.getElementById('misp_url_front').value = alerts.misp_url || '';
    document.getElementById('misp_key_front').value = alerts.api_key || '';
    document.getElementById('push_event_id_front').value = alerts.push_event_id || '';
    document.getElementById('vt_api_key_front').value = alerts.vt_api_key || '';
    const removeOnAbsentEl = document.getElementById('misp_remove_on_absent_front');
    if(removeOnAbsentEl){
      removeOnAbsentEl.checked = !!alerts.misp_remove_on_absent;
    }
    const vtTtlInput = document.getElementById('vt_cache_ttl_days_front');
    if(vtTtlInput){
      const vtTtlDays = parseBoundedInt(alerts.vt_cache_ttl_days, 1, 1, 3650);
      vtTtlInput.value = String(vtTtlDays);
      vtTtlInput.dataset.current = String(vtTtlDays);
    }
    const botnetEventEl = document.getElementById('ipIntelMispEventId');
    if(botnetEventEl && !String(botnetEventEl.value || '').trim() && alerts.push_event_id){
      botnetEventEl.value = String(alerts.push_event_id);
    }
    setAlertSettingsStatus('Loaded', 'ok');
  }catch(e){
    setAlertSettingsStatus('Load failed', 'err');
  }
}

async function saveAlertSettings(){
  const vtTtlEl = document.getElementById('vt_cache_ttl_days_front');
  const currentTtl = parseBoundedInt((vtTtlEl && vtTtlEl.dataset ? vtTtlEl.dataset.current : ''), 1, 1, 3650);
  const vtTtlDays = parseBoundedInt((vtTtlEl || {}).value, currentTtl, 1, 3650);
  const alerts = {
    teams_webhook: document.getElementById('teams_webhook_front').value.trim(),
    misp_url: document.getElementById('misp_url_front').value.trim(),
    api_key: document.getElementById('misp_key_front').value.trim(),
    push_event_id: document.getElementById('push_event_id_front').value.trim(),
    misp_remove_on_absent: !!((document.getElementById('misp_remove_on_absent_front') || {}).checked),
    vt_api_key: document.getElementById('vt_api_key_front').value.trim(),
    vt_cache_ttl_days: vtTtlDays
  };
  try{
    const r = await fetch('/settings', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({alerts})
    });
    const j = await r.json();
    if(!(r.ok && j && j.status === 'ok')){
      throw new Error((j && j.error) ? j.error : 'save failed');
    }
    if(vtTtlEl){
      vtTtlEl.value = String(vtTtlDays);
      vtTtlEl.dataset.current = String(vtTtlDays);
    }
    setAlertSettingsStatus('Saved', 'ok');
  }catch(e){
    setAlertSettingsStatus('Save failed', 'err');
  }
}

// Global decoder cache
window.DECODERS = [];
window.A_DECODERS = [];
window.ENS_DECODERS = [];
window.CUSTOM_DECODERS = [];
window.CUSTOM_A_DECODERS = [];

async function loadDecoders(){
  try{
    const r = await fetch('/decoders');
    if(!r.ok) return;
    const j = await r.json();
    if(j){
      window.DECODERS = Array.isArray(j.decoders) ? j.decoders : [];
      window.CUSTOM_DECODERS = Array.isArray(j.custom) ? j.custom : [];
      window.CUSTOM_A_DECODERS = Array.isArray(j.custom_a) ? j.custom_a : [];
      if ((!window.CUSTOM_DECODERS.length && !window.CUSTOM_A_DECODERS.length) && Array.isArray(j.custom_all)) {
        window.CUSTOM_DECODERS = j.custom_all.filter(x => String((x && x.decoder_type) || 'TXT').toUpperCase() === 'TXT');
        window.CUSTOM_A_DECODERS = j.custom_all.filter(x => String((x && x.decoder_type) || '').toUpperCase() === 'A');
      }
      window.A_DECODERS = Array.isArray(j.a_decoders) ? j.a_decoders : [];
      window.ENS_DECODERS = Array.isArray(j.ens_decoders) ? j.ens_decoders : [];
    }
  }catch(e){ /* ignore */ }
}

function addDomainRow(obj){
  const tbody = document.querySelector('#domainTable tbody');
  const tr = document.createElement('tr');

  const tdName = document.createElement('td');
  const inp = document.createElement('input');
  inp.type = 'text';
  inp.className = 'domain-name';
  inp.value = obj && obj.name ? obj.name : '';
  tdName.appendChild(inp);

  const tdType = document.createElement('td');
  const sel = document.createElement('select');
  sel.className = 'domain-type';
  // Expand supported record type list
  ['A','TXT','ENS','AAAA','CNAME','MX','NS','SRV','CAA'].forEach(t=>{ const o = document.createElement('option'); o.value=t; o.text=t; sel.appendChild(o); });
  if(obj && obj.type) sel.value = obj.type.toUpperCase();
  tdType.appendChild(sel);

  // TXT decoder select
  const tdTxtDecode = document.createElement('td');
  const selDecode = document.createElement('select');
  selDecode.className = 'txt-decode';
  // Decoder list is loaded dynamically from the backend; use fallback if not loaded yet
  const FALLBACK_DECODERS = ['cafebabe_xor_base64','plain_base64','btea_variant','xor_ipstring_base64_fixedkey','base64_xor_febabe','base56','safeb64_xor','c2_multiplex'];
  const decs = (window.DECODERS && window.DECODERS.length) ? window.DECODERS : FALLBACK_DECODERS;
  // include custom decoders names as well
  const customNames = (window.CUSTOM_DECODERS || [])
    .filter(c => String((c && c.decoder_type) || 'TXT').toUpperCase() === 'TXT')
    .map(c=>c.name);
  const finalDecs = (decs || []).concat(customNames.filter(n=>!(decs||[]).includes(n)));
  if(obj && obj.txt_decode && !finalDecs.includes(obj.txt_decode)){
    finalDecs.push(obj.txt_decode);
  }
  finalDecs.forEach(t=>{ const o = document.createElement('option'); o.value=t; o.text=t; selDecode.appendChild(o); });
  if(obj && obj.txt_decode && finalDecs.includes(obj.txt_decode)) selDecode.value = obj.txt_decode;
  tdTxtDecode.appendChild(selDecode);

  // A decoder select
  const tdADecode = document.createElement('td');
  const selADecode = document.createElement('select');
  selADecode.className = 'a-decode';
  const FALLBACK_A_DECODERS = ['none', 'xor32_ipv4'];
  const rawADecs = (window.A_DECODERS && window.A_DECODERS.length) ? window.A_DECODERS.slice() : FALLBACK_A_DECODERS.slice();
  const aDecs = Array.from(new Set(rawADecs.filter(Boolean)));
  // Keep 'none' as explicit first/default option to avoid alphabetical auto-selection confusion.
  const orderedADecs = ['none'].concat(aDecs.filter(n => n !== 'none'));
  if(obj && obj.a_decode && !orderedADecs.includes(obj.a_decode)){
    orderedADecs.push(obj.a_decode);
  }
  orderedADecs.forEach(t=>{
    const o = document.createElement('option');
    o.value = t;
    o.text = (t === 'none') ? 'None' : t;
    selADecode.appendChild(o);
  });
  if(obj && obj.a_decode && orderedADecs.includes(obj.a_decode)){
    selADecode.value = obj.a_decode;
  } else {
    selADecode.value = 'none';
  }
  tdADecode.appendChild(selADecode);

  // A XOR key input
  const tdAKey = document.createElement('td');
  const inpAKey = document.createElement('input');
  inpAKey.type = 'text';
  inpAKey.className = 'a-xor-key';
  inpAKey.placeholder = 'E7708E59 or 0xE7708E59';
  inpAKey.value = (obj && obj.a_xor_key) ? obj.a_xor_key : '';
  tdAKey.appendChild(inpAKey);

  // ENS text-key input
  const tdEnsKey = document.createElement('td');
  const inpEnsKey = document.createElement('input');
  inpEnsKey.type = 'text';
  inpEnsKey.className = 'ens-text-key';
  inpEnsKey.placeholder = 'ipv6';
  inpEnsKey.value = (obj && obj.ens_text_key) ? obj.ens_text_key : '';
  tdEnsKey.appendChild(inpEnsKey);

  // ENS decode select
  const tdEnsDecode = document.createElement('td');
  const selEnsDecode = document.createElement('select');
  selEnsDecode.className = 'ens-decode';
  const FALLBACK_ENS_DECODERS = ['ipv6_5to8_xor', 'legacy_doc_sample', 'none'];
  const ensDecsRaw = (window.ENS_DECODERS && window.ENS_DECODERS.length) ? window.ENS_DECODERS.slice() : FALLBACK_ENS_DECODERS.slice();
  const ensDecs = Array.from(new Set(ensDecsRaw.filter(Boolean)));
  if(obj && obj.ens_decode && !ensDecs.includes(obj.ens_decode)){
    ensDecs.push(obj.ens_decode);
  }
  ensDecs.forEach(t=>{
    const o = document.createElement('option');
    o.value = t;
    o.text = (t === 'none') ? 'None' : t;
    selEnsDecode.appendChild(o);
  });
  if(obj && obj.ens_decode && ensDecs.includes(obj.ens_decode)){
    selEnsDecode.value = obj.ens_decode;
  } else if(ensDecs.includes('ipv6_5to8_xor')){
    selEnsDecode.value = 'ipv6_5to8_xor';
  }
  tdEnsDecode.appendChild(selEnsDecode);

  // ENS options JSON input
  const tdEnsOptions = document.createElement('td');
  const inpEnsOptions = document.createElement('input');
  inpEnsOptions.type = 'text';
  inpEnsOptions.className = 'ens-options';
  inpEnsOptions.placeholder = '{"xor_byte":"0xA5"}';
  let ensOptionsText = '';
  if(obj && obj.ens_options && typeof obj.ens_options === 'object' && !Array.isArray(obj.ens_options)){
    ensOptionsText = formatJsonObjectCompact(obj.ens_options);
  } else if(obj && obj.ens_xor_byte){
    ensOptionsText = formatJsonObjectCompact({xor_byte: obj.ens_xor_byte});
  }
  inpEnsOptions.value = ensOptionsText;
  tdEnsOptions.appendChild(inpEnsOptions);

  // Toggle decoder fields by record type
  const toggleDecodeInputs = function(){
    const typ = (sel.value || 'A').toUpperCase();
    const isTXT = typ === 'TXT';
    const isA = typ === 'A';
    const isENS = typ === 'ENS';
    selDecode.disabled = !isTXT;
    selADecode.disabled = !isA;
    inpAKey.disabled = !isA;
    inpEnsKey.disabled = !isENS;
    selEnsDecode.disabled = !isENS;
    inpEnsOptions.disabled = !isENS;
  };
  sel.onchange = toggleDecodeInputs;
  toggleDecodeInputs();

  const tdBtn = document.createElement('td');
  const del = document.createElement('button'); 
  del.textContent='🗑️ Remove'; 
  del.title = 'Remove this domain';
  del.onclick = async ()=> { 
    tr.remove();
    uiOverview.configured = document.querySelectorAll('#domainTable tbody tr').length;
    updateOverviewPanel();
    try{
      // 자동으로 저장
      const payload = {
        domains: collectDomainsFromUI(),
        servers: document.getElementById('servers').value.split(',').map(s=>s.trim()).filter(Boolean),
        interval: parseInt(document.getElementById('interval').value) || 60,
        ens_rpc_url: ((document.getElementById('ensRpcUrl') || {}).value || '').trim()
      };
      const r = await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const j = await r.json();
      log('Removed domain and saved');
    }catch(e){ 
      log('Remove error:'+e); 
    }
  };
  tdBtn.appendChild(del);
  tr.appendChild(tdName);
  tr.appendChild(tdType);
  tr.appendChild(tdTxtDecode);
  tr.appendChild(tdADecode);
  tr.appendChild(tdAKey);
  tr.appendChild(tdEnsKey);
  tr.appendChild(tdEnsDecode);
  tr.appendChild(tdEnsOptions);
  tr.appendChild(tdBtn);
  tbody.appendChild(tr);
  uiOverview.configured = document.querySelectorAll('#domainTable tbody tr').length;
  updateOverviewPanel();
}

document.getElementById('addDomain').onclick = ()=> addDomainRow();

// Settings tab switching (domains vs custom decoders)
function showSettingsTab(tab){
  const dom = document.getElementById('domainSettingsSection');
  const custom = document.getElementById('customSection');
  const alerts = document.getElementById('alertsSection');
  const customTitle = document.getElementById('customSectionTitle');
  const btnDomains = document.getElementById('settingsTabDomains');
  const btnCustom = document.getElementById('settingsTabCustom');
  const btnAlerts = document.getElementById('settingsTabAlerts');
  if(tab === 'custom'){
    dom.style.display = 'none'; custom.style.display = 'block';
    alerts.style.display = 'none';
    customTitle.style.display = '';
    btnDomains.classList.remove('active');
    btnCustom.classList.add('active');
    btnAlerts.classList.remove('active');
    // Ensure latest custom decoder list is visible when entering the tab.
    if (typeof window.refreshCustomDecoders === 'function') {
      window.refreshCustomDecoders();
    }
  } else if(tab === 'alerts'){
    dom.style.display = 'none';
    custom.style.display = 'none';
    alerts.style.display = 'block';
    customTitle.style.display = 'none';
    btnDomains.classList.remove('active');
    btnCustom.classList.remove('active');
    btnAlerts.classList.add('active');
  } else {
    dom.style.display = '';
    custom.style.display = 'none';
    alerts.style.display = 'none';
    customTitle.style.display = '';
    btnCustom.classList.remove('active');
    btnAlerts.classList.remove('active');
    btnDomains.classList.add('active');
  }
}
document.getElementById('settingsTabDomains').onclick = ()=> showSettingsTab('domains');
document.getElementById('settingsTabCustom').onclick = ()=> showSettingsTab('custom');
document.getElementById('settingsTabAlerts').onclick = ()=> showSettingsTab('alerts');
document.getElementById('loadAlertSettingsBtn').onclick = ()=> loadAlertSettings();
document.getElementById('saveAlertSettingsBtn').onclick = ()=> saveAlertSettings();

function collectDomainsFromUI(){
  const rows = document.querySelectorAll('#domainTable tbody tr');
  const out = [];
  rows.forEach(r=>{
    const name = ((r.querySelector('.domain-name') || {}).value || '').trim();
    const typ = ((r.querySelector('.domain-type') || {}).value || 'A').toUpperCase();
    const txt_decode = ((r.querySelector('.txt-decode') || {}).value || '').trim();
    const a_decode = ((r.querySelector('.a-decode') || {}).value || 'none').trim();
    const a_xor_key = ((r.querySelector('.a-xor-key') || {}).value || '').trim();
    const ens_text_key = ((r.querySelector('.ens-text-key') || {}).value || '').trim();
    const ens_decode = ((r.querySelector('.ens-decode') || {}).value || 'ipv6_5to8_xor').trim();
    const ens_options_raw = ((r.querySelector('.ens-options') || {}).value || '').trim();
    if(name) {
      const obj = {name: name, type: typ};
      if(typ === 'TXT'){
        if(txt_decode) obj.txt_decode = txt_decode;
      } else if(typ === 'A'){
        if(a_decode && a_decode !== 'none') obj.a_decode = a_decode;
        // key를 넣었는데 method를 안 고른 경우 xor32 기본으로 자동 지정
        if(a_xor_key){
          if(!obj.a_decode) obj.a_decode = 'xor32_ipv4';
          obj.a_xor_key = a_xor_key;
        }
      } else if(typ === 'ENS'){
        if(ens_text_key) obj.ens_text_key = ens_text_key;
        if(ens_decode) obj.ens_decode = ens_decode;
        const parsed = parseJsonObjectInput(ens_options_raw, `ENS options (${name})`);
        if(!parsed.ok){
          throw new Error(parsed.error);
        }
        if(parsed.value){
          if(!obj.ens_decode) obj.ens_decode = 'ipv6_5to8_xor';
          obj.ens_options = parsed.value;
        }
      }
      out.push(obj);
    }
  });
  return out;
}

async function loadCfg(){
  try{
    const r = await fetch('/config');
    if(!r.ok){ log('Failed to load config'); return; }
    const j = await r.json();
    if(!j) { log('Invalid config response'); return; }
    document.querySelector('#domainTable tbody').innerHTML = '';
    const domains = j.domains || [];
    if(Array.isArray(domains)) {
      domains.forEach(d=>{
        if(typeof d === 'string') addDomainRow({name:d, type:'A'});
        else if(typeof d === 'object') addDomainRow(d);
      });
      uiOverview.configured = domains.length;
      updateOverviewPanel();
    }
    const servers = j.servers || [];
    document.getElementById('servers').value = (Array.isArray(servers) ? servers : []).join(',');
    const ensRpcEl = document.getElementById('ensRpcUrl');
    if(ensRpcEl) ensRpcEl.value = String(j.ens_rpc_url || '');
    document.getElementById('interval').value = j.interval || 60;
    log('Loaded config');
    touchOverviewTs();
  }catch(e){ log('Config load error:'+e); }
}
document.getElementById('load').onclick = loadCfg;

document.getElementById('save').onclick = async ()=>{
  try{
    const payload = {
      domains: collectDomainsFromUI(),
      servers: document.getElementById('servers').value.split(',').map(s=>s.trim()).filter(Boolean),
      interval: parseInt(document.getElementById('interval').value) || 60,
      ens_rpc_url: ((document.getElementById('ensRpcUrl') || {}).value || '').trim()
    };
    uiOverview.configured = payload.domains.length;
    updateOverviewPanel();
    const r = await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const j = await r.json();
    log('Saved: ' + JSON.stringify(j));
  }catch(e){ log('Save error:'+e); }
};

document.getElementById('force').onclick = async ()=>{
  try{
    const domains = collectDomainsFromUI();
    const r = await fetch('/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({domains: domains})});
    const j = await r.json();
    log('Force requested: '+JSON.stringify(j));
    await refreshResults();
  }catch(e){ log('Force error:'+e); }
};

document.getElementById('verifyBtn').onclick = async ()=>{
  const el = document.getElementById('verifyResult');
  el.textContent = 'Running verify...';
  try{
    const domains = collectDomainsFromUI();
    const r = await fetch('/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({domains: domains})});
    if(!r.ok){ el.textContent = 'Verify request failed: '+r.status; return; }
    const j = await r.json();
    renderVerifyResult(j, 'verifyResult');
  }catch(e){ el.textContent = 'Verify error: '+e; }
};

document.getElementById('statusVerifyBtn').onclick = async ()=>{
  const allDomains = [];
  const table = document.getElementById('resultsTable');
  if(table){
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row=>{
      if(row.classList && row.classList.contains('verify-row')) return;
      const domain = String(row.dataset && row.dataset.domain ? row.dataset.domain : '').trim()
        || String((row.cells && row.cells[0] && row.cells[0].textContent) || '').trim();
      if(domain && !allDomains.includes(domain)) allDomains.push(domain);
    });
  }
  if(allDomains.length===0){ log('No domains in status table to verify'); return; }
  const el = document.getElementById('statusVerifyResult');
  el.style.display='block';
  el.textContent = 'Running verify for '+allDomains.length+' domains...';
  try{
    const r = await fetch('/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({domains: allDomains})});
    if(!r.ok){ el.textContent = 'Verify request failed: '+r.status; return; }
    const j = await r.json();
    renderVerifyResult(j, 'statusVerifyResult');
  }catch(e){ el.textContent = 'Verify error: '+e; }
};

function renderVerifyResult(j, elementId){
  const el = document.getElementById(elementId);
  el.innerHTML = '';
  if(!j || j.error){ el.textContent = j && j.error ? 'Error: '+j.error : 'No result'; return; }
  const res = j.results || {};
  const doms = Object.keys(res).sort();
  if(doms.length===0){ el.textContent = 'No domains verified'; return; }
  doms.forEach(dom=>{
    const block = document.createElement('div');
    block.style.borderBottom='1px solid #eee'; block.style.padding='6px 0';
    const h = document.createElement('div'); h.textContent = dom; h.style.fontWeight='700';
    block.appendChild(h);
    const data = res[dom];
    if(data.error){ const e = document.createElement('div'); e.textContent = 'Error: '+data.error; block.appendChild(e); el.appendChild(block); return; }
    const analysis = data.analysis || {};
    const keys = Object.keys(analysis).sort((a,b)=> (analysis[b].score||0)-(analysis[a].score||0));
    keys.forEach(k=>{
      const info = analysis[k];
      const row = document.createElement('div');
      row.style.margin='6px 0';
      const title = document.createElement('div'); title.textContent = `${k} — score=${info.score} raw=${info.raw_count}`;
      title.style.fontWeight='600';
      row.appendChild(title);
      const ips = info.detailed_ips || [];
      if(ips.length===0){ const none = document.createElement('div'); none.textContent = 'No decoded IPs'; row.appendChild(none); }
      else{
        const tbl = document.createElement('table'); tbl.style.width='100%'; const th = document.createElement('tr'); th.innerHTML='<th>IP</th><th>Valid</th><th>VT(malicious/suspicious)</th><th>VT summary</th>'; tbl.appendChild(th);
        ips.forEach(it=>{
          const tr = document.createElement('tr');
          const tdIp = document.createElement('td'); tdIp.textContent = it.ip||'';
          const tdV = document.createElement('td'); tdV.textContent = it.valid ? 'YES' : 'NO';
          const tdVT = document.createElement('td');
          const tdSum = document.createElement('td');
          if(it.vt){ tdVT.textContent = `${it.vt.malicious||0}/${it.vt.suspicious||0}`; tdSum.textContent = `ASN:${it.vt.asn||''} ${it.vt.country||''}`; }
          else { tdVT.textContent = '-'; tdSum.textContent = '-'; }
          tr.appendChild(tdIp); tr.appendChild(tdV); tr.appendChild(tdVT); tr.appendChild(tdSum); tbl.appendChild(tr);
        });
        row.appendChild(tbl);
      }
      block.appendChild(row);
    });
    el.appendChild(block);
  });
}

function aggregateResultsByDomain(results){
  const out = {};
  Object.keys(results || {}).forEach(domain=>{
    const srvMap = results[domain];
    if(!srvMap || typeof srvMap !== 'object') return;
    const acc = {
      record_types: new Set(),
      values: new Set(),
      decoded_ips: new Set(),
      servers: new Set(),
      txt_decodes: new Set(),
      a_decodes: new Set(),
      a_xor_keys: new Set(),
      ts: 0
    };
    Object.keys(srvMap).forEach(server=>{
      const info = srvMap[server];
      if(!info || typeof info !== 'object') return;
      const rtype = String(info.type || 'A').toUpperCase();
      acc.record_types.add(rtype);
      acc.servers.add(String(server));
      (Array.isArray(info.values) ? info.values : []).forEach(v=>{
        const s = String(v || '').trim();
        if(s) acc.values.add(s);
      });
      (Array.isArray(info.decoded_ips) ? info.decoded_ips : []).forEach(v=>{
        const s = String(v || '').trim();
        if(s) acc.decoded_ips.add(s);
      });
      if(rtype === 'TXT' && info.txt_decode) acc.txt_decodes.add(String(info.txt_decode));
      if(rtype === 'A' && info.a_decode) acc.a_decodes.add(String(info.a_decode));
      if(rtype === 'A' && info.a_xor_key) acc.a_xor_keys.add(String(info.a_xor_key));
      const ts = Number(info.ts || 0);
      if(Number.isFinite(ts) && ts > acc.ts) acc.ts = ts;
    });

    const recordTypes = Array.from(acc.record_types).sort();
    let outType = 'A';
    if(recordTypes.length === 1){
      outType = recordTypes[0];
    } else if(recordTypes.length > 1){
      outType = 'MIXED';
    }
    const methodParts = [];
    if(acc.txt_decodes.size) methodParts.push(`TXT:${Array.from(acc.txt_decodes).sort().join(',')}`);
    if(acc.a_decodes.size){
      let aTxt = `A:${Array.from(acc.a_decodes).sort().join(',')}`;
      if(acc.a_xor_keys.size) aTxt += ` (${Array.from(acc.a_xor_keys).sort().join(',')})`;
      methodParts.push(aTxt);
    }
    out[domain] = {
      type: outType,
      record_types: recordTypes,
      values: Array.from(acc.values).sort(),
      decoded_ips: Array.from(acc.decoded_ips).sort(),
      servers: Array.from(acc.servers).sort(),
      server_count: acc.servers.size,
      ts: acc.ts || 0,
      method_summary: methodParts.length ? methodParts.join(' / ') : '-',
      txt_decodes: Array.from(acc.txt_decodes).sort(),
      a_decodes: Array.from(acc.a_decodes).sort(),
      a_xor_keys: Array.from(acc.a_xor_keys).sort()
    };
  });
  return out;
}

function formatDnsServerSummary(servers){
  const arr = Array.isArray(servers) ? servers.filter(Boolean) : [];
  if(!arr.length) return '-';
  if(arr.length <= 3) return arr.join(', ');
  return `${arr.length} servers (${arr.slice(0, 3).join(', ')}...)`;
}

function buildStatusFingerprint(resultsAgg, domainMeta){
  const keys = Object.keys(resultsAgg || {}).sort();
  const parts = [];
  keys.forEach(d=>{
    const it = resultsAgg[d] || {};
    const meta = (domainMeta && domainMeta[d]) || {};
    parts.push([
      d,
      Number(it.ts || 0),
      Array.isArray(it.values) ? it.values.length : 0,
      Array.isArray(it.decoded_ips) ? it.decoded_ips.length : 0,
      Array.isArray(it.servers) ? it.servers.length : 0,
      String(it.method_summary || ''),
      meta.nxdomain_active ? 1 : 0,
      Number(meta.nxdomain_since || 0),
      Number(meta.nxdomain_cleared_ts || 0),
    ].join('|'));
  });
  return `${keys.length}#${parts.join('||')}`;
}

function buildIpsFingerprint(arr){
  const list = Array.isArray(arr) ? arr : [];
  let totalCount = 0;
  let maxTs = 0;
  const limit = 400;
  const parts = [];
  list.forEach((it, idx)=>{
    const count = Number((it && it.count) || 0);
    const ts = Number((it && it.last_ts) || 0);
    totalCount += count;
    if(ts > maxTs) maxTs = ts;
    if(idx >= limit) return;
    parts.push([
      String((it && it.ip) || ''),
      count,
      ts,
      Array.isArray(it && it.domains) ? it.domains.length : 0,
      Number((it && ((it.vt || {}).malicious || 0)) || 0),
      Number((it && ((it.vt || {}).suspicious || 0)) || 0),
    ].join('|'));
  });
  return `${list.length}#${totalCount}#${maxTs}#${parts.join('||')}`;
}

async function refreshResults(){
  if(refreshResultsInFlight) return;
  refreshResultsInFlight = true;
  try{
    const r = await fetch('/results?aggregate=1');
    if(!r.ok){
      console.error('refreshResults: HTTP error', r.status);
      return;
    }
    const j = await r.json();
    const resultsAgg = (j && j.results_agg && typeof j.results_agg === 'object')
      ? j.results_agg
      : {};
    const domainMeta = (j && j.domain_meta && typeof j.domain_meta === 'object') ? j.domain_meta : {};
    const tbody = document.querySelector('#resultsTable tbody');
    const domains = Object.keys(resultsAgg).sort();
    const managedSet = new Set();

    domains.forEach(d=>{
      const info = resultsAgg[d] || {};
      const values = Array.isArray(info.values) ? info.values : [];
      const decodedIps = Array.isArray(info.decoded_ips) ? info.decoded_ips : [];
      const rowType = String(info.type || 'A').toUpperCase();
      const managedIps = rowType === 'TXT' ? decodedIps : (rowType === 'A' ? values : values.concat(decodedIps));
      managedIps.forEach(ip=>{
        const s = String(ip || '').trim();
        if(s) managedSet.add(s);
      });
    });
    uiOverview.statusRows = domains.length;
    uiOverview.managedIps = managedSet.size;

    const statusFp = buildStatusFingerprint(resultsAgg, domainMeta);
    if(statusFp === lastStatusRenderFingerprint){
      touchOverviewTs();
      return;
    }
    lastStatusRenderFingerprint = statusFp;

    tbody.innerHTML = '';
    if(!domains.length){
      setSummaryMessage(tbody, 8, 'No current results');
      touchOverviewTs();
      return;
    }

    const frag = document.createDocumentFragment();
    domains.forEach(d=>{
      const info = resultsAgg[d] || {};
      const values = Array.isArray(info.values) ? info.values : [];
      const decodedIps = Array.isArray(info.decoded_ips) ? info.decoded_ips : [];
      const servers = Array.isArray(info.servers) ? info.servers : [];
      const recordTypes = Array.isArray(info.record_types) ? info.record_types.map(x=>String(x || '').toUpperCase()) : [];
      const rowType = String(info.type || 'A').toUpperCase();
      const hasTxt = rowType === 'TXT' || rowType === 'MIXED' || recordTypes.includes('TXT');

      const tr = document.createElement('tr');
      tr.dataset.domain = d;

      const tdDomain = document.createElement('td');
      tdDomain.textContent = d;
      applyNxdomainLifecycleStyle(tdDomain, domainMeta[d], d);

      const tdType = document.createElement('td');
      tdType.textContent = rowType;

      const tdVals = document.createElement('td');
      renderCellWithClickableIps(tdVals, values, formatListPreview(values, 4), 10);

      const tdDecoded = document.createElement('td');
      renderCellWithClickableIps(tdDecoded, decodedIps, formatListPreview(decodedIps, 4), 10);

      const tdMethod = document.createElement('td');
      tdMethod.className = 'wrap-cell';
      const methodSummary = String(info.method_summary || '').trim();
      tdMethod.textContent = methodSummary || '-';
      tdMethod.title = methodSummary || '-';

      const tdServers = document.createElement('td');
      tdServers.className = 'wrap-cell';
      tdServers.textContent = formatDnsServerSummary(servers);
      tdServers.title = servers.join(', ');

      const tdTs = document.createElement('td');
      tdTs.textContent = formatUnixTsLocal(info.ts);

      const tdActions = document.createElement('td');

      const histBtn = document.createElement('button');
      histBtn.className = 'action-btn';
      histBtn.textContent = 'History';
      histBtn.title = 'View history for this domain';
      histBtn.onclick = ()=> loadHistory(d);
      tdActions.appendChild(histBtn);

      if(hasTxt){
        const sampleTxt = Array.from(new Set(values.map(v=>String(v || '').trim()).filter(Boolean))).slice(0, 20).join('|');

        const analyzeBtn = document.createElement('button');
        analyzeBtn.className = 'action-btn';
        analyzeBtn.textContent = 'Analyze';
        analyzeBtn.title = 'Analyze TXT decoding methods';
        analyzeBtn.onclick = async ()=>{
          try{
            const rr = await fetch('/analyze', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({domain: d, txt: sampleTxt})
            });
            const jj = await rr.json();
            renderAnalyzeResult(jj);
          }catch(e){
            document.getElementById('analyzeResult').textContent = 'Analyze error: ' + e;
          }
        };
        tdActions.appendChild(analyzeBtn);

        const verifyBtn = document.createElement('button');
        verifyBtn.className = 'action-btn';
        verifyBtn.textContent = 'Verify';
        verifyBtn.title = 'Verify this domain\'s TXT records';
        verifyBtn.onclick = async ()=>{
          const next = tr.nextElementSibling;
          if(next && next.classList && next.classList.contains('verify-row') && next.dataset && next.dataset.domain === d){
            next.remove();
            return;
          }
          const vtr = document.createElement('tr');
          vtr.className = 'verify-row';
          vtr.dataset.domain = d;
          const vtd = document.createElement('td');
          vtd.colSpan = 8;
          vtd.textContent = 'Verifying ' + d + '...';
          vtr.appendChild(vtd);
          tr.parentNode.insertBefore(vtr, tr.nextSibling);
          try{
            const vr = await fetch('/verify', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({domains: [d]})
            });
            const vj = await vr.json();
            vtd.innerHTML = '';
            if(vj && vj.results && vj.results[d]){
              const data = vj.results[d];
              if(data.error){
                vtd.textContent = 'Error: ' + data.error;
              } else {
                const analysis = data.analysis || {};
                const keys = Object.keys(analysis).sort((a, b)=>(analysis[b].score || 0) - (analysis[a].score || 0));
                keys.forEach(k=>{
                  const infoRow = analysis[k];
                  const h = document.createElement('div');
                  h.style.fontWeight = '600';
                  h.style.marginTop = '10px';
                  h.textContent = `${k} — score=${infoRow.score} raw=${infoRow.raw_count}`;
                  vtd.appendChild(h);
                  const ips = infoRow.detailed_ips || [];
                  if(!ips.length){
                    const none = document.createElement('div');
                    none.textContent = 'No decoded IPs';
                    vtd.appendChild(none);
                  } else {
                    const tbl = document.createElement('table');
                    tbl.style.width = '100%';
                    tbl.style.marginTop = '6px';
                    const thr = document.createElement('tr');
                    thr.innerHTML = '<th>IP</th><th>Valid</th><th>VT(malicious/suspicious)</th><th>Summary</th>';
                    tbl.appendChild(thr);
                    ips.forEach(it=>{
                      const trr = document.createElement('tr');
                      const tdIp = document.createElement('td');
                      tdIp.textContent = it.ip || '';
                      const tdV = document.createElement('td');
                      tdV.textContent = it.valid ? 'YES' : 'NO';
                      const tdVT = document.createElement('td');
                      const tdSum = document.createElement('td');
                      if(it.vt){
                        tdVT.textContent = `${it.vt.malicious || 0}/${it.vt.suspicious || 0}`;
                        tdSum.textContent = `ASN:${it.vt.asn || ''} ${it.vt.country || ''}`;
                      } else {
                        tdVT.textContent = '-';
                        tdSum.textContent = '-';
                      }
                      trr.appendChild(tdIp);
                      trr.appendChild(tdV);
                      trr.appendChild(tdVT);
                      trr.appendChild(tdSum);
                      tbl.appendChild(trr);
                    });
                    vtd.appendChild(tbl);
                  }
                });
              }
            } else {
              vtd.textContent = 'No data returned';
            }
          }catch(e){
            vtd.textContent = 'Verify error: ' + e;
          }
        };
        tdActions.appendChild(verifyBtn);
      }

      tr.appendChild(tdDomain);
      tr.appendChild(tdType);
      tr.appendChild(tdVals);
      tr.appendChild(tdDecoded);
      tr.appendChild(tdMethod);
      tr.appendChild(tdServers);
      tr.appendChild(tdTs);
      tr.appendChild(tdActions);
      frag.appendChild(tr);
    });

    tbody.appendChild(frag);
    touchOverviewTs();
  }catch(e){
    console.log('refresh error', e);
  }finally{
    refreshResultsInFlight = false;
  }
}

async function loadHistory(domain){
  try{
    const r = await fetch('/history?domain='+encodeURIComponent(domain));
    if(!r.ok) { log('history load failed'); return; }
    const j = await r.json();
    const el = document.getElementById('historyBox');
    // j.history is in the format { meta: {...}, events: [...], current: {...} }
    const hist = j.history || {};
    const events = hist.events || [];
    const meta = hist.meta || {};
    
    if(!events || events.length === 0) {
      el.textContent = 'No history for ' + domain + 
        (meta.first_seen ? '\nFirst seen: ' + formatUnixTsLocal(meta.first_seen) : '') +
        (meta.last_changed ? '\nLast changed: ' + formatUnixTsLocal(meta.last_changed) : '');
      return;
    }
    
    const lines = ['History for ' + domain];
    if(meta.first_seen) lines.push('First seen: ' + formatUnixTsLocal(meta.first_seen));
    if(meta.last_changed) lines.push('Last changed: ' + formatUnixTsLocal(meta.last_changed));
    lines.push('---');
    
    events.forEach(h=>{
      const t = formatUnixTsLocal(h.ts);
      if(h.new && h.old){
        lines.push(`${t} [${h.server}] (${h.type}) ${ (h.old.values||[]).join(',') } -> ${ (h.new.values||[]).join(',') }`);
      } else if(h.values){
        lines.push(`${t} [${h.server}] (${h.type}) ${ (h.values||[]).join(',') }`);
      } else {
        lines.push(JSON.stringify(h));
      }
    });
    el.textContent = lines.join('\n');
  }catch(e){ log('history error:'+e); }
}

document.getElementById('doQuery').onclick = async ()=>{
  const v = document.getElementById('queryValue').value.trim();
  await runQuery(v);
};

// All IPs pagination state
let ipsOffset = 0;

function getIpsPageSize(){
  const el = document.getElementById('ips_page_size');
  const n = parseBoundedInt(el ? el.value : 200, 200, 50, 5000);
  return n;
}

function updateIpsMeta(j){
  const el = document.getElementById('ips_meta');
  if(!el) return;
  if(!j){ el.textContent = '-'; return; }
  const total = Number(j.ips_total_count || 0);
  const shown = Number(j.ips_displayed_count || 0);
  const offset = Number(j.ips_offset || 0);
  const limit = Number(j.ips_limit || 0);
  const includeVT = !!j.include_vt;
  const vtBudget = Number(j.vt_budget || 0);
  const vtWorkers = Number(j.vt_workers || 0);
  const start = total ? (offset + 1) : 0;
  const end = Math.min(total, offset + shown);
  let txt = `showing ${start}-${end} / total ${total}`;
  if(includeVT) txt += ` / VT page budget ${vtBudget} (workers ${vtWorkers})`;
  el.textContent = txt;
}

async function refreshIPs(){
  if(refreshIPsInFlight) return;
  refreshIPsInFlight = true;
  try{
    const includeVT = !!(document.getElementById('ips_include_vt') && document.getElementById('ips_include_vt').checked);
    const limit = getIpsPageSize();
    const vtWorkers = parseBoundedInt((document.getElementById('ips_vt_workers') || {}).value, 8, 1, 32);
    const vtBudget = parseBoundedInt((document.getElementById('ips_vt_budget') || {}).value, limit, 0, 5000);

    const params = new URLSearchParams();
    params.set('limit', String(limit));
    params.set('offset', String(Math.max(0, ipsOffset)));
    if(includeVT) params.set('include_vt', '1');
    if(includeVT){
      params.set('vt_workers', String(vtWorkers));
      params.set('vt_budget', String(vtBudget));
    }

    const r = await fetch('/ips?' + params.toString());
    if(!r.ok) {
      console.error('refreshIPs: HTTP error', r.status);
      return;
    }
    const j = await r.json();
    const tbody = document.querySelector('#ipsTable tbody');
    const arr = j.ips || [];
    if(!Array.isArray(arr)) {
      console.error('refreshIPs: ips is not an array', arr);
      return;
    }

    // overview counts should reflect total, not just the current page
    uiOverview.allIps = Number(j.ips_total_count || arr.length || 0);
    uiOverview.validIps = null; // unknown without full set
    updateOverviewPanel();

    const fp = `vt:${includeVT ? 1 : 0}|off:${ipsOffset}|lim:${getIpsPageSize()}|${buildIpsFingerprint(arr)}`;
    if(fp === lastAllIpsRenderFingerprint){
      updateIpsMeta(j);
      touchOverviewTs();
      return;
    }
    lastAllIpsRenderFingerprint = fp;

    tbody.innerHTML = '';
    arr.forEach(it=>{
      if(typeof it !== 'object') return;
      const tr = document.createElement('tr');
      const tdIp = document.createElement('td');
      tdIp.textContent = it.ip || '';
      if(isIPv4(it.ip)){
        tdIp.style.cursor = 'pointer';
        tdIp.title = 'Open in Query';
        tdIp.onclick = ()=> openQueryForValue(it.ip);
      }

      const tdDomains = document.createElement('td');
      const domains = Array.isArray(it.domains) ? it.domains : [];
      tdDomains.textContent = domains.join(', ');
      tdDomains.title = domains.join(', ');

      const tdCount = document.createElement('td'); tdCount.textContent = it.count || 0;
      const tdTs = document.createElement('td'); tdTs.textContent = formatUnixTsLocal(it.last_ts);
      const tdVtScore = document.createElement('td');
      const tdVtCtx = document.createElement('td');
      const vt = it.vt || null;
      if(vt){
        const m = Number(vt.malicious || 0);
        const s = Number(vt.suspicious || 0);
        const badge = document.createElement('span');
        badge.className = 'vt-badge';
        if(m > 0) badge.classList.add('high');
        else if(s > 0) badge.classList.add('mid');
        badge.textContent = `${m}/${s}`;
        tdVtScore.appendChild(badge);
        tdVtCtx.textContent = `ASN:${vt.asn || '-'} ${vt.country || '-'}`;
      } else {
        tdVtScore.textContent = includeVT ? '-' : 'off';
        tdVtCtx.textContent = includeVT ? '-' : 'VT disabled';
      }

      tr.appendChild(tdIp);
      tr.appendChild(tdDomains);
      tr.appendChild(tdCount);
      tr.appendChild(tdTs);
      tr.appendChild(tdVtScore);
      tr.appendChild(tdVtCtx);
      tbody.appendChild(tr);
    });

    // enable/disable paging buttons
    const total = Number(j.ips_total_count || 0);
    const prevBtn = document.getElementById('ips_prev_btn');
    const nextBtn = document.getElementById('ips_next_btn');
    if(prevBtn) prevBtn.disabled = ipsOffset <= 0;
    if(nextBtn) nextBtn.disabled = (ipsOffset + arr.length) >= total;

    updateIpsMeta(j);
    touchOverviewTs();
  }catch(e){ console.log('refreshIPs error', e); }
  finally{ refreshIPsInFlight = false; }
}

function renderAnalyzeResult(j){
  const el = document.getElementById('analyzeResult');
  el.innerHTML = '';
  if(!j || j.error){ el.textContent = j && j.error ? 'Error: '+j.error : 'No result'; return; }
  const analysis = j.analysis || {};
  const keys = Object.keys(analysis);
  if(keys.length === 0){ el.textContent = 'No matching decoders'; return; }
  // find best
  let best = null; let bestScore = -999;
  keys.forEach(k=>{ const s = analysis[k].score || 0; if(s>bestScore){ bestScore=s; best=k; } });

  const title = document.createElement('div'); title.textContent = `Recommendation: ${best} (score=${analysis[best].score})`; title.style.fontWeight='bold'; title.style.marginBottom='6px';
  el.appendChild(title);

  keys.sort((a,b)=> (analysis[b].score||0) - (analysis[a].score||0));
  keys.forEach(k=>{
    const info = analysis[k];
    const box = document.createElement('div');
    box.style.borderBottom='1px solid #eee'; box.style.padding='6px 0';
    if(k===best) box.style.background='#fff7e6';
    const h = document.createElement('div'); h.textContent = `${k} — score=${info.score} raw_count=${info.raw_count}`;
    h.style.fontWeight = (k===best)?'700':'400';
    const ips = document.createElement('div'); ips.textContent = 'ips: ' + (info.ips||[]).join(', ');
    ips.style.marginTop='4px';
    box.appendChild(h); box.appendChild(ips);
    el.appendChild(box);
  });
}

async function refreshValidIPs(){
  if(refreshValidIPsInFlight) return;
  refreshValidIPsInFlight = true;
  try{
    const r = await fetch('/ips');
    if(!r.ok){ console.error('refreshValidIPs HTTP', r.status); return; }
    const j = await r.json();
    const tbody = document.querySelector('#validIpsTable tbody');
    const arr = j.ips || [];
    if(!Array.isArray(arr)) return;
    // display only syntactically valid IPs (backend also provides 'valid')
    const validOnly = arr.filter(it => it && it.valid);
    const fp = `valid|${buildIpsFingerprint(validOnly)}`;
    uiOverview.allIps = arr.length;
    uiOverview.validIps = validOnly.length;
    updateOverviewPanel();
    if(fp === lastValidIpsRenderFingerprint){
      touchOverviewTs();
      return;
    }
    lastValidIpsRenderFingerprint = fp;
    tbody.innerHTML = '';
    validOnly.forEach(it=>{
      const tr = document.createElement('tr');
      const tdIp = document.createElement('td');
      tdIp.textContent = it.ip || '';
      if(isIPv4(it.ip)){
        tdIp.style.cursor = 'pointer';
        tdIp.title = 'Open in Query';
        tdIp.onclick = ()=> openQueryForValue(it.ip);
      }
      const tdDomains = document.createElement('td'); tdDomains.textContent = (it.domains||[]).join(', ');
      const tdCount = document.createElement('td'); tdCount.textContent = it.count || 0;
      const tdTs = document.createElement('td'); tdTs.textContent = formatUnixTsLocal(it.last_ts);
      const tdValid = document.createElement('td'); tdValid.textContent = it.valid ? 'YES' : 'NO';
      tr.appendChild(tdIp); tr.appendChild(tdDomains); tr.appendChild(tdCount); tr.appendChild(tdTs); tr.appendChild(tdValid);
      tbody.appendChild(tr);
    });
    touchOverviewTs();
  }catch(e){ console.log('refreshValidIPs error', e); }
  finally{ refreshValidIPsInFlight = false; }
}

  // Auto-refresh control
  let manualPause = false; // user toggled pause
  let hoverPause = false;  // temporary pause while hovering over results

  function isPaused(){ return manualPause || hoverPause; }
  function updateRefreshStateBadge(){
    const el = document.getElementById('refreshState');
    if(!el) return;
    if(manualPause){
      el.textContent = 'Auto-refresh paused';
      el.classList.add('is-paused');
    } else if(hoverPause){
      el.textContent = 'Inspect mode (hover pause)';
      el.classList.add('is-paused');
    } else {
      el.textContent = 'Auto-refresh active';
      el.classList.remove('is-paused');
    }
  }

  document.getElementById('pauseRefreshBtn').onclick = function(){
    manualPause = !manualPause;
    this.textContent = manualPause ? '▶ Resume Auto-Refresh' : '⏸ Pause Auto-Refresh';
    updateRefreshStateBadge();
    if(!manualPause){ triggerSectionRefresh(getActiveSectionId()); }
  };

  // All IPs paging controls
  const ipsPrevBtn = document.getElementById('ips_prev_btn');
  const ipsNextBtn = document.getElementById('ips_next_btn');
  const ipsRefreshBtn = document.getElementById('ips_refresh_btn');
  const ipsPageSize = document.getElementById('ips_page_size');
  if(ipsPrevBtn){
    ipsPrevBtn.onclick = ()=>{
      ipsOffset = Math.max(0, ipsOffset - getIpsPageSize());
      refreshIPs();
    };
  }
  if(ipsNextBtn){
    ipsNextBtn.onclick = ()=>{
      ipsOffset = ipsOffset + getIpsPageSize();
      refreshIPs();
    };
  }
  if(ipsRefreshBtn){
    ipsRefreshBtn.onclick = ()=> refreshIPs();
  }
  if(ipsPageSize){
    ipsPageSize.onchange = ()=>{
      ipsOffset = 0;
      refreshIPs();
    };
  }

  // pause when user hovers results table to allow inspection of long URLs
  const resultsTable = document.getElementById('resultsTable');
  resultsTable.addEventListener('mouseenter', ()=>{ hoverPause = true; updateRefreshStateBadge(); });
  resultsTable.addEventListener('mouseleave', ()=>{ hoverPause = false; updateRefreshStateBadge(); });

  // periodic refresh — only refresh active sections to reduce UI/backend load.
  setInterval(()=>{
    if(isPaused()) return;
    if(getActiveSectionId() === 'status') refreshResults();
  }, 7000);
  setInterval(()=>{
    if(isPaused()) return;
    if(getActiveSectionId() === 'ips') refreshIPs();
  }, 12000);
  setInterval(()=>{
    if(isPaused()) return;
    if(getActiveSectionId() === 'validips'){
      const s = parseInt((document.getElementById('valid_since') || {}).value, 10) || 0;
      refreshValidIPs(s);
    }
  }, 15000);
  setInterval(()=>{
    if(isPaused()) return;
    const sec = document.getElementById('domainanalysis');
    if(!sec) return;
    if(sec.classList.contains('active')) refreshDomainAnalysis();
  }, 10000);

// initialize dynamic decoders and valid IPs refresh hook
window.addEventListener('load', ()=>{
  updateRefreshStateBadge();
  updateOverviewPanel();
  const openAlertsSettings = (window.location.hash || '').toLowerCase() === '#settings-alerts';
  
  // Initialize sections
  try {
    showSection(openAlertsSettings ? 'settings' : 'status');
  } catch(e) {
    console.error('Failed to show settings section:', e);
  }
  
  try {
    showSettingsTab(openAlertsSettings ? 'alerts' : 'domains');
  } catch(e) {
    console.error('Failed to show settings tab:', e);
  }
  
  loadAlertSettings();

  const verifyTypeEl = document.getElementById('verifyDomainType');
  if(verifyTypeEl){
    verifyTypeEl.addEventListener('change', ()=> updateDomainVerifyInputMode());
  }
  const runDomainVerifyBtn = document.getElementById('runDomainVerifyBtn');
  if(runDomainVerifyBtn){
    runDomainVerifyBtn.addEventListener('click', ()=> runDomainVerify());
  }
  const addVerifiedDomainBtn = document.getElementById('addVerifiedDomainBtn');
  if(addVerifiedDomainBtn){
    addVerifiedDomainBtn.addEventListener('click', ()=> addVerifiedDomainToConfig());
  }
  const clearDomainVerifyBtn = document.getElementById('clearDomainVerifyBtn');
  if(clearDomainVerifyBtn){
    clearDomainVerifyBtn.addEventListener('click', ()=>{
      const domainEl = document.getElementById('verifyDomainName');
      const typeEl = document.getElementById('verifyDomainType');
      const txtEl = document.getElementById('verifyTxtDecode');
      const aEl = document.getElementById('verifyADecode');
      const keyEl = document.getElementById('verifyAXorKey');
      const ensKeyEl = document.getElementById('verifyEnsTextKey');
      const ensDecodeEl = document.getElementById('verifyEnsDecode');
      const ensOptionsEl = document.getElementById('verifyEnsOptions');
      const includeVtEl = document.getElementById('verifyIncludeVt');
      if(domainEl) domainEl.value = '';
      if(typeEl) typeEl.value = 'AUTO';
      if(txtEl && includeOption(txtEl, 'cafebabe_xor_base64')) txtEl.value = 'cafebabe_xor_base64';
      if(aEl && includeOption(aEl, 'none')) aEl.value = 'none';
      if(keyEl) keyEl.value = '';
      if(ensKeyEl) ensKeyEl.value = 'ipv6';
      if(ensDecodeEl && includeOption(ensDecodeEl, 'ipv6_5to8_xor')) ensDecodeEl.value = 'ipv6_5to8_xor';
      if(ensOptionsEl) ensOptionsEl.value = '';
      if(includeVtEl) includeVtEl.checked = true;
      updateDomainVerifyInputMode();
      clearDomainVerifyResult();
    });
  }
  
  document.getElementById('refreshValidBtn').onclick = ()=>{
    const s = parseInt(document.getElementById('valid_since').value) || 0;
    refreshValidIPs(s);
  };
  const includeVtEl = document.getElementById('ips_include_vt');
  if(includeVtEl){
    includeVtEl.addEventListener('change', ()=>{ refreshIPs(); });
  }
  const domainAnalysisRefreshBtn = document.getElementById('refreshDomainAnalysisBtn');
  if(domainAnalysisRefreshBtn){
    domainAnalysisRefreshBtn.addEventListener('click', ()=> refreshDomainAnalysis());
  }
  const includeDomainVtEl = document.getElementById('domain_analysis_include_vt');
  if(includeDomainVtEl){
    includeDomainVtEl.addEventListener('change', ()=> refreshDomainAnalysis());
  }
  const domainFilterEl = document.getElementById('domainAnalysisDomainSelect');
  if(domainFilterEl){
    domainFilterEl.addEventListener('change', ()=> applyDomainAnalysisFilter());
  }
  const clearDomainFilterBtn = document.getElementById('clearDomainAnalysisFilterBtn');
  if(clearDomainFilterBtn){
    clearDomainFilterBtn.addEventListener('click', ()=>{
      const sel = document.getElementById('domainAnalysisDomainSelect');
      if(sel) sel.value = '';
      applyDomainAnalysisFilter();
    });
  }
  const selectNonResolvingBtn = document.getElementById('selectNonResolvingDomainsBtn');
  if(selectNonResolvingBtn){
    selectNonResolvingBtn.addEventListener('click', ()=> selectNonResolvingDomainsForBulk());
  }
  const clearSelectedDomainsBtn = document.getElementById('clearSelectedDomainsBtn');
  if(clearSelectedDomainsBtn){
    clearSelectedDomainsBtn.addEventListener('click', ()=> clearSelectedDomainsForBulk());
  }
  const removeSelectedDomainsBtn = document.getElementById('removeSelectedDomainsBtn');
  if(removeSelectedDomainsBtn){
    removeSelectedDomainsBtn.addEventListener('click', ()=> removeSelectedNonResolvingDomains());
  }
  const runIpIntelBtn = document.getElementById('runIpIntelBtn');
  if(runIpIntelBtn){
    runIpIntelBtn.addEventListener('click', ()=> analyzeIpIntel());
  }
  const runIpRelBtn = document.getElementById('runIpRelationshipBtn');
  if(runIpRelBtn){
    runIpRelBtn.addEventListener('click', ()=> analyzeIpRelationships());
  }
  const ipIntelInputEl = document.getElementById('ipIntelInput');
  if(ipIntelInputEl){
    ipIntelInputEl.addEventListener('input', ()=> renderMergedIpIntelHints());
  }
  renderMergedIpIntelHints();
  const loadIpIntelMispBtn = document.getElementById('loadIpIntelMispBtn');
  if(loadIpIntelMispBtn){
    loadIpIntelMispBtn.addEventListener('click', ()=> loadIpIntelFromMisp(true));
  }
  // custom decoder UI handlers
  function getCustomDecoderType(){
    return String((document.getElementById('custom_decoder_type') || {}).value || 'TXT').toUpperCase();
  }
  function refreshCustomSampleLabel(){
    const typ = getCustomDecoderType();
    const label = document.getElementById('custom_sample_label');
    const sample = document.getElementById('custom_sample');
    if(!label || !sample) return;
    if(typ === 'A'){
      label.firstChild.textContent = 'Sample A value (for preview) ';
      sample.placeholder = '104.132.5.177';
    } else {
      label.firstChild.textContent = 'Sample TXT (for preview) ';
      sample.placeholder = 'example sample txt';
    }
  }
  const customTypeEl = document.getElementById('custom_decoder_type');
  if(customTypeEl){
    customTypeEl.addEventListener('change', refreshCustomSampleLabel);
  }
  refreshCustomSampleLabel();

  function renderCustomList(){
    const el = document.getElementById('customList'); el.innerHTML='';
    const txtArr = (window.CUSTOM_DECODERS || []).map(c=>({...(c||{}), decoder_type: 'TXT'}));
    const aArr = (window.CUSTOM_A_DECODERS || []).map(c=>({...(c||{}), decoder_type: 'A'}));
    const arr = txtArr.concat(aArr);
    if(!arr.length){ el.textContent = 'No custom decoders registered'; return; }
    arr.forEach(c=>{
      const row = document.createElement('div'); row.style.borderBottom='1px solid #eee'; row.style.padding='6px 0';
      const dtype = String(c.decoder_type || 'TXT').toUpperCase();
      const title = document.createElement('div'); title.textContent = `${c.name} [${dtype}]`; title.style.fontWeight='700'; row.appendChild(title);
      const btnRow = document.createElement('div'); btnRow.style.marginTop='6px';
      const edit = document.createElement('button'); edit.textContent='Edit'; edit.onclick = ()=>{
        document.getElementById('custom_name').value = c.name; document.getElementById('custom_name').disabled = true;
        document.getElementById('custom_decoder_type').value = dtype;
        refreshCustomSampleLabel();
        document.getElementById('custom_steps').value = JSON.stringify(c.steps, null, 2);
        document.getElementById('customPreviewResult').textContent = `Editing ${c.name} [${dtype}] — change steps and click Update`;
      };
      const del = document.createElement('button'); del.textContent='Delete'; del.onclick = async ()=>{
        if(!confirm(`Delete decoder ${c.name} [${dtype}] ?`)) return;
        try{
          const r = await fetch('/decoders/custom',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:c.name, decoder_type:dtype})});
          const j = await r.json();
          if(j && j.status === 'ok'){ document.getElementById('customPreviewResult').textContent = `Deleted ${c.name} [${dtype}]`; await loadDecoders(); renderCustomList(); loadCfg(); }
          else { document.getElementById('customPreviewResult').textContent = 'Delete failed: '+JSON.stringify(j); }
        }catch(e){ document.getElementById('customPreviewResult').textContent = 'Delete error: '+e; }
      };
      const upd = document.createElement('button'); upd.textContent='Update'; upd.onclick = async ()=>{
        const stepsRaw = document.getElementById('custom_steps').value.trim(); let steps;
        try{ steps = JSON.parse(stepsRaw); }catch(e){ alert('Invalid JSON: '+e); return; }
        try{
          const r = await fetch('/decoders/custom',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:c.name,steps:steps, decoder_type:dtype})});
          const j = await r.json();
          if(j && j.status === 'ok'){ document.getElementById('customPreviewResult').textContent = `Updated ${c.name} [${dtype}]`; await loadDecoders(); renderCustomList(); loadCfg(); document.getElementById('custom_name').disabled = false; }
          else { document.getElementById('customPreviewResult').textContent = 'Update failed: '+JSON.stringify(j); }
        }catch(e){ document.getElementById('customPreviewResult').textContent = 'Update error: '+e; }
      };
      btnRow.appendChild(edit); btnRow.appendChild(upd); btnRow.appendChild(del); row.appendChild(btnRow);
      el.appendChild(row);
    });
  }
  async function refreshCustomDecoders(){
    try{
      await loadDecoders();
    }catch(e){
      // ignore and render whatever cache exists
    }
    renderCustomList();
  }
  window.refreshCustomDecoders = refreshCustomDecoders;

  document.getElementById('previewCustom').onclick = async ()=>{
    const stepsRaw = document.getElementById('custom_steps').value.trim();
    const sample = document.getElementById('custom_sample').value;
    const decoderType = getCustomDecoderType();
    let steps;
    try{ steps = JSON.parse(stepsRaw); }catch(e){ document.getElementById('customPreviewResult').textContent = 'Invalid JSON: '+e; return; }
    try{
      const r = await fetch('/decoders/custom/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({steps: steps, sample: sample, decoder_type: decoderType})});
      const j = await r.json();
      document.getElementById('customPreviewResult').textContent = JSON.stringify(j, null, 2);
    }catch(e){ document.getElementById('customPreviewResult').textContent = 'Preview error: '+e; }
  };

  document.getElementById('registerCustom').onclick = async ()=>{
    const name = document.getElementById('custom_name').value.trim();
    const decoderType = getCustomDecoderType();
    const stepsRaw = document.getElementById('custom_steps').value.trim();
    if(!name){ alert('Provide a name'); return; }
    let steps;
    try{ steps = JSON.parse(stepsRaw); }catch(e){ alert('Invalid JSON steps: '+e); return; }
    try{
      const r = await fetch('/decoders/custom',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name: name, steps: steps, decoder_type: decoderType})});
      const j = await r.json();
      if(j && j.status === 'ok'){
        document.getElementById('customPreviewResult').textContent = `Registered: ${name} [${decoderType}]`;
        // reload decoders and UI
        await loadDecoders();
        renderCustomList();
        loadCfg();
      } else {
        document.getElementById('customPreviewResult').textContent = 'Register failed: '+JSON.stringify(j);
      }
    }catch(e){ document.getElementById('customPreviewResult').textContent = 'Register error: '+e; }
  };
  document.getElementById('clearCustom').onclick = ()=>{
    document.getElementById('custom_name').value='';
    document.getElementById('custom_decoder_type').value='TXT';
    document.getElementById('custom_steps').value='';
    document.getElementById('custom_sample').value='';
    document.getElementById('custom_name').disabled = false;
    document.getElementById('customPreviewResult').textContent='';
    refreshCustomSampleLabel();
  };
  // initialize decoder cache, custom list, and domain rows in correct order
  initDomainVerifyUi();
  refreshCustomDecoders().then(()=>{
    initDomainVerifyUi();
    loadCfg();
  });
});

// --- Relationship analysis (Similarity, input IP list) ---
// Phase 1: score+evidence based similarity pairs + clustering
// Phase 2: IP-IP graph visualization (Cytoscape)
// Phase 3: Country bubble map (Leaflet)
window.IP_REL_CACHE = window.IP_REL_CACHE || null;
window.IP_REL_GRAPH = window.IP_REL_GRAPH || null;
window.IP_REL_MAP = window.IP_REL_MAP || null;
window.IP_REL_MAP_MARKERS = window.IP_REL_MAP_MARKERS || [];
window.IP_REL_MAP_SVG = window.IP_REL_MAP_SVG || null;
const IP_REL_CUSTOM_PROFILE_STORAGE_KEY = 'tracedns.iprel.custom_profile.v1';
const IP_REL_SELECTED_PROFILE_STORAGE_KEY = 'tracedns.iprel.selected_profile.v1';

function safeLocalStorageGet(key){
  try{
    return localStorage.getItem(String(key || ''));
  }catch(e){
    return null;
  }
}

function safeLocalStorageSet(key, value){
  try{
    localStorage.setItem(String(key || ''), String(value || ''));
    return true;
  }catch(e){
    return false;
  }
}

function setIpRelView(name){
  const table = document.getElementById('ipRelTableView');
  const graph = document.getElementById('ipRelGraphView');
  const map = document.getElementById('ipRelMapView');
  if(table) table.style.display = (name === 'table') ? '' : 'none';
  if(graph) graph.style.display = (name === 'graph') ? '' : 'none';
  if(map) map.style.display = (name === 'map') ? '' : 'none';

  const b1 = document.getElementById('ipRelViewTableBtn');
  const b2 = document.getElementById('ipRelViewGraphBtn');
  const b3 = document.getElementById('ipRelViewMapBtn');
  if(b1) b1.classList.toggle('active', name === 'table');
  if(b2) b2.classList.toggle('active', name === 'graph');
  if(b3) b3.classList.toggle('active', name === 'map');

  // Lazy render visualizations from last cache
  if(name === 'graph') renderIpRelGraphFromCache();
  if(name === 'map') renderIpRelMapFromCache();
}

function summarizeEvidence(evList){
  const ev = Array.isArray(evList) ? evList : [];
  if(!ev.length) return '-';
  // compact summary for high-signal triage
  const parts = [];
  ev.forEach(e=>{
    const t = String((e && e.type) || '').trim();
    const v = (e && e.value != null) ? String(e.value) : '';
    if(!t) return;
    if(t === 'same_asn') parts.push(`ASN:${v}`);
    else if(t === 'same_owner') parts.push('Owner');
    else if(t === 'same_csp') parts.push(`CSP:${v}`);
    else if(t === 'same_country') parts.push(`C:${v}`);
    else if(t === 'same_network_exact') parts.push('NET');
    else if(t === 'same_network_overlap') parts.push('NET~');
    else if(t === 'same_jarm') parts.push('JARM');
    else if(t === 'same_cert_sha256') parts.push('CERT');
    else if(t === 'same_rdap_name') parts.push('RDAP');
    else if(t === 'same_rdap_type') parts.push('RDAP-T');
    else if(t === 'same_rir') parts.push('RIR');
    else if(t === 'same_prefix24') parts.push('/24');
    else if(t === 'vt_detector_overlap') parts.push('VT:ENG');
    else if(t === 'vt_time_proximity') parts.push('VT:TIME');
    else if(t === 'vt_malicious_both') parts.push('VT:M');
    else if(t === 'vt_suspicious_both') parts.push('VT:S');
  });
  return parts.length ? parts.join(' + ') : '-';
}

function evidenceTypeLabel(t){
  const k = String(t || '').trim();
  if(k === 'same_asn') return 'Same ASN';
  if(k === 'same_owner') return 'Same Owner';
  if(k === 'same_csp') return 'Same CSP';
  if(k === 'same_country') return 'Same Country';
  if(k === 'same_network_exact') return 'Same Network';
  if(k === 'same_network_overlap') return 'Network Overlap';
  if(k === 'same_jarm') return 'Same JARM';
  if(k === 'same_cert_sha256') return 'Same Cert SHA256';
  if(k === 'same_rdap_name') return 'Same RDAP Name';
  if(k === 'same_rdap_type') return 'Same RDAP Type';
  if(k === 'same_rir') return 'Same RIR';
  if(k === 'same_prefix24') return 'Same /24';
  if(k === 'vt_detector_overlap') return 'VT Engine Overlap';
  if(k === 'vt_time_proximity') return 'VT Time Proximity';
  if(k === 'vt_malicious_both') return 'VT Malicious Both';
  if(k === 'vt_suspicious_both') return 'VT Suspicious Both';
  return k || 'Evidence';
}

function formatEvidenceDetails(evList){
  const ev = Array.isArray(evList) ? evList : [];
  if(!ev.length) return '-';
  const parts = [];
  ev.forEach(e=>{
    if(!e) return;
    const t = evidenceTypeLabel(e.type);
    const w = Number(e.weight || 0);
    const v = (e.value == null) ? '' : String(e.value).trim();
    let txt = w > 0 ? `${t}[${w}]` : t;
    if(v) txt += ` ${v}`;
    parts.push(txt);
  });
  return parts.length ? parts.join(' | ') : '-';
}

function getIpFeature(ip){
  const cache = window.IP_REL_CACHE;
  if(!cache || !cache.ip_features) return null;
  return cache.ip_features[ip] || null;
}

function getClusterColor(clusterIndex, clusterCount){
  const idx = Math.max(0, Number(clusterIndex || 0));
  const total = Math.max(1, Number(clusterCount || 1));
  const hue = Math.round(((idx % total) * 360) / total);
  return `hsl(${hue}, 66%, 46%)`;
}

function resetIpRelVisualCaches(){
  window.IP_REL_GRAPH_SIGNATURE = '';
  window.IP_REL_MAP_SIGNATURE = '';
  if(window.IP_REL_GRAPH){
    try{ window.IP_REL_GRAPH.destroy(); }catch(e){}
    window.IP_REL_GRAPH = null;
  }
}

function selectIpRelGraphPairs(rawPairs){
  const pairs = (Array.isArray(rawPairs) ? rawPairs : [])
    .filter(p=>p && String(p.a || '').trim() && String(p.b || '').trim())
    .slice()
    .sort((a, b)=>(
      Number((b && b.score) || 0) - Number((a && a.score) || 0)
    ) || String((a && a.a) || '').localeCompare(String((b && b.a) || '')) || String((a && a.b) || '').localeCompare(String((b && b.b) || '')));
  const selected = [];
  const nodesSet = new Set();
  for(const p of pairs){
    const a = String(p.a || '').trim();
    const b = String(p.b || '').trim();
    if(!a || !b || a === b) continue;
    let addCount = 0;
    if(!nodesSet.has(a)) addCount += 1;
    if(!nodesSet.has(b)) addCount += 1;
    if(nodesSet.size + addCount > IP_REL_GRAPH_NODE_RENDER_LIMIT) continue;
    selected.push(p);
    nodesSet.add(a);
    nodesSet.add(b);
    if(selected.length >= IP_REL_GRAPH_EDGE_RENDER_LIMIT) break;
  }
  return {pairs: selected, nodesSet};
}

function buildIpRelGraphSignature(cache, selectedPairs, nodesSet){
  const pairSig = (selectedPairs || []).map(p=>[
    String((p && p.a) || ''),
    String((p && p.b) || ''),
    Number((p && p.score) || 0)
  ].join(':')).join('|');
  return [
    Number((cache && cache.valid_count) || 0),
    Number((cache && cache.pair_count) || 0),
    Number((cache && cache.min_score) || 0),
    Number((cache && cache.top_pairs) || 0),
    (nodesSet && nodesSet.size) || 0,
    (selectedPairs || []).length,
    pairSig
  ].join('#');
}

function renderIpRelGraphFromCache(){
  const cache = window.IP_REL_CACHE;
  const el = document.getElementById('ipRelGraph');
  const details = document.getElementById('ipRelGraphDetails');
  if(!el) return;
  if(!cache || !Array.isArray(cache.pairs)){
    resetIpRelVisualCaches();
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">Run Relationships first.</div>';
    return;
  }
  if(typeof cytoscape !== 'function'){
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">Cytoscape not available (CDN blocked?).</div>';
    return;
  }

  const graphSelection = selectIpRelGraphPairs(cache.pairs || []);
  const pairs = graphSelection.pairs;
  const nodesSet = graphSelection.nodesSet;
  const graphSignature = buildIpRelGraphSignature(cache, pairs, nodesSet);
  const clusters = Array.isArray(cache.clusters) ? cache.clusters : [];
  const minScore = Number(cache.min_score || 40);
  const totalPairs = Array.isArray(cache.pairs) ? cache.pairs.length : 0;
  if(!pairs.length){
    resetIpRelVisualCaches();
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">No pairs available for graph rendering.</div>';
    if(details) details.textContent = `No graphable pairs.\nPairs: ${totalPairs} / MinScore: ${minScore}`;
    return;
  }
  if(window.IP_REL_GRAPH && window.IP_REL_GRAPH_SIGNATURE === graphSignature){
    try{
      window.IP_REL_GRAPH.resize();
      window.IP_REL_GRAPH.fit(undefined, 30);
    }catch(e){}
    if(details){
      const limited = (pairs.length < totalPairs) ? `\nRendered with caps: ${nodesSet.size}/${IP_REL_GRAPH_NODE_RENDER_LIMIT} nodes, ${pairs.length}/${totalPairs} edges.` : '';
      details.textContent = `Click a node/edge to see details.\nClusters: ${clusters.length} / MinScore: ${minScore}${limited}`;
    }
    return;
  }
  const ipToCluster = new Map();
  clusters.forEach((c, idx)=>{
    const ips = Array.isArray(c && c.ips) ? c.ips : [];
    ips.forEach(ip=> ipToCluster.set(String(ip || ''), Number(idx + 1)));
  });
  const degreeMap = {};
  pairs.forEach(p=>{
    const a = String((p && p.a) || '');
    const b = String((p && p.b) || '');
    if(!a || !b) return;
    degreeMap[a] = Number(degreeMap[a] || 0) + 1;
    degreeMap[b] = Number(degreeMap[b] || 0) + 1;
  });

  const elements = [];
  const clusterCount = Math.max(1, clusters.length);
  nodesSet.forEach(ip=>{
    const f = getIpFeature(ip) || {};
    const label = ip;
    const country = String(f.country || '-');
    const asn = String(f.asn || '-');
    const csp = String(f.csp_label || '');
    const clusterIdx = Number(ipToCluster.get(ip) || 0);
    const degree = Number(degreeMap[ip] || 0);
    const nodeColor = clusterIdx > 0 ? getClusterColor(clusterIdx - 1, clusterCount) : '#5e7891';
    const nodeSize = Math.max(18, Math.min(42, 18 + (degree * 2.2)));
    elements.push({ data: { id: ip, label: label, country, asn, csp, cluster_idx: clusterIdx, degree, color: nodeColor, node_size: nodeSize } });
  });
  pairs.forEach((p, idx)=>{
    const a = String(p.a||'');
    const b = String(p.b||'');
    const score = Number(p.score || 0);
    const ca = Number(ipToCluster.get(a) || 0);
    const cb = Number(ipToCluster.get(b) || 0);
    const sameCluster = (ca > 0 && cb > 0 && ca === cb);
    const edgeColor = sameCluster ? getClusterColor(ca - 1, clusterCount) : '#9bb0c4';
    const edgeStyle = score >= minScore ? 'solid' : 'dashed';
    const edgeOpacity = sameCluster ? 0.86 : 0.55;
    elements.push({
      data: {
        id: `e${idx}`,
        source: a,
        target: b,
        score: score,
        evidence: p.evidence || [],
        edge_color: edgeColor,
        edge_style: edgeStyle,
        edge_opacity: edgeOpacity,
        same_cluster: sameCluster ? 1 : 0
      }
    });
  });

  if(window.IP_REL_GRAPH){
    try{ window.IP_REL_GRAPH.destroy(); }catch(e){}
    window.IP_REL_GRAPH = null;
  }

  const layout =
    (nodesSet.size <= IP_REL_GRAPH_COSE_NODE_LIMIT && pairs.length <= IP_REL_GRAPH_COSE_EDGE_LIMIT)
      ? { name: 'cose', animate: false, padding: 30, componentSpacing: 80, nodeRepulsion: 5000 }
      : { name: 'grid', animate: false, fit: true, padding: 30 };

  window.IP_REL_GRAPH = cytoscape({
    container: el,
    elements,
    style: [
      { selector: 'node', style: {
        'label': 'data(label)',
        'font-size': 10,
        'text-valign': 'center',
        'text-halign': 'center',
        'background-color': 'data(color)',
        'color': '#ffffff',
        'width': 'data(node_size)',
        'height': 'data(node_size)'
      }},
      { selector: 'edge', style: {
        'width': 'mapData(score, 0, 100, 1, 6)',
        'line-color': 'data(edge_color)',
        'line-style': 'data(edge_style)',
        'curve-style': 'bezier',
        'opacity': 'data(edge_opacity)'
      }},
      { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#ffb703' } },
      { selector: 'edge:selected', style: { 'line-color': '#ff006e', 'opacity': 1.0 } }
    ],
    layout
  });
  window.IP_REL_GRAPH_SIGNATURE = graphSignature;

  const cy = window.IP_REL_GRAPH;
  if(details){
    const limited = (pairs.length < totalPairs) ? `\nRendered with caps: ${nodesSet.size}/${IP_REL_GRAPH_NODE_RENDER_LIMIT} nodes, ${pairs.length}/${totalPairs} edges.` : '';
    details.textContent = `Click a node/edge to see details.\nClusters: ${clusters.length} / MinScore: ${minScore} / Layout: ${layout.name}${limited}`;
  }

  cy.on('tap', 'node', (evt)=>{
    const d = evt.target.data();
    const f = getIpFeature(d.id) || {};
    const out = {
      type: 'ip',
      ip: d.id,
      country: f.country || '-',
      asn: f.asn || '-',
      as_owner: f.as_owner || '-',
      network: f.network || '-',
      rir: f.rir || '-',
      rdap_name: f.rdap_name || '-',
      rdap_type: f.rdap_type || '-',
      jarm: f.jarm || '-',
      cert_sha256: f.cert_sha256 || '-',
      vt_engine_positive_count: f.vt_engine_positive_count || 0,
      csp: f.csp_label || '-',
      cluster_index: d.cluster_idx || 0,
      degree: d.degree || 0,
      malicious: f.malicious || 0,
      suspicious: f.suspicious || 0
    };
    if(details) details.textContent = JSON.stringify(out, null, 2);
  });

  cy.on('tap', 'edge', (evt)=>{
    const d = evt.target.data();
    const out = {
      type: 'pair',
      a: d.source,
      b: d.target,
      score: d.score,
      same_cluster: !!d.same_cluster,
      evidence: d.evidence || []
    };
    if(details) details.textContent = JSON.stringify(out, null, 2);
  });
}

async function loadCountryCentroids(){
  // Served as a static file (see ALLOWED_STATIC_FILES in server)
  if(window.IP_REL_COUNTRY_CENTROIDS) return window.IP_REL_COUNTRY_CENTROIDS;
  if(window.IP_REL_COUNTRY_CENTROIDS_PROMISE) return window.IP_REL_COUNTRY_CENTROIDS_PROMISE;
  window.IP_REL_COUNTRY_CENTROIDS_PROMISE = (async ()=>{
    try{
      const r = await fetch('/country_centroids.json');
      if(!r.ok){
        window.IP_REL_COUNTRY_CENTROIDS_PROMISE = null;
        return null;
      }
      const j = await r.json();
      window.IP_REL_COUNTRY_CENTROIDS = j;
      return j;
    }catch(e){
      window.IP_REL_COUNTRY_CENTROIDS_PROMISE = null;
      return null;
    }
  })();
  return window.IP_REL_COUNTRY_CENTROIDS_PROMISE;
}

async function loadWorldGeoJson(){
  if(window.IP_REL_WORLD_GEOJSON) return window.IP_REL_WORLD_GEOJSON;
  if(window.IP_REL_WORLD_GEOJSON_PROMISE) return window.IP_REL_WORLD_GEOJSON_PROMISE;
  window.IP_REL_WORLD_GEOJSON_PROMISE = (async ()=>{
    try{
      const r = await fetch('/world_countries_110m.geojson');
      if(!r.ok){
        window.IP_REL_WORLD_GEOJSON_PROMISE = null;
        return null;
      }
      const j = await r.json();
      window.IP_REL_WORLD_GEOJSON = j;
      return j;
    }catch(e){
      window.IP_REL_WORLD_GEOJSON_PROMISE = null;
      return null;
    }
  })();
  return window.IP_REL_WORLD_GEOJSON_PROMISE;
}

function clearIpRelMapMarkers(){
  try{
    (window.IP_REL_MAP_MARKERS || []).forEach(m=>{ try{ m.remove(); }catch(e){} });
  }catch(e){}
  window.IP_REL_MAP_MARKERS = [];
  window.IP_REL_MAP_SVG = null;
  window.IP_REL_MAP_SIGNATURE = '';
}

function projectLatLon(lat, lon, width, height){
  const x = ((lon + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return [x, y];
}

function projectLonLat(lon, lat, width, height){
  return projectLatLon(lat, lon, width, height);
}

function buildSvgMap(el, width, height){
  el.innerHTML = '';
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', '100%');
  svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
  svg.style.display = 'block';

  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  bg.setAttribute('x', '0');
  bg.setAttribute('y', '0');
  bg.setAttribute('width', String(width));
  bg.setAttribute('height', String(height));
  bg.setAttribute('fill', '#f8fbff');
  bg.setAttribute('stroke', '#d7e4eb');
  bg.setAttribute('stroke-width', '1');
  svg.appendChild(bg);

  for(let lon=-180; lon<=180; lon+=60){
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    const x = ((lon + 180) / 360) * width;
    line.setAttribute('x1', String(x));
    line.setAttribute('x2', String(x));
    line.setAttribute('y1', '0');
    line.setAttribute('y2', String(height));
    line.setAttribute('stroke', '#e6eef5');
    line.setAttribute('stroke-width', '1');
    svg.appendChild(line);
  }
  for(let lat=-60; lat<=60; lat+=30){
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    const y = ((90 - lat) / 180) * height;
    line.setAttribute('x1', '0');
    line.setAttribute('x2', String(width));
    line.setAttribute('y1', String(y));
    line.setAttribute('y2', String(y));
    line.setAttribute('stroke', '#e6eef5');
    line.setAttribute('stroke-width', '1');
    svg.appendChild(line);
  }

  el.appendChild(svg);
  return svg;
}

function geojsonToPath(feature, width, height){
  const geom = feature && feature.geometry;
  if(!geom) return '';
  const type = geom.type;
  const coords = geom.coordinates || [];
  const parts = [];

  const ringToPath = (ring)=>{
    if(!Array.isArray(ring) || ring.length < 2) return '';
    let d = '';
    ring.forEach((pt, idx)=>{
      const lon = Number(pt[0]);
      const lat = Number(pt[1]);
      if(!Number.isFinite(lon) || !Number.isFinite(lat)) return;
      const [x, y] = projectLonLat(lon, lat, width, height);
      d += (idx === 0 ? 'M' : 'L') + x.toFixed(2) + ' ' + y.toFixed(2) + ' ';
    });
    return d + 'Z ';
  };

  if(type === 'Polygon'){
    coords.forEach(ring=>{ parts.push(ringToPath(ring)); });
  } else if(type === 'MultiPolygon'){
    coords.forEach(poly=>{
      (poly || []).forEach(ring=>{ parts.push(ringToPath(ring)); });
    });
  }

  return parts.join('');
}

function buildIpRelMapSignature(cache, width, height){
  const rows = Array.isArray(cache && cache.country_summary) ? cache.country_summary.slice() : [];
  rows.sort((a, b)=>String((a && a.country) || '').localeCompare(String((b && b.country) || '')));
  const rowSig = rows.map(row=>[
    String((row && row.country) || ''),
    Number((row && row.ip_count) || 0),
    Number((row && row.malicious_ips) || 0),
    Number((row && row.suspicious_ips) || 0),
    Number((row && row.asn_count) || 0)
  ].join(':')).join('|');
  return [Number(width || 0), Number(height || 0), rowSig].join('#');
}

async function renderIpRelMapFromCache(){
  const cache = window.IP_REL_CACHE;
  const el = document.getElementById('ipRelMap');
  if(!el) return;
  if(!cache || !Array.isArray(cache.country_summary)){
    window.IP_REL_MAP_SVG = null;
    window.IP_REL_MAP_SIGNATURE = '';
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">Run Relationships first.</div>';
    return;
  }

  const centroids = await loadCountryCentroids();
  if(!centroids){
    window.IP_REL_MAP_SVG = null;
    window.IP_REL_MAP_SIGNATURE = '';
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">country_centroids.json not available.</div>';
    return;
  }

  const world = await loadWorldGeoJson();
  if(!world || !Array.isArray(world.features)){
    window.IP_REL_MAP_SVG = null;
    window.IP_REL_MAP_SIGNATURE = '';
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">world_countries_110m.geojson not available.</div>';
    return;
  }

  const rect = el.getBoundingClientRect();
  const width = Math.max(520, Math.round(rect.width || 520));
  const height = Math.max(520, Math.round(rect.height || 520));
  const mapSignature = buildIpRelMapSignature(cache, width, height);
  if(window.IP_REL_MAP_SVG && window.IP_REL_MAP_SIGNATURE === mapSignature){
    return;
  }
  const svg = buildSvgMap(el, width, height);
  window.IP_REL_MAP_SVG = svg;
  window.IP_REL_MAP_SIGNATURE = mapSignature;

  const landGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  landGroup.setAttribute('fill', '#eef3f8');
  landGroup.setAttribute('stroke', '#c7d6e4');
  landGroup.setAttribute('stroke-width', '0.7');
  svg.appendChild(landGroup);

  world.features.forEach(feat=>{
    const d = geojsonToPath(feat, width, height);
    if(!d) return;
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d.trim());
    landGroup.appendChild(path);
  });

  const rows = cache.country_summary || [];
  const maxCount = Math.max(1, ...rows.map(x=>Number(x.ip_count||0)));
  const toColor = (ratio)=>{
    const r = Math.max(0, Math.min(1, Number(ratio||0)));
    const rr = Math.round(60 + (220-60)*r);
    const gg = Math.round(180 + (60-180)*r);
    const bb = 80;
    return `rgb(${rr},${gg},${bb})`;
  };

  rows.forEach(row=>{
    const cc = String(row.country || '').toUpperCase();
    const c = centroids[cc];
    if(!c || !Array.isArray(c) || c.length < 2) return;
    const ipCount = Number(row.ip_count || 0);
    if(!ipCount) return;

    const mal = Number(row.malicious_ips || 0);
    const ratio = mal / Math.max(1, ipCount);
    const radius = 6 + 26 * Math.sqrt(ipCount / maxCount);
    const lat = Number(c[0]);
    const lon = Number(c[1]);
    if(!Number.isFinite(lat) || !Number.isFinite(lon)) return;

    const [x, y] = projectLatLon(lat, lon, width, height);
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', String(x));
    circle.setAttribute('cy', String(y));
    circle.setAttribute('r', String(radius));
    circle.setAttribute('fill', toColor(ratio));
    circle.setAttribute('fill-opacity', '0.78');
    circle.setAttribute('stroke', '#1b2a41');
    circle.setAttribute('stroke-width', '1');
    circle.style.cursor = 'pointer';

    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${cc}  IPs:${ipCount}  M:${mal}`;
    circle.appendChild(title);

    circle.addEventListener('click', async ()=>{
      const ipFeat = cache.ip_features || {};
      const ips = Object.keys(ipFeat).filter(ip=> String((ipFeat[ip]||{}).country||'').toUpperCase() === cc);
      const ta = document.getElementById('ipIntelInput');
      if(ta) ta.value = ips.join('\n');
      await analyzeIpRelationships();
      setIpRelView('table');
    });

    svg.appendChild(circle);
  });
}

function wireIpRelViewButtons(){
  const b1 = document.getElementById('ipRelViewTableBtn');
  const b2 = document.getElementById('ipRelViewGraphBtn');
  const b3 = document.getElementById('ipRelViewMapBtn');
  if(b1) b1.onclick = ()=> setIpRelView('table');
  if(b2) b2.onclick = ()=> setIpRelView('graph');
  if(b3) b3.onclick = ()=> setIpRelView('map');
}

function setIpRelPairsPanelVisible(visible, options){
  const opts = options || {};
  const panel = document.getElementById('ipRelPairsPanel');
  const btn = document.getElementById('ipRelPairsToggleBtn');
  const isVisible = !!visible;
  if(panel){
    panel.style.display = isVisible ? '' : 'none';
  }
  if(btn){
    const hasCount = (opts.pairCount != null && Number.isFinite(Number(opts.pairCount)));
    const pairCount = hasCount ? Number(opts.pairCount) : null;
    let txt = isVisible ? 'Hide pairs' : 'Show pairs';
    if(!isVisible && pairCount != null){
      txt += ` (${pairCount})`;
    }
    btn.textContent = txt;
    btn.setAttribute('aria-expanded', isVisible ? 'true' : 'false');
  }
}

function wireIpRelPairsToggle(){
  const btn = document.getElementById('ipRelPairsToggleBtn');
  if(!btn) return;
  btn.addEventListener('click', ()=>{
    const panel = document.getElementById('ipRelPairsPanel');
    const currentlyVisible = !!(panel && panel.style.display !== 'none');
    let pairCount = null;
    try{
      const c = window.IP_REL_CACHE && window.IP_REL_CACHE.pair_count;
      if(c != null) pairCount = Number(c);
    }catch(e){}
    setIpRelPairsPanelVisible(!currentlyVisible, { pairCount });
  });
  let initialCount = null;
  try{
    const c = window.IP_REL_CACHE && window.IP_REL_CACHE.pair_count;
    if(c != null) initialCount = Number(c);
  }catch(e){}
  setIpRelPairsPanelVisible(false, { pairCount: initialCount });
}

const IP_REL_PROFILE_PRESETS = {
  conservative: {
    label: 'Conservative',
    hint: 'Higher confidence, fewer edges. Good for strict blocking review.',
    min_score: 55,
    top_pairs: 120,
    max_neighbors_per_ip: 20,
    bucket_max: 350,
    bucket_overflow_mode: 'skip',
    pair_gate_enabled: true,
    pair_gate_strong_min: 1,
    pair_gate_mid_min: 2,
    pair_gate_fallback_score: 75
  },
  balanced: {
    label: 'Balanced',
    hint: 'Practical default for daily triage with stable noise control.',
    min_score: 40,
    top_pairs: 200,
    max_neighbors_per_ip: 30,
    bucket_max: 450,
    bucket_overflow_mode: 'truncate',
    pair_gate_enabled: true,
    pair_gate_strong_min: 1,
    pair_gate_mid_min: 2,
    pair_gate_fallback_score: 55
  },
  aggressive: {
    label: 'Aggressive',
    hint: 'Broader exploration with more edges and larger candidate surface.',
    min_score: 28,
    top_pairs: 400,
    max_neighbors_per_ip: 60,
    bucket_max: 900,
    bucket_overflow_mode: 'truncate',
    pair_gate_enabled: true,
    pair_gate_strong_min: 1,
    pair_gate_mid_min: 1,
    pair_gate_fallback_score: 45
  }
};

const IP_REL_PROFILE_FIELD_IDS = [
  'ipRelMinScore',
  'ipRelTopPairs',
  'ipRelMaxNeighbors',
  'ipRelBucketMax',
  'ipRelBucketOverflowMode',
  'ipRelPairGateEnabled',
  'ipRelGateStrongMin',
  'ipRelGateMidMin',
  'ipRelGateFallbackScore'
];

function normalizeIpRelProfileName(name){
  const key = String(name || '').trim().toLowerCase();
  if(key === 'custom') return 'custom';
  if(Object.prototype.hasOwnProperty.call(IP_REL_PROFILE_PRESETS, key)) return key;
  return 'balanced';
}

function normalizeIpRelSettings(raw, fallbackProfile){
  const fb = normalizeIpRelProfileName(fallbackProfile || 'balanced');
  const base = IP_REL_PROFILE_PRESETS[fb] || IP_REL_PROFILE_PRESETS.balanced;
  const src = (raw && typeof raw === 'object') ? raw : {};
  const overflowRaw = String((src.bucket_overflow_mode != null ? src.bucket_overflow_mode : base.bucket_overflow_mode) || 'truncate').trim().toLowerCase();
  return {
    min_score: parseBoundedInt((src.min_score != null ? src.min_score : base.min_score), base.min_score, 0, 100),
    top_pairs: parseBoundedInt((src.top_pairs != null ? src.top_pairs : base.top_pairs), base.top_pairs, 1, 5000),
    max_neighbors_per_ip: parseBoundedInt((src.max_neighbors_per_ip != null ? src.max_neighbors_per_ip : base.max_neighbors_per_ip), base.max_neighbors_per_ip, 1, 200),
    bucket_max: parseBoundedInt((src.bucket_max != null ? src.bucket_max : base.bucket_max), base.bucket_max, 50, 2000),
    bucket_overflow_mode: (overflowRaw === 'skip') ? 'skip' : 'truncate',
    pair_gate_enabled: !!(src.pair_gate_enabled != null ? src.pair_gate_enabled : base.pair_gate_enabled),
    pair_gate_strong_min: parseBoundedInt((src.pair_gate_strong_min != null ? src.pair_gate_strong_min : base.pair_gate_strong_min), base.pair_gate_strong_min, 0, 3),
    pair_gate_mid_min: parseBoundedInt((src.pair_gate_mid_min != null ? src.pair_gate_mid_min : base.pair_gate_mid_min), base.pair_gate_mid_min, 0, 5),
    pair_gate_fallback_score: parseBoundedInt((src.pair_gate_fallback_score != null ? src.pair_gate_fallback_score : base.pair_gate_fallback_score), base.pair_gate_fallback_score, 0, 100)
  };
}

function readIpRelSettingsFromUi(){
  return normalizeIpRelSettings({
    min_score: (document.getElementById('ipRelMinScore') || {}).value,
    top_pairs: (document.getElementById('ipRelTopPairs') || {}).value,
    max_neighbors_per_ip: (document.getElementById('ipRelMaxNeighbors') || {}).value,
    bucket_max: (document.getElementById('ipRelBucketMax') || {}).value,
    bucket_overflow_mode: (document.getElementById('ipRelBucketOverflowMode') || {}).value,
    pair_gate_enabled: !!(document.getElementById('ipRelPairGateEnabled') && document.getElementById('ipRelPairGateEnabled').checked),
    pair_gate_strong_min: (document.getElementById('ipRelGateStrongMin') || {}).value,
    pair_gate_mid_min: (document.getElementById('ipRelGateMidMin') || {}).value,
    pair_gate_fallback_score: (document.getElementById('ipRelGateFallbackScore') || {}).value
  }, 'balanced');
}

function applyIpRelSettingsToUi(settings){
  const s = normalizeIpRelSettings(settings, 'balanced');
  const minScoreEl = document.getElementById('ipRelMinScore');
  const topPairsEl = document.getElementById('ipRelTopPairs');
  const maxNeighEl = document.getElementById('ipRelMaxNeighbors');
  const bucketMaxEl = document.getElementById('ipRelBucketMax');
  const overflowEl = document.getElementById('ipRelBucketOverflowMode');
  const gateEnabledEl = document.getElementById('ipRelPairGateEnabled');
  const gateStrongEl = document.getElementById('ipRelGateStrongMin');
  const gateMidEl = document.getElementById('ipRelGateMidMin');
  const gateFallbackEl = document.getElementById('ipRelGateFallbackScore');

  if(minScoreEl) minScoreEl.value = String(s.min_score);
  if(topPairsEl) topPairsEl.value = String(s.top_pairs);
  if(maxNeighEl) maxNeighEl.value = String(s.max_neighbors_per_ip);
  if(bucketMaxEl) bucketMaxEl.value = String(s.bucket_max);
  if(overflowEl) overflowEl.value = String(s.bucket_overflow_mode);
  if(gateEnabledEl) gateEnabledEl.checked = !!s.pair_gate_enabled;
  if(gateStrongEl) gateStrongEl.value = String(s.pair_gate_strong_min);
  if(gateMidEl) gateMidEl.value = String(s.pair_gate_mid_min);
  if(gateFallbackEl) gateFallbackEl.value = String(s.pair_gate_fallback_score);
  return s;
}

function setIpRelProfileHint(text){
  const hintEl = document.getElementById('ipRelProfileHint');
  if(hintEl) hintEl.textContent = String(text || '');
}

function loadCustomIpRelSettings(){
  const raw = safeLocalStorageGet(IP_REL_CUSTOM_PROFILE_STORAGE_KEY);
  if(!raw) return null;
  try{
    const parsed = JSON.parse(raw);
    return normalizeIpRelSettings(parsed, 'balanced');
  }catch(e){
    return null;
  }
}

function saveCustomIpRelSettings(settings){
  const normalized = normalizeIpRelSettings(settings, 'balanced');
  return safeLocalStorageSet(IP_REL_CUSTOM_PROFILE_STORAGE_KEY, JSON.stringify(normalized));
}

function loadSelectedIpRelProfile(){
  return normalizeIpRelProfileName(safeLocalStorageGet(IP_REL_SELECTED_PROFILE_STORAGE_KEY) || 'balanced');
}

function saveSelectedIpRelProfile(name){
  const key = normalizeIpRelProfileName(name);
  safeLocalStorageSet(IP_REL_SELECTED_PROFILE_STORAGE_KEY, key);
  return key;
}

function applyIpRelProfile(name, opts){
  const options = opts || {};
  const key = normalizeIpRelProfileName(name);
  const profileSel = document.getElementById('ipRelProfileSelect');
  if(profileSel && profileSel.value !== key){
    profileSel.value = key;
  }

  if(key === 'custom'){
    const loaded = loadCustomIpRelSettings();
    const src = loaded || readIpRelSettingsFromUi();
    const applied = applyIpRelSettingsToUi(src);
    saveCustomIpRelSettings(applied);
    setIpRelProfileHint('Custom: values are saved locally in this browser.');
  } else {
    const preset = IP_REL_PROFILE_PRESETS[key] || IP_REL_PROFILE_PRESETS.balanced;
    applyIpRelSettingsToUi(preset);
    setIpRelProfileHint(`${preset.label}: ${preset.hint}`);
  }

  if(options.saveSelected !== false){
    saveSelectedIpRelProfile(key);
  }
  updateIpRelGateUi();
}

function persistCustomProfileIfSelected(reason){
  const profileSel = document.getElementById('ipRelProfileSelect');
  const selected = normalizeIpRelProfileName((profileSel && profileSel.value) || 'balanced');
  if(selected !== 'custom') return;
  const saved = saveCustomIpRelSettings(readIpRelSettingsFromUi());
  if(saved){
    const ts = new Date().toLocaleTimeString();
    if(reason === 'button'){
      setIpRelProfileHint(`Custom: saved at ${ts} (local browser storage).`);
    } else {
      setIpRelProfileHint(`Custom: auto-saved at ${ts}.`);
    }
  }
}

function wireIpRelProfileControls(){
  const profileSel = document.getElementById('ipRelProfileSelect');
  const saveBtn = document.getElementById('ipRelSaveCustomBtn');

  if(profileSel){
    profileSel.addEventListener('change', ()=> applyIpRelProfile(profileSel.value, { saveSelected: true }));
  }
  if(saveBtn){
    saveBtn.addEventListener('click', ()=>{
      const cur = readIpRelSettingsFromUi();
      saveCustomIpRelSettings(cur);
      if(profileSel){
        profileSel.value = 'custom';
      }
      applyIpRelProfile('custom', { saveSelected: true });
      persistCustomProfileIfSelected('button');
    });
  }

  IP_REL_PROFILE_FIELD_IDS.forEach(id=>{
    const el = document.getElementById(id);
    if(!el) return;
    const onChange = ()=>{
      if(id === 'ipRelPairGateEnabled'){
        updateIpRelGateUi();
      }
      persistCustomProfileIfSelected('auto');
    };
    el.addEventListener('change', onChange);
    if(el.tagName !== 'SELECT' && String(el.type || '').toLowerCase() !== 'checkbox'){
      el.addEventListener('input', onChange);
    }
  });

  const initialProfile = profileSel
    ? normalizeIpRelProfileName(loadSelectedIpRelProfile() || profileSel.value || 'balanced')
    : 'balanced';
  applyIpRelProfile(initialProfile, { saveSelected: true });
}

function updateIpRelGateUi(){
  const enabled = !!(document.getElementById('ipRelPairGateEnabled') && document.getElementById('ipRelPairGateEnabled').checked);
  ['ipRelGateStrongMin', 'ipRelGateMidMin', 'ipRelGateFallbackScore'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.disabled = !enabled;
  });
}

function renderIpRelationshipPairsTable(tbody, pairs){
  if(!tbody) return;
  tbody.innerHTML = '';
  const allPairs = Array.isArray(pairs) ? pairs : [];
  if(!allPairs.length){
    setSummaryMessage(tbody, 4, 'No strong pairs found (try lowering min score)');
    return;
  }
  const shownPairs = allPairs.slice(0, IP_REL_PAIR_TABLE_RENDER_LIMIT);
  const frag = document.createDocumentFragment();
  shownPairs.forEach(it=>{
    const tr = document.createElement('tr');
    const a = String((it && it.a) || '');
    const b = String((it && it.b) || '');
    const score = Number((it && it.score) || 0);
    const ev = it && it.evidence;

    const tdA = document.createElement('td');
    tdA.textContent = a;
    if(isIPv4(a)){
      tdA.style.cursor = 'pointer';
      tdA.title = 'Open in Query';
      tdA.onclick = ()=> openQueryForValue(a);
    }

    const tdB = document.createElement('td');
    tdB.textContent = b;
    if(isIPv4(b)){
      tdB.style.cursor = 'pointer';
      tdB.title = 'Open in Query';
      tdB.onclick = ()=> openQueryForValue(b);
    }

    const tdS = document.createElement('td'); tdS.textContent = String(score);
    const tdE = document.createElement('td');
    tdE.className = 'evidence-cell';
    const evMain = document.createElement('div');
    evMain.className = 'evidence-main';
    evMain.textContent = summarizeEvidence(ev);
    const evSub = document.createElement('div');
    evSub.className = 'evidence-sub';
    evSub.textContent = formatEvidenceDetails(ev);
    tdE.appendChild(evMain);
    if(evSub.textContent !== '-'){
      tdE.appendChild(evSub);
    }
    if(it && it.gate_reason){
      const evNote = document.createElement('div');
      evNote.className = 'evidence-note';
      evNote.textContent = `gate: ${String(it.gate_reason)}`;
      tdE.appendChild(evNote);
    }
    tdE.title = formatEvidenceDetails(ev);

    tr.appendChild(tdA); tr.appendChild(tdB); tr.appendChild(tdS); tr.appendChild(tdE);
    frag.appendChild(tr);
  });
  tbody.appendChild(frag);
  if(allPairs.length > shownPairs.length){
    appendSummaryRow(tbody, 4, `Showing top ${shownPairs.length} of ${allPairs.length} pairs for browser stability.`);
  }
}

function renderIpRelationshipClustersTable(tbody, clusters, vtEnabled){
  if(!tbody) return;
  tbody.innerHTML = '';
  const allClusters = (Array.isArray(clusters) ? clusters : []).slice().sort((a, b)=>{
    const aMulti = Number((a && a.size) || 0) >= 2 ? 1 : 0;
    const bMulti = Number((b && b.size) || 0) >= 2 ? 1 : 0;
    if(aMulti !== bMulti) return bMulti - aMulti;
    return Number((b && b.size) || 0) - Number((a && a.size) || 0);
  });
  if(!allClusters.length){
    setSummaryMessage(tbody, 8, 'No clusters');
    return;
  }
  const shownClusters = allClusters.slice(0, IP_REL_CLUSTER_TABLE_RENDER_LIMIT);
  const frag = document.createDocumentFragment();
  shownClusters.forEach((c, idx)=>{
    const tr = document.createElement('tr');
    const ips = Array.isArray(c && c.ips) ? c.ips : [];
    const vt = c && c.vt_summary || null;
    const vtTxt = vt
      ? `M:${vt.malicious_total || 0} S:${vt.suspicious_total || 0}`
      : (vtEnabled ? '-' : 'VT off');

    const tdId = document.createElement('td'); tdId.textContent = String(idx + 1);
    const tdSz = document.createElement('td'); tdSz.textContent = String((c && c.size) || ips.length || 0);
    const tdCoh = document.createElement('td'); tdCoh.textContent = (c && c.cohesion != null) ? Number(c.cohesion).toFixed(1) : '-';
    const tdAsn = document.createElement('td'); tdAsn.textContent = ((c && c.top_asn) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdOwn = document.createElement('td'); tdOwn.textContent = ((c && c.top_owner) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdCty = document.createElement('td'); tdCty.textContent = ((c && c.top_country) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdCsp = document.createElement('td'); tdCsp.textContent = ((c && c.top_csp) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdVt = document.createElement('td'); tdVt.textContent = vtTxt;

    tr.style.cursor = 'pointer';
    const fp = [];
    if(Array.isArray(c && c.top_network) && c.top_network.length) fp.push('net ' + c.top_network.map(x=>x[0]+'('+x[1]+')').join(', '));
    if(Array.isArray(c && c.top_rir) && c.top_rir.length) fp.push('rir ' + c.top_rir.map(x=>x[0]+'('+x[1]+')').join(', '));
    if(Array.isArray(c && c.top_jarm) && c.top_jarm.length) fp.push('jarm ' + c.top_jarm.map(x=>x[0]+'('+x[1]+')').join(', '));
    if(Array.isArray(c && c.top_cert) && c.top_cert.length) fp.push('cert ' + c.top_cert.map(x=>x[0]+'('+x[1]+')').join(', '));
    tr.title = fp.length
      ? `Click to analyze this cluster in Per-IP Details\n${fp.join(' | ')}`
      : 'Click to analyze this cluster in Per-IP Details';
    tr.onclick = async ()=>{
      const ta = document.getElementById('ipIntelInput');
      if(ta) ta.value = ips.join('\n');
      await analyzeIpIntel();
    };

    tr.appendChild(tdId); tr.appendChild(tdSz); tr.appendChild(tdCoh); tr.appendChild(tdAsn); tr.appendChild(tdOwn); tr.appendChild(tdCty); tr.appendChild(tdCsp); tr.appendChild(tdVt);
    frag.appendChild(tr);
  });
  tbody.appendChild(frag);
  if(allClusters.length > shownClusters.length){
    appendSummaryRow(tbody, 8, `Showing top ${shownClusters.length} of ${allClusters.length} clusters for browser stability.`);
  }
}
// Ensure buttons are wired after DOM is ready.
if(document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', ()=>{
    wireIpRelViewButtons();
    wireIpRelPairsToggle();
    wireIpRelProfileControls();
  });
} else {
  wireIpRelViewButtons();
  wireIpRelPairsToggle();
  wireIpRelProfileControls();
}

async function analyzeIpRelationships(){
  const raw = String((document.getElementById('ipIntelInput') || {}).value || '').trim();
  const inputSignature = computeIpIntelInputSignature(raw);
  const includeVT = !!(document.getElementById('ipIntelIncludeVt') && document.getElementById('ipIntelIncludeVt').checked);
  const vtBudget = parseBoundedInt((document.getElementById('ipIntelVtBudget') || {}).value, 1200, 0, 5000);
  const vtWorkers = parseBoundedInt((document.getElementById('ipIntelVtWorkers') || {}).value, 8, 1, 32);

  const minScore = parseBoundedInt((document.getElementById('ipRelMinScore') || {}).value, 40, 0, 100);
  const topPairs = parseBoundedInt((document.getElementById('ipRelTopPairs') || {}).value, 200, 1, 5000);
  const maxNeighbors = parseBoundedInt((document.getElementById('ipRelMaxNeighbors') || {}).value, 30, 1, 200);
  const bucketMax = parseBoundedInt((document.getElementById('ipRelBucketMax') || {}).value, 450, 50, 2000);
  const overflowRaw = String((document.getElementById('ipRelBucketOverflowMode') || {}).value || 'truncate').trim().toLowerCase();
  const bucketOverflowMode = (overflowRaw === 'skip') ? 'skip' : 'truncate';
  const pairGateEnabled = !!(document.getElementById('ipRelPairGateEnabled') && document.getElementById('ipRelPairGateEnabled').checked);
  const pairGateStrongMin = parseBoundedInt((document.getElementById('ipRelGateStrongMin') || {}).value, 1, 0, 3);
  const pairGateMidMin = parseBoundedInt((document.getElementById('ipRelGateMidMin') || {}).value, 2, 0, 5);
  const pairGateFallbackScore = parseBoundedInt((document.getElementById('ipRelGateFallbackScore') || {}).value, Math.max(minScore, 55), 0, 100);
  const profileName = String((document.getElementById('ipRelProfileSelect') || {}).value || 'balanced').trim().toLowerCase();

  const meta = document.getElementById('ipRelMeta');
  const pairsBody = document.querySelector('#ipRelPairsTable tbody');
  const clustersBody = document.querySelector('#ipRelClustersTable tbody');

  if(ipRelAnalyzeController){
    try{ ipRelAnalyzeController.abort(); }catch(e){}
  }
  ipRelAnalyzeSeq += 1;

  if(!raw){
    resetIpRelVisualCaches();
    if(meta) meta.textContent = 'Input IP list first';
    if(pairsBody) setSummaryMessage(pairsBody, 4, 'No data');
    if(clustersBody) setSummaryMessage(clustersBody, 8, 'No data');
    renderMergedIpIntelHints();
    return;
  }

  const controller = (typeof AbortController === 'function') ? new AbortController() : null;
  ipRelAnalyzeController = controller;
  const requestSeq = ipRelAnalyzeSeq;
  const isStale = ()=> requestSeq !== ipRelAnalyzeSeq || ipRelAnalyzeController !== controller;
  setIpIntelBusy(true);

  // default view
  setIpRelView('table');

  if(meta) meta.textContent = 'Analyzing similarity...';
  if(pairsBody) setSummaryMessage(pairsBody, 4, 'Loading...');
  if(clustersBody) setSummaryMessage(clustersBody, 8, 'Loading...');

  try{
    const pairPanel = document.getElementById('ipRelPairsPanel');
    const pairPanelWasOpen = !!(pairPanel && pairPanel.style.display !== 'none');
    const r = await fetch('/ip-relationship-analysis', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      signal: controller ? controller.signal : undefined,
      body: JSON.stringify({
        ips: raw,
        min_score: minScore,
        top_pairs: topPairs,
        max_neighbors_per_ip: maxNeighbors,
        bucket_max: bucketMax,
        bucket_overflow_mode: bucketOverflowMode,
        include_vt: includeVT,
        vt_budget: Math.min(vtBudget, 5000),
        vt_workers: vtWorkers,
        pair_gate_enabled: pairGateEnabled,
        pair_gate_strong_min: pairGateStrongMin,
        pair_gate_mid_min: pairGateMidMin,
        pair_gate_fallback_score: pairGateFallbackScore
      })
    });
    const j = await r.json();
    if(isStale()) return;
    if(!r.ok || !j || j.status !== 'ok'){
      if(meta) meta.textContent = `Similarity analysis failed: ${(j && j.error) ? j.error : 'HTTP '+r.status}`;
      if(pairsBody) setSummaryMessage(pairsBody, 4, 'No data');
      if(clustersBody) setSummaryMessage(clustersBody, 8, 'No data');
      clearIpIntelRelationshipInsights(inputSignature);
      return;
    }

    window.IP_REL_CACHE = j;
    resetIpRelVisualCaches();
    setIpIntelRelationshipInsights(inputSignature, j);

    if(meta){
      const pairCount = Number(j.pair_count || 0);
      const clusterCount = Array.isArray(j.clusters) ? j.clusters.length : 0;
      let txt = `valid ${j.valid_count || 0} / edges ${pairCount} / clusters ${clusterCount} / minScore ${j.min_score || minScore}`;
      txt += ` / profile ${profileName || 'balanced'}`;
      if(j.vt_enabled){
        txt += ` / VT attempted ${j.vt_attempted || 0} (budget ${j.vt_budget || 0}, workers ${j.vt_workers || 0})`;
      } else {
        txt += ' / VT off';
      }
      if(j.pair_gate && typeof j.pair_gate === 'object'){
        txt += ` / gate ${j.pair_gate.enabled ? 'on' : 'off'} keep ${j.pair_gate.kept || 0} drop ${j.pair_gate.dropped || 0}`;
      }
      if(Number(j.bucket_oversized_count || 0) > 0){
        txt += ` / oversized buckets ${j.bucket_oversized_count || 0}`;
        if(Number(j.bucket_truncated_count || 0) > 0){
          txt += ` (truncated ${j.bucket_truncated_count || 0})`;
        }
      }
      if(j.geoip_enabled) txt += ' / GeoIP ok';
      meta.textContent = txt;
    }

    // pairs
    if(pairsBody){
      const pairs = Array.isArray(j.pairs) ? j.pairs : [];
      setIpRelPairsPanelVisible(pairPanelWasOpen, { pairCount: pairs.length });
      renderIpRelationshipPairsTable(pairsBody, pairs);
    }

    // clusters
    if(clustersBody){
      const clusters = Array.isArray(j.clusters) ? j.clusters : [];
      renderIpRelationshipClustersTable(clustersBody, clusters, !!j.vt_enabled);
    }

    touchOverviewTs();
  }catch(e){
    if(isAbortError(e) || isStale()) return;
    clearIpIntelRelationshipInsights(inputSignature);
    if(meta) meta.textContent = 'Similarity analysis error: ' + e;
  }finally{
    if(ipRelAnalyzeController === controller){
      ipRelAnalyzeController = null;
    }
    setIpIntelBusy(false);
  }
}
