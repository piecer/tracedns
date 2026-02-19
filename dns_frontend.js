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
window.DOMAIN_ANALYSIS_CACHE = [];
window.DOMAIN_ANALYSIS_INCLUDE_VT = true;
window.DOMAIN_ANALYSIS_SELECTED_REMOVE = window.DOMAIN_ANALYSIS_SELECTED_REMOVE || new Set();
window.DOMAIN_VERIFY_LAST = null;

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

function syncDomainVerifyDecoderOptions(){
  const txtFallback = ['cafebabe_xor_base64','plain_base64','btea_variant','xor_ipstring_base64_fixedkey'];
  const aFallback = ['none','xor32_ipv4'];
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

  const txtSel = document.getElementById('verifyTxtDecode');
  const aSel = document.getElementById('verifyADecode');
  fillSelectWithOptions(txtSel, txtNames, (txtSel || {}).value || 'cafebabe_xor_base64');
  fillSelectWithOptions(aSel, aNames, (aSel || {}).value || 'none');
  if(aSel && !aSel.value) aSel.value = 'none';
}

function updateDomainVerifyInputMode(){
  const typeEl = document.getElementById('verifyDomainType');
  const txtEl = document.getElementById('verifyTxtDecode');
  const aEl = document.getElementById('verifyADecode');
  const xorEl = document.getElementById('verifyAXorKey');
  if(!typeEl || !txtEl || !aEl || !xorEl) return;
  const t = String(typeEl.value || 'AUTO').toUpperCase();
  const isAOnly = t === 'A';
  const isTxtOnly = t === 'TXT';
  txtEl.disabled = isAOnly;
  aEl.disabled = isTxtOnly;
  xorEl.disabled = isTxtOnly;
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
    const tdSrv = document.createElement('td');
    tdSrv.textContent = row.server || '-';
    const tdType = document.createElement('td');
    tdType.textContent = String(row.type || '-').toUpperCase();
    const tdStatus = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = `verify-status-badge ${toVerifyStatusClass(row.status)}`;
    statusBadge.textContent = String(row.status || 'error').toUpperCase();
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
    tdMethod.textContent = row.method || '-';
    tdMethod.title = row.method || '-';
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

function clearDomainVerifyResult(){
  window.DOMAIN_VERIFY_LAST = null;
  setDomainVerifyStatus('', '');
  renderDomainVerifySummary(null);
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
  const includeVt = !!((document.getElementById('verifyIncludeVt') || {}).checked);

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
        include_vt: includeVt
      })
    });
    const j = await r.json();
    if(!r.ok || !j || j.error){
      const msg = (j && j.error) ? j.error : `Validation failed (${r.status})`;
      setDomainVerifyStatus(msg, 'err');
      window.DOMAIN_VERIFY_LAST = null;
      renderDomainVerifySummary({error: msg});
      renderDomainVerifyServerTable({by_server: []});
      renderDomainVerifyIpTable({ip_rows: []});
      return;
    }
    window.DOMAIN_VERIFY_LAST = j;
    renderDomainVerifySummary(j);
    renderDomainVerifyServerTable(j);
    renderDomainVerifyIpTable(j);
    setDomainVerifyStatus(j.can_add === false ? 'Validation complete (no addable IP)' : 'Validation complete', j.can_add === false ? 'err' : 'ok');
  }catch(e){
    const msg = `Validation error: ${e}`;
    setDomainVerifyStatus(msg, 'err');
    window.DOMAIN_VERIFY_LAST = null;
    renderDomainVerifySummary({error: msg});
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

async function runQuery(v){
  const value = String(v || '').trim();
  if(!value){ alert('Enter search value'); return; }
  if(isIPv4(value)){
    const r = await fetch('/ip?ip='+encodeURIComponent(value));
    const j = await r.json();
    document.getElementById('queryResult').textContent = JSON.stringify(j, null, 2);
    return;
  }
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
  document.getElementById('queryResult').textContent = JSON.stringify({current:matches, history:histMatches}, null, 2);
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
  }
}

async function analyzeIpIntel(){
  const raw = String((document.getElementById('ipIntelInput') || {}).value || '').trim();
  const includeVT = !!(document.getElementById('ipIntelIncludeVt') && document.getElementById('ipIntelIncludeVt').checked);
  const rowLimit = parseBoundedInt((document.getElementById('ipIntelRowLimit') || {}).value, 1500, 100, 5000);
  const vtBudget = parseBoundedInt((document.getElementById('ipIntelVtBudget') || {}).value, 1200, 0, 5000);
  const vtWorkers = parseBoundedInt((document.getElementById('ipIntelVtWorkers') || {}).value, 8, 1, 32);
  const meta = document.getElementById('ipIntelMeta');
  const hintsBox = document.getElementById('ipIntelHintsBox');
  const invalidBox = document.getElementById('ipIntelInvalidBox');
  const ipBody = document.querySelector('#ipIntelResultTable tbody');
  const asBody = document.querySelector('#ipIntelAsSummaryTable tbody');
  const cBody = document.querySelector('#ipIntelCountrySummaryTable tbody');
  const acBody = document.querySelector('#ipIntelAsCountrySummaryTable tbody');
  const cspBody = document.querySelector('#ipIntelCspSummaryTable tbody');

  if(!raw){
    if(meta) meta.textContent = 'Input IP list first';
    return;
  }
  if(meta) meta.textContent = 'Analyzing...';

  try{
    const r = await fetch('/ip-list-analysis', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        ips: raw,
        include_vt: includeVT,
        row_limit: rowLimit,
        vt_lookup_budget: vtBudget,
        vt_workers: vtWorkers
      })
    });
    const j = await r.json();
    if(!r.ok){
      if(meta) meta.textContent = `Analyze failed: ${(j && j.error) ? j.error : 'HTTP '+r.status}`;
      if(ipBody) setSummaryMessage(ipBody, 6, 'No data');
      if(asBody) setSummaryMessage(asBody, 6, 'No data');
      if(cBody) setSummaryMessage(cBody, 4, 'No data');
      if(acBody) setSummaryMessage(acBody, 6, 'No data');
      if(cspBody) setSummaryMessage(cspBody, 5, 'No data');
      if(hintsBox) hintsBox.textContent = '-';
      if(invalidBox) invalidBox.textContent = '-';
      return;
    }

    const rows = Array.isArray(j.ips) ? j.ips : [];
    const asRows = Array.isArray(j.as_summary) ? j.as_summary : [];
    const cRows = Array.isArray(j.country_summary) ? j.country_summary : [];
    const acRows = Array.isArray(j.as_country_summary) ? j.as_country_summary : [];
    const cspRows = Array.isArray(j.csp_summary) ? j.csp_summary : [];
    const hints = Array.isArray(j.hints) ? j.hints : [];
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

    if(hintsBox){
      hintsBox.innerHTML = '';
      if(!hints.length){
        hintsBox.textContent = 'No heuristics available';
      } else {
        hints.forEach(h=>{
          const div = document.createElement('div');
          const level = String((h && h.level) || 'info').toUpperCase();
          const title = String((h && h.title) || 'Hint');
          const detail = String((h && h.detail) || '-');
          div.style.padding = '4px 0';
          div.textContent = `[${level}] ${title}: ${detail}`;
          hintsBox.appendChild(div);
        });
      }
    }

    if(invalidBox){
      if(!invalid.length){
        invalidBox.textContent = 'No invalid inputs';
      } else {
        invalidBox.textContent = invalid.join(', ');
      }
    }
    touchOverviewTs();
  }catch(e){
    if(meta) meta.textContent = 'Analyze error: ' + e;
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
  set('metricIps', `${uiOverview.allIps} / valid ${uiOverview.validIps}`);
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
  ['A','TXT','AAAA','CNAME','MX','NS','SRV','CAA'].forEach(t=>{ const o = document.createElement('option'); o.value=t; o.text=t; sel.appendChild(o); });
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

  // Toggle decoder fields by record type
  const toggleDecodeInputs = function(){
    const typ = (sel.value || 'A').toUpperCase();
    const isTXT = typ === 'TXT';
    const isA = typ === 'A';
    selDecode.disabled = !isTXT;
    selADecode.disabled = !isA;
    inpAKey.disabled = !isA;
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
    // 자동으로 저장
    const payload = {
      domains: collectDomainsFromUI(),
      servers: document.getElementById('servers').value.split(',').map(s=>s.trim()).filter(Boolean),
      interval: parseInt(document.getElementById('interval').value) || 60
    };
    try{
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
    document.getElementById('interval').value = j.interval || 60;
    log('Loaded config');
    touchOverviewTs();
  }catch(e){ log('Config load error:'+e); }
}
document.getElementById('load').onclick = loadCfg;

document.getElementById('save').onclick = async ()=>{
  const payload = {
    domains: collectDomainsFromUI(),
    servers: document.getElementById('servers').value.split(',').map(s=>s.trim()).filter(Boolean),
    interval: parseInt(document.getElementById('interval').value) || 60
  };
  uiOverview.configured = payload.domains.length;
  updateOverviewPanel();
  try{
    const r = await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const j = await r.json();
    log('Saved: ' + JSON.stringify(j));
  }catch(e){ log('Save error:'+e); }
};

document.getElementById('force').onclick = async ()=>{
  const domains = collectDomainsFromUI();
  try{
    const r = await fetch('/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({domains: domains})});
    const j = await r.json();
    log('Force requested: '+JSON.stringify(j));
    await refreshResults();
  }catch(e){ log('Force error:'+e); }
};

document.getElementById('verifyBtn').onclick = async ()=>{
  const domains = collectDomainsFromUI();
  const el = document.getElementById('verifyResult');
  el.textContent = 'Running verify...';
  try{
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

function buildStatusFingerprint(resultsAgg){
  const keys = Object.keys(resultsAgg || {}).sort();
  const parts = [];
  keys.forEach(d=>{
    const it = resultsAgg[d] || {};
    parts.push([
      d,
      Number(it.ts || 0),
      Array.isArray(it.values) ? it.values.length : 0,
      Array.isArray(it.decoded_ips) ? it.decoded_ips.length : 0,
      Array.isArray(it.servers) ? it.servers.length : 0,
      String(it.method_summary || '')
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

    const statusFp = buildStatusFingerprint(resultsAgg);
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

async function refreshIPs(){
  if(refreshIPsInFlight) return;
  refreshIPsInFlight = true;
  try{
    const includeVT = !!(document.getElementById('ips_include_vt') && document.getElementById('ips_include_vt').checked);
    const r = await fetch('/ips' + (includeVT ? '?include_vt=1' : ''));
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
    const fp = `vt:${includeVT ? 1 : 0}|${buildIpsFingerprint(arr)}`;
    uiOverview.allIps = arr.length;
    uiOverview.validIps = arr.filter(it=>it && it.valid).length;
    updateOverviewPanel();
    if(fp === lastAllIpsRenderFingerprint){
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
      const tdDomains = document.createElement('td'); tdDomains.textContent = (it.domains||[]).join(', ');
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
      tr.appendChild(tdIp); tr.appendChild(tdDomains); tr.appendChild(tdCount); tr.appendChild(tdTs); tr.appendChild(tdVtScore); tr.appendChild(tdVtCtx);
      tbody.appendChild(tr);
    });
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
      const includeVtEl = document.getElementById('verifyIncludeVt');
      if(domainEl) domainEl.value = '';
      if(typeEl) typeEl.value = 'AUTO';
      if(txtEl && includeOption(txtEl, 'cafebabe_xor_base64')) txtEl.value = 'cafebabe_xor_base64';
      if(aEl && includeOption(aEl, 'none')) aEl.value = 'none';
      if(keyEl) keyEl.value = '';
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
