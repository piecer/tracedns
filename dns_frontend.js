const SECTION_BUTTON_MAP = {
  settings: 'menuSettings',
  status: 'menuStatus',
  query: 'menuQuery',
  domainanalysis: 'menuDomainAnalysis',
  ipintel: 'menuIpIntel',
  ips: 'menuIPs',
  validips: 'menuValidIPs'
};

function showSection(name){
  ['settings','status','query','domainanalysis','ipintel','ips','validips'].forEach(id=>document.getElementById(id).classList.remove('active'));
  document.getElementById(name).classList.add('active');
  Object.keys(SECTION_BUTTON_MAP).forEach(sec=>{
    const btn = document.getElementById(SECTION_BUTTON_MAP[sec]);
    if(!btn) return;
    btn.classList.toggle('active', sec === name);
  });
}
document.getElementById('menuSettings').onclick = ()=> showSection('settings');
document.getElementById('menuStatus').onclick = ()=> showSection('status');
document.getElementById('menuQuery').onclick = ()=> showSection('query');
document.getElementById('menuDomainAnalysis').onclick = ()=> { showSection('domainanalysis'); refreshDomainAnalysis(); };
document.getElementById('menuIpIntel').onclick = ()=> showSection('ipintel');
document.getElementById('menuIPs').onclick = ()=> showSection('ips');
document.getElementById('menuValidIPs').onclick = ()=> showSection('validips');

function log(msg){ document.getElementById('log').textContent += msg + "\n"; }
const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
window.DOMAIN_ANALYSIS_CACHE = [];
window.DOMAIN_ANALYSIS_INCLUDE_VT = true;

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

function openQueryForValue(value){
  const v = String(value || '').trim();
  if(!v) return;
  const q = document.getElementById('queryValue');
  if(q) q.value = v;
  showSection('query');
  runQuery(v);
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
  // search value across history/current by fetching /results + /history client-side (simple approach)
  const r1 = await fetch('/results'); const res = await r1.json();
  const matches = [];
  for(const d of Object.keys(res.results||{})){
    const srvMap = res.results[d];
    for(const s of Object.keys(srvMap)){
      const info = srvMap[s];
      if((info.values||[]).some(x=>x.includes(value))){
        matches.push({domain:d, server:s, type:info.type, ts:info.ts, values:info.values});
      }
    }
  }
  // fallback: fetch history per domain from results list
  const histMatches = [];
  for(const d of Object.keys(res.results||{})){
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
  if(!arr.length){
    setSummaryMessage(tbody, 9, 'No domains available');
    return;
  }
  arr.sort((a,b)=>String((a && a.domain) || '').localeCompare(String((b && b.domain) || '')));
  arr.forEach(d=>{
    const name = String((d && d.domain) || '');
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
    const c2 = document.createElement('td'); c2.textContent = String(st.resolvedCount);
    const c3 = document.createElement('td'); c3.textContent = String(st.decodedCount);
    const c4 = document.createElement('td'); c4.textContent = String(st.asCount);
    const c5 = document.createElement('td'); c5.textContent = String(st.countryCount);
    const c6 = document.createElement('td'); c6.textContent = st.topAs;
    const c7 = document.createElement('td'); c7.textContent = st.topCountry;
    const c8 = document.createElement('td'); c8.textContent = tsText;
    const c9 = document.createElement('td');
    const btn = document.createElement('button');
    btn.style.margin = '0';
    btn.textContent = (selectedDomain && name === selectedDomain) ? 'Viewing' : 'View';
    btn.onclick = ()=>{
      const sel = document.getElementById('domainAnalysisDomainSelect');
      if(sel){
        sel.value = name;
      }
      applyDomainAnalysisFilter();
    };
    c9.appendChild(btn);
    tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6); tr.appendChild(c7); tr.appendChild(c8); tr.appendChild(c9);
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
  if(meta){
    meta.textContent = `${arr.length}/${Math.max(0, Number(totalDomainsCount || arr.length))} domains / ${ipRowsCount} IP rows / AS ${summary.asGroups} / Countries ${summary.countries} / AS×Country ${summary.intersections} / NXDOMAIN ${nxdomainActiveCount} / Error-only ${errorOnlyCount}${selected ? ` / Filter: ${selected}` : ''}`;
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
        vt_lookup_budget: vtBudget
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

    if(meta){
      let txt = `submitted ${j.submitted_count || 0} / valid ${j.valid_count || 0} / invalid ${j.invalid_count || 0} / displayed ${ipsShown}/${ipsTotal}`;
      if(ipsLimited){
        txt += ' (row-limited)';
      }
      if(includeVT){
        txt += ` / VT budget ${vtBudgetInfo} (attempted ${vtAttemptedInfo})`;
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

function renderCellWithClickableIps(td, rawValues, fallbackText){
  const values = Array.isArray(rawValues) ? rawValues : [];
  const ips = values.filter(isIPv4);
  td.className = 'wrap-cell';
  if(!ips.length){
    const full = String(fallbackText || '');
    td.textContent = full.length > 200 ? full.slice(0,200) + '…' : full;
    td.title = full;
    return;
  }
  td.innerHTML = '';
  td.title = ips.join(' | ');
  ips.forEach((ip, idx)=>{
    const a = document.createElement('a');
    a.href = '#';
    a.textContent = ip;
    a.onclick = (e)=>{
      e.preventDefault();
      openQueryForValue(ip);
    };
    td.appendChild(a);
    if(idx < ips.length - 1){
      td.appendChild(document.createTextNode(' | '));
    }
  });
}

const uiOverview = {
  configured: 0,
  statusRows: 0,
  managedIps: 0,
  allIps: 0,
  validIps: 0,
  lastRefreshLocal: '-'
};

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
  const alerts = {
    teams_webhook: document.getElementById('teams_webhook_front').value.trim(),
    misp_url: document.getElementById('misp_url_front').value.trim(),
    api_key: document.getElementById('misp_key_front').value.trim(),
    push_event_id: document.getElementById('push_event_id_front').value.trim(),
    vt_api_key: document.getElementById('vt_api_key_front').value.trim()
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
  if(table && table.rows){
    for(let i=1; i<table.rows.length; i++){
      const domain = table.rows[i].cells[0].textContent.trim();
      if(domain && !allDomains.includes(domain)) allDomains.push(domain);
    }
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

async function refreshResults(){
  try{
    const r = await fetch('/results'); 
    if(!r.ok) {
      console.error('refreshResults: HTTP error', r.status);
      return;
    }
    const j = await r.json();
    const tbody = document.querySelector('#resultsTable tbody');
    const results = j.results || {};
    // build a map of existing rows keyed by domain||srv to preserve verify rows and avoid full re-render
    const existing = {};
    Array.from(tbody.querySelectorAll('tr')).forEach(r => {
      if(r.classList && r.classList.contains('verify-row')) return;
      const kd = r.dataset.domain || '';
      const ks = r.dataset.server || '';
      if(kd) existing[kd + '||' + ks] = r;
    });

    const newKeys = [];
    let statusRows = 0;
    const managedSet = new Set();
    Object.keys(results).sort().forEach(d=>{
      const srvMap = results[d];
      if(typeof srvMap !== 'object') return;
      Object.keys(srvMap).forEach(srv=>{
        const info = srvMap[srv];
        if(typeof info !== 'object') return;
        statusRows += 1;
        const rtype = (info.type || '').toUpperCase();
        if(rtype === 'TXT'){
          (info.decoded_ips || []).forEach(ip=>{ if(ip) managedSet.add(ip); });
        } else if(rtype === 'A'){
          (info.values || []).forEach(ip=>{ if(ip) managedSet.add(ip); });
        }
        const key = d + '||' + srv;
        newKeys.push(key);
        let tr = existing[key];
        const fullVals = (info.values||[]).join(' | ');
        const fullDecoded = (info.decoded_ips||[]).join(', ');
        if(tr){
          // update existing row in-place
          tr.dataset.domain = d; tr.dataset.server = srv;
          tr.innerHTML = '';
        } else {
          tr = document.createElement('tr');
          tr.dataset.domain = d; tr.dataset.server = srv;
        }
        const tdDomain = document.createElement('td'); tdDomain.textContent = d;
        const tdType = document.createElement('td'); tdType.textContent = info.type || 'A';
        const tdSrv = document.createElement('td'); tdSrv.textContent = srv;
        const tdVals = document.createElement('td');
        const tdDecoded = document.createElement('td');
        renderCellWithClickableIps(tdVals, info.values || [], fullVals);
        renderCellWithClickableIps(tdDecoded, info.decoded_ips || [], fullDecoded);
        const tdMethod = document.createElement('td');
        if(info.type === 'TXT' && info.txt_decode){
          tdMethod.textContent = info.txt_decode;
        } else if(info.type === 'A' && info.a_decode){
          tdMethod.textContent = info.a_xor_key ? `${info.a_decode} (${info.a_xor_key})` : info.a_decode;
        } else {
          tdMethod.textContent = '-';
        }
        const tdTs = document.createElement('td'); tdTs.textContent = formatUnixTsLocal(info.ts);
        const tdActions = document.createElement('td');
        
        // History 버튼 (모든 레코드)
        const histBtn = document.createElement('button'); 
        histBtn.className = 'action-btn';
        histBtn.textContent = 'History';
        histBtn.title = 'View history for this domain';
        histBtn.onclick = ()=> loadHistory(d);
        tdActions.appendChild(histBtn);
        
        // TXT 레코드인 경우만 Analyze와 Verify 버튼 추가
        if(info.type === 'TXT'){
          // Analyze 버튼
          const analyzeBtn = document.createElement('button'); 
          analyzeBtn.className = 'action-btn';
          analyzeBtn.textContent = 'Analyze';
          analyzeBtn.title = 'Analyze TXT decoding methods';
          analyzeBtn.onclick = async ()=>{
            const sample = (info.values||[]).join('|');
            try{ 
              const r = await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:d,txt:sample})}); 
              const j = await r.json(); 
              renderAnalyzeResult(j);
            }catch(e){ 
              document.getElementById('analyzeResult').textContent = 'Analyze error: '+e; 
            }
          };
          tdActions.appendChild(analyzeBtn);
          
          // Verify 버튼
          const verifyBtn = document.createElement('button'); 
          verifyBtn.className = 'action-btn';
          verifyBtn.textContent = 'Verify';
          verifyBtn.title = 'Verify this domain\'s TXT records';
          verifyBtn.onclick = async ()=>{
            const next = tr.nextElementSibling;
            if(next && next.classList && next.classList.contains('verify-row') && next.dataset && next.dataset.domain===d){ 
              next.remove(); 
              return; 
            }
            const vtr = document.createElement('tr'); 
            vtr.className = 'verify-row'; 
            vtr.dataset.domain = d;
            const vtd = document.createElement('td'); 
            // Match Current Status table column count exactly.
            vtd.colSpan = 8;
            vtd.textContent = 'Verifying '+d+'...'; 
            vtr.appendChild(vtd);
            tr.parentNode.insertBefore(vtr, tr.nextSibling);
            try{ 
              const r = await fetch('/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domains:[d]})}); 
              const j = await r.json(); 
              vtd.innerHTML=''; 
              if(j && j.results && j.results[d]){ 
                const data = j.results[d]; 
                if(data.error){ 
                  vtd.textContent = 'Error: '+data.error; 
                } else { 
                  const analysis = data.analysis||{}; 
                  const keys = Object.keys(analysis).sort((a,b)=>(analysis[b].score||0)-(analysis[a].score||0)); 
                  keys.forEach(k=>{ 
                    const info = analysis[k]; 
                    const h = document.createElement('div'); 
                    h.style.fontWeight='600'; 
                    h.style.marginTop='10px';
                    h.textContent = `${k} — score=${info.score} raw=${info.raw_count}`; 
                    vtd.appendChild(h); 
                    const ips = info.detailed_ips||[]; 
                    if(ips.length===0){ 
                      const none=document.createElement('div'); 
                      none.textContent='No decoded IPs'; 
                      vtd.appendChild(none);
                    } else{ 
                      const tbl=document.createElement('table'); 
                      tbl.style.width='100%'; 
                      tbl.style.marginTop='6px'; 
                      const thr=document.createElement('tr'); 
                      thr.innerHTML='<th>IP</th><th>Valid</th><th>VT(malicious/suspicious)</th><th>Summary</th>'; 
                      tbl.appendChild(thr); 
                      ips.forEach(it=>{ 
                        const trr=document.createElement('tr'); 
                        const tdIp=document.createElement('td'); 
                        tdIp.textContent=it.ip||''; 
                        const tdV=document.createElement('td'); 
                        tdV.textContent=it.valid?'YES':'NO'; 
                        const tdVT=document.createElement('td'); 
                        const tdSum=document.createElement('td'); 
                        if(it.vt){ 
                          tdVT.textContent=`${it.vt.malicious||0}/${it.vt.suspicious||0}`; 
                          tdSum.textContent=`ASN:${it.vt.asn||''} ${it.vt.country||''}`; 
                        } else { 
                          tdVT.textContent='-'; 
                          tdSum.textContent='-'; 
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
                vtd.textContent='No data returned'; 
              } 
            }catch(e){ 
              vtd.textContent='Verify error: '+e; 
            } 
          };
          tdActions.appendChild(verifyBtn);
        }
        
        tr.appendChild(tdDomain); tr.appendChild(tdType); tr.appendChild(tdSrv); tr.appendChild(tdVals); tr.appendChild(tdDecoded); tr.appendChild(tdMethod); tr.appendChild(tdTs); tr.appendChild(tdActions);

        // insert or move row into tbody in desired order
        const existingRow = tbody.querySelector(`tr[data-domain="${d}"][data-server="${srv}"]`);
        if(existingRow){
          // replace in-place
          existingRow.parentNode.replaceChild(tr, existingRow);
        } else {
          tbody.appendChild(tr);
        }
      });
    });
    // remove any stale rows (and their verify rows) not present in newKeys
    Array.from(tbody.querySelectorAll('tr')).forEach(r=>{
      if(r.classList && r.classList.contains('verify-row')) return;
      const key = (r.dataset.domain||'') + '||' + (r.dataset.server||'');
      if(!newKeys.includes(key)){
        // remove associated verify row if any
        const next = r.nextElementSibling;
        if(next && next.classList && next.classList.contains('verify-row') && next.dataset && next.dataset.domain===r.dataset.domain){ next.remove(); }
        r.remove();
      }
    });
    uiOverview.statusRows = statusRows;
    uiOverview.managedIps = managedSet.size;
    touchOverviewTs();
  }catch(e){ console.log('refresh error', e); }
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
  try{
    const includeVT = !!(document.getElementById('ips_include_vt') && document.getElementById('ips_include_vt').checked);
    const r = await fetch('/ips' + (includeVT ? '?include_vt=1' : ''));
    if(!r.ok) {
      console.error('refreshIPs: HTTP error', r.status);
      return;
    }
    const j = await r.json();
    const tbody = document.querySelector('#ipsTable tbody');
    tbody.innerHTML = '';
    const arr = j.ips || [];
    if(!Array.isArray(arr)) {
      console.error('refreshIPs: ips is not an array', arr);
      return;
    }
    uiOverview.allIps = arr.length;
    uiOverview.validIps = arr.filter(it=>it && it.valid).length;
    updateOverviewPanel();
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
  try{
    const r = await fetch('/ips');
    if(!r.ok){ console.error('refreshValidIPs HTTP', r.status); return; }
    const j = await r.json();
    const tbody = document.querySelector('#validIpsTable tbody');
    tbody.innerHTML = '';
    const arr = j.ips || [];
    if(!Array.isArray(arr)) return;
    // display only syntactically valid IPs (backend also provides 'valid')
    const validOnly = arr.filter(it => it && it.valid);
    uiOverview.allIps = arr.length;
    uiOverview.validIps = validOnly.length;
    updateOverviewPanel();
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
    if(!manualPause){ refreshResults(); refreshIPs(); }
  };

  // pause when user hovers results table to allow inspection of long URLs
  const resultsTable = document.getElementById('resultsTable');
  resultsTable.addEventListener('mouseenter', ()=>{ hoverPause = true; updateRefreshStateBadge(); });
  resultsTable.addEventListener('mouseleave', ()=>{ hoverPause = false; updateRefreshStateBadge(); });

  // periodic refresh — skip work if paused to avoid wiping user's view
  setInterval(()=>{ if(!isPaused()) refreshResults(); }, 5000);
  setInterval(()=>{ if(!isPaused()) refreshIPs(); }, 5000);
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
  
  try {
    refreshResults();
    refreshIPs();
  } catch(e) {
    console.error('Failed to refresh:', e);
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
  const runIpIntelBtn = document.getElementById('runIpIntelBtn');
  if(runIpIntelBtn){
    runIpIntelBtn.addEventListener('click', ()=> analyzeIpIntel());
  }
  const loadIpIntelMispBtn = document.getElementById('loadIpIntelMispBtn');
  if(loadIpIntelMispBtn){
    loadIpIntelMispBtn.addEventListener('click', ()=> loadIpIntelFromMisp(true));
  }
  // initial load of valid ips
  refreshValidIPs(parseInt(document.getElementById('valid_since').value) || 0);
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
  refreshCustomDecoders().then(()=> loadCfg());
});
