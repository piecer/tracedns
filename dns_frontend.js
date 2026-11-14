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

const localFeedbackOwners = new Map();
function viewFeedbackOwner(name, elementId){
  if(!window.TraceViewFeedback || !document.getElementById(elementId)) return null;
  if(!localFeedbackOwners.has(name)) localFeedbackOwners.set(name, window.TraceViewFeedback.register(name, state => {
    const el = document.getElementById(elementId);
    if(!el) return;
    if(state.error) el.setAttribute('data-feedback-id', state.error.identity);
    else el.removeAttribute('data-feedback-id');
  }));
  return localFeedbackOwners.get(name);
}
function feedbackCurrent(token){ return !token || window.TraceViewFeedback.current(token); }
function feedbackFailure(scope, token, error, mutation = false){
  if(scope) scope.fail(token, window.TraceViewFeedback.code(error, mutation));
}
window.TraceAuth?.onInvalidated?.(() => {
  cancelSectionRefreshes();
  closeTargetDetail(false);
  preparedViews.clear();
  statusPageRows.clear();
  document.getElementById('ipDetail')?.remove();
  for(const id of ['resultsTable', 'ipsTable', 'validIpsTable', 'domainDomainStatsTable']){
    const body = document.querySelector('#' + id + ' tbody');
    if(body){ body.replaceChildren(); body._preparedRows = new Map(); }
  }
  for(const section of Object.keys(preparedOffsets)){
    preparedOffsets[section] = 0;
    document.getElementById(section + '_page_meta')?.replaceChildren();
    for(const suffix of ['_prev_btn', '_next_btn']){
      const button = document.getElementById(section + suffix);
      if(button) button.disabled = true;
    }
    setSectionRefreshStatus(section, 'Access changed. Reload to check permissions.');
  }
  cancelQuery('Access changed. Reload to check permissions.');
  invalidateAnalysisAccess();
  queryResultViews.clear();
  for(const [root] of Object.values(queryParts)) document.getElementById(root)?.replaceChildren();
  loadHistory.lastGood = null;
  for(const scope of localFeedbackOwners.values()) scope.forget();
  const history = document.getElementById('historyBox');
  if(history) history.textContent = '';
  configRevision = alertRevision = decoderRevision = null;
  window.DOMAIN_VERIFY_LAST = null;
});

function setSectionRefreshStatus(section, text){
  const parent = document.getElementById(section);
  if(!parent) return;
  let status = document.getElementById(section + '-refresh-status');
  if(!status){
    status = document.createElement('p');
    status.id = section + '-refresh-status';
    status.setAttribute('role', 'status');
    parent.prepend(status);
  }
  status.textContent = text;
}

const sectionRefreshOwners = new Map();
// Only the currently displayed query may negotiate an unchanged body. A prior
// page's validator without its rows would incorrectly retain the current page.
const preparedViews = new Map();
async function readPreparedJSON(owner){
  const url = owner.url;
  const previous = preparedViews.get(owner.section);
  const query = new URL(url, location.href);
  if(previous && previous.url === url && previous.version){
    query.searchParams.set('if_version', previous.version);
  }
  const data = await window.TraceAuth.readJSON(query.href, {signal:owner.controller.signal, feedback:owner.feedback});
  owner.payload = data;
  return data;
}
function preparedStatus(owner){
  const j = owner.payload || {};
  const s = j.snapshot || {};
  const time = s.generated_at ? formatUnixTsLocal(s.generated_at) : 'unknown time';
  setSectionRefreshStatus(owner.section, `Snapshot from ${time}${s.stale ? ' (stale)' : ''}; source checks are periodic.` +
    (j.enrichment ? ` VT: ${j.enrichment.status}.` : ''));
}
function completePreparedRender(owner){
  if(!isSectionRefreshCurrent(owner)) return;
  const j = owner.payload || {};
  updatePreparedPage(owner.section, j.page);
  preparedStatus(owner);
  owner.feedbackScope?.succeed(owner.feedback);
  const status = document.getElementById(owner.section + '-refresh-status');
  preparedViews.set(owner.section, {url:owner.url, version:j.view_version || null, page:j.page, status:status ? status.textContent : ''});
}
function preparedResponseHandled(owner){
  if(!isSectionRefreshCurrent(owner)) return true;
  const j = owner.payload || {};
  if(j.snapshot && j.snapshot.ready === false){
    const previous = preparedViews.get(owner.section);
    setSectionRefreshStatus(owner.section, 'Preparing snapshot... Previous data retained. ' + (previous ? previous.status : ''));
    return true;
  }
  if(j.unchanged){
    completePreparedRender(owner);
    return true;
  }
  return false;
}

const preparedOffsets = {status:0, ips:0, validips:0, domainanalysis:0};
function preparedQuery(section){
  const params = new URLSearchParams({read_mode:'background', limit:String(section === 'ips' ? getIpsPageSize() : 100), offset:String(preparedOffsets[section])});
  let path = '/ips';
  if(section === 'status'){ path = '/results'; params.set('aggregate', '1'); }
  if(section === 'validips'){
    params.set('valid_only', '1');
    const since = parseBoundedInt((document.getElementById('valid_since') || {}).value, 0, 0, 315360000);
    if(since > 0) params.set('since', String(since));
  }
  if(section === 'domainanalysis' || section === 'ips'){
    const domain = section === 'domainanalysis';
    if(domain) path = '/domain-analysis';
    const includeVT = !!(document.getElementById(domain ? 'domain_analysis_include_vt' : 'ips_include_vt') || {}).checked;
    params.set('include_vt', includeVT ? '1' : '0');
    params.set('vt_mode', 'background');
    if(domain) params.set('q', String((document.getElementById('domain_analysis_query') || {}).value || '').trim());
    else if(includeVT){
      params.set('vt_workers', String(parseBoundedInt((document.getElementById('ips_vt_workers') || {}).value, 8, 1, 32)));
      params.set('vt_budget', String(parseBoundedInt((document.getElementById('ips_vt_budget') || {}).value, getIpsPageSize(), 0, 200)));
    }
  }
  return path + '?' + params.toString();
}
function updatePreparedPage(section, page){
  if(!page) return;
  const meta = document.getElementById(section + '_page_meta');
  if(meta) meta.textContent = `Showing ${page.displayed ? page.offset + 1 : 0}-${page.offset + page.displayed} / ${page.total} ${page.unit}${page.domains_total != null ? ` / ${page.domains_total} domains` : ''}`;
  for(const direction of ['previous', 'next']){
    const btn = document.getElementById(section + (direction === 'previous' ? '_prev_btn' : '_next_btn'));
    if(btn) btn.disabled = page[direction + '_offset'] == null;
  }
}
function navigatePreparedPage(section, direction){
  const state = preparedViews.get(section);
  const offset = state && state.page && state.page[direction + '_offset'];
  if(!Number.isInteger(offset) || offset < 0) return;
  if(section === 'status') closeTargetDetail(false);
  preparedOffsets[section] = offset;
  triggerSectionRefresh(section);
}
function beginSectionRefresh(section){
  if(document.hidden || window.TraceAuth?.accessInvalidated) return null;
  const url = preparedQuery(section);
  const previous = sectionRefreshOwners.get(section);
  if(previous){
    if(previous.url === url) return null;
    previous.controller.abort();
    sectionRefreshOwners.delete(section);
  }
  setSectionRefreshStatus(section, (document.getElementById(section + '-refresh-status') || {}).textContent || 'Loading snapshot…');
  const feedbackScope = viewFeedbackOwner('prepared-' + section, section + '-refresh-status');
  const owner = {section, url, controller: new AbortController(), feedbackScope, feedback:feedbackScope?.begin(url)};
  sectionRefreshOwners.set(section, owner);
  return owner;
}

function isSectionRefreshCurrent(owner){
  return !window.TraceAuth?.accessInvalidated && sectionRefreshOwners.get(owner.section) === owner && !owner.controller.signal.aborted;
}

function finishSectionRefresh(owner){
  if(isSectionRefreshCurrent(owner)) sectionRefreshOwners.delete(owner.section);
}

function failSectionRefresh(owner, error){
  if(isSectionRefreshCurrent(owner)){
    feedbackFailure(owner.feedbackScope, owner.feedback, error);
    const oversize = error?.status === 422;
    setSectionRefreshStatus(owner.section, oversize
      ? 'Prepared entry is too large (422). Previous data retained. Use the full JSON download below; no automatic fallback.'
      : 'Data may be stale. Refresh failed; will retry on the next refresh.');
  }
}

function cancelSectionRefreshes(exceptSection){
  for(const owner of sectionRefreshOwners.values()){
    if(owner.section === exceptSection) continue;
    owner.controller.abort();
    owner.feedbackScope?.invalidate();
    setSectionRefreshStatus(owner.section, 'Data may be stale. Refresh paused while hidden.');
    sectionRefreshOwners.delete(owner.section);
  }
}

document.addEventListener('visibilitychange', () => {
  if(document.hidden){ cancelSectionRefreshes(); cancelHistoryRead(); if(currentQuery) cancelQuery(); if(domainVerifyController) cancelDomainVerify(); suspendAnalysisView(); }
  else {
    resumeAnalysisView();
    if(!isPaused()) triggerSectionRefresh(getActiveSectionId());
  }
});
window.addEventListener('pagehide', () => { cancelSectionRefreshes(); cancelHistoryRead(); if(currentQuery) cancelQuery(); if(domainVerifyController) cancelDomainVerify(); suspendAnalysisView(); clearDomainAnalysisDetail(); setDomainAnalysisManageMode(false); });
window.addEventListener('pageshow', event => { if(event.persisted) resumeAnalysisView(); });

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
    refreshValidIPs();
    return;
  }
  if(name === 'domainanalysis'){
    refreshDomainAnalysis();
  }
}

function showSection(name){
  cancelSectionRefreshes(name);
  if(name !== 'domainanalysis' && getActiveSectionId()==='domainanalysis'){
    clearDomainAnalysisDetail(); setDomainAnalysisManageMode(false);
  }
  if(name !== 'ipintel' && getActiveSectionId()==='ipintel') suspendAnalysisView();
  if(name !== 'query' && currentQuery) cancelQuery();
  if(name !== 'domainverify' && domainVerifyController) cancelDomainVerify();
  document.getElementById('ipDetail')?.remove();
  if(name !== 'status') closeTargetDetail(false);
  ['settings','domainverify','status','query','domainanalysis','ipintel','ips','validips'].forEach(id=>document.getElementById(id).classList.remove('active'));
  document.getElementById(name).classList.add('active');
  if(name === 'ipintel'){
    if(suspendedAnalysisView) resumeAnalysisView();
    else setIpRelView('table');
  }
  Object.keys(SECTION_BUTTON_MAP).forEach(sec=>{
    const btn = document.getElementById(SECTION_BUTTON_MAP[sec]);
    if(!btn) return;
    btn.classList.toggle('active', sec === name);
    if(sec === name) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  });
  const currentView = document.getElementById('currentView');
  if(currentView) currentView.textContent = ({status:'Monitoring / Status', ips:'Monitoring / All IPs',
    validips:'Monitoring / Valid IPs', query:'Lookup / Query', domainverify:'Lookup / Domain Verify',
    domainanalysis:'Analysis / Domains', ipintel:'Analysis / IP relationships', settings:'Operations / Settings'})[name];
  const overview = document.getElementById('overviewGrid');
  if(overview) overview.hidden = name !== 'status';
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

function openViewAnchor(){
  const hash = window.location.hash;
  if(hash === '#settings-alerts'){
    showSection('settings');
    showSettingsTab('alerts');
    document.getElementById('settingsTabAlerts').focus();
  }
  const ids = hash === '#deliveryHealth' ? ['deliveryDisclosure','deliveryHeading']
    : hash === '#deliveryDiagnostics' ? ['deliveryOperations','diagnosticsHeading'] : null;
  if(!ids) return;
  const disclosure = document.getElementById(ids[0]);
  if(disclosure){
    disclosure.open = true;
    const heading = document.getElementById(ids[1]);
    heading.focus();
    heading.scrollIntoView({block:'nearest'});
  }
}
window.addEventListener('hashchange', openViewAnchor);
window.addEventListener('load', () => {
  if(['#deliveryHealth','#deliveryDiagnostics'].includes(window.location.hash)) openViewAnchor();
});

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
let ipIntelMispController = null;
let ipIntelMispSeq = 0;
let ipRelAnalyzeController = null;
let ipRelAnalyzeSeq = 0;
let ipIntelBusyCount = 0;


function setIpIntelBusy(isBusy){
  ipIntelBusyCount = Math.max(0, ipIntelBusyCount + (isBusy ? 1 : -1));
  const busy = ipIntelBusyCount > 0;
  ['runIpIntelBtn', 'runIpRelationshipBtn', 'loadIpIntelMispBtn'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.disabled = busy || el.hidden;
  });
}

function finalizeIpRelationshipRun(controller){
  const isCurrent = ipRelAnalyzeController === controller;
  if(isCurrent) ipRelAnalyzeController = null;
  setIpIntelBusy(false);
  return isCurrent;
}

function invalidateAnalysisAccess(){
  ++ipRelAnalyzeSeq; ++ipIntelAnalyzeSeq;
  ++ipIntelMispSeq; ipIntelMispController?.abort(); ipIntelMispController=null;
  for(const controller of [ipRelAnalyzeController,ipIntelAnalyzeController]){
    if(controller){controller.browserDetached=true;controller.abort();}
  }
  ipRelAnalyzeController=ipIntelAnalyzeController=null;
  ipRelActiveJobId=null;
  window.IP_REL_CACHE=window.IP_REL_LAST_SUCCESS=window.IP_INTEL_LAST_RESULT=null;
  window.IP_INTEL_INSIGHTS=window.IP_REL_MISP_CONTEXT=null;
  setIpRelView('table');
  renderIpIntelCachedEvidence();
  for(const selector of ['#ipRelPairsTable tbody','#ipRelClustersTable tbody','#ipIntelHintsBox','#ipIntelInvalidBox','#ipRelMeta','#ipIntelMeta','#ipIntelMispStatus']){
    const el=document.querySelector(selector); if(el) el.textContent='';
  }
  const input=document.getElementById('ipIntelInput'); if(input) input.value='';
  for(const id of ['ipRelMetricIps','ipRelMetricPairs','ipRelMetricClusters','ipRelMetricCoverage']){
    const el=document.getElementById(id); if(el) el.textContent='—';
  }
  setIpIntelResultState('idle','Access changed. Reload to check permissions.');
  setIpRelationshipRunState('idle','Access changed. Cached analysis was discarded; server work status is unknown.');
  const quality=document.getElementById('ipRelQualityBanner'); if(quality) quality.textContent='Analysis unavailable after access change.';
}

let suspendedAnalysisView = null;
function resumeAnalysisView(){
  if(!suspendedAnalysisView || document.hidden || getActiveSectionId() !== 'ipintel') return;
  const previous = suspendedAnalysisView;
  suspendedAnalysisView = null;
  if(window.TraceAuth?.accessInvalidated || !window.IP_REL_LAST_SUCCESS || window.IP_REL_CACHE !== window.IP_REL_LAST_SUCCESS) return;
  const active = document.activeElement;
  // Reconstruct only the selected bounded visualization; never rerun analysis.
  setIpRelView(previous.view);
  if(previous.focus && (active === document.body || active === previous.focus)){
    const target = previous.focus.isConnected ? previous.focus : document.getElementById(previous.tabId);
    target?.focus({preventScroll:true});
  }
}
function suspendAnalysisView(){
  if(!suspendedAnalysisView && getActiveSectionId() === 'ipintel'){
    const tab = ['Table','Graph','Map'].find(name=>document.getElementById('ipRelView'+name+'Btn')?.getAttribute('aria-selected') === 'true') || 'Table';
    suspendedAnalysisView = {view:tab.toLowerCase(), tabId:'ipRelView'+tab+'Btn',
      focus:document.getElementById('ipintel')?.contains(document.activeElement) ? document.activeElement : null};
  }
  cancelIpIntelInputReads();
  if(ipRelAnalyzeController){
    ipRelAnalyzeController.browserDetached=true;
    ipRelAnalyzeController.abort(); ++ipRelAnalyzeSeq;
    ipRelAnalyzeController=null; ipRelActiveJobId=null;
    localFeedbackOwners.get('ip-relationships')?.invalidate();
    restorePreviousIpRelationshipResult(window.IP_REL_LAST_SUCCESS,
      document.querySelector('#ipRelPairsTable tbody'),document.querySelector('#ipRelClustersTable tbody'));
    setIpRelationshipRunState('cancelled','Browser read stopped. Server work may continue; cancellation was not requested. Previous export, if present, is from the previous successful run.');
  }
  closeIpRelationshipEvidence(false); resetIpRelVisualCaches(); clearIpRelMapMarkers();
  for(const selector of ['#ipRelGraph','#ipRelGraphDetails','#ipRelPairsTable tbody','#ipRelClustersTable tbody']){
    const el=document.querySelector(selector); if(el) el.textContent='';
  }
  const evidence=document.getElementById('ipIntelEvidence'); if(evidence) evidence.open=false;
  renderIpIntelCachedEvidence();
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

function domainConfigIdentity(domainObj){
  if(!domainObj || typeof domainObj !== 'object'){
    return normalizeDomainName(domainObj);
  }
  const name = normalizeDomainName(domainObj.name);
  const type = String(domainObj.type || 'A').trim().toUpperCase() || 'A';
  if(type === 'RPC'){
    return `${String(domainObj.name || '').trim().toLowerCase()}|RPC|${domainObj.rpc_profile ?? 'polygon_aes_gcm_v1'}`;
  }
  if(type === 'DHT'){
    // A DHT name is a display label, not a DNS name (a trailing dot is literal).
    const label = String(domainObj.name || '').trim().toLowerCase();
    return `${label}|DHT|${String(domainObj.dht_public_key || '').toLowerCase()}`;
  }
  if(type === 'ENS'){
    const textKey = String(domainObj.ens_text_key || 'ipv6').trim() || 'ipv6';
    const node = String(domainObj.ens_node || '').trim().toLowerCase();
    const resolver = String(domainObj.ens_resolver || '').trim().toLowerCase();
    return `${name}|ENS|${textKey}|${node}|${resolver}`;
  }
  if(type === 'SNS'){
    const textKey = String(domainObj.ens_text_key || 'TXT').trim() || 'TXT';
    return `${name}|SNS|${textKey}`;
  }
  return name;
}

function domainStorageName(target){
  const name = String(typeof target === 'string' ? target : (target && target.name) || '').trim();
  if(target && String(target.type || '').toUpperCase() === 'RPC'){
    return `${name} [RPC:${target.rpc_profile ?? 'polygon_aes_gcm_v1'}]`;
  }
  if(target && String(target.type || '').toUpperCase() === 'DHT'){
    return `${name} [DHT:${String(target.dht_public_key || '').toLowerCase()}]`;
  }
  return name;
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

function parseDhtInputs(publicKey, optionsText){
  // Validate the literal token before any normalization or request.
  const key = String(publicKey || '');
  if(key.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(key)){
    return {ok: false, error: 'DHT public key must be exactly 64 hexadecimal characters (no prefix or whitespace)'};
  }
  const options = parseJsonObjectInput(optionsText, 'DHT lookup options');
  if(!options.ok) return options;
  const allowed = ['duration', 'max_queries', 'timeout', 'rate', 'concurrency', 'max_nodes', 'bootstraps'];
  const unknown = Object.keys(options.value || {}).filter(key=>!allowed.includes(key));
  if(unknown.length) return {ok: false, error: `Unknown DHT lookup options: ${unknown.join(', ')}`};
  const value = {dht_public_key: key};
  if(options.value !== null) value.dht_options = options.value;
  return {ok: true, value};
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
  const txtFallback = ['cafebabe_xor_base64','plain_base64','btea_variant','xor_ipstring_base64_fixedkey','ROT13_XOR0x30'];
  const aFallback = ['none','xor32_ipv4','2byte_swap'];
  const ensFallback = ['ipv6_5to8_xor', 'ipv6_last4_xor32', 'ROL3210_decode'];
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
  const snsSel = document.getElementById('verifySnsDecode');
  fillSelectWithOptions(txtSel, txtNames, (txtSel || {}).value || 'cafebabe_xor_base64');
  fillSelectWithOptions(aSel, aNames, (aSel || {}).value || 'none');
  fillSelectWithOptions(ensSel, ensNames, (ensSel || {}).value || 'ipv6_5to8_xor');
  fillSelectWithOptions(snsSel, ensNames, (snsSel || {}).value || 'ROL3210_decode');
  if(aSel && !aSel.value) aSel.value = 'none';
  if(ensSel && !ensSel.value) ensSel.value = 'ipv6_5to8_xor';
  if(snsSel && !snsSel.value) snsSel.value = 'ROL3210_decode';
}

function updateDomainVerifyInputMode(){
  const typeEl = document.getElementById('verifyDomainType');
  const txtEl = document.getElementById('verifyTxtDecode');
  const aEl = document.getElementById('verifyADecode');
  const xorEl = document.getElementById('verifyAXorKey');
  const ensKeyEl = document.getElementById('verifyEnsTextKey');
  const ensDecodeEl = document.getElementById('verifyEnsDecode');
  const ensOptionsEl = document.getElementById('verifyEnsOptions');
  const snsDecodeEl = document.getElementById('verifySnsDecode');
  const snsOptionsEl = document.getElementById('verifySnsOptions');
  if(!typeEl || !txtEl || !aEl || !xorEl || !ensKeyEl || !ensDecodeEl || !ensOptionsEl || !snsDecodeEl || !snsOptionsEl) return;
  const t = String(typeEl.value || 'AUTO').toUpperCase();
  const isAOnly = t === 'A';
  const isTxtOnly = t === 'TXT';
  const isEnsOnly = t === 'ENS';
  const isSnsOnly = t === 'SNS';
  const isDhtOnly = t === 'DHT';
  const isRpcOnly = t === 'RPC';
  const rpcProfile = document.getElementById('verifyRpcProfile');
  if(rpcProfile){ rpcProfile.disabled = !isRpcOnly; rpcProfile.parentElement.hidden = !isRpcOnly; }
  const rpcHelp = document.getElementById('verifyRpcHelp');
  if(rpcHelp) rpcHelp.hidden = !isRpcOnly;
  ['verifyDhtPublicKey', 'verifyDhtOptions'].forEach(id=>{
    const el = document.getElementById(id);
    if(el){ el.disabled = !isDhtOnly; el.parentElement.hidden = !isDhtOnly; }
  });
  const dhtHelp = document.getElementById('verifyDhtHelp');
  if(dhtHelp) dhtHelp.hidden = !isDhtOnly;
  const addButton = document.getElementById('addVerifiedDomainBtn');
  if(addButton) addButton.textContent = isDhtOnly ? 'Add DHT target' : (isRpcOnly ? 'Add RPC target' : '➕ Add Verified Domain');
  ['verifyAnalyzeDecoders', 'verifyDecoderTopN', 'verifyIncludeVt', 'verifyVtBudget', 'verifyVtWorkers'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.disabled = isDhtOnly || isRpcOnly;
  });
  txtEl.disabled = isAOnly || isEnsOnly || isSnsOnly || isDhtOnly || isRpcOnly;
  aEl.disabled = isTxtOnly || isEnsOnly || isSnsOnly || isDhtOnly || isRpcOnly;
  xorEl.disabled = isTxtOnly || isEnsOnly || isSnsOnly || isDhtOnly || isRpcOnly;
  ensKeyEl.disabled = !isEnsOnly;
  ensDecodeEl.disabled = !isEnsOnly;
  ensOptionsEl.disabled = !isEnsOnly;
  snsDecodeEl.disabled = !isSnsOnly;
  snsOptionsEl.disabled = !isSnsOnly;
  [txtEl, aEl, xorEl, ensKeyEl, ensDecodeEl, ensOptionsEl, snsDecodeEl, snsOptionsEl].forEach(el=>{
    el.parentElement.hidden = el.disabled;
  });
}

function initDomainVerifyUi(){
  renderDomainAddOutcome();
  syncDomainVerifyDecoderOptions();
  updateDomainVerifyInputMode();
  const form = document.getElementById('domainverify');
  if(form && !form._verifyBound){
    form._verifyBound = true;
    const edited = event=>{
      if(!event.target.matches('input, select, textarea')) return;
      cancelDomainVerify();
      setDomainVerifyStatus('Inputs changed — validate again before adding.', '');
    };
    form.addEventListener('input', edited);
    form.addEventListener('change', edited);
    window.TraceAuth?.onInvalidated?.(()=>cancelDomainVerify());
    updateDomainVerifyAddButton();
  }
  document.querySelectorAll('#domainverify .verify-evidence').forEach(panel=>{
    if(panel._verifyBound) return;
    panel._verifyBound = true;
    panel.addEventListener('toggle', ()=>{
      if(panel.open) document.querySelectorAll('#domainverify .verify-evidence').forEach(other=>{
        if(other !== panel) other.open = false;
      });
      renderDomainVerifyEvidence(window.DOMAIN_VERIFY_LAST);
    });
  });
}

function renderDomainVerifyEvidence(result){
  renderDomainVerifyDecoderTable(result);
  renderDomainVerifyServerTable(result);
  renderDomainVerifyIpTable(result);
  const raw = document.getElementById('verifyRaw');
  if(raw) raw.querySelector('pre').textContent = raw.open && result ? JSON.stringify(result, null, 2) : '';
}

// One mounted evidence page. The response remains intact for raw inspection;
// paging and disclosure only project cached data and never perform I/O.
function domainVerifyPage(result, field, panelId, render){
  const panel = document.getElementById(panelId);
  if(!panel || !panel.open){
    panel?.querySelector('.verify-pager')?.remove();
    return null;
  }
  const rows = Array.isArray(result?.[field]) ? result[field] : [];
  if(panel._verifyResult !== result){ panel._verifyResult = result; panel._verifyOffset = 0; }
  const offset = panel._verifyOffset || 0;
  let pager = panel.querySelector('.verify-pager');
  if(!pager){
    pager = document.createElement('div'); pager.className = 'verify-pager';
    panel.querySelector('table').before(pager);
  }
  pager.replaceChildren();
  const previous = document.createElement('button'); previous.type = 'button'; previous.textContent = 'Previous';
  previous.disabled = offset === 0;
  previous.onclick = ()=>{ panel._verifyOffset = Math.max(0, offset - 8); render(result); };
  const next = document.createElement('button'); next.type = 'button'; next.textContent = 'Next';
  next.disabled = offset + 8 >= rows.length;
  next.onclick = ()=>{ panel._verifyOffset = offset + 8; render(result); };
  const range = document.createElement('span'); range.setAttribute('role', 'status');
  range.textContent = `${rows.length ? offset + 1 : 0}–${Math.min(offset + 8, rows.length)} of ${rows.length}`;
  pager.append(previous, range, next);
  return rows.slice(offset, offset + 8);
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
    `Registration: ${result.can_add === false ? 'not eligible' : 'eligible'} — lookup success and registration eligibility are separate.`,
  ];
  if(selectedType === 'DHT'){
    const target = result.domain_object || result.domain_obj || {};
    lines.push(dhtEvidenceText({...target, ...result}, result.dht_observation));
  }
  if(selectedType === 'RPC') lines.push(rpcEvidenceText(result, result.rpc_observation));
  if(notes.length){
    lines.push(`Notes: ${notes.join(' | ')}`);
  }
  el.textContent = lines.join('\n');
}

function renderDomainVerifyServerTable(result){
  const body = document.querySelector('#domainVerifyServerTable tbody');
  if(!body) return;
  body.innerHTML = '';
  const rows = domainVerifyPage(result, 'by_server', 'verifyServers', renderDomainVerifyServerTable);
  if(rows === null) return;
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
    tdVals.textContent = values.join(', ') || '-';
    tdVals.title = values.join(', ');
    const tdManaged = document.createElement('td');
    renderCellWithClickableIps(tdManaged, Array.isArray(row.managed_ips) ? row.managed_ips : [], formatListPreview(row.managed_ips || [], 4), 6);
    const tdMethod = document.createElement('td');
    tdMethod.className = 'wrap-cell';
    if(rowErr){
      tdMethod.textContent = `${row.method || '-'} | ERROR: ${rowErr}`;
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
  const rows = domainVerifyPage(result, 'ip_rows', 'verifyIps', renderDomainVerifyIpTable);
  if(rows === null) return;
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
  const rows = domainVerifyPage(result, 'decoder_candidates', 'verifyCandidates', renderDomainVerifyDecoderTable);
  if(rows === null) return;
  if(!rows.length){
    setSummaryMessage(body, 8, 'No decoder analysis (disable "Try all decoders" or no TXT/A values)');
    return;
  }
  rows.forEach(row=>{
    const tr = document.createElement('tr');


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

    const apply = document.createElement('button');
    apply.type = 'button'; apply.textContent = 'Apply decoder and validate';
    tdN.appendChild(apply);
    apply.onclick = async ()=>{
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

let domainVerifyGeneration = 0;
let domainVerifyController = null;
let domainAddPending = null;
let domainAddUncertain = false;
try { domainAddUncertain = sessionStorage.getItem('tracedns.verify-add-uncertain') === '1'; } catch (_) { /* Memory still owns the notice. */ }
let domainAddReviewGeneration = 0;
function setDomainAddUncertain(value){
  domainAddUncertain = value;
  try {
    if(value) sessionStorage.setItem('tracedns.verify-add-uncertain', '1');
    else sessionStorage.removeItem('tracedns.verify-add-uncertain');
  } catch (_) { /* Storage may be unavailable; never discard in-memory uncertainty. */ }
  renderDomainAddOutcome();
}
function renderDomainAddOutcome(){
  let panel = document.getElementById('domainVerifyAddOutcome');
  if(!panel){
    panel = viewNode('section'); panel.id = 'domainVerifyAddOutcome';
    const notice = viewNode('p', 'The submitted Add outcome is unknown. Do not retry blindly. Review the saved targets, then explicitly acknowledge reconciliation. The Settings draft and revision are unchanged.');
    notice.setAttribute('role', 'status');
    const review = viewNode('button', 'Review saved targets'); review.id = 'reconcileVerifiedDomainBtn';
    const saved = viewNode('pre'); saved.id = 'domainVerifySavedTargets';
    const acknowledge = viewNode('button', 'I reviewed saved targets; reconciliation complete');
    acknowledge.id = 'acknowledgeVerifiedDomainBtn'; acknowledge.disabled = true;
    review.onclick = async ()=>{
      if(domainAddPending || window.TraceAuth?.accessInvalidated) return;
      const generation = ++domainAddReviewGeneration;
      acknowledge.disabled = true; saved.textContent = '';
      try {
        const data = await window.TraceAuth.readJSON('/config');
        if(generation !== domainAddReviewGeneration || window.TraceAuth?.accessInvalidated) return;
        if(!Array.isArray(data.domains) || !Number.isSafeInteger(data.revision)) throw new Error('Invalid saved configuration');
        saved.textContent = JSON.stringify({revision:data.revision, domains:data.domains}, null, 2);
        acknowledge.disabled = false;
      } catch (_) {
        if(generation === domainAddReviewGeneration && !window.TraceAuth?.accessInvalidated) saved.textContent = 'Saved targets could not be checked. Outcome remains unknown.';
      }
    };
    acknowledge.onclick = ()=>{
      if(acknowledge.disabled || domainAddPending || window.TraceAuth?.accessInvalidated) return;
      saved.textContent = ''; acknowledge.disabled = true;
      setDomainAddUncertain(false); updateDomainVerifyAddButton();
    };
    panel.append(notice, review, saved, acknowledge);
    document.getElementById('domainVerifyStatus').after(panel);
  }
  panel.hidden = !domainAddUncertain;
  document.getElementById('reconcileVerifiedDomainBtn').disabled = !!domainAddPending || !!window.TraceAuth?.accessInvalidated;
}
function updateDomainVerifyAddButton(){
  const state = window.DOMAIN_VERIFY_LAST;
  const button = document.getElementById('addVerifiedDomainBtn');
  if(button) button.disabled = !!domainAddPending || domainAddUncertain || !!window.TraceAuth?.accessInvalidated || !state || state.can_add === false || !(state.domain_object || state.domain_obj)?.name;
}

// Also available to the shell when leaving/replacing this view. Aborting a
// browser read does not claim cancellation of server/provider work.
function cancelDomainVerify(){
  ++domainAddReviewGeneration;
  document.getElementById('domainVerifySavedTargets')?.replaceChildren();
  const acknowledge = document.getElementById('acknowledgeVerifiedDomainBtn');
  if(acknowledge) acknowledge.disabled = true;
  ++domainVerifyGeneration;
  domainVerifyController?.abort();
  domainVerifyController = null;
  localFeedbackOwners.get('domain-verify')?.invalidate();
  localFeedbackOwners.get('domain-verify-add')?.invalidate();
  window.DOMAIN_VERIFY_LAST = null;
  setDomainVerifyStatus('', '');
  renderDomainVerifySummary(null);
  document.querySelectorAll('#domainverify .verify-evidence').forEach(panel=>{
    panel._verifyResult = null; panel._verifyOffset = 0; panel.open = false;
  });
  renderDomainVerifyEvidence(null);
  updateDomainVerifyAddButton();
  renderDomainAddOutcome();
}

function clearDomainVerifyResult(){ cancelDomainVerify(); }

async function runDomainVerify(){
  cancelDomainVerify();
  if(window.TraceAuth?.accessInvalidated) return;
  const generation = domainVerifyGeneration;
  const controller = new AbortController();
  domainVerifyController = controller;
  const feedback = viewFeedbackOwner('domain-verify', 'domainVerifyStatus');
  const token = feedback?.begin(JSON.stringify([...document.querySelectorAll('#domainverify input, #domainverify select, #domainverify textarea')].map(el=>[el.id, el.value, el.checked])));
  const current = ()=>generation === domainVerifyGeneration && !controller.signal.aborted && feedbackCurrent(token);
  const domain = String((document.getElementById('verifyDomainName') || {}).value || '').trim();
  if(!domain){
    setDomainVerifyStatus('Domain is required', 'err');
    return;
  }
  updateDomainVerifyInputMode();
  const type = String((document.getElementById('verifyDomainType') || {}).value || 'AUTO').toUpperCase();
  const txtDecode = String((document.getElementById('verifyTxtDecode') || {}).value || '').trim();
  const aDecode = String((document.getElementById('verifyADecode') || {}).value || 'none').trim();
  const aXorKey = String((document.getElementById('verifyAXorKey') || {}).value || '').trim();
  const ensTextKey = String((document.getElementById('verifyEnsTextKey') || {}).value || '').trim();
  const ensDecode = String((document.getElementById('verifyEnsDecode') || {}).value || 'ipv6_5to8_xor').trim();
  const ensOptionsRaw = String((document.getElementById('verifyEnsOptions') || {}).value || '').trim();
  const snsDecode = String((document.getElementById('verifySnsDecode') || {}).value || 'ROL3210_decode').trim();
  const snsOptionsRaw = String((document.getElementById('verifySnsOptions') || {}).value || '').trim();
  let ensOptions = null;
  let snsOptions = null;
  let dhtFields = {};
  if(type === 'DHT'){
    const dht = parseDhtInputs((document.getElementById('verifyDhtPublicKey') || {}).value, (document.getElementById('verifyDhtOptions') || {}).value);
    if(!dht.ok){
      setDomainVerifyStatus(dht.error, 'err');
      return;
    }
    dhtFields = dht.value;
  }else if(type === 'ENS'){
    const parsedEnsOptions = parseJsonObjectInput(ensOptionsRaw, 'ENS options');
    if(!parsedEnsOptions.ok){
      setDomainVerifyStatus(parsedEnsOptions.error, 'err');
      return;
    }
    ensOptions = parsedEnsOptions.value;
  }else if(type === 'SNS'){
    const parsedSnsOptions = parseJsonObjectInput(snsOptionsRaw, 'SNS options');
    if(!parsedSnsOptions.ok){
      setDomainVerifyStatus(parsedSnsOptions.error, 'err');
      return;
    }
    snsOptions = parsedSnsOptions.value;
  }
  const includeVt = !['DHT','RPC'].includes(type) && !!((document.getElementById('verifyIncludeVt') || {}).checked);
  const analyzeDecoders = !['DHT','RPC'].includes(type) && !!((document.getElementById('verifyAnalyzeDecoders') || {}).checked);
  const decoderTopN = parseBoundedInt((document.getElementById('verifyDecoderTopN') || {}).value, 8, 1, 50);
  const vtBudget = parseBoundedInt((document.getElementById('verifyVtBudget') || {}).value, 200, 0, 5000);
  const vtWorkers = parseBoundedInt((document.getElementById('verifyVtWorkers') || {}).value, 8, 1, 32);

  setDomainVerifyStatus('Validating...', '');
  try{
    const r = await fetch('/domain-precheck', {
      method: 'POST',
      signal: controller.signal,
      feedback: token,
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        domain: domain,
        type: type,
        ...dhtFields,
        ...(type === 'RPC' ? {rpc_profile:document.getElementById('verifyRpcProfile').value} : {}),
        txt_decode: txtDecode,
        a_decode: aDecode,
        a_xor_key: aXorKey,
        ens_text_key: ensTextKey,
        ens_decode: ensDecode,
        ens_options: ensOptions,
        sns_decode: snsDecode,
        sns_options: snsOptions,
        include_vt: includeVt,
        analyze_decoders: analyzeDecoders,
        decoder_top_n: decoderTopN,
        vt_lookup_budget: vtBudget,
        vt_workers: vtWorkers
      })
    });
    const j = await r.json();
    if(!current()) return;
    if(!r.ok || !j || j.error || typeof j.can_add !== 'boolean'){
      const msg = 'Validation failed. No usable result was returned; validate again explicitly.';
      feedbackFailure(feedback, token, {status:r.status});
      setDomainVerifyStatus(msg, 'err');
      window.DOMAIN_VERIFY_LAST = null;
      renderDomainVerifySummary({error: msg});
      renderDomainVerifyDecoderTable({decoder_candidates: []});
      renderDomainVerifyServerTable({by_server: []});
      renderDomainVerifyIpTable({ip_rows: []});
      return;
    }
    window.DOMAIN_VERIFY_LAST = j;
    feedback?.succeed(token);
    updateDomainVerifyAddButton();
    renderDomainVerifySummary(j);
    renderDomainVerifyDecoderTable(j);
    renderDomainVerifyServerTable(j);
    renderDomainVerifyIpTable(j);
    if(type === 'DHT'){
      const status = String((j.dht_observation || {}).status || 'unknown');
      const confirmed = ['initial', 'updated', 'unchanged'].includes(status);
      setDomainVerifyStatus(`Validation complete — DHT lookup: ${status}; ${j.can_add === false ? 'configuration cannot be added' : 'configuration can be added (not proof of retrieval)'}`, confirmed && j.can_add !== false ? 'ok' : 'err');
    }else if(type === 'RPC'){
      const status = String((j.rpc_observation || {}).status || 'error');
      setDomainVerifyStatus(`Validation complete — RPC lookup: ${status}; ${j.can_add === false ? 'configuration cannot be added' : 'configuration can be added (not proof of retrieval)'}`, status === 'authenticated' && j.can_add !== false ? 'ok' : 'err');
    }else{
      setDomainVerifyStatus(j.can_add === false ? 'Validation complete (no addable IP)' : 'Validation complete', j.can_add === false ? 'err' : 'ok');
    }
  }catch(e){
    if(!current()) return;
    feedbackFailure(feedback, token, e);
    const msg = 'Validation failed. '+(feedback?.snapshot().error?.message || 'The browser read did not complete.');
    setDomainVerifyStatus(msg, 'err');
    window.DOMAIN_VERIFY_LAST = null;
    renderDomainVerifySummary({error: msg});
    renderDomainVerifyDecoderTable({decoder_candidates: []});
    renderDomainVerifyServerTable({by_server: []});
    renderDomainVerifyIpTable({ip_rows: []});
  }
}

async function addVerifiedDomainToConfig(){
  if(domainAddPending || domainAddUncertain || window.TraceAuth?.accessInvalidated) return;
  const state = window.DOMAIN_VERIFY_LAST || {};
  const domainObj = state.domain_object || state.domain_obj;
  if(!domainObj || !domainObj.name){
    setDomainVerifyStatus('Validate first, then add', 'err');
    return;
  }
  if(state.can_add === false){
    setDomainVerifyStatus('Validation has no resolvable result to add', 'err');
    return;
  }
  const feedback = viewFeedbackOwner('domain-verify-add', 'domainVerifyStatus');
  const token = feedback?.begin(domainConfigIdentity(domainObj));
  const generation = domainVerifyGeneration;
  const signal = domainVerifyController?.signal;
  const current = ()=>generation === domainVerifyGeneration && state === window.DOMAIN_VERIFY_LAST && feedbackCurrent(token);
  const button = document.getElementById('addVerifiedDomainBtn');
  const operation = domainAddPending = {};
  button.disabled = true;
  let submitted = false;
  try{
    const cfgResp = await fetch('/config', {feedback:token, signal});
    const cfgJson = await cfgResp.json();
    if(!current()) return;
    if(!cfgResp.ok || !cfgJson){
      setDomainVerifyStatus('Failed to load config', 'err');
      return;
    }
    const existing = Array.isArray(cfgJson.domains) ? cfgJson.domains : [];
    const targetIdentity = domainConfigIdentity(domainObj);
    const normalizedDomains = existing.map(item=>{
      if(typeof item === 'string'){
        return {name: item, type: 'A'};
      }
      return (item && typeof item === 'object') ? {...item} : null;
    }).filter(Boolean);

    const idx = normalizedDomains.findIndex(d=> domainConfigIdentity(d) === targetIdentity);
    if(idx >= 0){
      normalizedDomains[idx] = {...domainObj};
    } else {
      normalizedDomains.push({...domainObj});
    }
    const payload = {
      domains: normalizedDomains,
      revision: cfgJson.revision
    };
    submitted = true;
    // Only a non-sensitive uncertainty marker persists across reloads.
    setDomainAddUncertain(true);
    const saveResp = await fetch('/config', {
      // A submitted write outlives the replaceable validation/read owner.
      method: 'POST',
      feedback: token,
      signal,
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const saveJson = await saveResp.json();
    if(!current()) return;
    if(!saveResp.ok || !saveJson || saveJson.error || !Number.isSafeInteger(saveJson.revision)){
      throw new Error((saveJson && saveJson.error) ? saveJson.error : `save failed (${saveResp.status})`);
    }
    feedback?.succeed(token);
    setDomainAddUncertain(false);
    setDomainVerifyStatus((idx >= 0 ? 'Updated existing domain' : 'Added domain')+commitWarningText(saveJson), 'ok');
    // Verify uses its own fresh revision; it must never rebase the settings form.
    document.getElementById('domainSettingsStatus').textContent = 'Saved configuration changed in Verify. Displayed draft and revision retained; Load explicitly to review saved targets.';
    if(window.TraceDeliveryResend) window.TraceDeliveryResend.invalidateConfig();
    uiOverview.configured = normalizedDomains.length;
    updateOverviewPanel();
  }catch(e){
    if(!current()) return;
    feedbackFailure(feedback, token, e, submitted);
    setDomainVerifyStatus(`Add failed: ${feedback?.snapshot().error?.message || e}`, 'err');
  }finally{
    if(domainAddPending === operation) domainAddPending = null;
    renderDomainAddOutcome();
    if(current()) updateDomainVerifyAddButton();
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

let currentQuery = null;
const queryResultViews = new Map();
const queryParts = {local:['queryResult','queryLocalStatus'], history:['queryHistoryResult','queryHistoryStatus'], misp:['queryMispResult','queryMispStatus']};
function cancelQuery(message = 'Browser read cancelled. Already dispatched provider work may finish; previous results, if any, are stale.'){
  if(currentQuery){
    currentQuery.controller.abort();
    for(const part of Object.values(currentQuery.parts)) part.scope?.invalidate();
    currentQuery = null;
  }
  const status=document.getElementById('queryStatus'); if(status) status.textContent=message;
  const cancel=document.getElementById('cancelQuery'); if(cancel) cancel.disabled=true;
}
function renderQueryList(part, value, rows){
  const root=document.getElementById(queryParts[part][0]);
  const projection={value,rows}; queryResultViews.set(part,projection);
  const render=offset=>{
    if(queryResultViews.get(part)!==projection) return;
    const fragment=document.createDocumentFragment();
    const empty=part==='local'?'No current matches':part==='history'?'No history matches':'No MISP matches';
    fragment.appendChild(viewNode('p',`${rows.length ? rows.length+' matches' : empty} · query: ${value} · ${rows.length ? `showing ${offset+1}–${Math.min(offset+50,rows.length)}` : 'recorded data only'}`));
    for(const [label,next] of [['Previous matches',offset-50],['Next matches',offset+50]]){
      const button=viewNode('button',label); button.disabled=next<0 || next>=rows.length;
      button.onclick=()=>render(next); fragment.appendChild(button);
    }
    rows.slice(offset,offset+50).forEach(row=>{
      const title=part==='misp'?`${row.value || 'value unknown'} · ${row.type || 'type unknown'} · event ${row.event_id || 'unknown'}`
        : `${row.domain || 'target unknown'} · ${row.rtype || row.type || 'observation'} · ${formatUnixTsLocal(row.ts)}`;
      fragment.appendChild(lazyViewDetails(title,body=>{
        if(queryResultViews.get(part)===projection) body.appendChild(viewNode('pre',JSON.stringify(row,null,2)));
      }));
    });
    root.replaceChildren(fragment);
  };
  render(0);
}
async function runQuery(v){
  const value=String(v || '').trim();
  if(!value){ document.getElementById('queryStatus').textContent='Enter a search value.'; return; }
  cancelQuery();
  const owner={value,controller:new AbortController(),parts:{}}; currentQuery=owner;
  const current=()=>currentQuery===owner && !owner.controller.signal.aborted;
  for(const [part,[root,id]] of Object.entries(queryParts)){
    const scope=viewFeedbackOwner('query-'+part,id);
    owner.parts[part]={scope,token:scope?.begin(value)};
    if(queryResultViews.get(part)?.value!==value){queryResultViews.delete(part);document.getElementById(root).replaceChildren();}
    document.getElementById(id).textContent=`Reading ${part} for ${value}…${queryResultViews.has(part)?' Previous result is stale.':''}`;
  }
  document.getElementById('queryStatus').textContent=`Searching ${isIPv4(value)?'IPv4 index':'text fragment'}: ${value}. Local and MISP outcomes are independent.`;
  document.getElementById('cancelQuery').disabled=false;
  const read=(part,url)=>window.TraceAuth.readJSON(url,{signal:owner.controller.signal,feedback:owner.parts[part].token});
  const success=(part,rows,text)=>{
    if(!current()) return;
    renderQueryList(part,value,rows); owner.parts[part].scope?.succeed(owner.parts[part].token);
    document.getElementById(queryParts[part][1]).textContent=text+' · last read (browser): '+new Date().toISOString();
  };
  const failed=(part,error,text)=>{
    if(!current()) return;
    feedbackFailure(owner.parts[part].scope,owner.parts[part].token,error);
    document.getElementById(queryParts[part][1]).textContent=text+' Previous results, if any, are stale. Search again explicitly.';
  };
  const local=async()=>{
    let domains;
    try{
      if(isIPv4(value)){
        const data=await read('local','/ip?ip='+encodeURIComponent(value));
        if(!Array.isArray(data.matches)) throw new Error('Invalid local index');
        success('local',data.matches.filter(row=>row.type==='current'),'Current read complete');
        success('history',data.matches.filter(row=>row.type==='history'),'History index read complete');
        return;
      }
      const data=await read('local','/results?aggregate=1');
      if(!data.results_agg || typeof data.results_agg!=='object' || Array.isArray(data.results_agg)) throw new Error('Invalid aggregate');
      domains=Object.keys(data.results_agg);
      const matches=[];
      for(const domain of domains){
        const info=data.results_agg[domain];
        if([...(info.values||[]),...(info.decoded_ips||[])].some(item=>String(item).includes(value))) matches.push({domain,...info});
      }
      success('local',matches,'Current read complete; currently listed targets only');
    }catch(error){
      failed('local',error,'Current read failed.');
      failed('history',error,'History not searched: current target list or IP index unavailable.');
      return;
    }
    const history=[]; let failures=0;
    for(const domain of domains){
      if(!current()) return;
      try{
        const data=await read('history','/history?domain='+encodeURIComponent(domain));
        const events=Array.isArray(data.history)?data.history:(data.history?.events || []);
        if(!Array.isArray(events)) throw new Error('Invalid history');
        for(const event of events){
          if([...(event.new?.values||[]),...(event.old?.values||[]),...(event.values||[])].some(item=>String(item).includes(value))) history.push({domain,...event});
        }
      }catch(error){
        if(!current()) return;
        failures++; feedbackFailure(owner.parts.history.scope,owner.parts.history.token,error);
      }
    }
    if(!current()) return;
    if(failures){
      renderQueryList('history',value,history);
      document.getElementById('queryHistoryStatus').textContent=`History partial: ${failures} of ${domains.length} target reads failed. Only successful target histories are represented; search again explicitly.`;
    }else success('history',history,`History read complete for ${domains.length} currently listed targets; not global history search`);
  };
  const misp=async()=>{
    try{
      const user=await window.TraceAuth.ready;
      if(!current()) return;
      if(window.TraceAuth.accessInvalidated || !['admin','operator'].includes(user?.role)){
        document.getElementById('queryMispStatus').textContent='MISP requires operator/admin access; no external request made.';
        return;
      }
      const data=await read('misp','/misp/search?value='+encodeURIComponent(value));
      if(data.status!=='ok' || !Array.isArray(data.attributes)) throw new Error('Invalid MISP result');
      success('misp',data.attributes,'MISP read complete; external source, not local observation');
    }catch(error){ failed('misp',error,'MISP read failed.'); }
  };
  await Promise.all([local(),misp()]);
  if(current()){
    document.getElementById('cancelQuery').disabled=true;
    document.getElementById('queryStatus').textContent=`Search finished for ${value}. Check each source status for failures or partial coverage.`;
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

// Domain Analysis owns only cached-page selection and disclosures. No disclosure
// starts a request. Page/query changes retire these nodes before a new read.
let domainAnalysisPageKey = '';
let domainAnalysisPageReady = false;
let domainAnalysisManageMode = false;
let domainAnalysisManageEpoch = 0;
let domainAnalysisRemovalPending = false;
function canManageDomainAnalysis(){
  return !window.TraceAuth?.accessInvalidated && ['admin', 'operator'].includes(window.TraceAuth?.user?.role);
}
function setDomainAnalysisManageMode(enabled){
  domainAnalysisManageMode = !!enabled && domainAnalysisPageReady && canManageDomainAnalysis();
  domainAnalysisManageEpoch++;
  if(!domainAnalysisManageMode){
    getDomainAnalysisSelectionSet().clear();
    localFeedbackOwners.get('domain-remove')?.invalidate();
  }
  const button = document.getElementById('domainAnalysisManageBtn');
  if(button){
    button.hidden = !canManageDomainAnalysis();
    button.textContent = domainAnalysisManageMode ? 'Close management' : 'Manage domains';
    button.setAttribute('aria-expanded', String(domainAnalysisManageMode));
  }
  document.getElementById('domainAnalysisManageTools').hidden = !domainAnalysisManageMode;
  applyDomainAnalysisFilter();
}
window.TraceAuth?.onInvalidated?.(()=>{
  window.DOMAIN_ANALYSIS_CACHE = [];
  domainAnalysisPageReady = false;
  domainAnalysisPageKey = '';
  populateDomainAnalysisFilter([]);
  setDomainAnalysisManageMode(false);
  clearDomainAnalysisDetail();
});
function clearDomainAnalysisDetail(restoreFocus=false){
  const select = document.getElementById('domainAnalysisDomainSelect');
  const previous = select?.value;
  if(select) select.value = '';
  const detail = document.getElementById('domainAnalysisDetail');
  if(detail){ detail.replaceChildren(); detail.hidden = true; detail._signature = null; }
  const summary = document.getElementById('domainAnalysisSummaries');
  if(summary){ summary.open = false; summary._signature = null; summary.ontoggle = null; }
  document.getElementById('domainAnalysisSummaryContent')?.replaceChildren();
  if(restoreFocus){
    applyDomainAnalysisFilter();
    const row = Array.from(document.querySelectorAll('#domainDomainStatsTable tbody tr')).find(row=>row.dataset.domain === previous);
    row?.querySelector('button')?.focus();
  }
}

function populateDomainAnalysisFilter(domains, commits=null){
  const sel = document.getElementById('domainAnalysisDomainSelect');
  if(!sel) return '';
  const prev = String(sel.value || '');
  const names = Array.from(new Set((domains || []).map(d=>String((d && d.domain) || '')).filter(Boolean))).sort();
  const selected = names.includes(prev) ? prev : '';
  // Preserve the select and its options on same-owner full or unchanged reads.
  const signature = JSON.stringify(names);
  if(sel._signature === signature) return selected;
  const options = [viewNode('option', 'Select a domain on this page')];
  options[0].value = '';
  names.forEach(name=>{ const option = viewNode('option', name); option.value = name; options.push(option); });
  const commit = ()=>{ sel.replaceChildren(...options); sel.value = selected; sel._signature = signature; };
  if(commits) commits.push(commit); else commit();
  return selected;
}

function renderDomainStatsTable(allDomains, selectedDomain, commits=null){
  const tbody = document.querySelector('#domainDomainStatsTable tbody');
  if(!tbody) return;
  const arr = Array.isArray(allDomains) ? allDomains.slice(0, 200) : [];
  const selectedSet = getDomainAnalysisSelectionSet();
  const manage = domainAnalysisManageMode && canManageDomainAnalysis();
  arr.sort((a,b)=>String(a.domain || '').localeCompare(String(b.domain || '')));
  const items = arr.map(d=>({key:d.domain, time:d.last_ts, value:d, content:{domain:rowContentWithoutTime(d, 'last_ts'), selected:selectedDomain === d.domain, checked:selectedSet.has(d.domain), manage, available:domainAnalysisPageReady}}));
  reconcilePreparedRows(tbody, items, item=>{
    const d = item.value, name = String(d.domain || '');
    const nonResolving = isDomainNonResolving(d);
    const status = getDomainLifecycleStatus(d);
    const tr = viewNode('tr'); tr.dataset.domain = name;
    tr.classList.toggle('is-selected', name === selectedDomain);
    const domain = viewNode('td', name); applyNxdomainLifecycleStyle(domain, d, name);
    const state = viewNode('td');
    const badge = viewNode('span', status.label === 'Normal' && nonResolving ? 'No-data' : status.label);
    badge.className = `domain-state-badge ${status.label === 'Normal' && nonResolving ? 'error' : status.cls}`;
    state.append(badge);
    if(d.ip_rows_total != null){
      const count = Array.isArray(d.ip_rows) ? d.ip_rows.length : 0;
      const offset = Number(d.ip_rows_offset || 0);
      state.append(viewNode('span', ` — IP rows ${count ? offset + 1 : 0}-${offset + count} / ${d.ip_rows_total}${d.ip_rows_truncated ? ' (partial domain)' : ''}`));
    }
    const actions = viewNode('td');
    const view = viewNode('button', name === selectedDomain ? 'Viewing' : 'View');
    view.setAttribute('aria-pressed', String(name === selectedDomain));
    view.disabled = !domainAnalysisPageReady;
    view.onclick = ()=>{
      if(window.TraceAuth?.accessInvalidated || !domainAnalysisPageReady || !view.isConnected) return;
      document.getElementById('domainAnalysisDomainSelect').value = name;
      applyDomainAnalysisFilter();
      document.querySelector('#domainAnalysisDetail h4')?.focus();
    };
    actions.append(view);
    if(manage){
      const check = viewNode('input'); check.type = 'checkbox';
      check.disabled = !nonResolving; check.checked = nonResolving && selectedSet.has(name);
      check.setAttribute('aria-label', `Select ${name} for removal`);
      check.onchange = ()=>{
        if(!check.isConnected || !domainAnalysisManageMode || !canManageDomainAnalysis()) return;
        if(check.checked) getDomainAnalysisSelectionSet().add(name); else getDomainAnalysisSelectionSet().delete(name);
        applyDomainAnalysisFilter();
      };
      const remove = viewNode('button', d.nxdomain_active ? 'Remove NX' : 'Remove');
      remove.disabled = !nonResolving;
      remove.onclick = ()=>removeDomainsFromConfig([name], `${name} removed`);
      actions.append(check, remove);
    }
    tr.append(domain, state, viewNode('td', (d.record_types || []).join(', ') || '-'), viewNode('td', formatUnixTsLocal(d.last_ts)), actions);
    return tr;
  }, 3, commits);
}

function domainAnalysisDisclosure(id, title, build){
  const details = viewNode('details'); details.id = id;
  const body = viewNode('div');
  details.append(viewNode('summary', title), body);
  details.ontoggle = ()=>{
    body.replaceChildren();
    if(!window.TraceAuth?.accessInvalidated && domainAnalysisPageReady && details.open && details.isConnected) build(body);
  };
  return details;
}

function mountDomainAnalysisPage(root, id, headers, rows, pageSize){
  const tools = viewNode('div'); tools.className = 'domain-analysis-tools';
  const prev = viewNode('button', 'Previous'), next = viewNode('button', 'Next'), label = viewNode('span');
  label.setAttribute('role', 'status');
  tools.append(prev, next, label);
  const table = viewNode('table'); table.id = id;
  const head = viewNode('thead'), heading = viewNode('tr'), body = viewNode('tbody');
  headers.forEach(text=>heading.append(viewNode('th', text))); head.append(heading); table.append(head, body);
  root.append(tools, table);
  let offset = 0;
  const render = ()=>{
    body.replaceChildren();
    rows.slice(offset, offset + pageSize).forEach(values=>{
      const tr = viewNode('tr'); values.forEach(value=>tr.append(viewNode('td', String(value ?? '-')))); body.append(tr);
    });
    label.textContent = `${rows.length ? offset + 1 : 0}-${Math.min(offset + pageSize, rows.length)} / ${rows.length} cached rows`;
    prev.disabled = offset === 0; next.disabled = offset + pageSize >= rows.length;
  };
  prev.onclick = ()=>{ if(root.isConnected && offset > 0){ offset -= pageSize; render(); } };
  next.onclick = ()=>{ if(root.isConnected && offset + pageSize < rows.length){ offset += pageSize; render(); } };
  render();
}

function renderDomainAnalysisSummaries(domains, includeVT, commits=null, selected=''){
  const disclosure = document.getElementById('domainAnalysisSummaries');
  const root = document.getElementById('domainAnalysisSummaryContent');
  if(!disclosure || !root) return;
  const signature = JSON.stringify([domainAnalysisPageKey, selected, includeVT, domains]);
  if(disclosure._signature === signature) return;
  const build = ()=>{
    if(!includeVT){ root.append(viewNode('p', 'VT context is disabled for this cached page.')); return; }
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

    const tables = [
      ['domainAsSummaryTable', 'AS groups', ['ASN','AS owner','IPs (resolved / decoded)','Domains','Countries'], asRows.map(e=>[e.asn,e.as_owner,`${e.ip_count} (${e.resolved} / ${e.decoded})`,e.domain_count,e.countries.join(', ')])],
      ['domainCountrySummaryTable', 'Countries', ['Country','IPs','Domains','ASNs'], countryRows.map(e=>[e.country,e.ip_count,e.domain_count,e.asn_count])],
      ['domainAsCountrySummaryTable', 'AS × country', ['ASN','Country','AS owner','IPs (resolved / decoded)','Domains'], crossRows.map(e=>[e.asn,e.country,e.as_owner,`${e.ip_count} (${e.resolved} / ${e.decoded})`,e.domain_count])]
    ];
    tables.forEach(([id,title,headers,rows])=>{
      const group = viewNode('section'); group.setAttribute('aria-label', title);
      group.append(viewNode('h5', title + ' — current page only'));
      mountDomainAnalysisPage(group, id, headers, rows, 8); root.append(group);
    });
  };
  const commit = ()=>{
    disclosure.open = false; root.replaceChildren(); disclosure._signature = signature;
    disclosure.ontoggle = ()=>{
      root.replaceChildren();
      if(!window.TraceAuth?.accessInvalidated && domainAnalysisPageReady && disclosure.open && disclosure.isConnected && disclosure._signature === signature) build();
    };
  };
  if(commits) commits.push(commit); else commit();
}

function renderDomainAnalysisTable(domains, includeVT, totalDomainsCount, commits=null){
  const root = document.getElementById('domainAnalysisDetail');
  if(!root) return;
  const d = domains[0];
  const signature = d ? JSON.stringify([domainAnalysisPageKey, includeVT, d]) : '';
  if(root._signature === signature) return;
  const nodes = [];
  if(d){
    const heading = viewNode('h4', d.domain); heading.tabIndex = -1;
    const close = viewNode('button', 'Close selected domain'); close.id = 'closeDomainAnalysisDetail';
    close.onclick = ()=>clearDomainAnalysisDetail(true);
    const status = getDomainLifecycleStatus(d);
    const state = status.label === 'Normal' && isDomainNonResolving(d) ? 'No-data' : status.label;
    const summary = viewNode('p', `${state} · ${(d.record_types || []).join(', ') || '-'} · Last seen ${formatUnixTsLocal(d.last_ts)}. Evidence below is cached and current-page only.`);
    applyNxdomainLifecycleStyle(heading, d, d.domain);
    const evidence = domainAnalysisDisclosure('domainAnalysisEvidence', 'Cached IP / AS / country evidence (current page only)', body=>{
      const st = getDomainStatsEntry(d);
      body.append(viewNode('p', `Page counts: ${st.resolvedCount} resolved / ${st.decodedCount} decoded IPs / ${st.asCount} AS / ${st.countryCount} countries. Top AS: ${st.topAs}; top country: ${st.topCountry}.`));
      const rows = (d.ip_rows || []).map(row=>{
        const vt = row.vt || {};
        return [row.role || '-', row.ip || '-', vt.asn, vt.as_owner, vt.country,
          includeVT ? `${Number(vt.malicious || 0)}/${Number(vt.suspicious || 0)}` : 'off'];
      });
      mountDomainAnalysisPage(body, 'domainAnalysisTable', ['Role','IP','ASN','AS owner','Country','VT (M/S)'], rows, 12);
    });
    const raw = domainAnalysisDisclosure('domainAnalysisRaw', 'Raw cached domain facts (complete identifiers; current page only)', body=>{
      body.append(viewNode('pre', JSON.stringify(d, null, 2)));
    });
    nodes.push(heading, close, summary, evidence, raw);
  }
  const commit = ()=>{ root.replaceChildren(...nodes); root.hidden = !d; root._signature = signature; };
  if(commits) commits.push(commit); else commit();
}

function applyDomainAnalysisFilter(commits=null, selectedOverride){
  if(window.TraceAuth?.accessInvalidated){
    clearDomainAnalysisDetail();
    document.getElementById('domainAnalysisDomainSelect').disabled = true;
    document.getElementById('domainAnalysisManageBtn').disabled = true;
    document.getElementById('domainAnalysisMeta').textContent = 'Access changed. Reload to check permissions.';
    return;
  }
  const allDomains = Array.isArray(window.DOMAIN_ANALYSIS_CACHE) ? window.DOMAIN_ANALYSIS_CACHE : [];
  const includeVT = !!window.DOMAIN_ANALYSIS_INCLUDE_VT;
  const selected = selectedOverride === undefined
    ? String((document.getElementById('domainAnalysisDomainSelect') || {}).value || '') : selectedOverride;
  const filtered = selected && domainAnalysisPageReady ? allDomains.filter(d=>String(d.domain || '') === selected) : [];
  const staged = commits || [];
  renderDomainStatsTable(allDomains, selected, staged);
  renderDomainAnalysisTable(filtered, includeVT, allDomains.length, staged);
  renderDomainAnalysisSummaries(allDomains, includeVT, staged, selected);
  staged.push(()=>{
    document.getElementById('domainAnalysisDomainSelect').disabled = !domainAnalysisPageReady;
    document.getElementById('domainAnalysisManageBtn').disabled = !domainAnalysisPageReady || !canManageDomainAnalysis();
    document.getElementById('domainAnalysisMeta').textContent = `Current page: ${allDomains.length} domains; ${selected ? 'selected: ' + selected : 'select one domain for cached evidence'}.`;
    touchOverviewTs();
  });
  if(!commits) staged.forEach(commit=>commit());
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
  if(!domainAnalysisManageMode || !canManageDomainAnalysis() || domainAnalysisRemovalPending) return false;
  const epoch = domainAnalysisManageEpoch;
  const names = Array.from(new Set((domainNames || []).map(v=>String(v || '').trim()).filter(Boolean)));
  if(!names.length){
    setDomainRemoveStatus('No domains selected', 'err');
    return false;
  }

  const confirmed = window.confirm(`Remove ${names.length} domain(s) from monitoring?\n\n${names.join('\n')}`);
  if(!confirmed){
    return false;
  }

  domainAnalysisRemovalPending = true;
  const feedback=viewFeedbackOwner('domain-remove','domainRemoveStatus');
  const token=feedback?.begin(JSON.stringify(names));
  const current=()=>epoch===domainAnalysisManageEpoch && domainAnalysisManageMode && canManageDomainAnalysis() && feedbackCurrent(token);
  let submitted=false;
  try{
    const cfgResp = await fetch('/config',{feedback:token});
    if(!cfgResp.ok) throw new Error('config load failed');
    const cfg = await cfgResp.json();
    if(!current()) return false;
    if(!Array.isArray(cfg?.domains) || !Number.isSafeInteger(cfg.revision) || cfg.revision<0) throw new Error('Invalid configuration receipt');
    const currentDomains = Array.isArray(cfg.domains) ? cfg.domains : [];
    const removeSet = new Set(names);
    const nextDomains = currentDomains.filter(item=>{
      const name = domainStorageName(item);
      return name && !removeSet.has(name);
    });
    const removedCount = currentDomains.length - nextDomains.length;
    if(removedCount <= 0){
      setDomainRemoveStatus('No matching domains found in config', 'err');
      return false;
    }

    submitted=true;
    const saveResp = await fetch('/config', {
      method: 'POST',
      feedback:token,
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({domains: nextDomains, revision: cfg.revision})
    });
    const saveJson = await saveResp.json();
    if(!current()) return false;
    if(!(saveResp.ok && saveJson?.status==='ok' && Number.isSafeInteger(saveJson.revision) && saveJson.revision>=0 && Array.isArray(saveJson.config?.domains))){
      throw Object.assign(new Error('Invalid removal receipt'),{status:saveResp.ok?0:saveResp.status});
    }

    const sel = getDomainAnalysisSelectionSet();
    names.forEach(n=>sel.delete(n));
    // This mutation has its own revision; never reload/rebase a Settings draft.
    clearDomainAnalysisDetail();
    await refreshDomainAnalysis();
    if(!current()) return false;
    feedback?.succeed(token);
    setDomainRemoveStatus(successMessage || `Removed ${removedCount} domain(s)`, 'ok');
    return true;
  }catch(e){
    if(!current()) return false;
    feedbackFailure(feedback,token,e,submitted);
    setDomainRemoveStatus('Remove failed: '+(feedback?.snapshot().error?.message || 'The operation could not be confirmed. Reload explicitly before retrying.'), 'err');
    return false;
  }finally{
    domainAnalysisRemovalPending = false;
  }
}

function selectNonResolvingDomainsForBulk(){
  if(!domainAnalysisManageMode || !canManageDomainAnalysis()) return;
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
  if(!domainAnalysisManageMode || !canManageDomainAnalysis()) return;
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
  const pageKey = preparedQuery('domainanalysis');
  if(domainAnalysisPageKey !== pageKey){
    clearDomainAnalysisDetail();
    domainAnalysisPageReady = false;
    setDomainAnalysisManageMode(false);
    domainAnalysisPageKey = pageKey;
  }
  const owner = beginSectionRefresh('domainanalysis');
  if(!owner) return;
  try{
    const includeVT = !!(document.getElementById('domain_analysis_include_vt') && document.getElementById('domain_analysis_include_vt').checked);
    const j = await readPreparedJSON(owner);
    if(isSectionRefreshCurrent(owner) && j.unchanged && !domainAnalysisPageReady && preparedViews.get('domainanalysis')?.url === owner.url){
      domainAnalysisPageReady = true;
      applyDomainAnalysisFilter();
    }
    if(preparedResponseHandled(owner)) return;
    if(!Array.isArray(j.domains)) throw new Error('Invalid domain page');
    const previousPageReady = domainAnalysisPageReady;
    const previousCache = window.DOMAIN_ANALYSIS_CACHE;
    const previousVT = window.DOMAIN_ANALYSIS_INCLUDE_VT;
    const previousSelection = window.DOMAIN_ANALYSIS_SELECTED_REMOVE;
    try{
      domainAnalysisPageReady = true;
      window.DOMAIN_ANALYSIS_CACHE = j.domains.slice(0, 200);
      window.DOMAIN_ANALYSIS_INCLUDE_VT = includeVT;
      pruneDomainAnalysisSelection();
      // Stage the whole view: no filter/table/timestamp is published until all
      // renderers succeed. A retained validator must describe every panel.
      const commits = [];
      const selected = populateDomainAnalysisFilter(window.DOMAIN_ANALYSIS_CACHE, commits);
      applyDomainAnalysisFilter(commits, selected);
      commits.forEach(commit=>commit());
    }catch(error){
      domainAnalysisPageReady = previousPageReady;
      window.DOMAIN_ANALYSIS_CACHE = previousCache;
      window.DOMAIN_ANALYSIS_INCLUDE_VT = previousVT;
      window.DOMAIN_ANALYSIS_SELECTED_REMOVE = previousSelection;
      throw error;
    }
    completePreparedRender(owner);
  }catch(e){
    failSectionRefresh(owner, e);
  }finally{
    finishSectionRefresh(owner);
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
  const payload = (relCache && typeof relCache === 'object') ? relCache : {};
  const serverHints = Array.isArray(payload.insights) ? payload.insights : null;
  const serverCharacteristics = (payload.characteristics && typeof payload.characteristics === 'object') ? payload.characteristics : null;
  const built = serverHints ? { hints: serverHints, characteristics: serverCharacteristics } : buildIpIntelRelationshipInsights(relCache);
  const hints = Array.isArray(built.hints) ? [...built.hints] : [];
  const quality = (payload.quality && typeof payload.quality === 'object') ? payload.quality : null;
  if(quality && quality.analysis_complete === false){
    const warnings = Array.isArray(quality.warning_codes) ? quality.warning_codes.map(code=>String(code).replace(/_/g, ' ')) : [];
    hints.unshift({
      level: 'warn',
      title: 'Incomplete Relationship Analysis',
      detail: warnings.length ? `Partial results: ${warnings.join(', ')}.` : 'Resource or enrichment limits produced partial results.',
      source: 'Cluster',
      signal: 'analysis_quality'
    });
  }
  state.relationship = {
    signature: String(inputSignature || ''),
    hints,
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

function setIpIntelResultState(state, message){
  const empty = document.getElementById('ipIntelResultsEmpty');
  const content = document.getElementById('ipIntelResultsContent');
  const ready = state === 'ready';
  if(empty){
    empty.hidden = ready;
    if(!ready){
      empty.textContent = message || (state === 'loading'
        ? 'Enriching per-IP details…'
        : 'Run “Enrich Per-IP Details” to populate summaries and evidence.');
    }
  }
  if(content) content.hidden = !ready && !window.IP_INTEL_LAST_RESULT;
}

function cancelIpIntelInputReads(cancelMisp = true){
  if(ipIntelAnalyzeController){
    ++ipIntelAnalyzeSeq; ipIntelAnalyzeController.abort(); ipIntelAnalyzeController=null;
    localFeedbackOwners.get('ip-enrichment')?.invalidate();
  }
  if(cancelMisp && ipIntelMispController){
    ++ipIntelMispSeq; ipIntelMispController.abort(); ipIntelMispController=null;
    localFeedbackOwners.get('misp-input')?.invalidate();
    document.getElementById('ipIntelMispStatus').textContent='MISP browser read stopped. Already dispatched provider work may continue.';
  }
}

function renderIpIntelCachedEvidence(){
  const state=window.IP_INTEL_LAST_RESULT;
  const panel=document.getElementById('ipIntelEvidence');
  const raw=document.getElementById('ipIntelRaw');
  const bodies=['ipIntelResultTable','ipIntelAsSummaryTable','ipIntelCountrySummaryTable','ipIntelAsCountrySummaryTable','ipIntelCspSummaryTable'].map(id=>document.querySelector('#'+id+' tbody'));
  for(const body of bodies) if(body) body.textContent='';
  if(raw) raw.querySelector('pre').textContent='';
  if(!panel || !panel.open || !state){if(raw) raw.open=false;return;}
  const j=state.response, includeVT=state.includeVT, offset=state.offset;
  const page=key=>(Array.isArray(j[key])?j[key]:[]).slice(offset,offset+8);
  const rows=page('ips'), asRows=page('as_summary'), cRows=page('country_summary'), acRows=page('as_country_summary'), cspRows=page('csp_summary');
  const [ipBody,asBody,cBody,acBody,cspBody]=bodies;
  const counts=['ips','as_summary','country_summary','as_country_summary','csp_summary'].map(key=>Array.isArray(j[key])?j[key].length:0);
  const total=Math.max(...counts);
  document.getElementById('ipIntelEvidenceRange').textContent=`Cached response: IP/AS/country/intersection/CSP entries ${counts.join(' / ')}. Showing entries ${total?offset+1:0}–${Math.min(offset+8,total)} in each category (up to 8 per category). Empty categories have no entries at this offset, not zero global observations.`;
  for(const [id,next] of [['ipIntelEvidencePrevious',offset-8],['ipIntelEvidenceNext',offset+8]]){
    const button=document.getElementById(id); button.disabled=next<0 || next>=total;
    button.onclick=()=>{
      if(window.IP_INTEL_LAST_RESULT!==state) return;
      state.offset=next;renderIpIntelCachedEvidence();
      if(button.disabled) document.getElementById(id==='ipIntelEvidenceNext'?'ipIntelEvidencePrevious':'ipIntelEvidenceNext').focus();
    };
  }
  if(raw?.open) raw.querySelector('pre').textContent=JSON.stringify(j,null,2);
    if(ipBody){
      ipBody.innerHTML = '';
      if(!rows.length){
        setSummaryMessage(ipBody, 6, 'No IP entries on this evidence page');
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
        setSummaryMessage(asBody, 6, 'No AS entries on this evidence page');
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
        setSummaryMessage(cBody, 4, 'No country entries on this evidence page');
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
        setSummaryMessage(acBody, 6, 'No intersections on this evidence page');
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
        setSummaryMessage(cspBody, 5, 'No CSP entries on this evidence page');
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

  if(ipIntelAnalyzeController){
    try{ ipIntelAnalyzeController.abort(); }catch(e){}
  }
  ipIntelAnalyzeSeq += 1;

  if(!raw){
    if(meta) meta.textContent = 'Input IP list first';
    setIpIntelResultState('idle');
    renderMergedIpIntelHints();
    return;
  }

  const controller = (typeof AbortController === 'function') ? new AbortController() : null;
  ipIntelAnalyzeController = controller;
  const feedback=viewFeedbackOwner('ip-enrichment','ipIntelMeta');
  const token=feedback?.begin(inputSignature);
  const requestSeq = ipIntelAnalyzeSeq;
  const isStale = ()=> requestSeq !== ipIntelAnalyzeSeq || ipIntelAnalyzeController !== controller;
  setIpIntelBusy(true);
  setIpIntelResultState('loading');

  if(meta) meta.textContent = 'Analyzing...';

  try{
    const r = await fetch('/ip-list-analysis', {
      method: 'POST',
      feedback: token,
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
    if(!r.ok || !j || j.error || !Array.isArray(j.ips)) throw Object.assign(new Error('Invalid enrichment result'),{status:r.ok ? 0 : r.status});
    feedback?.succeed(token);

    const rows = Array.isArray(j.ips) ? j.ips : [];
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

    window.IP_INTEL_LAST_RESULT={response:j,includeVT,inputSignature,generation:requestSeq,offset:0};
    renderIpIntelCachedEvidence();

    setIpIntelInfraInsights(inputSignature, hints, characteristics);

    if(invalidBox){
      if(!invalid.length){
        invalidBox.textContent = 'No invalid inputs';
      } else {
        invalidBox.textContent = invalid.join(', ');
      }
    }
    setIpIntelResultState('ready');
    touchOverviewTs();
  }catch(e){
    if(isAbortError(e) || isStale()) return;
    setIpIntelInfraInsights(inputSignature, [], null);
    feedbackFailure(feedback,token,e);
    if(meta) meta.textContent = 'Per-IP enrichment failed. '+(feedback?.snapshot().error?.message || 'No usable result was returned.');
    setIpIntelResultState('error', 'Per-IP enrichment failed. Previous returned data, if present, is stale. Retry explicitly.');
  }finally{
    if(ipIntelAnalyzeController === controller){
      ipIntelAnalyzeController = null;
    }
    setIpIntelBusy(false);
  }
}

async function loadIpIntelFromMisp(autoAnalyze){
  ipIntelMispController?.abort();
  const controller=new AbortController(); ipIntelMispController=controller;
  const generation=++ipIntelMispSeq;
  const eventId = String((document.getElementById('ipIntelMispEventId') || {}).value || '').trim();
  const feedback=viewFeedbackOwner('misp-input','ipIntelMispStatus');
  const token=feedback?.begin(eventId);
  const current=()=>generation===ipIntelMispSeq && !controller.signal.aborted && feedbackCurrent(token);
  const meta = document.getElementById('ipIntelMispStatus');
  const invalidBox = document.getElementById('ipIntelInvalidBox');
  if(meta) meta.textContent = 'Loading MISP ip-src...';
  try{
    const payload = {};
    if(eventId) payload.event_id = eventId;
    const r = await fetch('/misp/event-ips', {
      method: 'POST',
      signal: controller.signal, feedback:token,
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json();
    if(!current()) return;
    if(!r.ok || !j || j.status !== 'ok'){
      feedbackFailure(feedback,token,{status:r.ok ? 0 : r.status});
      if(meta) meta.textContent = 'MISP load failed. No usable external result was returned; retry explicitly.';
      return;
    }
    feedback?.succeed(token);

    const ips = Array.isArray(j.ips) ? j.ips : [];
    if(typeof window !== 'undefined'){
      window.IP_REL_MISP_CONTEXT = (j.misp_context && typeof j.misp_context === 'object')
        ? j.misp_context
        : null;
    }
    setIpIntelInputValue(ips.join('\n'));
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
    if(!current()) return;
    feedbackFailure(feedback,token,e);
    if(meta) meta.textContent = 'MISP load failed. '+(feedback?.snapshot().error?.message || 'External result unavailable.');
  }finally{
    if(ipIntelMispController===controller) ipIntelMispController=null;
  }
}

function renderPreparedValues(td, values){
  const list = Array.isArray(values) ? values.map(String) : [];
  td.className = 'wrap-cell';
  if(!list.length){ td.textContent = '-'; return; }
  const preview = list.slice(0, 20);
  preview.forEach((value, index)=>{
    if(index) td.appendChild(document.createTextNode(' | '));
    if(isIPv4(value)){
      const link = document.createElement('a');
      link.href = '#'; link.textContent = value;
      link.onclick = event=>{event.preventDefault();openQueryForValue(value);};
      td.appendChild(link);
    }else{
      td.appendChild(document.createTextNode(value.length > 200 ? value.slice(0, 200) + '…' : value));
    }
  });
  if(list.length > preview.length || preview.some(value=>value.length > 200)){
    td.appendChild(lazyViewDetails(`Show all ${list.length} values (plain text)`, body => {
      body.appendChild(viewNode('pre', list.join('\n')));
    }));
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

// Delivery health owns its lifecycle independently of data/settings refreshes.
(() => {
  const panel = document.getElementById('deliveryHealth');
  if(!panel || !window.TraceAuth) return;
  const status = document.getElementById('deliveryStatus');
  const details = document.getElementById('deliveryDetails');
  const checked = document.getElementById('deliveryChecked');
  const disclosure = document.getElementById('deliveryDisclosure');
  const warnings = document.getElementById('deliveryWarnings');
  const feedback = window.TraceViewFeedback?.register('delivery-health', state => {
    if(state.error) status.setAttribute('data-feedback-id', state.error.identity);
    else status.removeAttribute('data-feedback-id');
  });
  const reasons = new Set([
    'delivery_storage', 'delivery_capacity', 'tracking_overflow', 'old_binding_blocked',
    'client_unavailable', 'configuration_unavailable', 'provider_auth', 'provider_tls',
    'provider_timeout', 'provider_transport', 'provider_rate_limit', 'provider_unavailable',
    'provider_response', 'provider_work_limit', 'attempts_exhausted', 'invalid_payload',
    'recovery_gap', 'receipt_persistence', 'history_persistence', 'delivery_unknown',
    'destination_disabled', 'destination_invalid', 'adapter_unapplied', 'removal_disabled',
    'tls_config', 'tls_error', 'provider_transient', 'provider_http', 'provider_protocol',
    'transport_error', 'response_limit', 'attribute_limit', 'payload_invalid', 'payload_limit',
    'sighting_absent'
  ]);
  const count = n => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 2 ** 63;
  const optionalCount = n => n === null || count(n);
  const flag = n => typeof n === 'boolean';
  const reason = n => n === null || typeof n === 'string' && reasons.has(n);
  const enumeration = values => n => values.includes(n);
  function closed(value, fields){
    if(value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const keys = Reflect.ownKeys(value);
    return keys.length === Object.keys(fields).length && Object.entries(fields).every(([key, validate]) => {
      const d = Object.getOwnPropertyDescriptor(value, key);
      return d && d.enumerable && Object.hasOwn(d, 'value') && validate(d.value);
    });
  }
  const channel = value => closed(value, {enabled:flag, pending:count, blocked:count,
    last_success_at:optionalCount, last_error:reason});
  const progressChannel = c => closed(c, {
    state:enumeration(['disabled','idle','queued','retry_wait','blocked','active','stalled','unavailable']),
    last_attempt_at:optionalCount, in_flight_age_seconds:optionalCount
  });
  function validate(value){
    const extended = {
      progress_version:enumeration([1]), counts_age_seconds:optionalCount,
      progress:p => closed(p, {
        state:enumeration(['not_started','idle','active','stalled','recovering','failed','stopping','stopped']),
        operation:enumeration([null,'recover_storage','seal_batches','claim','provider_step','finish_step','observation_hook','sightings_step']),
        channel:enumeration([null,'teams','misp']), last_progress_at:optionalCount,
        last_progress_age_seconds:optionalCount, in_flight_age_seconds:optionalCount, stall_after_seconds:count,
        channels:c => closed(c, {teams:progressChannel, misp:progressChannel})
      }),
      recovery:r => closed(r, {state:enumeration(['ready','recovering','backoff','uncertain','stopped','failed']),
        retry_in_seconds:optionalCount, targets_rebaselining:count, absence_state:enumeration(['ready','awaiting_full','unknown'])}),
      lookup:l => closed(l, {last_attempt_at:optionalCount,last_success_at:optionalCount,in_flight:count,
        failed_targets:count,uncertain_targets:count,coverage:enumeration(['complete','partial','unknown']),counts_stale:flag})
    };
    if(!closed(value, {
      ...(value && Object.hasOwn(value, 'progress_version') ? extended : {}),
      status:enumeration(['disabled','ok','degraded','blocked']), observation_policy:enumeration(['continue']),
      storage_ok:flag, worker_running:flag, coverage:enumeration(['covered','gap','rebaselining']),
      accounting_complete:flag, missed_total:count, missed_unpersisted:count, failed_total:count,
      acked_total:count, pending:count, retry_wait:count, blocked:count, oldest_pending_age_seconds:optionalCount,
      capacity:v => closed(v, {used_receipts:count, max_receipts:count, used_payload_bytes:count, max_payload_bytes:count}),
      channels:v => closed(v, {teams:channel, misp:channel}), tracking_complete:flag, counts_stale:flag, last_error:reason
    })) throw new Error('Invalid health');
    return value;
  }
  const number = n => Number.isSafeInteger(n) ? String(n) : 'precision unavailable';
  const errorText = code => code === null ? 'no reported error' : code.replaceAll('_', ' ');
  function timestamp(n){
    if(n === null) return 'unknown';
    if(!Number.isSafeInteger(n) || n > 8640000000000) return 'precision unavailable';
    return new Date(n * 1000).toISOString();
  }
  function capacity(used, max){
    if(!Number.isSafeInteger(used) || !Number.isSafeInteger(max) || max <= 0 || used > max) return 'unknown';
    return `${number(used)} / ${number(max)} (${(used / max * 100).toFixed(1)}%)`;
  }
  let lastGood = false;
  let incompleteSeen = false;
  let lastLines = ['Unknown — no successful health read yet.'];
  let lastHeadline = '';
  function renderDetails(){
    const fragment = document.createDocumentFragment();
    if(!disclosure || disclosure.open){
      for(const line of lastLines){
        const p = document.createElement('p');
        p.textContent = line;
        fragment.appendChild(p);
      }
    }
    details.replaceChildren(fragment);
  }
  if(disclosure) disclosure.addEventListener('toggle', renderDetails);
  function render(h){
    const unsafe = JSON.stringify(h, (_, v) => typeof v === 'number' && !Number.isSafeInteger(v) ? 'UNSAFE' : v).includes('UNSAFE');
    incompleteSeen = incompleteSeen || !h.accounting_complete || unsafe;
    lastHeadline = [
      `Backend delivery status: ${h.status}.`,
      `Worker: ${h.worker_running ? 'running' : 'not running'}; ${h.progress_version === 1 ? 'progress: ' + h.progress.state : 'progress unavailable on this server'}.`
    ].join(' ');
    const cautions = [
      `${number(h.missed_total)} not admitted (durable); ${number(h.missed_unpersisted)} volatile known misses; ${number(h.failed_total)} failed (historical terminal). Unit: destination-items.`,
      incompleteSeen ? 'Accounting incomplete — lower bound; total loss unknown.' : 'Accounting complete for this epoch.',
      h.blocked ? `${number(h.blocked)} currently blocked.` : '',
      !h.storage_ok ? 'Storage degraded.' : '',
      h.coverage !== 'covered' ? `Coverage: ${h.coverage}.` : '',
      !h.tracking_complete ? 'Tracking incomplete.' : '',
      h.counts_stale ? 'Counts stale.' : '',
      h.lookup && (h.lookup.coverage !== 'complete' || h.lookup.counts_stale || h.lookup.failed_targets || h.lookup.uncertain_targets)
        ? `Source coverage: ${h.lookup.coverage}; ${number(h.lookup.failed_targets)} failed, ${number(h.lookup.uncertain_targets)} uncertain targets${h.lookup.counts_stale ? '; lookup counts stale' : ''}.` : ''
    ].filter(Boolean).join(' ');
    status.textContent = lastHeadline;
    if(warnings) warnings.textContent = cautions;
    const lines = [
      `${number(h.missed_total)} destination-items not admitted (durably recorded).`,
      `Volatile known misses: ${number(h.missed_unpersisted)} — not included in the durable count; may be lost on restart.`,
      incompleteSeen ? 'Accounting incomplete: known misses are a lower bound; total loss unknown.' : 'Accounting complete for this epoch.',
      `Pending: ${number(h.pending)} · Retrying: ${number(h.retry_wait)} · Blocked: ${number(h.blocked)}`,
      `Failed: ${number(h.failed_total)} · ACKed: ${number(h.acked_total)}`,
      `Storage: ${h.storage_ok ? 'available' : 'degraded'} · Worker: ${h.worker_running ? 'running' : 'not running'}`,
      `Coverage: ${h.coverage} · Tracking: ${h.tracking_complete ? 'complete' : 'incomplete'} · ${h.counts_stale ? 'Counts stale' : 'Counts from last cached sample'}`,
      `Oldest outstanding age: ${h.oldest_pending_age_seconds === null ? 'unknown' : number(h.oldest_pending_age_seconds) + ' seconds'}`,
      `Receipt capacity: ${capacity(h.capacity.used_receipts, h.capacity.max_receipts)}`,
      `Payload capacity (bytes): ${capacity(h.capacity.used_payload_bytes, h.capacity.max_payload_bytes)}`,
      `Delivery error: ${errorText(h.last_error)}`
    ];
    for(const [key, title] of [['teams','Teams'], ['misp','MISP']]){
      const c = h.channels[key];
      lines.push(`${title}: ${c.enabled ? 'enabled' : 'disabled'} · ${errorText(c.last_error)} · Pending: ${number(c.pending)} · Blocked: ${number(c.blocked)} · Last success: ${timestamp(c.last_success_at)}`);
    }
    if(h.progress_version === 1){
      const p = h.progress, r = h.recovery, l = h.lookup;
      const age = n => n === null ? 'unknown' : number(n) + ' seconds';
      lines.push(`Progress: ${p.state} · Operation: ${p.operation === null ? 'none' : p.operation.replaceAll('_',' ')} · Channel: ${p.channel || 'none'} · In-flight: ${age(p.in_flight_age_seconds)} · Last boundary: ${age(p.last_progress_age_seconds)} ago (${timestamp(p.last_progress_at)}) · Stall threshold: ${age(p.stall_after_seconds)}; no observed boundary progress is not proof of thread death.`);
      for(const [key,title] of [['teams','Teams'],['misp','MISP']]){
        const c = p.channels[key];
        lines.push(`${title} dispatch: ${c.state} · Last attempt: ${timestamp(c.last_attempt_at)} · In-flight: ${age(c.in_flight_age_seconds)}`);
      }
      lines.push(`Delivery storage recovery: ${r.state} · Retry in: ${age(r.retry_in_seconds)} · Targets rebaselining: ${number(r.targets_rebaselining)} · Full-only absence gate: ${r.absence_state}`);
      lines.push(`Source coverage: ${l.coverage} · Lookup in-flight: ${number(l.in_flight)} · Failed targets: ${number(l.failed_targets)} · Uncertain targets: ${number(l.uncertain_targets)} · ${l.counts_stale ? 'Lookup counts stale' : 'Lookup counts sampled'} · Last attempt: ${timestamp(l.last_attempt_at)} · Last accepted target success (not universal coverage): ${timestamp(l.last_success_at)}`);
      lines.push(`Count snapshot age: ${age(h.counts_age_seconds)} · ${h.counts_stale ? 'Counts stale' : 'Counts sampled'}; oldest outstanding age advances independently.`);
    }
    lastLines = lines;
    renderDetails();
    checked.textContent = 'Last successful health read: ' + new Date().toISOString();
    lastGood = true;
  }
  async function readHealth(response, signal){
    if(!response.ok || !response.body) throw new Error('Health unavailable');
    const reader = response.body.getReader();
    const cancel = () => { reader.cancel().catch(() => {}); };
    signal.addEventListener('abort', cancel, {once:true});
    let length = 0;
    let text = '';
    const decoder = new TextDecoder('utf-8', {fatal:true});
    try {
      if(signal.aborted) throw new Error('Health cancelled');
      while(true){
        const {done, value} = await reader.read();
        if(signal.aborted) throw new Error('Health cancelled');
        if(done) break;
        length += value.byteLength;
        if(length > 4096) throw new Error('Health too large');
        text += decoder.decode(value, {stream:true});
      }
      text += decoder.decode();
      // Check integer wire tokens before JSON.parse can round them. Strings are
      // consumed whole, so numbers inside strings are never treated as counters.
      for(const token of text.matchAll(/"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g)){
        if(token[0].startsWith('"')) continue;
        if(!/^(0|[1-9]\d*)$/.test(token[0]) || BigInt(token[0]) > 9223372036854775807n) throw new Error('Invalid counter');
      }
      return validate(JSON.parse(text));
    } finally {
      signal.removeEventListener('abort', cancel);
      cancel();
      reader.releaseLock();
    }
  }
  const intervalMs = 15000;
  const deadlineMs = 10000;
  let nextAttempt = 0;
  let timer = null;
  let active = null;
  let pageStopped = false;
  let permitted = true;
  function schedule(){
    clearTimeout(timer);
    if(!pageStopped && !document.hidden && permitted && !active){
      timer = setTimeout(poll, Math.max(0, nextAttempt - performance.now()));
    }
  }
  async function poll(){
    if(pageStopped || document.hidden || !permitted || active) return;
    if(performance.now() < nextAttempt) return schedule();
    const controller = new AbortController();
    active = controller;
    const token = feedback?.begin('/delivery-health?progress=1');
    nextAttempt = performance.now() + intervalMs;
    let abortListener;
    const aborted = new Promise((_, reject) => {
      abortListener = () => reject(new Error('Health read cancelled'));
      controller.signal.addEventListener('abort', abortListener, {once:true});
    });
    const deadline = setTimeout(() => controller.abort(), deadlineMs);
    const work = async () => {
      const user = await window.TraceAuth.ready;
      if(controller.signal.aborted) return;
      if(!user || !['admin', 'operator'].includes(user.role)){
        permitted = false;
        panel.hidden = true;
        return;
      }
      panel.hidden = false;
      // Auth can consume most of the deadline: pace actual requests too.
      nextAttempt = performance.now() + intervalMs;
      const response = await fetch('/delivery-health?progress=1', {cache:'no-store', signal:controller.signal, feedback:token});
      const health = await readHealth(response, controller.signal);
      if(!controller.signal.aborted){ render(health); feedback?.succeed(token); }
    };
    try {
      await Promise.race([work(), aborted]);
    } catch (error) {
      // TraceAuth deliberately exposes only this fixed local permission error,
      // never the server's body. Stop after revocation rather than spamming 403.
      if(error?.status === 401 || error?.status === 403){
        permitted = false;
        panel.hidden = true;
        details.replaceChildren();
        lastLines = [];
        lastHeadline = '';
        if(warnings) warnings.textContent = '';
        checked.textContent = 'Last successful health read: unknown';
        lastGood = false;
      }
      if(feedback && !window.TraceViewFeedback.current(token)) return;
      feedback?.fail(token, window.TraceViewFeedback.code(error));
      status.textContent = lastGood ? 'Delivery health unavailable — stale last successful snapshot. ' + lastHeadline : 'Delivery health unavailable — unknown.';
    } finally {
      clearTimeout(deadline);
      controller.signal.removeEventListener('abort', abortListener);
      if(active === controller) active = null;
      // Pace from completion/cancellation as well, including auth-wrapper time.
      nextAttempt = Math.max(nextAttempt, performance.now() + intervalMs);
      schedule();
    }
  }
  function pause(){
    clearTimeout(timer);
    feedback?.invalidate();
    if(active) active.abort();
    if(lastGood) status.textContent = 'Delivery health paused — stale last successful snapshot. ' + lastHeadline;
  }
  window.TraceAuth.onInvalidated?.(() => {
    permitted = false;
    pause();
    feedback?.forget();
    lastGood = false; lastHeadline = ''; lastLines = [];
    panel.hidden = true;
    details.replaceChildren();
    if(warnings) warnings.textContent = '';
    status.textContent = 'Access changed. Reload to check permissions.';
    checked.textContent = 'Last successful health read: unknown';
  });
  // Join the console's ordinary load lifecycle. Installing the script alone
  // (for an embedded view or a fixture) must not start unrelated background I/O.
  window.addEventListener('load', () => {
    document.addEventListener('visibilitychange', () => document.hidden ? pause() : schedule());
    window.addEventListener('pagehide', () => { pageStopped = true; pause(); });
    window.addEventListener('pageshow', () => { pageStopped = false; schedule(); });
    schedule();
  });
})();

const uiOverview = {
  configured: null,
  statusRows: null,
  managedIps: null,
  allIps: null,
  validIps: null,
  lastRefreshLocal: '—'
};



function updateOverviewPanel(){
  const set = (id, value)=>{
    const el = document.getElementById(id);
    if(el) el.textContent = value;
  };
  const count = value => value == null ? '—' : String(value);
  set('metricConfigured', count(uiOverview.configured));
  set('metricStatusRows', count(uiOverview.statusRows));
  set('metricDecoded', count(uiOverview.managedIps));
  set('metricIps', count(uiOverview.allIps));
  set('metricValidIps', count(uiOverview.validIps));
  set('metricUpdated', uiOverview.lastRefreshLocal);
}

function touchOverviewTs(section){
  if(section !== 'status') return;
  uiOverview.lastRefreshLocal = formatLocalDateTime(new Date());
  updateOverviewPanel();
}

function settingsDraftStamp(sectionId){
  const section = document.getElementById(sectionId);
  if(!section._draftBound){
    section._draftBound = true;
    section._draftGeneration = 0;
    const changed = event=>{
      if(event.target.matches('input, select, textarea') && event.target.id !== 'domainSettingsSearch') ++section._draftGeneration;
    };
    section.addEventListener('input', changed);
    section.addEventListener('change', changed);
  }
  return JSON.stringify([section._draftGeneration,
    sectionId === 'alertsSection' ? alertRevision : configRevision,
    [...section.querySelectorAll('input, select, textarea')].filter(el=>el.id !== 'domainSettingsSearch').map(el=>[el.id, el.className, el.value, el.checked])]);
}

function setAlertSettingsStatus(message, kind){
  const el = document.getElementById('alertSettingsStatus');
  if(!el) return;
  clearTimeout(el._statusTimer);
  el.textContent = message || '';
  el.classList.remove('ok', 'err');
  if(kind === 'ok') el.classList.add('ok');
  if(kind === 'err') el.classList.add('err');
  if(message && kind === 'ok'){
    el._statusTimer = setTimeout(()=>{
      el.textContent = '';
      el.classList.remove('ok', 'err');
    }, 2800);
  }
}

function applyAlertSettings(alerts, revision){
    alertRevision = revision;
    alertSettingsReady = true;
    const summary = document.getElementById('alertConfigurationSummary');
    if(summary) summary.textContent = `Saved configuration (revision ${revision}): ` +
      [['Teams', 'teams_webhook'], ['MISP URL', 'misp_url'], ['MISP API key', 'api_key'], ['VirusTotal', 'vt_api_key']].map(([label, key])=>`${label}: ${alerts.configured?.[key] ? 'configured' : 'not configured'}`).join(' · ') + '. Configuration presence is not connection or delivery readiness.';
    document.getElementById('teams_webhook_front').value = alerts.teams_webhook || '';
    document.getElementById('misp_url_front').value = alerts.misp_url || '';
    document.getElementById('misp_key_front').value = alerts.api_key || '';
    document.getElementById('push_event_id_front').value = alerts.push_event_id || '';
    document.getElementById('vt_api_key_front').value = alerts.vt_api_key || '';
    const secretIds = {teams_webhook:'teams_webhook_front', api_key:'misp_key_front', vt_api_key:'vt_api_key_front', misp_url:'misp_url_front', misp_ca_bundle:'misp_ca_bundle_front'};
    for(const [key, id] of Object.entries(secretIds)) secretInput(id, key, !!(alerts.configured || {})[key], 'alerts');
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
    if(window.TraceDeliveryResend) window.TraceDeliveryResend.savedAlerts();
    if(window.TraceTeamsTest) window.TraceTeamsTest.settingsChanged();
}

async function loadAlertSettings(){
  const feedback = viewFeedbackOwner('alert-settings', 'alertSettingsStatus');
  const token = feedback?.begin('/settings');
  const draft = settingsDraftStamp('alertsSection');
  try{
    alertSettingsReady = false;
    if(window.TraceTeamsTest) window.TraceTeamsTest.settingsChanged();
    if(window.TraceAuth && (await window.TraceAuth.ready).role !== 'admin') return;
    const r = await fetch('/settings', {feedback:token});
    if(!r.ok) throw Object.assign(new Error('HTTP '+r.status), {status:r.status});
    const j = await r.json();
    if(!feedbackCurrent(token)) return;
    if(draft !== settingsDraftStamp('alertsSection')){
      setAlertSettingsStatus('Load not applied — later draft retained with its original revision. Load explicitly again to discard it.', 'warn');
      return;
    }
    applyAlertSettings(j.settings?.alerts || {}, j.revision);
    setAlertSettingsStatus('Loaded', 'ok');
    feedback?.succeed(token);
  }catch(e){
    if(!feedbackCurrent(token)) return;
    feedbackFailure(feedback, token, e);
    setAlertSettingsStatus('Load failed', 'err');
  }
}

async function saveAlertSettings(){
  const feedback = viewFeedbackOwner('alert-settings', 'alertSettingsStatus');
  const token = feedback?.begin('/settings');
  const draft = settingsDraftStamp('alertsSection');
  const caInput = document.getElementById('misp_ca_bundle_front');
  const caPath = caInput.value.trim();
  const clearFields = selectedSecretClears('alerts');
  // The server checks existence and PEM contents; never reflect a private path.
  if(caPath && !clearFields.includes('misp_ca_bundle') &&
     (!(/^(?:\/|[A-Za-z]:[\\/]|\\\\)/.test(caPath)) || /[\x00-\x1f\x7f]/.test(caPath))){
    setAlertSettingsStatus('Use an absolute PEM path on the server.', 'warn');
    caInput.focus();
    return;
  }
  const vtTtlEl = document.getElementById('vt_cache_ttl_days_front');
  const currentTtl = parseBoundedInt((vtTtlEl && vtTtlEl.dataset ? vtTtlEl.dataset.current : ''), 1, 1, 3650);
  const vtTtlDays = parseBoundedInt((vtTtlEl || {}).value, currentTtl, 1, 3650);
  const alerts = {
    teams_webhook: document.getElementById('teams_webhook_front').value.trim(),
    misp_url: document.getElementById('misp_url_front').value.trim(),
    misp_ca_bundle: clearFields.includes('misp_ca_bundle') ? '' : caPath,
    api_key: document.getElementById('misp_key_front').value.trim(),
    push_event_id: document.getElementById('push_event_id_front').value.trim(),
    misp_remove_on_absent: !!((document.getElementById('misp_remove_on_absent_front') || {}).checked),
    vt_api_key: document.getElementById('vt_api_key_front').value.trim(),
    vt_cache_ttl_days: vtTtlDays
  };
  try{
    const r = await fetch('/settings', {
      method:'POST',
      feedback:token,
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({alerts, revision: alertRevision, clear_fields: clearFields})
    });
    const j = await r.json();
    if(!feedbackCurrent(token)) return;
    if(!(r.ok && j && j.status === 'ok' && Number.isSafeInteger(j.revision) && j.revision >= 0 && j.alerts && typeof j.alerts === 'object' && !Array.isArray(j.alerts))){
      throw new Error((j && j.error) ? j.error : 'save failed');
    }
    // POST returns the committed redacted alerts and revision. A follow-up GET
    // can fail or race another writer; it is not evidence for this commit.
    const unchanged = draft === settingsDraftStamp('alertsSection');
    if(unchanged) applyAlertSettings(j.alerts || {}, j.revision);
    const warnings = Array.isArray(j.warnings) ? j.warnings : [];
    const saved = warnings.length ? `Saved with warnings (revision ${j.revision}): `+warnings.join(', ')+'. Runtime application may be incomplete.' : `Saved (revision ${j.revision}). No runtime apply warnings reported.`;
    setAlertSettingsStatus(saved + (unchanged ? '' : ' Later draft retained with its original revision; Load explicitly to review the committed settings.'), warnings.length || !unchanged ? 'warn' : 'ok');
    feedback?.succeed(token);
  }catch(e){
    if(!feedbackCurrent(token)) return;
    feedbackFailure(feedback, token, e, true);
    setAlertSettingsStatus('Save failed. ' + (feedback?.snapshot().error?.message || 'Check the saved state before retrying.'), 'err');
  }
}

// Global decoder cache
window.DECODERS = [];
window.A_DECODERS = [];
window.ENS_DECODERS = [];
window.CUSTOM_DECODERS = [];
window.CUSTOM_A_DECODERS = [];

let decoderRevision = null;
function applyDecoderCatalog(j){
  if(!j || !Number.isInteger(j.revision)) throw new Error('Invalid decoder catalog revision');
  decoderRevision = j.revision;
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

async function loadDecoders(){
  const r = await fetch('/decoders');
  if(!r.ok) throw new Error('Decoder catalog load failed');
  applyDecoderCatalog(await r.json());
}

function commitWarningText(result){
  return Array.isArray(result.warnings) && result.warnings.length
    ? ' — committed with warnings: '+result.warnings.join(', ') : '';
}

async function mutateDecoder(method, data){
  const r = await fetch('/decoders/custom', {method, headers: {'Content-Type':'application/json'},
    body: JSON.stringify({...data, revision: decoderRevision})});
  const j = await r.json();
  if(r.status === 409){
    document.getElementById('customPreviewResult').textContent = 'Conflict: configuration changed. Draft retained. Reload catalog and review before retrying.';
    return null;
  }
  if(!r.ok || !j || j.status !== 'ok') throw new Error(j && j.error || 'Decoder save failed');
  applyDecoderCatalog(j.catalog);
  return j;
}

function filterDomainSettings(){
  const query = document.getElementById('domainSettingsSearch').value.trim().toLowerCase();
  const rows = [...document.querySelectorAll('#domainTable tbody tr')];
  let visible = 0;
  rows.forEach(row=>{
    const text = row.querySelector('.domain-full-name').textContent + ' ' + row.querySelector('.domain-type').value
      + ' ' + ((row.querySelector('.dht-public-key') || {}).value || '');
    row.hidden = !!query && !text.toLowerCase().includes(query);
    if(!row.hidden) visible++;
  });
  document.getElementById('domainSettingsSummary').textContent = `${visible} of ${rows.length} targets shown`;
  document.getElementById('domainSettingsEmpty').hidden = visible !== 0;
}
document.getElementById('domainSettingsSearch').oninput = filterDomainSettings;

function domainEditorState(row){
  return JSON.stringify([...row.querySelectorAll('input, select, textarea')].map(el=>el.value));
}

function addDomainRow(obj, metadata){
  const tbody = document.querySelector('#domainTable tbody');
  const tr = document.createElement('tr');
  tr._original = obj ? {...obj} : null;

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
  ['A','TXT','ENS','SNS','DHT','RPC','AAAA','CNAME','MX','NS','SRV','CAA'].forEach(t=>{ const o = document.createElement('option'); o.value=t; o.text=t; sel.appendChild(o); });
  if(obj && obj.type) sel.value = obj.type.toUpperCase();
  tdType.appendChild(sel);

  // TXT decoder select
  const tdTxtDecode = document.createElement('td');
  const selDecode = document.createElement('select');
  selDecode.className = 'txt-decode';
  // Decoder list is loaded dynamically from the backend; use fallback if not loaded yet
  const FALLBACK_DECODERS = ['cafebabe_xor_base64','plain_base64','btea_variant','xor_ipstring_base64_fixedkey','base64_xor_febabe','base56','safeb64_xor','c2_multiplex','ROT13_XOR0x30'];
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
  const FALLBACK_A_DECODERS = ['none', 'xor32_ipv4', '2byte_swap'];
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

  // ENS/SNS decode select
  const tdEnsDecode = document.createElement('td');
  const selEnsDecode = document.createElement('select');
  selEnsDecode.className = 'ens-decode';
  const FALLBACK_ENS_DECODERS = ['ipv6_5to8_xor', 'ipv6_last4_xor32', 'ROL3210_decode', 'legacy_doc_sample', 'none'];
  const ensDecsRaw = (window.ENS_DECODERS && window.ENS_DECODERS.length) ? window.ENS_DECODERS.slice() : FALLBACK_ENS_DECODERS.slice();
  const ensDecs = Array.from(new Set(ensDecsRaw.filter(Boolean)));
  const configuredType = String((obj && obj.type) || 'A').toUpperCase();
  const configuredDecode = obj
    ? (configuredType === 'SNS' ? obj.sns_decode : obj.ens_decode)
    : '';
  const defaultDecode = configuredType === 'SNS' ? 'ROL3210_decode' : 'ipv6_5to8_xor';
  if(configuredDecode && !ensDecs.includes(configuredDecode)){
    ensDecs.push(configuredDecode);
  }
  ensDecs.forEach(t=>{
    const o = document.createElement('option');
    o.value = t;
    o.text = (t === 'none') ? 'None' : t;
    selEnsDecode.appendChild(o);
  });
  if(configuredDecode && ensDecs.includes(configuredDecode)){
    selEnsDecode.value = configuredDecode;
  } else if(ensDecs.includes(defaultDecode)){
    selEnsDecode.value = defaultDecode;
  }
  tdEnsDecode.appendChild(selEnsDecode);

  // ENS/SNS options JSON input
  const tdEnsOptions = document.createElement('td');
  const inpEnsOptions = document.createElement('input');
  inpEnsOptions.type = 'text';
  inpEnsOptions.className = 'ens-options';
  inpEnsOptions.placeholder = '{"xor_byte":"0xA5"}';
  let ensOptionsText = '';
  const configuredOptions = obj
    ? (configuredType === 'SNS' ? obj.sns_options : obj.ens_options)
    : null;
  if(configuredOptions && typeof configuredOptions === 'object' && !Array.isArray(configuredOptions)){
    ensOptionsText = formatJsonObjectCompact(configuredOptions);
  } else if(configuredType === 'ENS' && obj && obj.ens_xor_byte){
    ensOptionsText = formatJsonObjectCompact({xor_byte: obj.ens_xor_byte});
  }
  inpEnsOptions.value = ensOptionsText;
  tdEnsOptions.appendChild(inpEnsOptions);

  const tdEnsNode = document.createElement('td');
  const inpEnsNode = document.createElement('input');
  inpEnsNode.className = 'ens-node';
  inpEnsNode.value = (obj && obj.ens_node) || '';
  tdEnsNode.appendChild(inpEnsNode);
  const tdEnsResolver = document.createElement('td');
  const inpEnsResolver = document.createElement('input');
  inpEnsResolver.className = 'ens-resolver';
  inpEnsResolver.value = (obj && obj.ens_resolver) || '';
  tdEnsResolver.appendChild(inpEnsResolver);

  const tdDhtKey = document.createElement('td');
  const inpDhtKey = document.createElement('textarea');
  inpDhtKey.className = 'dht-public-key';
  inpDhtKey.rows = 3;
  inpDhtKey.spellcheck = false;
  inpDhtKey.placeholder = '64 hexadecimal characters; public, not secret';
  inpDhtKey.value = (obj && obj.dht_public_key) || '';
  tdDhtKey.appendChild(inpDhtKey);
  const tdDhtOptions = document.createElement('td');
  const inpDhtOptions = document.createElement('textarea');
  inpDhtOptions.className = 'dht-options';
  inpDhtOptions.rows = 3;
  inpDhtOptions.spellcheck = false;
  inpDhtOptions.placeholder = 'Optional JSON object';
  inpDhtOptions.value = formatJsonObjectCompact(obj && obj.dht_options);
  tdDhtOptions.appendChild(inpDhtOptions);
  const dhtKeyDisplay = document.createElement('p');
  dhtKeyDisplay.className = 'dht-key-display';
  const dhtHelp = document.createElement('p');
  dhtHelp.className = 'field-help';
  dhtHelp.textContent = 'Read-only BEP44 signed DNS lookup. No C2 contact or republish. The public key is not secret. No DNS server, ENS RPC or SNS proxy is required. Lookup options: duration, max_queries, timeout, rate, concurrency, max_nodes, bootstraps.';
  const updateDhtKeyDisplay = ()=>{
    dhtKeyDisplay.textContent = `Public key: ${inpDhtKey.value || 'not set'}`;
  };
  updateDhtKeyDisplay();
  inpDhtKey.addEventListener('input', updateDhtKeyDisplay);

  const tdRpcProfile = document.createElement('td');
  const selRpcProfile = document.createElement('select');
  selRpcProfile.className = 'rpc-profile';
  const rpcOption = document.createElement('option');
  rpcOption.value = 'polygon_aes_gcm_v1';
  rpcOption.textContent = 'Polygon AES-128-GCM (rpc.txt)';
  selRpcProfile.appendChild(rpcOption);
  if(obj && obj.rpc_profile && obj.rpc_profile !== rpcOption.value){
    const unknown = document.createElement('option');
    unknown.value = obj.rpc_profile; unknown.textContent = obj.rpc_profile;
    selRpcProfile.appendChild(unknown);
  }
  selRpcProfile.value = (obj && obj.rpc_profile) || rpcOption.value;
  tdRpcProfile.appendChild(selRpcProfile);
  const rpcHelp = document.createElement('p');
  rpcHelp.className = 'field-help';
  rpcHelp.textContent = 'Read-only Polygon eth_call → AES-128-GCM → C2 IP:port. Fixed public RPC fallback; no ENS RPC setting required. Relay, download and mining roles are not C2. No C2 contact.';

  // Toggle decoder fields by record type
  const toggleDecodeInputs = function(){
    const typ = (sel.value || 'A').toUpperCase();
    const isTXT = typ === 'TXT';
    const isA = typ === 'A';
    const isENS = typ === 'ENS';
    const isSNS = typ === 'SNS';
    const isDHT = typ === 'DHT';
    selRpcProfile.disabled = typ !== 'RPC';
    rpcHelp.hidden = typ !== 'RPC';
    inpDhtKey.disabled = !isDHT;
    inpDhtOptions.disabled = !isDHT;
    dhtKeyDisplay.hidden = !isDHT;
    dhtHelp.hidden = !isDHT;
    selDecode.disabled = !isTXT;
    selADecode.disabled = !isA;
    inpAKey.disabled = !isA;
    inpEnsKey.disabled = !(isENS || isSNS);
    selEnsDecode.disabled = !(isENS || isSNS);
    inpEnsOptions.disabled = !(isENS || isSNS);
    inpEnsNode.disabled = !isENS;
    inpEnsResolver.disabled = !isENS;
    [selDecode, selADecode, inpAKey, inpEnsKey, selEnsDecode, inpEnsOptions, inpEnsNode, inpEnsResolver, inpDhtKey, inpDhtOptions, selRpcProfile].forEach(control=>{
      if(control.parentElement.tagName === 'LABEL') control.parentElement.hidden = control.disabled;
    });
  };
  sel.onchange = toggleDecodeInputs;
  toggleDecodeInputs();

  const tdBtn = document.createElement('td');
  const del = document.createElement('button'); 
  del.textContent='🗑️ Remove'; 
  del.title = 'Remove this domain';
  del.onclick = async ()=> { 
    if(!window.confirm(`Remove ${inp.value || 'this target'} and save the current settings?`)) return;
    const status = document.getElementById('domainSettingsStatus');
    const feedback = viewFeedbackOwner('config-settings', 'domainSettingsStatus');
    const token = feedback?.begin('/config');
    const draft = settingsDraftStamp('domainSettingsSection');
    let submitted = false;
    del.disabled = true;
    try{
      // 자동으로 저장
      const payload = {
        domains: collectDomainsFromUI(tr),
        revision: configRevision,
        servers: document.getElementById('servers').value.split(',').map(s=>s.trim()).filter(Boolean),
        interval: parseInt(document.getElementById('interval').value) || 60,
        ens_rpc_url: ((document.getElementById('ensRpcUrl') || {}).value || '').trim()
        ,DEFAULT_SNS_PROXY_HOSTS: ((document.getElementById('snsProxyHosts') || {}).value || '').split(',').map(s=>s.trim()).filter(Boolean)
      };
      submitted = true;
      const r = await fetch('/config',{method:'POST',feedback:token,headers:{'Content-Type':'application/json'},body:JSON.stringify(domainWritePayload(payload))});
      const j = await r.json();
      if(!feedbackCurrent(token)) return;
      if(!r.ok || j?.status !== 'ok' || !Number.isSafeInteger(j.revision) || j.revision < 0 || !Array.isArray(j.config?.domains)) throw new Error(j?.error || 'Removal response could not confirm the committed configuration');
      const unchanged = draft === settingsDraftStamp('domainSettingsSection');
      if(unchanged) applyDomainConfig({...j.config, revision: j.revision});
      feedback?.succeed(token);
      status.textContent = 'Removed domain and saved'+commitWarningText(j)+(unchanged ? '' : ` (revision ${j.revision}). Later draft retained with its original revision; Load explicitly to review saved settings.`);
      log('Removed domain and saved');
    }catch(e){ 
      if(!feedbackCurrent(token)) return;
      feedbackFailure(feedback, token, submitted ? e : {status:400}, true);
      status.textContent = `Remove failed: ${submitted ? (feedback?.snapshot().error?.message || e.message) : e.message}`;
      log('Remove error:'+e); 
    }finally{
      del.disabled = false;
    }
  };
  tdBtn.appendChild(del);
  const card = document.createElement('td');
  card.className = 'domain-card';
  const heading = document.createElement('div');
  heading.className = 'domain-card-heading';
  const name = document.createElement('strong');
  name.className = 'domain-full-name';
  name.textContent = inp.value || 'New target';
  const badge = document.createElement('span');
  badge.className = 'domain-type-badge';
  badge.textContent = sel.value;
  heading.append(name, badge);
  const dates = document.createElement('dl');
  dates.className = 'domain-dates';
  [['Registered in TraceDNS', 'created_at', 'domain-created'], ['Last configuration change', 'updated_at', 'domain-updated']].forEach(([label, key, cls])=>{
    const group = document.createElement('div');
    group.className = cls;
    const dt = document.createElement('dt'); dt.textContent = label;
    const dd = document.createElement('dd');
    const raw = metadata && metadata[key];
    const date = raw ? new Date(raw) : null;
    if(date && !Number.isNaN(date.getTime())){
      const time = document.createElement('time');
      time.dateTime = raw;
      time.textContent = formatLocalDateTime(date);
      time.title = date.toISOString();
      dd.appendChild(time);
    }else{
      dd.textContent = obj ? 'Not recorded' : 'Not saved yet';
    }
    group.append(dt, dd); dates.appendChild(group);
  });
  const detail = document.createElement('details');
  detail.open = !obj;
  const summary = document.createElement('summary');
  summary.textContent = 'View / edit configuration';
  const fields = document.createElement('div');
  fields.className = 'domain-editor-grid';
  [[tdName,'Domain name / DHT or RPC display label'], [tdType,'Record type'], [tdTxtDecode,'TXT decoder'], [tdADecode,'A decoder'], [tdAKey,'A XOR key'], [tdEnsKey,'ENS / SNS record key'], [tdEnsDecode,'ENS / SNS decoder'], [tdEnsOptions,'Decoder options (JSON)'], [tdEnsNode,'ENS node'], [tdEnsResolver,'ENS resolver'], [tdDhtKey,'DHT public key'], [tdDhtOptions,'DHT lookup options (JSON)'], [tdRpcProfile,'RPC profile']].forEach(([cell, title])=>{
    const label = document.createElement('label');
    label.textContent = title;
    const control = cell.firstChild;
    label.appendChild(control);
    label.hidden = control.disabled;
    fields.appendChild(label);
  });
  detail.append(summary, fields, dhtHelp, rpcHelp);
  card.append(heading, dhtKeyDisplay, dates, detail, del);
  if(obj && ['A','TXT','ENS','SNS','DHT','RPC'].includes(String(obj.type || 'A').toUpperCase())){
    const resend = document.createElement('button');
    resend.className = 'delivery-resend-btn';
    resend.type = 'button'; resend.dataset.access = 'admin';
    resend.hidden = true; resend.disabled = true;
    resend.textContent = 'Resend current IPs';
    card.appendChild(resend);
  }
  tr.appendChild(card);
  inp.addEventListener('input', ()=>{ name.textContent = inp.value || 'New target'; });
  sel.addEventListener('change', ()=>{ badge.textContent = sel.value; });
  tr._initialState = domainEditorState(tr);
  tbody.appendChild(tr);
  filterDomainSettings();
  uiOverview.configured = document.querySelectorAll('#domainTable tbody tr').length;
  updateOverviewPanel();
}

document.getElementById('addDomain').onclick = ()=>{
  if(window.TraceDeliveryResend) window.TraceDeliveryResend.changed();
  document.getElementById('domainSettingsSearch').value = '';
  addDomainRow();
  document.querySelector('#domainTable tbody tr:last-child .domain-name').focus();
};

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
    // The catalog revision belongs to the loaded draft, not a tab switch.
    // Refresh only at startup or through the explicit reload/review action.
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
if(window.TraceTeamsTest) window.TraceTeamsTest.bind(() => alertSettingsReady ? alertRevision : null);

function collectDomainsFromUI(excludedRow){
  const rows = document.querySelectorAll('#domainTable tbody tr');
  const out = [];
  rows.forEach(r=>{
    if(r === excludedRow) return;
    const typ = ((r.querySelector('.domain-type') || {}).value || 'A').toUpperCase();
    if(typ === 'RPC' && !String((r.querySelector('.domain-name') || {}).value || '').trim()) throw new Error('RPC display label is required');
    let dht = null;
    if(typ === 'DHT'){
      dht = parseDhtInputs((r.querySelector('.dht-public-key') || {}).value, (r.querySelector('.dht-options') || {}).value);
      if(!dht.ok) throw new Error(dht.error);
      if(!String((r.querySelector('.domain-name') || {}).value || '').trim()) throw new Error('DHT display label is required');
    }
    if(r._original && domainEditorState(r) === r._initialState){
      out.push({...r._original});
      return;
    }
    const name = ((r.querySelector('.domain-name') || {}).value || '').trim();
    const txt_decode = ((r.querySelector('.txt-decode') || {}).value || '').trim();
    const a_decode = ((r.querySelector('.a-decode') || {}).value || 'none').trim();
    const a_xor_key = ((r.querySelector('.a-xor-key') || {}).value || '').trim();
    const ens_text_key = ((r.querySelector('.ens-text-key') || {}).value || '').trim();
    const ens_decode = ((r.querySelector('.ens-decode') || {}).value || 'ipv6_5to8_xor').trim();
    const ens_options_raw = ((r.querySelector('.ens-options') || {}).value || '').trim();
    if(name) {
      const obj = typ === 'DHT' && r._original && r._original.type === 'DHT' ? {...r._original, name, type: typ} : {name: name, type: typ};
      if(typ === 'DHT'){
        delete obj.dht_options;
        Object.assign(obj, dht.value);
      } else if(typ === 'RPC'){
        obj.rpc_profile = r.querySelector('.rpc-profile').value;
      } else if(typ === 'TXT'){
        if(txt_decode) obj.txt_decode = txt_decode;
      } else if(typ === 'A'){
        if(a_decode && a_decode !== 'none') obj.a_decode = a_decode;
        // key를 넣었는데 method를 안 고른 경우 xor32 기본으로 자동 지정
        if(a_xor_key){
          if(!obj.a_decode) obj.a_decode = 'xor32_ipv4';
          obj.a_xor_key = a_xor_key;
        }
      } else if(typ === 'ENS'){
        const node = r.querySelector('.ens-node').value.trim();
        const resolver = r.querySelector('.ens-resolver').value.trim();
        if(node) obj.ens_node = node;
        if(resolver) obj.ens_resolver = resolver;
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
      } else if(typ === 'SNS'){
        if(ens_text_key) obj.ens_text_key = ens_text_key;
        if(ens_decode) obj.sns_decode = ens_decode;
        const parsed = parseJsonObjectInput(ens_options_raw, `SNS options (${name})`);
        if(!parsed.ok){
          throw new Error(parsed.error);
        }
        if(parsed.value){
          if(!obj.sns_decode) obj.sns_decode = 'ROL3210_decode';
          obj.sns_options = parsed.value;
        }
      }
      out.push(obj);
    }
  });
  return out;
}

// Build only the fields this user's form is allowed to change.
function domainWritePayload(payload){
  if(window.TraceAuth && window.TraceAuth.user.role !== 'admin'){
    return {domains:payload.domains, revision:payload.revision};
  }
  return {...payload, clear_fields:selectedSecretClears('config')};
}

function selectedSecretClears(scope){
  return [...document.querySelectorAll(`[data-clear-scope="${scope}"]:checked`)].map(el=>el.dataset.clearField);
}

function secretInput(id, field, configured, scope){
  const input = document.getElementById(id);
  if(!input) return;
  input.value = '';
  input.placeholder = configured ? 'Configured — leave blank to keep' : 'Not configured';
  let clear = document.getElementById('clear-'+id);
  if(!clear){
    const label = document.createElement('label');
    clear = document.createElement('input');
    clear.id = 'clear-'+id; clear.type = 'checkbox';
    clear.dataset.clearScope = scope; clear.dataset.clearField = field;
    label.append(clear, document.createTextNode(' Clear saved value'));
    input.after(label);
  }
  clear.checked = false;
  clear.disabled = !configured;
}

// Revision belongs to the displayed form, not an unrelated background read.
let configRevision = null;
let alertRevision = null;
// Keep the form's revision on failed/ignored reads without enabling a real test
// from an unconfirmed reload. This is separate from the editable draft identity.
let alertSettingsReady = false;
if(window.TraceDeliveryResend) window.TraceDeliveryResend.bind(() => configRevision, domainConfigIdentity);

function applyDomainConfig(j){
  configRevision = j.revision;
  document.querySelector('#domainTable tbody').innerHTML = '';
  const domains = j.domains || [];
  if(Array.isArray(domains)) {
    domains.forEach(d=>{
      const obj = typeof d === 'string' ? {name:d, type:'A'} : d;
      if(obj) addDomainRow(obj, (j.domain_metadata || {})[domainConfigIdentity(obj)]);
    });
    uiOverview.configured = domains.length;
    updateOverviewPanel();
  }
  const servers = j.servers || [];
  filterDomainSettings();
  document.getElementById('servers').value = (Array.isArray(servers) ? servers : []).join(',');
  const ensRpcEl = document.getElementById('ensRpcUrl');
  if(ensRpcEl) secretInput('ensRpcUrl', 'ens_rpc_url', !!(j.configured || {}).ens_rpc_url, 'config');
  const snsHostsEl = document.getElementById('snsProxyHosts');
  if(snsHostsEl) secretInput('snsProxyHosts', 'DEFAULT_SNS_PROXY_HOSTS', !!(j.configured || {}).DEFAULT_SNS_PROXY_HOSTS, 'config');
  document.getElementById('interval').value = j.interval || 60;
  if(window.TraceDeliveryResend) window.TraceDeliveryResend.savedConfig();
}

async function loadCfg(){
  const feedback = viewFeedbackOwner('config-settings', 'domainSettingsStatus');
  const token = feedback?.begin('/config');
  const draft = settingsDraftStamp('domainSettingsSection');
  const status = document.getElementById('domainSettingsStatus');
  if(window.TraceDeliveryResend) window.TraceDeliveryResend.invalidateConfig();
  try{
    const r = await fetch('/config', {feedback:token});
    if(!r.ok) throw Object.assign(new Error('HTTP '+r.status), {status:r.status});
    const j = await r.json();
    if(!feedbackCurrent(token)) return;
    if(!j) { log('Invalid config response'); return; }
    if(draft !== settingsDraftStamp('domainSettingsSection')){
      status.textContent = 'Load not applied — later draft retained with its original revision. Load explicitly again to discard it.';
      return;
    }
    applyDomainConfig(j);
    feedback?.succeed(token);
    status.textContent = 'Loaded saved configuration';
    log('Loaded config');
    touchOverviewTs();
  }catch(e){
    if(!feedbackCurrent(token)) return;
    feedbackFailure(feedback, token, e);
    status.textContent = 'Load failed. Displayed draft and revision retained.';
    log('Config load error:'+e);
  }
}
document.getElementById('load').onclick = loadCfg;

document.getElementById('save').onclick = async ()=>{
  const status = document.getElementById('domainSettingsStatus');
  const feedback = viewFeedbackOwner('config-settings', 'domainSettingsStatus');
  const token = feedback?.begin('/config');
  const draft = settingsDraftStamp('domainSettingsSection');
  status.textContent = 'Saving…';
  document.getElementById('save').disabled = true;
  let submitted = false;
  try{
    const payload = {
      revision: configRevision,
      domains: collectDomainsFromUI(),
      servers: document.getElementById('servers').value.split(',').map(s=>s.trim()).filter(Boolean),
      interval: parseInt(document.getElementById('interval').value) || 60,
      ens_rpc_url: ((document.getElementById('ensRpcUrl') || {}).value || '').trim()
      ,DEFAULT_SNS_PROXY_HOSTS: ((document.getElementById('snsProxyHosts') || {}).value || '').split(',').map(s=>s.trim()).filter(Boolean)
    };
    uiOverview.configured = payload.domains.length;
    updateOverviewPanel();
    submitted = true;
    const r = await fetch('/config',{method:'POST',feedback:token,headers:{'Content-Type':'application/json'},body:JSON.stringify(domainWritePayload(payload))});
    const j = await r.json();
    if(!feedbackCurrent(token)) return;
    if(!r.ok || j?.status !== 'ok' || !Number.isSafeInteger(j.revision) || j.revision < 0 || !Array.isArray(j.config?.domains)) throw new Error(j?.error || 'Save response could not confirm the committed configuration');
    const unchanged = draft === settingsDraftStamp('domainSettingsSection');
    if(unchanged) applyDomainConfig({...j.config, revision: j.revision});
    feedback?.succeed(token);
    status.textContent = 'Settings saved'+commitWarningText(j)+(unchanged ? '' : ` (revision ${j.revision}). Later draft retained with its original revision; Load explicitly to review saved settings.`);
    log('Settings saved');
  }catch(e){
    if(!feedbackCurrent(token)) return;
    feedbackFailure(feedback, token, submitted ? e : {status:400}, true);
    status.textContent = `Save failed: ${submitted ? (feedback?.snapshot().error?.message || e.message) : e.message}`;
    log('Save error:'+e);
  }finally{
    document.getElementById('save').disabled = false;
  }
};

document.getElementById('force').onclick = async ()=>{
  const feedback = viewFeedbackOwner('force-resolve', 'forceResolveStatus');
  const token = feedback?.begin('/resolve');
  const status = document.getElementById('forceResolveStatus');
  status.textContent = 'Requesting resolution using saved definitions…';
  try{
    const domains = collectDomainsFromUI();
    const r = await fetch('/resolve', {method:'POST', feedback:token, headers:{'Content-Type':'application/json'}, body: JSON.stringify({domains: domains})});
    const j = await r.json();
    if(!feedbackCurrent(token)) return;
    if(!r.ok || j?.requested !== true) throw Object.assign(new Error(j?.error || 'Admission not confirmed'), {status:r.ok ? undefined : r.status});
    feedback?.succeed(token);
    status.textContent = `Resolve request admitted${j.job_id ? ' (job '+j.job_id+')' : ''}. Completion not confirmed; inspect Status for observations.`;
    log('Force requested: '+JSON.stringify(j));
    await refreshResults();
  }catch(e){
    if(!feedbackCurrent(token)) return;
    feedbackFailure(feedback, token, e, true);
    status.textContent = 'Force Resolve failed. '+(feedback?.snapshot().error?.message || e.message);
    log('Force error:'+e);
  }
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

function managedIpsForResult(info){
  const values = Array.isArray(info.values) ? info.values : [];
  const decoded = Array.isArray(info.decoded_ips) ? info.decoded_ips : [];
  const type = String(info.type || 'A').toUpperCase();
  if(type === 'DHT' || type === 'TXT' || type === 'RPC') return decoded;
  return type === 'A' ? values : values.concat(decoded);
}

function rpcEvidenceText(info, observation){
  const record = info.rpc_record || {};
  const obs = observation || {};
  const endpoints = info.decoded_endpoints || record.decoded_endpoints || [];
  const lines = [
    `Latest RPC attempt: ${obs.status || 'unknown'}${obs.reason ? ' — '+obs.reason : ''}`,
    endpoints.length ? `Last authenticated C2 endpoints: ${endpoints.join(', ')}` : 'No authenticated C2 configuration available.',
    'Last authenticated data is retained after failed lookups; it is not proof of current reachability.',
    `Profile: ${info.rpc_profile || record.profile || 'polygon_aes_gcm_v1'}`,
    `Chain: Polygon (${record.chain_id || 137}) / block: ${record.block || 'latest'}`,
    `Contract: ${record.contract || 'unknown'} / selector: ${record.selector || 'unknown'}`,
    `Authentication: ${record.authentication || 'not verified'}`,
    `Source RPC (not C2): ${record.source_rpc || 'unknown'}`,
    `Auxiliary roles (not C2): ${JSON.stringify(record.roles || {})}`,
    'No C2 contact. Public RPC observation is not independent chain-finality proof.'
  ];
  if(record.plaintext) lines.push(`Authenticated plaintext:\n${record.plaintext}`);
  return lines.join('\n');
}

function renderRpcEvidence(cell, info, observation){
  const text = rpcEvidenceText(info, observation);
  const summary = document.createElement('div');
  summary.textContent = text.split('\n').slice(0,3).join('\n');
  const details = document.createElement('details');
  const title = document.createElement('summary');
  title.textContent = 'RPC identity, auxiliary roles and plaintext';
  const evidence = document.createElement('pre');
  evidence.textContent = text;
  details.append(title, evidence);
  cell.className = 'rpc-evidence';
  cell.replaceChildren(summary, details);
  cell.removeAttribute('title');
}

function formatDhtSequence(seq){
  // BEP44 sequence values are decimal strings, never JS floating point numbers.
  return typeof seq === 'string' && /^[0-9]+$/.test(seq) ? seq : 'unknown (expected decimal string)';
}

function dhtEvidenceText(info, observation, storageName=''){
  const record = info.dht_record || {};
  const obs = observation || {};
  const storageKey = String(storageName).match(/\[DHT:([0-9a-fA-F]{64})\]$/);
  const keys = Array.isArray(info.dht_public_keys) ? info.dht_public_keys : [info.dht_public_key || (storageKey && storageKey[1])].filter(Boolean);
  const targets = Array.isArray(info.dht_targets) ? info.dht_targets : [record.target].filter(Boolean);
  const sequences = Array.isArray(info.dht_sequences) ? info.dht_sequences : (record.seq != null ? [record.seq] : []);
  const labels = {
    initial:'Initial verified record', updated:'Updated verified record', unchanged:'Unchanged verified record',
    no_verified_record:'No verified record found', stale_only:'Only stale records observed',
    same_seq_conflict:'Conflicting signed records at the same sequence',
    signed_dns_invalid:'Signed value is not valid DNS', cancelled:'Lookup cancelled'
  };
  const lines = [`Public key: ${keys.join(', ') || 'unknown'}`];
  if(sequences.length){
    lines.push(`Last-confirmed sequence: ${sequences.map(formatDhtSequence).join(', ')}`);
    lines.push(`Last-confirmed target: ${targets.join(', ') || 'unknown'}`);
    lines.push('Decoded IPs show the last-confirmed record, not necessarily the latest attempt.');
  }else{
    lines.push('No last-confirmed record available.');
  }
  if(record.signature_valid != null) lines.push(`Selected record signature: ${record.signature_valid === true ? 'valid' : 'not verified'}`);
  if(record.value_sha256) lines.push(`Value SHA-256: ${record.value_sha256}`);
  if(Array.isArray(record.source_node)) lines.push(`Storage node (unsigned observation, not signer/C2): ${JSON.stringify(record.source_node)}`);
  const status = String(obs.status || 'unknown');
  lines.push(`Latest lookup attempt: ${status}${labels[status] ? ' — '+labels[status] : ''}`);
  lines.push(`Attempt observed at: ${obs.observed_at ? formatUnixTsLocal(obs.observed_at) : 'unknown'}`);
  const observedSeq = obs.observed_seq ?? obs.seq;
  if(observedSeq != null) lines.push(`Observed sequence: ${formatDhtSequence(observedSeq)}`);
  lines.push(`Coverage: ${obs.coverage == null ? 'unknown' : JSON.stringify(obs.coverage)}`);
  lines.push('Coverage warning: a bounded lookup is not proof of absence or deletion.');
  lines.push('Signed DNS is not proof of actual C2 activity. No C2 contact or republish.');
  return lines.join('\n');
}

function renderDhtEvidence(cell, info, observation, storageName){
  const text = dhtEvidenceText(info, observation, storageName);
  const lines = text.split('\n');
  const summary = document.createElement('div');
  const prefixes = ['Latest lookup attempt:', 'Last-confirmed sequence:', 'No last-confirmed record',
    'Decoded IPs show', 'Public key:', 'Coverage warning:'];
  summary.textContent = prefixes.flatMap(prefix=>lines.filter(line=>line.startsWith(prefix))).join('\n');
  const details = document.createElement('details');
  const title = document.createElement('summary');
  title.textContent = 'Signature, source and coverage details';
  const evidence = document.createElement('pre');
  evidence.textContent = text;
  details.append(title, evidence);
  cell.className = 'dht-evidence';
  cell.replaceChildren(summary, details);
  cell.removeAttribute('title');
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
      dht_public_keys: new Set(),
      dht_targets: new Set(),
      dht_sequences: new Set(),
      decoded_endpoints: new Set(),
      rpc_record: null,
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
      (info.decoded_endpoints || []).forEach(endpoint=>acc.decoded_endpoints.add(String(endpoint)));
      if(rtype === 'RPC' && info.rpc_record) acc.rpc_record = info.rpc_record;
      if(rtype === 'DHT'){
        if(info.dht_public_key) acc.dht_public_keys.add(String(info.dht_public_key));
        const record = info.dht_record || {};
        if(record.target) acc.dht_targets.add(String(record.target));
        if(typeof record.seq === 'string') acc.dht_sequences.add(record.seq);
      }
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
      a_xor_keys: Array.from(acc.a_xor_keys).sort(),
      dht_public_keys: Array.from(acc.dht_public_keys).sort(),
      dht_targets: Array.from(acc.dht_targets).sort(),
      dht_sequences: Array.from(acc.dht_sequences).sort(),
      decoded_endpoints: Array.from(acc.decoded_endpoints).sort(),
      ...(acc.rpc_record ? {rpc_record:acc.rpc_record, rpc_profile:acc.rpc_record.profile} : {})
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

// Compare actual values, not lengths or aggregates. Timestamp is a separate
// text-only patch; all other content (including VT flags) is part of identity.
function rowContentWithoutTime(value, timeKey){
  const content = {...value};
  delete content[timeKey];
  return content;
}
function reconcilePreparedRows(tbody, items, createRow, timeCell, commits=null){
  const previous = tbody._preparedRows || new Map();
  const next = new Map();
  const updates = [];
  for(const item of items.slice(0, 200)){
    const signature = JSON.stringify(item.content);
    const old = previous.get(item.key);
    const row = old && old.signature === signature ? old.row : createRow(item);
    next.set(item.key, {row, signature, item});
    updates.push({row, text:formatUnixTsLocal(item.time)});
  }
  // Build every changed row off-DOM before touching the last-good display.
  const desired = [];
  for(const {row} of updates){
    desired.push(row);
    const detail = row.nextElementSibling;
    if(detail && detail.classList.contains('verify-row')) desired.push(detail);
  }
  const keep = new Set(desired);
  const commit = ()=>{
    for(const {row, text} of updates){
      const cell = row.children[timeCell];
      if(cell && cell.textContent !== text) cell.textContent = text;
    }
    for(const child of Array.from(tbody.children)) if(!keep.has(child)) child.remove();
    desired.forEach((row, index)=>{
      if(tbody.children[index] !== row) tbody.insertBefore(row, tbody.children[index] || null);
    });
    tbody._preparedRows = next;
  };
  if(commits) commits.push(commit); else commit();
}

const statusPageRows = new Map();
let selectedTarget = null;
function viewNode(tag, text){
  const node = document.createElement(tag);
  if(text !== undefined) node.textContent = text;
  return node;
}
function lazyViewDetails(title, build, id){
  const disclosure = viewNode('details');
  if(id) disclosure.id = id;
  disclosure.appendChild(viewNode('summary', title));
  let body = null;
  disclosure.addEventListener('toggle', () => {
    if(body){ body.remove(); body = null; }
    if(disclosure.open){ body = viewNode('div'); build(body); disclosure.appendChild(body); }
  });
  return disclosure;
}
function statusObservation(info, meta){
  const dht = meta.dht_observation, rpc = meta.rpc_observation;
  if(dht) return `DHT: ${dht.status || 'unknown'} · ${info.ts ? 'last-confirmed retained' : 'no confirmed record'} · bounded coverage`;
  if(rpc) return `RPC: ${rpc.status || 'unknown'}${rpc.reason ? ' · '+rpc.reason : ''} · ${info.ts ? 'last-authenticated retained' : 'no authenticated record'}`;
  if(meta.nxdomain_active) return 'NXDOMAIN · previous data may be retained';
  if(meta.dns_error_only_active) return 'Latest attempts failed · retained data';
  return info.ts ? 'Recorded result · not a live check' : 'Unknown · no observation time';
}
function closeTargetDetail(restoreFocus = true){
  const previous = selectedTarget;
  selectedTarget = null;
  cancelHistoryRead();
  loadHistory.lastGood = null;
  if(previous?.controller) previous.controller.abort();
  localFeedbackOwners.get('target-action')?.invalidate();
  const panel = document.getElementById('targetDetail');
  if(panel){ panel.replaceChildren(); panel.hidden = true; }
  document.getElementById('statusLayout')?.classList.remove('has-selection');
  if(restoreFocus && previous?.opener?.isConnected) previous.opener.focus();
}
function openTargetDetail(domain, opener, focus = true){
  if(window.TraceAuth?.accessInvalidated) return;
  const entry = statusPageRows.get(domain) || {info:{}, meta:{}, snapshot:'unknown'};
  closeTargetDetail(false);
  const selection = selectedTarget = {domain, ...entry, opener, controller:null};
  const panel = document.getElementById('targetDetail');
  const heading = viewNode('h4', domain); heading.id = 'targetDetailHeading'; heading.tabIndex = -1;
  const close = viewNode('button', 'Close details'); close.id = 'closeTargetDetail'; close.onclick = () => closeTargetDetail();
  const when = viewNode('p', 'Last observed: '+formatUnixTsLocal(entry.info.ts)); when.id = 'targetObserved';
  const update = viewNode('button', 'Update selected details from current page'); update.id = 'targetDetailUpdate'; update.hidden = true;
  update.onclick = () => openTargetDetail(domain, opener);
  panel.append(heading, close, when, viewNode('p', 'Status snapshot: '+entry.snapshot),
    viewNode('p', statusObservation(entry.info, entry.meta)), update);
  panel.appendChild(lazyViewDetails('Observations, managed IPs and decoders', body => {
    if(selectedTarget !== selection) return;
    const info = selection.info;
    body.appendChild(viewNode('h5', 'Managed IPs · selected target'));
    const ips = viewNode('div'); renderPreparedValues(ips, managedIpsForResult(info)); body.appendChild(ips);
    body.appendChild(viewNode('h5', 'Observed values'));
    const raw = viewNode('div'); renderPreparedValues(raw, info.values); body.appendChild(raw);
    body.appendChild(viewNode('p', 'Decoder: '+(info.method_summary || 'not reported')));
    body.appendChild(viewNode('pre', 'Servers: '+(info.servers || []).join('\n')));
    if(selection.meta.dht_observation || info.type === 'DHT'){
      const evidence = viewNode('div'); renderDhtEvidence(evidence, info, selection.meta.dht_observation, domain); body.appendChild(evidence);
    }
    if(selection.meta.rpc_observation || info.type === 'RPC'){
      const evidence = viewNode('div'); renderRpcEvidence(evidence, info, selection.meta.rpc_observation); body.appendChild(evidence);
    }
  }, 'targetEvidence'));
  const history = viewNode('button', 'History'); history.id = 'targetHistory';
  history.onclick = () => { if(selectedTarget === selection) loadHistory(domain); };
  panel.appendChild(history);
  panel.appendChild(lazyViewDetails('Raw projection and explicit actions', body => {
    if(selectedTarget !== selection) return;
    body.appendChild(viewNode('p', 'This is the selected prepared projection. The full legacy export below the table retains all current server raw facts.'));
    body.appendChild(lazyViewDetails('Show complete selected JSON', raw => raw.appendChild(viewNode('pre', JSON.stringify({target:domain,...entry}, null, 2)))));
    if(['admin','operator'].includes(window.TraceAuth?.user?.role) && (entry.info.type === 'TXT' || entry.info.record_types?.includes('TXT'))){
      for(const [label, path] of [['Analyze TXT','/analyze'], ['Legacy TXT verify','/verify']]){
        const button = viewNode('button', label); button.dataset.access = 'operator';
        button.onclick = () => runSelectedTargetAction(selection, path, button);
        body.appendChild(button);
      }
      const result = viewNode('pre'); result.id = 'analyzeResult'; result.setAttribute('role','status'); body.appendChild(result);
    }
  }));
  panel.hidden = false;
  document.getElementById('statusLayout').classList.add('has-selection');
  if(focus){ heading.focus({preventScroll:true}); panel.scrollIntoView({block:'nearest'}); }
}
async function runSelectedTargetAction(selection, path, button){
  if(selectedTarget !== selection) return;
  selection.controller?.abort();
  const controller = selection.controller = new AbortController();
  const feedback = viewFeedbackOwner('target-action', 'analyzeResult');
  const token = feedback?.begin(selection.domain + ':' + path);
  const result = document.getElementById('analyzeResult');
  result.textContent = 'Running explicit action…'; button.disabled = true;
  const payload = path === '/verify' ? {domains:[selection.domain]} : {domain:selection.domain,
    txt:[...new Set((selection.info.values || []).map(String))].slice(0,20).join('|')};
  try{
    const data = await window.TraceAuth.readJSON(path, {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload), signal:controller.signal, feedback:token});
    if(selectedTarget !== selection || controller.signal.aborted) return;
    result.textContent = JSON.stringify(data, null, 2); feedback?.succeed(token);
  }catch(error){
    if(selectedTarget !== selection || controller.signal.aborted) return;
    feedbackFailure(feedback, token, error, true);
    result.textContent = error.status === 501 ? 'Legacy verify is not implemented by this server. Use Domain Verify for an explicit precheck.'
      : feedback?.snapshot().error?.message || 'Action failed. Check saved state before retrying.';
  }finally{ button.disabled = false; }
}
function ensureTargetHistory(domain){
  if(!selectedTarget || selectedTarget.domain !== domain) openTargetDetail(domain, null, false);
  let box = document.getElementById('historyBox');
  if(!box){
    box = viewNode('div'); box.id = 'historyBox';
    document.getElementById('targetDetail').append(viewNode('h5','History · selected target'), box);
  }
  return box;
}

async function refreshResults(){
  const owner = beginSectionRefresh('status');
  if(!owner) return;
  try{
    const j = await readPreparedJSON(owner);
    if(preparedResponseHandled(owner)) return;
    const resultsAgg = (j && j.results_agg && typeof j.results_agg === 'object')
      ? j.results_agg
      : {};
    const domainMeta = (j && j.domain_meta && typeof j.domain_meta === 'object') ? j.domain_meta : {};
    const tbody = document.querySelector('#resultsTable tbody');
    // A never-confirmed target can have attempt metadata but no retained record.
    const domains = Array.from(new Set([...Object.keys(resultsAgg), ...Object.keys(domainMeta).filter(d=>domainMeta[d] && domainMeta[d].dht_observation)])).sort();
    const managedSet = new Set();

    domains.forEach(d=>{
      const info = resultsAgg[d] || {};
      const managedIps = managedIpsForResult(info);
      managedIps.forEach(ip=>{
        const s = String(ip || '').trim();
        if(s) managedSet.add(s);
      });
    });
    const items = domains.map(d=>({key:d, time:(resultsAgg[d] || {}).ts,
      content:{info:rowContentWithoutTime(resultsAgg[d] || {}, 'ts'), meta:domainMeta[d] || {}}}));
    reconcilePreparedRows(tbody, items, item=>{
      const d = item.key;
      const info = resultsAgg[d] || {};
      const meta = domainMeta[d] || {};
      const tr = viewNode('tr'); tr.dataset.domain = d;
      const name = viewNode('td', d); name.className = 'target-name';
      applyNxdomainLifecycleStyle(name, meta, d);
      const observation = viewNode('td', statusObservation(info, meta)); observation.className = 'observation-cell';
      const ips = managedIpsForResult(info);
      const managed = viewNode('td', ips.length ? ips.slice(0,3).join(' · ') + (ips.length > 3 ? ` · +${ips.length-3} (see details)` : '') : 'None recorded');
      managed.className = 'managed-summary';
      const action = viewNode('td');
      const details = viewNode('button', 'Details'); details.setAttribute('aria-controls','targetDetail');
      details.onclick = () => openTargetDetail(d, details);
      action.appendChild(details);
      for(const cell of [name, viewNode('td', info.type || (meta.dht_observation ? 'DHT' : 'Unknown')), observation,
        managed, viewNode('td', formatUnixTsLocal(info.ts)), action]) tr.appendChild(cell);
      return tr;
    }, 4);
    statusPageRows.clear();
    for(const d of domains.slice(0,200)) statusPageRows.set(d, {info:resultsAgg[d] || {}, meta:domainMeta[d] || {},
      snapshot:formatUnixTsLocal(j.snapshot?.generated_at)});
    if(selectedTarget){
      const current = statusPageRows.get(selectedTarget.domain);
      if(!current) closeTargetDetail(false);
      else if(JSON.stringify(current.info) !== JSON.stringify(selectedTarget.info) || JSON.stringify(current.meta) !== JSON.stringify(selectedTarget.meta)){
        document.getElementById('targetDetailUpdate').hidden = false;
      }
    }
    uiOverview.statusRows = j.results_total_count ?? (j.page && j.page.total) ?? domains.length;
    uiOverview.managedIps = managedSet.size;
    touchOverviewTs('status');
    completePreparedRender(owner);
  }catch(e){
    failSectionRefresh(owner, e);
  }finally{
    finishSectionRefresh(owner);
  }
}

function cancelHistoryRead(){
  const previous = loadHistory.active;
  if(previous){
    previous.controller.abort(); previous.feedback?.invalidate();
    if(selectedTarget === previous.selection){
      const status = document.getElementById('historyStatus');
      if(status) status.textContent = (previous.selection.historyFailure || '') +
        ' History read stopped. Select History again to retry.' + (loadHistory.lastGood ? ' Previous history is stale.' : '');
    }
  }
  loadHistory.active = null;
}

function historyEventText(h){
  const t = formatUnixTsLocal(h.ts);
  if(h.new && h.old){
    if(String(h.type).toUpperCase() === 'RPC'){
      const lines = [`${t} [${h.server}] (${h.type}) C2 ${(h.old.decoded_endpoints||[]).join(',') || '(none)'} -> ${(h.new.decoded_endpoints||[]).join(',') || '(none)'}`];
      for(const side of ['old','new']){
        const snapshot = h[side];
        lines.push(`  ${side} raw ABI: ${(snapshot.values||[]).join(',')}`);
        lines.push(`  ${side} RPC provenance (auxiliary roles are not C2): ${JSON.stringify({profile:snapshot.rpc_profile,record:snapshot.rpc_record||{}})}`);
      }
      return lines.join('\n');
    }
    return `${t} [${h.server}] (${h.type}) ${(h.old.values||[]).join(',')} -> ${(h.new.values||[]).join(',')}`;
  }
  return h.values ? `${t} [${h.server}] (${h.type}) ${(h.values||[]).join(',')}` : JSON.stringify(h);
}
function historyPageText(domain, hist, offset = 0){
  const events = hist.events || [], meta = hist.meta || {};
  const lines = [(events.length ? 'History for ' : 'No history for ') + domain];
  if(meta.first_seen) lines.push('First seen: '+formatUnixTsLocal(meta.first_seen));
  if(meta.last_changed) lines.push('Last changed: '+formatUnixTsLocal(meta.last_changed));
  if(events.length) lines.push('---', ...events.slice(offset,offset+50).map(historyEventText));
  return lines.join('\n');
}
function renderHistoryPage(record, offset = 0){
  const box = document.getElementById('historyBox');
  const selection = selectedTarget;
  if(!box || !selection || selection !== record.selection || window.TraceAuth?.accessInvalidated) return;
  const events = record.history.events || [];
  const fragment = document.createDocumentFragment();
  const summary = viewNode('p', events.length ? `History for ${record.domain} · Events ${offset+1}–${Math.min(offset+50,events.length)} of ${events.length}` : historyPageText(record.domain, record.history));
  fragment.appendChild(summary);
  fragment.appendChild(viewNode('p', 'Entire history response received by the browser; pages bound rendering only, not server response size. Last read (browser): '+record.readAt));
  for(const [id,label,next] of [['historyPrev','Previous events',offset-50],['historyNext','Next events',offset+50]]){
    const button = viewNode('button',label); button.id=id; button.disabled=next<0 || next>=events.length;
    button.onclick = () => {
      if(button.isConnected && !button.disabled && selectedTarget === selection && loadHistory.lastGood === record){
        renderHistoryPage(record,next);
        const same = document.getElementById(id);
        (same?.disabled ? document.getElementById(id === 'historyNext' ? 'historyPrev' : 'historyNext') : same)?.focus();
      }
    };
    fragment.appendChild(button);
  }
  events.slice(offset,offset+50).forEach((event,index) => {
    const detail = lazyViewDetails(`${formatUnixTsLocal(event.ts)} · ${event.type || 'Event'} · ${event.server || 'source unknown'}`, body => {
      if(detail.isConnected && selectedTarget === selection && loadHistory.lastGood === record && !window.TraceAuth?.accessInvalidated) body.appendChild(viewNode('pre',historyEventText(event)));
    });
    detail.className='history-event'; detail.dataset.index=String(offset+index); fragment.appendChild(detail);
  });
  // Request outcome belongs to the selected target, not the cached event page.
  // Keep its live node mounted while paging, including during an in-flight read.
  let page = box.querySelector('.history-page');
  if(!page){ page = viewNode('div'); page.className = 'history-page'; box.appendChild(page); }
  page.replaceChildren(fragment);
}

async function loadHistory(domain){
  if(window.TraceAuth?.accessInvalidated) return;
  cancelHistoryRead();
  const el = ensureTargetHistory(domain);
  const feedback = viewFeedbackOwner('history', 'historyBox');
  const selection = selectedTarget;
  const owner = {domain, selection, controller:new AbortController(), feedback, token:feedback?.begin(domain)};
  const current = () => loadHistory.active === owner && selectedTarget === selection && el.isConnected &&
    !owner.controller.signal.aborted && feedbackCurrent(owner.token) && !window.TraceAuth?.accessInvalidated;
  loadHistory.active = owner;
  const retained = loadHistory.lastGood?.domain === domain ? loadHistory.lastGood : null;
  let status = document.getElementById('historyStatus');
  if(!status){ status=viewNode('p'); status.id='historyStatus'; status.setAttribute('role','status'); el.appendChild(status); }
  status.textContent = (selection.historyFailure || '') + ` Loading history for ${domain}…` + (retained ? ' Previous history is stale.' : '');
  try{
    const j = await window.TraceAuth.readJSON('/history?domain='+encodeURIComponent(domain),
      {signal:owner.controller.signal, feedback:owner.token});
    if(!current()) return;
    const hist = j?.history;
    if(!hist || typeof hist !== 'object' || Array.isArray(hist) || !Array.isArray(hist.events ?? [])) throw new Error('Invalid history');
    const record = {domain, selection, history:hist, readAt:new Date().toISOString()};
    renderHistoryPage(record);
    loadHistory.lastGood = record;
    selection.historyFailure = '';
    status.textContent = 'History for ' + domain;
    feedback?.succeed(owner.token);
  }catch(e){
    if(!current()) return;
    feedbackFailure(feedback, owner.token, e);
    selection.historyFailure = `History read failed for ${domain}. Select History again to retry.` +
      (retained ? ' Previous history is stale.' : ' No successful history read for this target.');
    status.textContent = selection.historyFailure;
  }finally{
    if(loadHistory.active === owner) loadHistory.active = null;
  }
}

document.getElementById('doQuery').onclick = async ()=>{
  const v = document.getElementById('queryValue').value.trim();
  await runQuery(v);
};
document.getElementById('cancelQuery').onclick = ()=>cancelQuery();
document.getElementById('queryValue').addEventListener('input', ()=>{
  if(currentQuery) cancelQuery('Input changed; previous results belong to their labeled query and may be stale. Search explicitly.');
});



function getIpsPageSize(){
  const el = document.getElementById('ips_page_size');
  const n = parseBoundedInt(el ? el.value : 100, 100, 50, 200);
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

function openIpDetail(section, item, opener){
  if(window.TraceAuth?.accessInvalidated || getActiveSectionId() !== section || !opener?.isConnected) return;
  const row = opener.closest('tr'), tbody = row?.parentElement;
  const accepted = tbody?._preparedRows?.get(item.ip);
  if(accepted?.row !== row || !accepted?.item.value) return;
  // Timestamp-only refreshes reuse the row and its controls, not the old data.
  item = accepted.item.value;
  document.getElementById('ipDetail')?.remove();
  const panel = viewNode('aside'); panel.id='ipDetail'; panel.className='selection-detail';
  const current = () => panel.isConnected && opener.isConnected && getActiveSectionId() === section &&
    !window.TraceAuth?.accessInvalidated && tbody._preparedRows?.get(item.ip)?.row === row;
  const heading = viewNode('h4',item.ip); heading.tabIndex=-1;
  const close = viewNode('button','Close IP details'); close.onclick=()=>{panel.remove();if(opener.isConnected)opener.focus();};
  panel.append(heading, close, viewNode('p','Last observed: '+formatUnixTsLocal(item.last_ts)),
    viewNode('p',`Retained occurrences: ${item.count ?? 'unknown'}; not independent queries or infections.`),
    viewNode('pre','Related targets:\n'+(item.domains||[]).join('\n')),
    viewNode('p',item.vt ? `VT M/S: ${item.vt.malicious ?? 'unknown'}/${item.vt.suspicious ?? 'unknown'} · ASN: ${item.vt.asn ?? 'unknown'} · ${item.vt.country || 'country unknown'}` : 'No VT result in this accepted page.'));
  panel.appendChild(lazyViewDetails('Source / AS / VT record',body=>{
    if(current()) body.appendChild(viewNode('pre',JSON.stringify(item,null,2)));
  }));
  if(isIPv4(item.ip)){
    const query=viewNode('button','Query this IPv4 address (local + MISP)'); query.dataset.access='operator';
    query.hidden=window.TraceAuth?.user?.role==='viewer';
    query.onclick=()=>{if(current())openQueryForValue(item.ip);}; panel.appendChild(query);
  }
  document.getElementById(section).appendChild(panel); heading.focus(); panel.scrollIntoView({block:'nearest'});
}
function ipDetailButton(section, item){
  const cell=viewNode('td'), button=viewNode('button','Details');
  button.onclick=()=>openIpDetail(section,item,button); cell.appendChild(button); return cell;
}

async function refreshIPs(){
  const owner = beginSectionRefresh('ips');
  if(!owner) return;
  try{
    const includeVT = !!(document.getElementById('ips_include_vt') && document.getElementById('ips_include_vt').checked);
    const j = await readPreparedJSON(owner);
    if(preparedResponseHandled(owner)) return;
    const tbody = document.querySelector('#ipsTable tbody');
    const arr = j.ips || [];
    if(!Array.isArray(arr)) throw new Error('Invalid IP page');


    const items = arr.map(it=>({key:it.ip, time:it.last_ts, content:{includeVT, info:rowContentWithoutTime(it, 'last_ts')}, value:it}));
    reconcilePreparedRows(tbody, items, item=>{
      const it = item.value;
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

      const tdTs = document.createElement('td'); tdTs.textContent = formatUnixTsLocal(it.last_ts);
      const tdVtScore = document.createElement('td');
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

      } else {
        tdVtScore.textContent = includeVT ? '-' : 'off';

      }

      tr.appendChild(tdIp);
      tr.appendChild(tdDomains);
      tr.appendChild(tdTs);
      tr.appendChild(tdVtScore);
      tr.appendChild(ipDetailButton('ips',it));
      return tr;
    }, 2);

    uiOverview.allIps = j.all_ips_total_count ?? j.ips_total_count ?? arr.length;
    updateOverviewPanel();
    updateIpsMeta(j);
    touchOverviewTs();
    completePreparedRender(owner);
  }catch(e){ failSectionRefresh(owner, e); }
  finally{ finishSectionRefresh(owner); }
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
  const owner = beginSectionRefresh('validips');
  if(!owner) return;
  try{
    const j = await readPreparedJSON(owner);
    if(preparedResponseHandled(owner)) return;
    const tbody = document.querySelector('#validIpsTable tbody');
    const arr = j.ips || [];
    if(!Array.isArray(arr)) throw new Error('Invalid IP page');
    // display only syntactically valid IPs (backend also provides 'valid')
    const validOnly = arr.filter(it => it && it.valid);

    const items = validOnly.map(it=>({key:it.ip, time:it.last_ts, content:rowContentWithoutTime(it, 'last_ts'), value:it}));
    reconcilePreparedRows(tbody, items, item=>{
      const it = item.value;
      const tr = document.createElement('tr');
      const tdIp = document.createElement('td');
      tdIp.textContent = it.ip || '';
      if(isIPv4(it.ip)){
        tdIp.style.cursor = 'pointer';
        tdIp.title = 'Open in Query';
        tdIp.onclick = ()=> openQueryForValue(it.ip);
      }
      const tdDomains = document.createElement('td'); tdDomains.textContent = (it.domains||[]).join(', ');
      const tdTs = document.createElement('td'); tdTs.textContent = formatUnixTsLocal(it.last_ts);
      const tdValid = document.createElement('td'); tdValid.textContent = it.valid ? 'YES' : 'NO';
      tr.appendChild(tdIp); tr.appendChild(tdDomains); tr.appendChild(tdTs); tr.appendChild(tdValid);
      tr.appendChild(ipDetailButton('validips',it));
      return tr;
    }, 2);
    uiOverview.allIps = j.all_ips_total_count ?? uiOverview.allIps;
    uiOverview.validIps = j.ips_total_count ?? (j.page && j.page.total) ?? validOnly.length;
    updateOverviewPanel();
    touchOverviewTs();
    completePreparedRender(owner);
  }catch(e){ failSectionRefresh(owner, e); }
  finally{ finishSectionRefresh(owner); }
}

  // Auto-refresh control
  let manualPause = false; // user toggled pause
  let hoverPause = false;  // temporary pause while hovering over results

  function isPaused(){ return document.hidden || manualPause || hoverPause; }
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

  // Page controls use server-issued offsets, never inferred full-data fetches.
  for(const section of ['status', 'ips', 'validips', 'domainanalysis']){
    for(const direction of ['previous', 'next']){
      const button = document.getElementById(section + (direction === 'previous' ? '_prev_btn' : '_next_btn'));
      if(button) button.onclick = ()=>navigatePreparedPage(section, direction);
    }
  }
  const ipsRefreshBtn = document.getElementById('ips_refresh_btn');
  if(ipsRefreshBtn) ipsRefreshBtn.onclick = ()=>refreshIPs();
  for(const id of ['ips_page_size', 'ips_include_vt', 'ips_vt_workers', 'ips_vt_budget']){
    const el = document.getElementById(id);
    if(el) el.onchange = ()=>{ preparedOffsets.ips = 0; refreshIPs(); };
  }
  const domainQuery = document.getElementById('domain_analysis_query');
  if(domainQuery) domainQuery.oninput = ()=>{ preparedOffsets.domainanalysis = 0; refreshDomainAnalysis(); };
  const validSince = document.getElementById('valid_since');
  if(validSince) validSince.onchange = ()=>{ preparedOffsets.validips = 0; refreshValidIPs(); };

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
      refreshValidIPs();
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
      const snsDecodeEl = document.getElementById('verifySnsDecode');
      const snsOptionsEl = document.getElementById('verifySnsOptions');
      const includeVtEl = document.getElementById('verifyIncludeVt');
      if(domainEl) domainEl.value = '';
      if(typeEl) typeEl.value = 'AUTO';
      if(txtEl && includeOption(txtEl, 'cafebabe_xor_base64')) txtEl.value = 'cafebabe_xor_base64';
      if(aEl && includeOption(aEl, 'none')) aEl.value = 'none';
      if(keyEl) keyEl.value = '';
      if(ensKeyEl) ensKeyEl.value = 'ipv6';
      if(ensDecodeEl && includeOption(ensDecodeEl, 'ipv6_5to8_xor')) ensDecodeEl.value = 'ipv6_5to8_xor';
      if(ensOptionsEl) ensOptionsEl.value = '';
      if(snsDecodeEl && includeOption(snsDecodeEl, 'ROL3210_decode')) snsDecodeEl.value = 'ROL3210_decode';
      if(snsOptionsEl) snsOptionsEl.value = '';
      ['verifyDhtPublicKey', 'verifyDhtOptions'].forEach(id=>{
        const el = document.getElementById(id);
        if(el) el.value = '';
      });
      if(includeVtEl) includeVtEl.checked = true;
      updateDomainVerifyInputMode();
      clearDomainVerifyResult();
    });
  }
  
  document.getElementById('refreshValidBtn').onclick = ()=>{
    preparedOffsets.validips = 0;
    refreshValidIPs();
  };
  const includeVtEl = document.getElementById('ips_include_vt');
  if(includeVtEl){
    includeVtEl.addEventListener('change', ()=>{ refreshIPs(); });
  }
  const manageDomainsBtn = document.getElementById('domainAnalysisManageBtn');
  if(manageDomainsBtn){
    manageDomainsBtn.onclick = ()=>setDomainAnalysisManageMode(!domainAnalysisManageMode);
    window.TraceAuth.ready.then(()=>{ manageDomainsBtn.hidden = !canManageDomainAnalysis(); }).catch(()=>{});
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
          const j = await mutateDecoder('DELETE', {name:c.name, decoder_type:dtype});
          if(j){ document.getElementById('customPreviewResult').textContent = `Deleted ${c.name} [${dtype}]${commitWarningText(j)}`; renderCustomList(); }
        }catch(e){ document.getElementById('customPreviewResult').textContent = 'Delete error: '+e; }
      };
      const upd = document.createElement('button'); upd.textContent='Update'; upd.onclick = async ()=>{
        const stepsRaw = document.getElementById('custom_steps').value.trim(); let steps;
        try{ steps = JSON.parse(stepsRaw); }catch(e){ alert('Invalid JSON: '+e); return; }
        try{
          const j = await mutateDecoder('PUT', {name:c.name, steps, decoder_type:dtype});
          if(j){ document.getElementById('customPreviewResult').textContent = `Updated ${c.name} [${dtype}]${commitWarningText(j)}`; renderCustomList(); document.getElementById('custom_name').disabled = false; }
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
  document.getElementById('reloadCustom').onclick = async ()=>{
    try{
      await loadDecoders();
      renderCustomList();
      document.getElementById('customPreviewResult').textContent = 'Catalog reloaded; draft retained — review it before saving.';
    }catch(e){
      document.getElementById('customPreviewResult').textContent = 'Reload failed; draft retained: '+e;
    }
  };

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
      const j = await mutateDecoder('POST', {name, steps, decoder_type:decoderType});
      if(j){
        document.getElementById('customPreviewResult').textContent = `Registered: ${name} [${decoderType}]${commitWarningText(j)}`;
        renderCustomList();
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
window.IP_REL_LAST_SUCCESS = window.IP_REL_LAST_SUCCESS || null;
let ipRelActiveJobId = null;
const ipRelCancelRequestedJobs = new Set();
const IP_REL_CUSTOM_PROFILE_STORAGE_KEY = 'tracedns.iprel.custom_profile.v1';

function summarizeIpIntelInput(rawInput){
  const tokens = String(rawInput || '').split(/[\s,;|]+/).map(value=>value.trim()).filter(Boolean);
  const unique = new Set(tokens);
  return {
    tokenCount: tokens.length,
    uniqueCount: unique.size,
    duplicateCount: tokens.length - unique.size,
    isEmpty: tokens.length === 0
  };
}

function updateIpIntelInputStats(){
  const input = document.getElementById('ipIntelInput');
  const output = document.getElementById('ipIntelInputStats');
  if(!output) return;
  const summary = summarizeIpIntelInput((input || {}).value);
  output.textContent = summary.isEmpty
    ? 'No IPs entered'
    : `${summary.tokenCount} tokens · ${summary.uniqueCount} unique · ${summary.duplicateCount} duplicates`;
}

function setIpIntelInputValue(value){
  const input = document.getElementById('ipIntelInput');
  if(!input) return false;
  const nextValue = String(value == null ? '' : value);
  if(String(input.value || '') === nextValue) return false;
  cancelIpIntelInputReads(false);
  input.value = nextValue;
  updateIpIntelInputStats();
  renderMergedIpIntelHints();
  markIpRelationshipResultsStale();
  return true;
}

function buildIpRelationshipResultModel(rawResult){
  const result = (rawResult && typeof rawResult === 'object') ? rawResult : {};
  const quality = (result.quality && typeof result.quality === 'object') ? result.quality : {};
  const hasQualityContract = Object.prototype.hasOwnProperty.call(quality, 'analysis_complete');
  const count = value=>{
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0;
  };
  const pairs = Array.isArray(result.pairs) ? result.pairs : [];
  const clusters = Array.isArray(result.clusters) ? result.clusters : [];
  const invalidCount = count(result.invalid_count);
  const pairCount = Object.prototype.hasOwnProperty.call(result, 'pair_count') ? count(result.pair_count) : pairs.length;
  const evaluated = count(quality.evaluated_candidate_count);
  // candidate_limit is a resource safety ceiling, not the number of available
  // candidates.  Treating it as a denominator makes a complete small analysis
  // look almost entirely uncovered.  Only use an explicit candidate_count;
  // otherwise communicate completeness without fake precision.
  const candidateTotal = count(result.candidate_count);
  const vtReports = count(quality.vt_report_count);
  const vtEligible = count(quality.vt_eligible_count);
  const rawVtCoverage = Number(quality.vt_report_coverage);
  const vtCoverage = Number.isFinite(rawVtCoverage)
    ? rawVtCoverage
    : (vtEligible > 0 ? vtReports / vtEligible : 1);
  const pct = ratio=>`${Math.round(Math.max(0, Math.min(1, ratio)) * 100)}%`;
  const warningCodes = Array.isArray(quality.warning_codes) ? quality.warning_codes.map(String) : [];
  const vtPartial = quality.vt_enabled === true
    && (vtCoverage < 1 || warningCodes.includes('vt_partial_coverage'));
  const candidateIncomplete = quality.candidate_analysis_complete === false
    || warningCodes.some(code=>code !== 'vt_partial_coverage');
  const vtOnlyIncomplete = vtPartial && !candidateIncomplete;
  const candidateCoverage = !hasQualityContract
    ? 'Unknown'
    : vtOnlyIncomplete
    ? pct(vtCoverage)
    : candidateIncomplete && candidateTotal <= evaluated
    ? 'Partial'
    : candidateTotal > 0
    ? pct(evaluated / candidateTotal)
    : (quality.analysis_complete === false ? 'Partial' : 'Complete');
  let state = 'neutral';
  let label = 'Quality unavailable';
  let detail = 'This response does not include analysis quality metadata.';
  if(hasQualityContract && vtOnlyIncomplete){
    state = 'vt-partial';
    label = '⚠ VT partial coverage';
    detail = `VirusTotal reports cover ${pct(vtCoverage)} of eligible IPs.`;
  }else if(hasQualityContract && quality.analysis_complete === false){
    state = 'incomplete';
    label = '⚠ Incomplete analysis';
    const warningLabels = {
      bucket_truncated: 'Oversized candidate buckets were truncated.',
      bucket_skipped: 'Oversized candidate buckets were skipped.',
      candidate_limit_reached: 'Candidate evaluation reached its configured limit.',
      candidate_work_limit_reached: 'Candidate enumeration reached its work limit.',
      pair_heap_truncated: 'Pair results were truncated.',
      pair_display_truncated: 'Some admitted pairs were omitted by display or neighbor limits.',
      local_context_truncated: 'Local DNS context was bounded before analysis.',
      vt_partial_coverage: 'VirusTotal enrichment is partial.'
    };
    detail = warningCodes.map(code=>warningLabels[code] || String(code).replace(/_/g, ' ')).join(' ') || 'Resource limits produced partial results.';
  }else if(hasQualityContract && vtPartial){
    state = 'vt-partial';
    label = '⚠ VT partial coverage';
    detail = `VirusTotal reports cover ${pct(vtCoverage)} of eligible IPs.`;
  }else if(hasQualityContract && quality.analysis_complete === true && pairCount === 0){
    state = 'empty';
    label = '○ Complete — no relationships found';
    detail = 'The analysis completed successfully but no pairs met the current threshold.';
  }else if(hasQualityContract && quality.analysis_complete === true){
    state = 'complete';
    label = '✓ Complete analysis';
    detail = 'All available relationship candidates were evaluated.';
  }
  if(hasQualityContract){
    const dimensions = [
      ['Candidate discovery', 'candidate_analysis_complete'],
      ['Cluster topology', 'cluster_topology_complete'],
      ['Pair details', 'pair_detail_complete'],
      ['Enrichment', 'enrichment_complete']
    ].filter(item=>Object.prototype.hasOwnProperty.call(quality, item[1]))
      .map(item=>`${item[0]}: ${quality[item[1]] === true ? 'complete' : 'partial'}`);
    if(dimensions.length) detail += ` ${dimensions.join(' · ')}.`;
  }
  if(invalidCount > 0){
    detail += ` ${invalidCount} invalid input${invalidCount === 1 ? '' : 's'} ${invalidCount === 1 ? 'was' : 'were'} excluded.`;
  }
  return {
    metrics: {
      ips: count(result.valid_count != null ? result.valid_count : result.submitted_count),
      pairs: pairCount,
      clusters: clusters.length,
      coverage: candidateCoverage
    },
    quality: {state, label, detail}
  };
}

function relationshipValueMatches(value, normalizedQuery){
  if(value == null) return false;
  if(Array.isArray(value)) return value.some(item=>relationshipValueMatches(item, normalizedQuery));
  if(typeof value === 'object'){
    return Object.keys(value).some(key=>relationshipValueMatches(value[key], normalizedQuery));
  }
  return String(value).toLowerCase().includes(normalizedQuery);
}

function filterIpRelationshipResults(cache, query){
  const source = (cache && typeof cache === 'object') ? cache : {};
  const normalized = String(query || '').trim().toLowerCase();
  const pairs = Array.isArray(source.pairs) ? source.pairs : [];
  const clusters = Array.isArray(source.clusters) ? source.clusters : [];
  return {
    pairs: (normalized ? pairs.filter(item=>relationshipValueMatches(item, normalized)) : pairs).slice(),
    clusters: (normalized ? clusters.filter(item=>relationshipValueMatches(item, normalized)) : clusters).slice()
  };
}

function stableJsonValue(value){
  if(Array.isArray(value)) return value.map(stableJsonValue);
  if(value && typeof value === 'object'){
    const output = {};
    Object.keys(value).sort().forEach(key=>{
      Object.defineProperty(output, key, {
        value: stableJsonValue(value[key]),
        enumerable: true,
        configurable: true,
        writable: true
      });
    });
    return output;
  }
  return value;
}

function serializeIpRelationshipResult(result){
  return JSON.stringify(stableJsonValue(result), null, 2) + '\n';
}

function buildIpRelationshipExport(result, now){
  const date = (now instanceof Date && !Number.isNaN(now.getTime())) ? now : new Date();
  const stamp = date.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
  return {
    filename: `tracedns-ip-relationships-${stamp}.json`,
    content: serializeIpRelationshipResult(result)
  };
}

function isKeyboardActivation(event){
  const key = String((event && event.key) || '');
  return key === 'Enter' || key === ' ' || key === 'Spacebar';
}

function setIpRelationshipRunState(state, message){
  const normalized = ['idle', 'running', 'complete', 'stale', 'cancelled', 'error'].includes(state) ? state : 'idle';
  const defaults = {
    idle: 'Ready to analyze relationships',
    running: 'Analyzing relationships…',
    complete: 'Relationship analysis complete',
    stale: 'Inputs changed — showing results from the previous run',
    cancelled: 'Relationship analysis cancelled',
    error: 'Relationship analysis failed'
  };
  const status = document.getElementById('ipRelRunStatus');
  if(status){
    status.textContent = String(message || defaults[normalized]);
    if(status.dataset) status.dataset.state = normalized;
  }
  const running = normalized === 'running';
  const cancel = document.getElementById('cancelIpRelationshipBtn');
  const run = document.getElementById('runIpRelationshipBtn');
  const filter = document.getElementById('ipRelFilterInput');
  const exportButton = document.getElementById('exportIpRelationshipBtn');
  if(cancel){
    cancel.disabled = !running;
    cancel.hidden = !running;
    cancel.setAttribute('aria-hidden', running ? 'false' : 'true');
  }
  if(run) run.disabled = running;
  [
    'ipIntelInput', 'ipIntelIncludeVt', 'ipIntelVtBudget', 'ipIntelVtWorkers',
    'ipRelProfileSelect', 'ipRelSaveCustomBtn', 'ipRelMinScore', 'ipRelTopPairs',
    'ipRelMaxNeighbors', 'ipRelBucketMax', 'ipRelBucketOverflowMode',
    'ipRelPairGateEnabled', 'ipRelGateStrongMin', 'ipRelGateMidMin',
    'ipRelGateFallbackScore'
  ].forEach(id=>{
    const control = document.getElementById(id);
    if(control) control.disabled = running;
  });
  if(!running && typeof updateIpRelGateUi === 'function') updateIpRelGateUi();
  const hasResult = !!window.IP_REL_LAST_SUCCESS;
  if(filter) filter.disabled = running || !hasResult;
  if(exportButton) exportButton.disabled = running || !hasResult;
}

function markIpRelationshipResultsStale(){
  if(!window.IP_REL_LAST_SUCCESS) return false;
  const status = document.getElementById('ipRelRunStatus');
  if(status && status.dataset && status.dataset.state === 'running') return false;
  setIpRelationshipRunState('stale');
  const banner = document.getElementById('ipRelQualityBanner');
  if(banner){
    if(banner.dataset) banner.dataset.state = 'stale';
    const quality=buildIpRelationshipResultModel(window.IP_REL_LAST_SUCCESS).quality;
    banner.textContent = 'Inputs changed — these results are from the previous run. Run the analysis again before making a decision. Previous run quality: '+quality.label+' '+quality.detail;
  }
  return true;
}

function cancelActiveIpRelationshipAnalysis(){
  const controller = ipRelAnalyzeController;
  if(!controller || (controller.signal && controller.signal.aborted)) return false;
  const jobId = ipRelActiveJobId;
  const requestSeq = ipRelAnalyzeSeq;
  controller.abort();
  if(jobId && !ipRelCancelRequestedJobs.has(jobId)){
    ipRelCancelRequestedJobs.add(jobId);
    void cancelIpRelationshipJob(jobId).then(cancelled=>{
      if(requestSeq !== ipRelAnalyzeSeq || controller.browserDetached) return;
      controller.serverCancelConfirmed = cancelled;
      controller.serverCancelUnconfirmed = !cancelled;
      setIpRelationshipRunState(
        'cancelled',
        cancelled ? 'Server cancellation confirmed. Previous results, if any, belong to the previous successful run.'
          : 'Client polling stopped, but server cancellation could not be confirmed.'
      );
    });
  }
  setIpRelationshipRunState('cancelled','Browser polling stopped; server cancellation not yet confirmed.');
  renderIpRelationshipError(
    document.querySelector('#ipRelPairsTable tbody'),
    document.querySelector('#ipRelClustersTable tbody'),
    'Analysis cancelled'
  );
  return true;
}

function renderIpRelationshipProductSummary(result){
  const model = buildIpRelationshipResultModel(result);
  const metricValues = {
    ipRelMetricIps: model.metrics.ips,
    ipRelMetricPairs: model.metrics.pairs,
    ipRelMetricClusters: model.metrics.clusters,
    ipRelMetricCoverage: model.metrics.coverage
  };
  Object.keys(metricValues).forEach(id=>{
    const element = document.getElementById(id);
    if(element) element.textContent = String(metricValues[id]);
  });
  const banner = document.getElementById('ipRelQualityBanner');
  if(banner){
    banner.dataset.state = model.quality.state;
    banner.textContent = `${model.quality.label} ${model.quality.detail}`;
  }
  return model;
}

function renderFilteredIpRelationshipResults(){
  if(!window.IP_REL_CACHE) return;
  closeIpRelationshipEvidence(false);
  const filter = document.getElementById('ipRelFilterInput');
  const filtered = filterIpRelationshipResults(window.IP_REL_CACHE, (filter || {}).value);
  renderIpRelationshipPairsTable(document.querySelector('#ipRelPairsTable tbody'), filtered.pairs);
  renderIpRelationshipClustersTable(document.querySelector('#ipRelClustersTable tbody'), filtered.clusters, !!window.IP_REL_CACHE.vt_enabled);
}

function exportLastIpRelationshipResult(){
  if(!window.IP_REL_LAST_SUCCESS) return false;
  const exported = buildIpRelationshipExport(window.IP_REL_LAST_SUCCESS, new Date());
  const blob = new Blob([exported.content], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = exported.filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  return true;
}
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
  closeIpRelationshipEvidence(false);
  if(name !== 'graph'){
    resetIpRelVisualCaches();
    const root=document.getElementById('ipRelGraph'); if(root) root.textContent='';
    const details=document.getElementById('ipRelGraphDetails'); if(details) details.textContent='';
  }
  if(name !== 'map') clearIpRelMapMarkers();
  if(name !== 'table'){
    for(const selector of ['#ipRelPairsTable tbody','#ipRelClustersTable tbody']){
      const body=document.querySelector(selector); if(body) body.textContent='';
    }
  }else if(window.IP_REL_CACHE) renderFilteredIpRelationshipResults();
  const table = document.getElementById('ipRelTableView');
  const graph = document.getElementById('ipRelGraphView');
  const map = document.getElementById('ipRelMapView');
  const panels = [[table, 'table'], [graph, 'graph'], [map, 'map']];
  panels.forEach(([panel, panelName])=>{
    if(!panel) return;
    const selected = name === panelName;
    panel.hidden = !selected;
    panel.style.display = selected ? '' : 'none';
    panel.setAttribute('aria-hidden', selected ? 'false' : 'true');
  });

  const b1 = document.getElementById('ipRelViewTableBtn');
  const b2 = document.getElementById('ipRelViewGraphBtn');
  const b3 = document.getElementById('ipRelViewMapBtn');
  [[b1, 'table'], [b2, 'graph'], [b3, 'map']].forEach(([button, buttonName])=>{
    if(!button) return;
    const selected = name === buttonName;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-selected', selected ? 'true' : 'false');
    button.setAttribute('tabindex', selected ? '0' : '-1');
  });

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
    else if(t === 'shared_observed_domain') parts.push('DNS:DOMAIN');
    else if(t === 'shared_decoder_provenance') parts.push('DNS:DECODER');
    else if(t === 'coincident_dns_change') parts.push('DNS:CHANGE');
    else if(t === 'shared_misp_event') parts.push('MISP:EVENT');
    else if(t === 'shared_misp_campaign') parts.push('MISP:CAMPAIGN');
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
  if(k === 'shared_observed_domain') return 'Observed Domain Reuse';
  if(k === 'shared_decoder_provenance') return 'Decoder Provenance Reuse';
  if(k === 'coincident_dns_change') return 'Coincident DNS Change';
  if(k === 'shared_misp_event') return 'Shared MISP Event';
  if(k === 'shared_misp_campaign') return 'Shared MISP Campaign';
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
  return `hsl(${hue}, 70%, 25%)`;
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

function getServerIpRelGraphSelection(cache){
  const graph = (cache && cache.graph && typeof cache.graph === 'object') ? cache.graph : null;
  if(!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) return null;
  const nodeIds = new Set();
  const nodes = [];
  graph.nodes.forEach(n=>{
    const id = String((n && n.id) || '').trim();
    if(!id || nodeIds.has(id)) return;
    nodeIds.add(id);
    nodes.push(n);
  });
  const edges = graph.edges.filter(e=>e && String(e.source || '').trim() && String(e.target || '').trim());
  return { nodes, edges, nodesSet: nodeIds, totalPairCount: Number(graph.total_pair_count || edges.length) };
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
  const serverGraph = getServerIpRelGraphSelection(cache);
  if(!cache || (!Array.isArray(cache.pairs) && !serverGraph)){
    resetIpRelVisualCaches();
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">Run Relationships first.</div>';
    return;
  }
  if(typeof cytoscape !== 'function'){
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">Cytoscape not available (CDN blocked?).</div>';
    return;
  }

  const graphSelection = serverGraph || selectIpRelGraphPairs(cache.pairs || []);
  const pairs = serverGraph
    ? graphSelection.edges.map(e=>({ a: e.source, b: e.target, score: e.score, evidence: e.evidence, same_cluster: e.same_cluster }))
    : graphSelection.pairs;
  const nodesSet = graphSelection.nodesSet;
  const graphSignature = buildIpRelGraphSignature(cache, pairs, nodesSet);
  const clusters = Array.isArray(cache.clusters) ? cache.clusters : [];
  const minScore = Number(cache.min_score || 40);
  const totalPairs = serverGraph ? Number(graphSelection.totalPairCount || pairs.length) : (Array.isArray(cache.pairs) ? cache.pairs.length : 0);
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
  const serverNodeMap = new Map();
  if(serverGraph){
    graphSelection.nodes.forEach(n=>{
      const id = String((n && n.id) || '').trim();
      if(id) serverNodeMap.set(id, n);
    });
  }
  nodesSet.forEach(ip=>{
    const srv = serverNodeMap.get(ip) || {};
    const f = getIpFeature(ip) || {};
    const label = String(srv.label || ip);
    const country = String(srv.country || f.country || '-');
    const asn = String(srv.asn || f.asn || '-');
    const csp = String(srv.csp || f.csp_label || '');
    const clusterIdx = Number(srv.cluster_idx || ipToCluster.get(ip) || 0);
    const degree = Number(srv.degree || degreeMap[ip] || 0);
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
    const sameCluster = (p.same_cluster != null) ? !!p.same_cluster : (ca > 0 && cb > 0 && ca === cb);
    const edgeColor = sameCluster ? getClusterColor(Math.max(0, ca - 1), clusterCount) : '#9bb0c4';
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
    details.textContent = `Click a node/edge to see details. Keyboard users can use the equivalent pair and cluster controls in Table view.\nClusters: ${clusters.length} / MinScore: ${minScore} / Layout: ${layout.name}${serverGraph ? ' / Server graph' : ''}${limited}`;
  }

  cy.on('tap', 'node', (evt)=>{
    if(cache !== window.IP_REL_CACHE || cy !== window.IP_REL_GRAPH) return;
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
    if(cache !== window.IP_REL_CACHE || cy !== window.IP_REL_GRAPH) return;
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
  const root=document.getElementById('ipRelMap');
  if(root){root._viewGeneration=(root._viewGeneration || 0)+1;root.textContent='';}
  const summary=document.getElementById('ipRelMapSummary'); if(summary) summary.textContent='';
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

function getIpRelMapRadius(ipCount, maxCount){
  const count = Math.max(0, Number(ipCount || 0));
  const maximum = Math.max(1, Number(maxCount || 1));
  return 12 + 20 * Math.sqrt(Math.min(1, count / maximum));
}

function formatIpRelCountrySummary(row){
  const country = String((row && row.country) || 'Unknown').toUpperCase();
  const ipCount = Math.max(0, Number((row && row.ip_count) || 0));
  const malicious = Math.max(0, Number((row && row.malicious_ips) || 0));
  const ratio = ipCount > 0 ? Math.round((malicious / ipCount) * 100) : 0;
  return `${country}: ${ipCount} IPs, ${malicious} malicious (${ratio}%)`;
}

function renderIpRelCountrySummary(rows){
  const summary = document.getElementById('ipRelMapSummary');
  if(!summary) return;
  summary.innerHTML = '';
  const values = (Array.isArray(rows) ? rows : [])
    .filter(row=>Number((row && row.ip_count) || 0) > 0)
    .slice()
    .sort((a, b)=>Number(b.ip_count || 0) - Number(a.ip_count || 0));
  if(!values.length){
    const item = document.createElement('li');
    item.textContent = 'No country risk values are available.';
    summary.appendChild(item);
    return;
  }
  values.forEach(row=>{
    const item = document.createElement('li');
    item.textContent = formatIpRelCountrySummary(row);
    summary.appendChild(item);
  });
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
  const generation=el._viewGeneration;
  const current=()=>cache===window.IP_REL_CACHE && generation===el._viewGeneration && !document.getElementById('ipRelMapView')?.hidden;
  if(!cache || !Array.isArray(cache.country_summary)){
    renderIpRelCountrySummary([]);
    window.IP_REL_MAP_SVG = null;
    window.IP_REL_MAP_SIGNATURE = '';
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">Run Relationships first.</div>';
    return;
  }

  const rows = cache.country_summary || [];
  renderIpRelCountrySummary(rows);

  const centroids = await loadCountryCentroids();
  if(!current()) return;
  if(!centroids){
    window.IP_REL_MAP_SVG = null;
    window.IP_REL_MAP_SIGNATURE = '';
    el.innerHTML = '<div style="padding:12px;color:#5b6a77;">country_centroids.json not available.</div>';
    return;
  }

  const world = await loadWorldGeoJson();
  if(!current()) return;
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
    const radius = getIpRelMapRadius(ipCount, maxCount);
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
    circle.setAttribute('role', 'button');
    circle.setAttribute('tabindex', '0');
    circle.setAttribute('aria-label', `${cc}: ${ipCount} IPs, ${mal} malicious. Analyze this country`);

    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${cc}  IPs:${ipCount}  M:${mal}`;
    circle.appendChild(title);

    const activateCountry = async ()=>{
      if(!current()) return;
      const ipFeat = cache.ip_features || {};
      const ips = Object.keys(ipFeat).filter(ip=> String((ipFeat[ip]||{}).country||'').toUpperCase() === cc);
      setIpIntelInputValue(ips.join('\n'));
      await analyzeIpRelationships();
      returnIpRelFocusToTable();
    };
    circle.addEventListener('click', activateCountry);
    circle.addEventListener('keydown', event=>{
      if(!isKeyboardActivation(event)) return;
      event.preventDefault();
      void activateCountry();
    });

    svg.appendChild(circle);
  });
}

function returnIpRelFocusToTable(){
  setIpRelView('table');
  const tableTab = document.getElementById('ipRelViewTableBtn');
  if(tableTab) tableTab.focus();
}

function wireIpRelViewButtons(){
  const b1 = document.getElementById('ipRelViewTableBtn');
  const b2 = document.getElementById('ipRelViewGraphBtn');
  const b3 = document.getElementById('ipRelViewMapBtn');
  const tabs = [[b1, 'table', 'ipRelTableView'], [b2, 'graph', 'ipRelGraphView'], [b3, 'map', 'ipRelMapView']];
  tabs.forEach(([button, name, panelId], index)=>{
    if(!button) return;
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-controls', panelId);
    button.onclick = ()=>{
      setIpRelView(name);
      // Visualization libraries may move focus to their canvas while rendering.
      // Restore the active tab so arrow-key navigation remains available.
      button.focus();
    };
    button.onkeydown = event=>{
      if(isKeyboardActivation(event)){
        event.preventDefault();
        setIpRelView(name);
        return;
      }
      if(event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      const direction = event.key === 'ArrowRight' ? 1 : -1;
      const available = tabs.filter(item=>!!item[0]);
      const current = available.findIndex(item=>item[0] === tabs[index][0]);
      const next = available[(current + direction + available.length) % available.length];
      setIpRelView(next[1]);
      next[0].focus();
    };
  });
  setIpRelView('table');
}

function wireIpRelationshipProductControls(){
  for(const id of ['ipIntelEvidence','ipIntelRaw']){
    document.getElementById(id)?.addEventListener('toggle',()=>renderIpIntelCachedEvidence());
  }
  const input = document.getElementById('ipIntelInput');
  const cancel = document.getElementById('cancelIpRelationshipBtn');
  const filter = document.getElementById('ipRelFilterInput');
  const exportButton = document.getElementById('exportIpRelationshipBtn');
  if(input) input.addEventListener('input', ()=>{
    cancelIpIntelInputReads();
    setIpIntelResultState('stale','Input changed. Previous per-IP data, if present, is stale; enrich explicitly.');
    updateIpIntelInputStats();
    markIpRelationshipResultsStale();
  });
  document.getElementById('ipIntelMispEventId')?.addEventListener('input',()=>cancelIpIntelInputReads());
  ['ipIntelIncludeVt', 'ipIntelVtBudget', 'ipIntelVtWorkers'].forEach(id=>{
    const control = document.getElementById(id);
    if(!control) return;
    control.addEventListener('change', markIpRelationshipResultsStale);
    if(String(control.type || '').toLowerCase() !== 'checkbox'){
      control.addEventListener('input', markIpRelationshipResultsStale);
    }
  });
  if(cancel) cancel.addEventListener('click', cancelActiveIpRelationshipAnalysis);
  if(filter) filter.addEventListener('input', renderFilteredIpRelationshipResults);
  if(exportButton) exportButton.addEventListener('click', exportLastIpRelationshipResult);
  updateIpIntelInputStats();
  setIpRelationshipRunState('idle');
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
  if(window.IP_REL_CACHE) renderFilteredIpRelationshipResults();
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
    profileSel.addEventListener('change', ()=>{
      applyIpRelProfile(profileSel.value, { saveSelected: true });
      markIpRelationshipResultsStale();
    });
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
      markIpRelationshipResultsStale();
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
      markIpRelationshipResultsStale();
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

function formatMispInputContext(result){
  const inputContext = (result && result.input_context && typeof result.input_context === 'object')
    ? result.input_context
    : {};
  const misp = (inputContext.misp && typeof inputContext.misp === 'object') ? inputContext.misp : null;
  if(!misp) return '';
  const event = (misp.event && typeof misp.event === 'object') ? misp.event : {};
  const access = (misp.access && typeof misp.access === 'object') ? misp.access : {};
  const parts = [`MISP event ${String(event.id || '?')}`];
  const producer = (event.producer && typeof event.producer === 'object') ? event.producer : {};
  if(producer.name) parts.push(`producer ${String(producer.name)}`);
  const tlpTags = Array.isArray(access.tlp_tags) ? access.tlp_tags.map(String).filter(Boolean) : [];
  if(tlpTags.length) parts.push(tlpTags.join(','));
  if(access.contains_restricted_attributes) parts.push('restricted distribution');
  return parts.join(' · ');
}

function formatPairAssessment(pair){
  const item = (pair && typeof pair === 'object') ? pair : {};
  const assessment = (item.assessment && typeof item.assessment === 'object') ? item.assessment : null;
  const strengthRaw = (item.relationship_strength != null) ? item.relationship_strength : item.score;
  const strength = Number.isFinite(Number(strengthRaw)) ? Number(strengthRaw) : 0;
  if(!assessment){
    return {strength, verdict:'Relationship only', evidenceScore:null, confidence:'unknown'};
  }
  const verdictLabels = {
    same_botnet_likely: 'Likely same botnet',
    related_infrastructure: 'Related infrastructure',
    insufficient_evidence: 'Insufficient botnet evidence'
  };
  const evidenceRaw = (assessment.botnet_evidence_score != null)
    ? assessment.botnet_evidence_score
    : assessment.evidence_score;
  const evidenceScore = Number.isFinite(Number(evidenceRaw)) ? Number(evidenceRaw) : null;
  const confidenceObj = (assessment.confidence && typeof assessment.confidence === 'object')
    ? assessment.confidence
    : {};
  return {
    strength,
    verdict: verdictLabels[String(assessment.verdict || '')] || 'Insufficient botnet evidence',
    evidenceScore,
    confidence: String(confidenceObj.level || 'unknown')
  };
}

let ipRelationshipEvidenceOwner = null;
function closeIpRelationshipEvidence(restoreFocus = true){
  const old = ipRelationshipEvidenceOwner; ipRelationshipEvidenceOwner = null;
  const root = document.getElementById('ipRelEvidence');
  if(root){root.replaceChildren();root.hidden=true;}
  if(restoreFocus && old?.button?.isConnected) old.button.focus();
}
function openIpRelationshipEvidence(title, record, button, cache, generation){
  if(cache !== window.IP_REL_CACHE || generation !== ipRelAnalyzeSeq) return;
  closeIpRelationshipEvidence(false);
  const root=document.getElementById('ipRelEvidence'); if(!root) return;
  ipRelationshipEvidenceOwner={cache,generation,button};
  const close=viewNode('button','Close evidence'); close.onclick=()=>closeIpRelationshipEvidence();
  root.appendChild(close);
  root.appendChild(viewNode('h4',title));
  root.appendChild(viewNode('p','Cached evidence from the accepted run. Inspecting does not change inputs or issue provider requests.'));
  root.appendChild(viewNode('pre',JSON.stringify(record,null,2)));
  root.hidden=false;
  close.focus();
}

function renderIpRelationshipPairsTable(tbody, pairs){
  if(!tbody) return;
  tbody.innerHTML = '';
  if(document.getElementById('ipRelPairsPanel')?.style.display === 'none') return;
  const cache=window.IP_REL_CACHE, generation=ipRelAnalyzeSeq;
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
    const pairAssessment = formatPairAssessment(it);
    const ev = it && it.evidence;

    const ipCell = ip=>{
      const td = document.createElement('td');
      if(!isIPv4(ip)){
        td.textContent = ip;
        return td;
      }
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'table-link-button';
      button.textContent = ip;
      button.setAttribute('aria-label', `Open ${ip} in Query`);
      button.title = 'Open in Query';
      button.onclick = ()=> openQueryForValue(ip);
      td.appendChild(button);
      return td;
    };
    const tdA = ipCell(a);
    const tdB = ipCell(b);

    const tdS = document.createElement('td');
    const strengthMain = document.createElement('div');
    strengthMain.className = 'evidence-main';
    strengthMain.textContent = `Relationship ${pairAssessment.strength}`;
    const verdictSub = document.createElement('div');
    verdictSub.className = 'evidence-sub';
    const evidenceText = pairAssessment.evidenceScore == null
      ? ''
      : ` · botnet evidence ${pairAssessment.evidenceScore}`;
    verdictSub.textContent = `${pairAssessment.verdict}${evidenceText} · confidence ${pairAssessment.confidence}`;
    tdS.appendChild(strengthMain);
    tdS.appendChild(verdictSub);
    const tdE = document.createElement('td');
    tdE.className = 'evidence-cell';
    const evMain = document.createElement('div');
    evMain.className = 'evidence-main';
    evMain.textContent = summarizeEvidence(ev);
    tdE.appendChild(evMain);
    const inspect = document.createElement('button');
    inspect.type = 'button'; inspect.textContent = 'Inspect pair';
    inspect.setAttribute('aria-label',`Inspect pair ${a} and ${b}`);
    inspect.onclick = ()=>openIpRelationshipEvidence(`${a} ↔ ${b}`,it,inspect,cache,generation);
    tdE.appendChild(inspect);

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
  const cache=window.IP_REL_CACHE, generation=ipRelAnalyzeSeq;
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

    const tdId = document.createElement('td');
    const tdSz = document.createElement('td'); tdSz.textContent = String((c && c.size) || ips.length || 0);
    const tdCoh = document.createElement('td'); tdCoh.textContent = (c && c.cohesion != null) ? Number(c.cohesion).toFixed(1) : '-';
    const tdAsn = document.createElement('td'); tdAsn.textContent = ((c && c.top_asn) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdOwn = document.createElement('td'); tdOwn.textContent = ((c && c.top_owner) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdCty = document.createElement('td'); tdCty.textContent = ((c && c.top_country) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdCsp = document.createElement('td'); tdCsp.textContent = ((c && c.top_csp) || []).map(x=>x[0]+'('+x[1]+')').join(', ') || '-';
    const tdVt = document.createElement('td'); tdVt.textContent = vtTxt;

    const fp = [];
    if(Array.isArray(c && c.top_network) && c.top_network.length) fp.push('net ' + c.top_network.map(x=>x[0]+'('+x[1]+')').join(', '));
    if(Array.isArray(c && c.top_rir) && c.top_rir.length) fp.push('rir ' + c.top_rir.map(x=>x[0]+'('+x[1]+')').join(', '));
    if(Array.isArray(c && c.top_jarm) && c.top_jarm.length) fp.push('jarm ' + c.top_jarm.map(x=>x[0]+'('+x[1]+')').join(', '));
    if(Array.isArray(c && c.top_cert) && c.top_cert.length) fp.push('cert ' + c.top_cert.map(x=>x[0]+'('+x[1]+')').join(', '));
    const activateCluster = async ()=>{
      setIpIntelInputValue(ips.join('\n'));
      await analyzeIpIntel();
    };
    const clusterButton = document.createElement('button');
    clusterButton.type = 'button';
    clusterButton.className = 'table-link-button';
    clusterButton.textContent = `Analyze cluster ${idx + 1}`;
    clusterButton.setAttribute('aria-label', `Analyze cluster ${idx + 1}, ${ips.length} IPs`);
    clusterButton.title = fp.length
      ? `Analyze this cluster in Per-IP Details\n${fp.join(' | ')}`
      : 'Analyze this cluster in Per-IP Details';
    clusterButton.onclick = activateCluster;
    tdId.appendChild(clusterButton);
    const inspect = document.createElement('button');
    inspect.type='button'; inspect.textContent=`Inspect cluster ${idx + 1}`;
    inspect.onclick=()=>openIpRelationshipEvidence(`Cluster ${idx + 1}`,c,inspect,cache,generation);
    tdId.appendChild(inspect);

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
    wireIpRelationshipProductControls();
  });
} else {
  wireIpRelViewButtons();
  wireIpRelPairsToggle();
  wireIpRelProfileControls();
  wireIpRelationshipProductControls();
}

function renderIpRelationshipError(pairBody, clusterBody, message){
  if(pairBody) setSummaryMessage(pairBody, 4, message);
  if(clusterBody) setSummaryMessage(clusterBody, 8, message);
}

function restorePreviousIpRelationshipResult(previous, pairsBody, clustersBody){
  if(!previous || typeof previous !== 'object') return false;
  window.IP_REL_CACHE = previous;
  window.IP_REL_LAST_SUCCESS = previous;
  renderIpRelationshipProductSummary(previous);
  renderIpRelationshipPairsTable(pairsBody, Array.isArray(previous.pairs) ? previous.pairs : []);
  renderIpRelationshipClustersTable(clustersBody, Array.isArray(previous.clusters) ? previous.clusters : [], !!previous.vt_enabled);
  const banner = document.getElementById('ipRelQualityBanner');
  if(banner){
    if(banner.dataset) banner.dataset.state = 'stale';
    const quality=buildIpRelationshipResultModel(previous).quality;
    banner.textContent = 'Previous successful result preserved — the latest run did not complete. These metrics and exports belong to the previous successful run. Previous run quality: '+quality.label+' '+quality.detail;
  }
  return true;
}

function formatIpRelationshipQuality(j){
  const quality = (j && j.quality && typeof j.quality === 'object') ? j.quality : null;
  if(!quality) return '';

  const finiteCount = (value)=>{
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0;
  };
  const evaluated = finiteCount(quality.evaluated_candidate_count);
  const candidateLimit = finiteCount(quality.candidate_limit);
  const vtReports = finiteCount(quality.vt_report_count);
  const vtEligible = finiteCount(quality.vt_eligible_count);
  const vtSkipped = finiteCount(quality.vt_skipped_non_global);
  const rawCoverage = Number(quality.vt_report_coverage);
  const fallbackCoverage = vtEligible > 0 ? vtReports / vtEligible : 0;
  const coverage = Number.isFinite(rawCoverage) ? rawCoverage : fallbackCoverage;
  const coveragePct = Math.round(Math.max(0, Math.min(1, coverage)) * 100);

  const warningLabels = {
    bucket_truncated: 'oversized buckets truncated',
    bucket_skipped: 'oversized buckets skipped',
    candidate_limit_reached: 'candidate limit reached',
    candidate_work_limit_reached: 'candidate work limit reached',
    pair_heap_truncated: 'pair results truncated',
    pair_display_truncated: 'pair display or neighbor limit reached',
    local_context_truncated: 'local DNS context bounded',
    vt_partial_coverage: 'partial VT coverage'
  };
  const warnings = (Array.isArray(quality.warning_codes) ? quality.warning_codes : [])
    .map(code=> warningLabels[String(code || '')] || String(code || '').replace(/_/g, ' '))
    .filter(Boolean);

  const hasValue = (name)=> Object.prototype.hasOwnProperty.call(quality, name) && quality[name] !== null;
  let text = '';
  if(hasValue('evaluated_candidate_count') || hasValue('candidate_limit')){
    text += ` / candidates evaluated ${hasValue('evaluated_candidate_count') ? evaluated : 'unknown'}`;
    text += ` / limit ${hasValue('candidate_limit') ? candidateLimit : 'unknown'}`;
  }
  if(quality.vt_enabled === true){
    text += ` / VT reports ${hasValue('vt_report_count') ? vtReports : 'unknown'}`;
    text += ` / eligible ${hasValue('vt_eligible_count') ? vtEligible : 'unknown'}`;
    text += ` / skipped ${hasValue('vt_skipped_non_global') ? vtSkipped : 'unknown'}`;
    const hasCoverage = hasValue('vt_report_coverage') || (hasValue('vt_report_count') && hasValue('vt_eligible_count'));
    text += ` / coverage ${hasCoverage ? `${coveragePct}%` : 'unknown'}`;
  }
  if(quality.analysis_complete === false){
    text += ' / ⚠ incomplete analysis';
    if(warnings.length) text += ` (${warnings.join(', ')})`;
  }else if(warnings.length){
    text += ` / warnings: ${warnings.join(', ')}`;
  }
  return text;
}

async function cancelIpRelationshipJob(jobId){
  const scope=viewFeedbackOwner('relationship-cancel','ipRelRunStatus');
  const token=scope?.begin(jobId);
  try{
    const response = await fetch(`/ip-relationship-jobs/${encodeURIComponent(jobId)}/cancel`, {
      method: 'POST', feedback:token
    });
    const data=await response.json();
    return response.ok && data.status==='cancelled' && data.cancelled===true;
  }catch(e){
    return false;
  }
}

async function fetchIpRelationshipJobResult(requestBody, controller, onStatus){
  const submit = await fetch('/ip-relationship-jobs', {
    method: 'POST',
    feedback: controller?.feedback,
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(requestBody)
  });
  const sj = await submit.json();
  if(!submit.ok || !sj || !sj.job_id){
    return { ok: false, status: submit.status, body: sj || {} };
  }
  const jobId = String(sj.job_id || '');
  if(onStatus) onStatus(jobId, 'active');
  if(controller && controller.signal && controller.signal.aborted){
    if(!controller.browserDetached){
      controller.serverCancelConfirmed=await cancelIpRelationshipJob(jobId);
      controller.serverCancelUnconfirmed=!controller.serverCancelConfirmed;
    }
    if(onStatus) onStatus(jobId, 'terminal');
    return { ok: false, status: 499, body: { error: 'relationship request cancelled' } };
  }
  let delayMs = 600;
  for(let attempt = 0; attempt < 900; attempt += 1){
    if(onStatus) onStatus(jobId, 'running');
    await new Promise((resolve, reject)=>{
      const signal = controller && controller.signal;
      let onAbort = null;
      const cleanup = ()=>{
        if(signal && onAbort) signal.removeEventListener('abort', onAbort);
      };
      const timer = setTimeout(()=>{ cleanup(); resolve(); }, delayMs);
      if(!signal) return;
      onAbort = ()=>{ clearTimeout(timer); cleanup(); reject(new DOMException('Aborted', 'AbortError')); };
      if(signal.aborted){
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    });
    const rr = await fetch(`/ip-relationship-jobs/${encodeURIComponent(jobId)}?result=1`, {
      method: 'GET',
      feedback: controller?.feedback,
      signal: controller ? controller.signal : undefined
    });
    const jj = await rr.json();
    if(!rr.ok){
      return { ok: false, status: rr.status, body: jj || {} };
    }
    if(jj.status === 'completed'){
      if(onStatus) onStatus(jobId, 'terminal');
      return { ok: true, status: Number(jj.status_code || 200), body: jj.result || {} };
    }
    if(jj.status === 'failed' || jj.status === 'cancelled'){
      if(onStatus) onStatus(jobId, 'terminal');
      return { ok: false, status: Number(jj.status_code || 500), body: jj.result || { error: jj.error || `job ${jj.status}` } };
    }
    delayMs = Math.min(2500, Math.round(delayMs * 1.25));
  }
  return { ok: false, status: 504, body: { error: 'relationship job timed out' } };
}

async function analyzeIpRelationships(){
  const updateRelationshipRunState = (...args)=>{
    if(typeof setIpRelationshipRunState === 'function') setIpRelationshipRunState(...args);
  };
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
  const previousSuccessfulResult = window.IP_REL_LAST_SUCCESS || null;
  let activeRelationshipJobId = null;
  let relationshipJobTerminal = false;
  let relationshipJobCancelRequested = false;
  const cancelActiveRelationshipJob = ()=>{
    if(controller?.browserDetached) return;
    if(!activeRelationshipJobId || relationshipJobTerminal || relationshipJobCancelRequested) return;
    if(typeof ipRelCancelRequestedJobs !== 'undefined' && ipRelCancelRequestedJobs.has(activeRelationshipJobId)){
      relationshipJobCancelRequested = true;
      return;
    }
    relationshipJobCancelRequested = true;
    if(typeof ipRelCancelRequestedJobs !== 'undefined') ipRelCancelRequestedJobs.add(activeRelationshipJobId);
    void cancelIpRelationshipJob(activeRelationshipJobId);
  };

  if(ipRelAnalyzeController){
    try{ ipRelAnalyzeController.abort(); }catch(e){}
  }
  ipRelAnalyzeSeq += 1;

  if(!raw){
    if(previousSuccessfulResult){
      if(meta) meta.textContent = 'Input is empty. Previous successful result retained as stale.';
      markIpRelationshipResultsStale();
    }else{
      resetIpRelVisualCaches();
      if(meta) meta.textContent = 'Input IP list first';
      if(pairsBody) setSummaryMessage(pairsBody, 4, 'No data');
      if(clustersBody) setSummaryMessage(clustersBody, 8, 'No data');
      updateRelationshipRunState('idle', 'Enter IPs to begin analysis');
    }
    renderMergedIpIntelHints();
    return;
  }

  const controller = (typeof AbortController === 'function') ? new AbortController() : null;
  ipRelAnalyzeController = controller;
  const feedback=viewFeedbackOwner('ip-relationships','ipRelRunStatus');
  const token=feedback?.begin(inputSignature);
  if(controller) controller.feedback=token;
  const requestSeq = ipRelAnalyzeSeq;
  const isStale = ()=> requestSeq !== ipRelAnalyzeSeq || ipRelAnalyzeController !== controller;
  setIpIntelBusy(true);
  ipRelActiveJobId = null;
  updateRelationshipRunState('running');

  // default view
  setIpRelView('table');

  if(meta) meta.textContent = 'Analyzing similarity...';
  if(pairsBody) setSummaryMessage(pairsBody, 4, 'Loading...');
  if(clustersBody) setSummaryMessage(clustersBody, 8, 'Loading...');

  try{
    const pairPanel = document.getElementById('ipRelPairsPanel');
    const pairPanelWasOpen = !!(pairPanel && pairPanel.style.display !== 'none');
    const lookbackRaw = parseInt(String((document.getElementById('ipRelLookbackDays') || {}).value || '30'), 10);
    const lookbackDays = Math.min(365, Math.max(0, Number.isFinite(lookbackRaw) ? lookbackRaw : 30));
    const requestBody = {
      ips: raw,
      lookback_days: lookbackDays,
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
    };
    const mispEventId = String((document.getElementById('ipIntelMispEventId') || {}).value || '').trim();
    if(mispEventId) requestBody.misp_event_id = mispEventId;
    const jobResult = await fetchIpRelationshipJobResult(requestBody, controller, (jobId, state)=>{
      if(isStale()) return;
      if(state === 'active'){
        activeRelationshipJobId = jobId;
      }
      if(state === 'active') ipRelActiveJobId = jobId;
      if(state === 'terminal'){
        relationshipJobTerminal = true;
      }
      if(state === 'terminal' && typeof ipRelCancelRequestedJobs !== 'undefined') ipRelCancelRequestedJobs.delete(jobId);
      if(state === 'terminal' && ipRelActiveJobId === jobId) ipRelActiveJobId = null;
      if(meta && !isStale()) meta.textContent = `Analyzing similarity... job ${jobId.slice(0, 8)}`;
    });
    const j = jobResult.body;
    if(isStale()){
      cancelActiveRelationshipJob();
      return;
    }
    if(!jobResult.ok || !j || j.status !== 'ok'){
      cancelActiveRelationshipJob();
      const errorText = jobResult.status === 504 ? 'relationship job timed out' : 'Relationship analysis failed. No usable result was returned.';
      const cancelled = jobResult.status === 499;
      feedbackFailure(feedback,token,{status:jobResult.status});
      const restored = restorePreviousIpRelationshipResult(previousSuccessfulResult, pairsBody, clustersBody);
      if(meta){
        const statusText = cancelled ? 'Similarity analysis cancelled' : `Similarity analysis failed: ${errorText}`;
        meta.textContent = restored ? `${statusText}. Previous successful result preserved.` : statusText;
      }
      if(!restored) renderIpRelationshipError(pairsBody, clustersBody, cancelled ? 'Analysis cancelled' : 'No data');
      updateRelationshipRunState(cancelled ? 'cancelled' : 'error', cancelled ? undefined : errorText);
      clearIpIntelRelationshipInsights(inputSignature);
      return;
    }

    window.IP_REL_CACHE = j;
    window.IP_REL_LAST_SUCCESS = j;
    feedback?.succeed(token);
    resetIpRelVisualCaches();
    setIpIntelRelationshipInsights(inputSignature, j);
    renderIpRelationshipProductSummary(j);

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
      txt += formatIpRelationshipQuality(j);
      const mispContextText = formatMispInputContext(j);
      if(mispContextText) txt += ` / ${mispContextText}`;
      meta.textContent = txt;
    }

    const pairs = Array.isArray(j.pairs) ? j.pairs : [];
    setIpRelPairsPanelVisible(pairPanelWasOpen, { pairCount: pairs.length });
    renderFilteredIpRelationshipResults();

    touchOverviewTs();
    updateRelationshipRunState('complete');
  }catch(e){
    if(isAbortError(e) || isStale()){
      cancelActiveRelationshipJob();
      if(isAbortError(e) && !isStale()){
        const restored = restorePreviousIpRelationshipResult(previousSuccessfulResult, pairsBody, clustersBody);
        const cancellationMessage = controller && controller.serverCancelUnconfirmed
          ? 'Client polling stopped, but server cancellation could not be confirmed.'
          : controller && controller.serverCancelConfirmed ? 'Server cancellation confirmed.'
          : 'Browser polling stopped; server cancellation not yet confirmed.';
        if(meta) meta.textContent = `${cancellationMessage}${restored ? ' Previous successful result preserved.' : ''}`;
        if(!restored) renderIpRelationshipError(pairsBody, clustersBody, 'Analysis cancelled');
        updateRelationshipRunState('cancelled', cancellationMessage);
      }
      return;
    }
    clearIpIntelRelationshipInsights(inputSignature);
    const restored = restorePreviousIpRelationshipResult(previousSuccessfulResult, pairsBody, clustersBody);
    feedbackFailure(feedback,token,e,true);
    const errorText=feedback?.snapshot().error?.message || 'Relationship analysis failed. Server admission or completion is not confirmed.';
    if(meta) meta.textContent = `${errorText}${restored ? ' Previous successful result preserved.' : ''}`;
    if(!restored) renderIpRelationshipError(pairsBody, clustersBody, 'Analysis failed');
    updateRelationshipRunState('error', errorText);
  }finally{
    if(activeRelationshipJobId && typeof ipRelCancelRequestedJobs !== 'undefined'){
      ipRelCancelRequestedJobs.delete(activeRelationshipJobId);
    }
    if(ipRelAnalyzeController === controller) ipRelActiveJobId = null;
    finalizeIpRelationshipRun(controller);
  }
}
