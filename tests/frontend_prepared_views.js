'use strict';
// Chromium fixture gate: real scripts/DOM/auth transport, synthetic prepared API.
// Does not establish live backend/deployed acceptance.
const {chromium} = require('@playwright/test');
const fs=require('fs'), http=require('http'), assert=require('assert/strict');
const tests=[]; const test=(name,run)=>tests.push({name,run});
const views=[['refreshResults','status','resultsTable'],['refreshIPs','ips','ipsTable'],['refreshValidIPs','validips','validIpsTable'],['refreshDomainAnalysis','domainanalysis','domainAnalysisTable']];
const snapshot={ready:true,stale:false,status:'ready',generated_at:1700000000,version:'s1',source_version:'source1',error_code:null};
const payload=()=>({snapshot:{...snapshot},view_version:'v1',page:{offset:0,limit:100,displayed:1,total:201,next_offset:100,previous_offset:null,unit:'domains'},results_agg:{'full-long-domain.example.test':{type:'A',values:['8.8.8.8'],decoded_ips:[],servers:['one'],ts:1}},ips:[{ip:'8.8.8.8',valid:true,domains:['full-long-domain.example.test'],count:1,last_ts:1}],domains:[{domain:'full-long-domain.example.test',record_types:['A'],last_ts:1,resolving:true,ip_rows_total:1,ip_rows_offset:0,ip_rows_truncated:false,ip_rows:[{ip:'8.8.8.8',role:'resolved'}]}]});
let browser,server,origin;
async function environment(){
 const page=await browser.newPage();
 await page.goto(origin);
 await page.evaluate(()=>{window.setInterval=()=>0; window.__requests=[]; window.__payload={}; window.fetch=async (url,options)=>{
   if(String(url).endsWith('/auth/me'))return new Response(JSON.stringify({csrf_token:'fixture',user:{role:'admin'}}));
   window.__requests.push({url:String(url),signal:options.signal});
   return new Response(JSON.stringify(window.__payload),{status:window.__status||200});
 };});
 await page.addScriptTag({content:fs.readFileSync('auth_frontend.js','utf8')});
 await page.addScriptTag({content:fs.readFileSync('dns_frontend.js','utf8')});
 await page.evaluate(()=>TraceAuth.ready);
 return page;
}
async function refresh(page,fn,data=payload(),status=200){await page.evaluate(({fn,data,status})=>{window.__payload=data;window.__status=status;return window[fn]();},{fn,data,status});}
test('all four pollers negotiate bounded prepared pages',async()=>{
 const page=await environment();
 try{for(const [fn] of views){await refresh(page,fn);}
 const urls=await page.evaluate(()=>__requests.map(r=>r.url));
 assert.equal(urls.length,4);
 for(const url of urls){const q=new URL(url).searchParams;assert.equal(q.get('read_mode'),'background');assert(+q.get('limit')<=200 && +q.get('limit')>0);assert.equal(q.get('offset'),'0');}
 assert.equal(new URL(urls[2]).searchParams.get('valid_only'),'1');
 }finally{await page.close();}
});
test('cold, stale and unchanged snapshots preserve last-good DOM and version',async()=>{
 for(const [fn,section,table] of views){const page=await environment();try{
 await refresh(page,fn);
 await page.evaluate(table=>{window.__row=document.querySelector(`#${table} tbody tr`);},table);
 await refresh(page,fn,{snapshot:{ready:false,status:'pending'},view_version:'cold'},202);
 assert(await page.evaluate(table=>__row===document.querySelector(`#${table} tbody tr`),table),fn+' cold preserves row');
 assert.match(await page.locator('#'+section+'-refresh-status').textContent(),/Preparing snapshot/);
 await refresh(page,fn,{unchanged:true,view_version:'v1',snapshot:{...snapshot,stale:true},page:payload().page});
 assert(await page.evaluate(table=>__row===document.querySelector(`#${table} tbody tr`),table),fn+' unchanged preserves row');
 assert.match(await page.locator('#'+section+'-refresh-status').textContent(),/stale/i);
 const requests=await page.evaluate(()=>__requests.map(r=>r.url));
 assert.equal(new URL(requests[1]).searchParams.get('if_version'),'v1');
 assert.equal(new URL(requests[2]).searchParams.get('if_version'),'v1');
 assert.doesNotMatch(await page.locator('#'+section+'-refresh-status').textContent(),/Data current/i);
 }finally{await page.close();}}
});
test('page controls cancel a pending body on the same section and use server offsets',async()=>{
 for(const [fn,section,table] of views){const page=await environment();try{
 await refresh(page,fn);
 assert(await page.locator(`#${section}_next_btn`).count(),section+' needs Next');
 await page.evaluate(({fn})=>{const original=window.fetch;window.fetch=async (...args)=>{const r=await original(...args);r.json=()=>new Promise(resolve=>{window.__oldBody=resolve;});return r;};window.__oldRefresh=window[fn]();},{fn});
 await page.waitForFunction(()=>!!window.__oldBody);
 await page.evaluate(()=>{window.fetch=async (url,options)=>{__requests.push({url:String(url),signal:options.signal});return new Response(JSON.stringify({...__payload,view_version:'page2',page:{...__payload.page,offset:100,previous_offset:0,next_offset:200}}));};});
 await page.locator(`#${section}_next_btn`).dispatchEvent('click');
 await page.waitForFunction(()=>__requests.length===3);
 assert(await page.evaluate(()=>__requests[1].signal.aborted),fn+' must abort old body');
 const url=await page.evaluate(()=>__requests[2].url);
 assert.equal(new URL(url).searchParams.get('offset'),'100');assert.equal(new URL(url).searchParams.get('if_version'),null);
 await page.evaluate(()=>{__oldBody({results_agg:{obsolete:{}},ips:[],domains:[],view_version:'bad'});return __oldRefresh;});
 assert.doesNotMatch(await page.locator(`#${table}`).textContent(),/obsolete/);
 assert.match(await page.locator(`#${section}_page_meta`).textContent(),/101.*201/);
 }finally{await page.close();}}
});
test('remote domain query is distinct from the current-page filter and cancels prior query',async()=>{
 const page=await environment();try{
 await refresh(page,'refreshDomainAnalysis');
 assert.equal(await page.locator('#domain_analysis_query').count(),1);
 await page.locator('#domain_analysis_query').fill('needle');
 await page.waitForFunction(()=>__requests.length===2);
 const q=new URL(await page.evaluate(()=>__requests[1].url)).searchParams;
 assert.equal(q.get('q'),'needle');assert.equal(q.get('offset'),'0');assert.equal(q.get('if_version'),null);
 assert.match(await page.locator('#domainanalysis').textContent(),/current.page/i);
 }finally{await page.close();}
});
test('all views reuse unchanged rows, patch timestamps and replace only changed row',async()=>{
 for(const [fn,section,table] of views){const page=await environment();try{
 const data=payload(); data.results_agg['second.test']={...data.results_agg['full-long-domain.example.test']};data.ips.push({...data.ips[0],ip:'9.9.9.9'});data.domains.push({...structuredClone(data.domains[0]),domain:'second.test'});
 await refresh(page,fn,data);
 await page.evaluate(table=>{window.__rows=[...document.querySelector(`#${table} tbody`).children];window.__cells=__rows.map(r=>[...r.children]);},table);
 const timestamp=structuredClone(data);Object.values(timestamp.results_agg).forEach(r=>r.ts=2);timestamp.ips.forEach(r=>r.last_ts=2);timestamp.domains.forEach(r=>r.last_ts=2);timestamp.view_version='v2';
 await refresh(page,fn,timestamp);
 assert(await page.evaluate(table=>__rows.every((r,i)=>r===document.querySelector(`#${table} tbody`).children[i]),table),fn+' timestamp keeps nodes');
 assert(await page.evaluate(()=>__rows.every((r,i)=>[...r.children].every((c,j)=>c===__cells[i][j]))),fn+' timestamp keeps cells');
 const changed=structuredClone(timestamp);changed.view_version='v3';changed.results_agg['full-long-domain.example.test'].values=['1.1.1.1'];changed.ips[0].vt={asn:1234,malicious:0,suspicious:0};changed.domains[0].ip_rows[0].vt={asn:1234,malicious:0,suspicious:0};
 await refresh(page,fn,changed);
 const identity=await page.evaluate(table=>[__rows[0]===document.querySelector(`#${table} tbody`).children[0],__rows[1]===document.querySelector(`#${table} tbody`).children[1]],table);
 assert.deepEqual(identity,[false,true],fn+' replaces changed row only');
 await page.evaluate(table=>window.__rows=[...document.querySelector(`#${table} tbody`).children],table);
 await refresh(page,fn,changed);
 assert(await page.evaluate(table=>__rows.every((r,i)=>r===document.querySelector(`#${table} tbody`).children[i]),table),fn+' identical full body keeps nodes');
 }finally{await page.close();}}
});
test('heavy results use bounded clickable previews and plaintext expansion, all primary pages cap at 200',async()=>{
 const page=await environment();try{
 const data=payload(); data.results_agg['full-long-domain.example.test'].values=Array.from({length:3000},(_,i)=>`token-${i}`);
 await refresh(page,'refreshResults',data);
 const cell=page.locator('#resultsTable tbody tr').first().locator('td').nth(2);
 assert.equal(await cell.locator('details').count(),1,'heavy values need explicit expansion');
 assert.match(await cell.locator('pre').textContent(),/token-2999/);
 assert(await cell.locator('*').count()<60,'expansion must not create per-token DOM');
 await cell.locator('summary').dispatchEvent('click');
 await page.evaluate(()=>window.__details=document.querySelector('#resultsTable details'));
 await refresh(page,'refreshResults',data);
 assert(await page.evaluate(()=>__details===document.querySelector('#resultsTable details')));
 for(const [fn,,table] of views){const big=payload();big.results_agg={};big.ips=[];big.domains=[];for(let i=0;i<250;i++){big.results_agg['d'+i]={type:'A',values:[],ts:1};big.ips.push({ip:`1.1.1.${i}`,valid:true});big.domains.push({domain:'d'+i,ip_rows:[]});}await refresh(page,fn,big);assert(await page.locator(`#${table} tbody > tr`).count()<=200);}
 }finally{await page.close();}
});
test('422 preserves rows and validators and exposes manual same-origin full JSON only',async()=>{
 for(const [fn,section,table] of views){const page=await environment();try{
 await refresh(page,fn);
 await page.evaluate(table=>window.__row=document.querySelector(`#${table} tbody tr`),table);
 await refresh(page,fn,{error:'oversize'},422);
 assert(await page.evaluate(table=>__row===document.querySelector(`#${table} tbody tr`),table));
 assert.match(await page.locator('#'+section+'-refresh-status').textContent(),/422|too large/i);
 const link=page.locator(`#${section} a[data-full-json]`);assert.equal(await link.count(),1,'manual full JSON access');
 const url=new URL(await link.getAttribute('href'),origin);assert.equal(url.origin,origin);assert.equal(url.searchParams.has('read_mode'),false);
 assert.equal(await page.evaluate(()=>__requests.length),2,'never automated synchronous fallback');
 await refresh(page,fn);assert.equal(new URL(await page.evaluate(()=>__requests[2].url)).searchParams.get('if_version'),'v1');
 }finally{await page.close();}}
});
test('render failure does not advance validator and preserves last-good primary rows',async()=>{
 for(const [fn,,table] of views){const page=await environment();try{
 await refresh(page,fn);
 await page.evaluate(table=>{window.__row=document.querySelector(`#${table} tbody tr`);window.__create=document.createElement;document.createElement=function(tag){if(tag==='tr')throw Error('injected renderer failure');return __create.call(this,tag);};},table);
 const changed=payload();changed.view_version='must-not-commit';changed.results_agg['full-long-domain.example.test'].values=['1.1.1.1'];changed.ips[0].count=2;changed.domains[0].ip_rows[0].vt={asn:9};
 await refresh(page,fn,changed);
 assert(await page.evaluate(table=>__row===document.querySelector(`#${table} tbody tr`),table));
 await page.evaluate(()=>document.createElement=__create);
 await refresh(page,fn);assert.equal(new URL(await page.evaluate(()=>__requests[2].url)).searchParams.get('if_version'),'v1');
 }finally{await page.close();}}
});
test('overview uses backend totals and domain coverage stays explicitly page-only',async()=>{
 const page=await environment();try{
 const data=payload();data.results_total_count=801;data.ips_total_count=501;data.all_ips_total_count=900;data.page.domains_total=333;
 await refresh(page,'refreshResults',data);assert.equal(await page.locator('#metricStatusRows').textContent(),'801');
 await refresh(page,'refreshValidIPs',data);assert.match(await page.locator('#metricIps').textContent(),/^900 \/ valid 501$/);
 const domain=data.domains[0];domain.ip_rows_total=300;domain.ip_rows_offset=40;domain.ip_rows_truncated=true;domain.resolved_ips=[];domain.decoded_ips=[];domain.resolving=true;
 await refresh(page,'refreshDomainAnalysis',data);
 assert.match(await page.locator('#domainanalysis_page_meta').textContent(),/333 domains/);
 assert.match(await page.locator('#domainDomainStatsTable tbody').textContent(),/41.*300/);
 assert.equal(await page.locator('#domainDomainStatsTable tbody input').isDisabled(),true,'page omissions must not imply non-resolving');
 assert.match(await page.locator('#domainDomainStatsTable thead').textContent(),/page/i);
 }finally{await page.close();}
});
test('short byte-limited pages follow exact next_offset and pending keeps snapshot time',async()=>{
 const page=await environment();try{
 const data=payload();data.page.next_offset=17;data.page.displayed=17;
 await refresh(page,'refreshResults',data);
 const previous=await page.locator('#status-refresh-status').textContent();
 await refresh(page,'refreshResults',{snapshot:{ready:false}},202);
 assert((await page.locator('#status-refresh-status').textContent()).includes(previous),'pending retains last-good snapshot metadata');
 await page.evaluate(data=>{__payload=data;__status=200;},data);
 await page.locator('#status_next_btn').dispatchEvent('click');await page.waitForFunction(()=>__requests.length===3);
 assert.equal(new URL(await page.evaluate(()=>__requests[2].url)).searchParams.get('offset'),'17');
 }finally{await page.close();}
});
test('failed domain render keeps cache and invalid IP payload never advances version',async()=>{
 const page=await environment();try{
 await refresh(page,'refreshDomainAnalysis');
 await page.evaluate(()=>{window.__cache=DOMAIN_ANALYSIS_CACHE;window.__create=document.createElement;document.createElement=function(tag){if(tag==='tr')throw Error('render failure');return __create.call(this,tag);};});
 const changed=payload();changed.view_version='bad';changed.domains[0].domain='different.test';await refresh(page,'refreshDomainAnalysis',changed);
 assert(await page.evaluate(()=>DOMAIN_ANALYSIS_CACHE===__cache),'failed rendering cannot publish domain cache');
 await page.evaluate(()=>document.createElement=__create);
 await refresh(page,'refreshIPs');await refresh(page,'refreshIPs',{...payload(),ips:'malformed',view_version:'bad'});await refresh(page,'refreshIPs');
 assert.equal(new URL(await page.evaluate(()=>__requests.at(-1).url)).searchParams.get('if_version'),'v1');
 }finally{await page.close();}
});
test('late domain render failures preserve every table, filter, selection and validator',async()=>{
 for(const target of ['renderDomainAnalysisTable','renderDomainAnalysisSummaries']){
 const page=await environment();try{
 const data=payload();data.domains[0].resolving=false;data.domains[0].ip_rows=[];
 await refresh(page,'refreshDomainAnalysis',data);
 await page.evaluate(()=>{
   const name=DOMAIN_ANALYSIS_CACHE[0].domain;
   document.getElementById('domainAnalysisDomainSelect').value=name;
   DOMAIN_ANALYSIS_SELECTED_REMOVE.add(name);applyDomainAnalysisFilter();
   window.__beforeCache=DOMAIN_ANALYSIS_CACHE;window.__beforeSelection=DOMAIN_ANALYSIS_SELECTED_REMOVE;
   window.__beforeRoots=[...document.querySelectorAll('#domainanalysis tbody'),document.getElementById('domainAnalysisDomainSelect'),document.getElementById('domainAnalysisMeta')];
   window.__beforeDom=__beforeRoots.map(node=>({html:node.innerHTML,children:[...node.children],value:node.value}));
 });
 await page.evaluate(target=>{window.__originalRender=window[target];window[target]=()=>{throw Error('injected late render failure');};},target);
 const changed=structuredClone(data);changed.view_version='failed-B';changed.domains[0].domain='changed-B.test';
 await refresh(page,'refreshDomainAnalysis',changed);
 const check=()=>page.evaluate(()=>({
   cache:DOMAIN_ANALYSIS_CACHE===__beforeCache,selection:DOMAIN_ANALYSIS_SELECTED_REMOVE===__beforeSelection,
   dom:__beforeRoots.every((node,i)=>node.innerHTML===__beforeDom[i].html && node.value===__beforeDom[i].value && __beforeDom[i].children.every((child,j)=>child===node.children[j]))
 }));
 assert.deepEqual(await check(),{cache:true,selection:true,dom:true},target+' must not publish partial B');
 await page.evaluate(target=>{window[target]=__originalRender;},target);
 await refresh(page,'refreshDomainAnalysis',{unchanged:true,view_version:'v1',snapshot,page:data.page});
 assert.equal(new URL(await page.evaluate(()=>__requests.at(-1).url)).searchParams.get('if_version'),'v1');
 assert.deepEqual(await check(),{cache:true,selection:true,dom:true},'unchanged A must retain coherent A');
 await refresh(page,'refreshDomainAnalysis',changed);
 assert.match(await page.locator('#domainDomainStatsTable tbody').textContent(),/changed-B/);
 assert.match(await page.locator('#domainAnalysisTable tbody').textContent(),/changed-B/);
 }finally{await page.close();}}
});
test('Valid IP recent-seconds filter is sent and changes reset pagination',async()=>{
 const page=await environment();try{
 await page.locator('#valid_since').fill('120');
 await refresh(page,'refreshValidIPs');
 assert.equal(new URL(await page.evaluate(()=>__requests.at(-1).url)).searchParams.get('since'),'120');
 await page.locator('#validips_next_btn').dispatchEvent('click');
 await page.waitForFunction(()=>__requests.length===2);
 assert.equal(new URL(await page.evaluate(()=>__requests.at(-1).url)).searchParams.get('offset'),'100');
 await page.locator('#valid_since').fill('60');
 await page.locator('#valid_since').dispatchEvent('change');
 await page.waitForFunction(()=>__requests.length===3);
 const query=new URL(await page.evaluate(()=>__requests.at(-1).url)).searchParams;
 assert.equal(query.get('since'),'60');assert.equal(query.get('offset'),'0');assert.equal(query.get('if_version'),null);
 }finally{await page.close();}
});
test('domain stats rows also preserve identity on timestamp-only refresh',async()=>{
 const page=await environment();try{
 const data=payload();await refresh(page,'refreshDomainAnalysis',data);
 await page.evaluate(()=>window.__stats=document.querySelector('#domainDomainStatsTable tbody tr'));
 data.domains[0].last_ts=2;data.view_version='v2';await refresh(page,'refreshDomainAnalysis',data);
 assert(await page.evaluate(()=>__stats===document.querySelector('#domainDomainStatsTable tbody tr')));
 }finally{await page.close();}
});
(async()=>{
 server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html');res.end(fs.readFileSync('dns_frontend.html','utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'').replace(/<link\b[^>]*>/gi,''));});
 await new Promise(r=>server.listen(0,'127.0.0.1',r)); origin=`http://127.0.0.1:${server.address().port}`;
 let failed=0;
 try{browser=await chromium.launch({headless:true});for(const {name,run} of tests){try{await run();console.log('PASS '+name);}catch(e){failed++;console.error('FAIL '+name+'\n'+e.stack);}}}
 finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
 console.log(`${tests.length-failed} passed, ${failed} failed (Chromium fixture gate)`);process.exitCode=failed?1:0;
})();
