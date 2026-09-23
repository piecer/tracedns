'use strict';
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const tests = [];
const test = (name, run) => tests.push({name, run});
const pending = () => new Promise(() => {});
const response = data => ({ok:true, status:200, json:async()=>data});
const identity = {csrf_token:'test-only', user:{role:'admin'}};
async function drain(){ for(let i=0;i<50;i++) await Promise.resolve(); }
function environment(transport){
  let now=0, next=0;
  const timers = new Map(), elements = new Map(), listeners = new Map();
  const node = id => {
    if(!elements.has(id)) elements.set(id, {style:{},dataset:{},textContent:'',innerHTML:'retained',value:'',checked:false,
      children:[], setAttribute(){}, prepend(el){elements.set(el.id,el);},
      get childNodes(){return this.children;},
      replaceChildren(...children){this.children=[];children.forEach(el=>this.appendChild(el));},
      appendChild(el){this.children.push(el);el.parentNode=this;},
      insertBefore(el){this.appendChild(el);},
      remove(){if(this.parentNode)this.parentNode.children=this.parentNode.children.filter(n=>n!==this);},
      querySelectorAll(){return [];},
      classList:{add(){},remove(){},toggle(){},contains(){return false;}}, addEventListener(){}});
    return elements.get(id);
  };
  const context = vm.createContext({URL, URLSearchParams, Request, Response, Headers, AbortController, DOMException,
    console, Date:class extends Date {static now(){return now;}},
    location:{href:'http://localhost/dns_frontend.html',origin:'http://localhost',pathname:'/dns_frontend.html',replace:p=>redirects.push(p)},
    document:{hidden:false,getElementById:node,querySelector:node,querySelectorAll:()=>[],createElement:()=>node(Symbol()),body:node('body'),
      addEventListener:(event,fn)=>listeners.set(event,fn)},
    addEventListener:(event,fn)=>listeners.set('window:'+event,fn),setInterval:()=>0,
    setTimeout:(fn,ms)=>{timers.set(++next,{fn,at:now+ms});return next;},clearTimeout:id=>timers.delete(id),
    fetch:transport,
  });
  const redirects=[];
  context.window=context;
  vm.runInContext(fs.readFileSync('auth_frontend.js','utf8'),context);
  return {context,timers,elements,node,listeners,redirects, async tick(ms){
    now+=ms;
    for(const [id,t] of [...timers]) if(t.at<=now){timers.delete(id);t.fn();}
    await drain();
  }};
}

test('transient auth failure recovers single-flight on future reads', async()=>{
  let authCalls=0, reads=0;
  const env=environment(async url=>{
    if(String(url).endsWith('/auth/me')){
      if(++authCalls===1) throw new Error('offline');
      return response(identity);
    }
    reads++; return response({ok:true});
  });
  await assert.rejects(env.context.TraceAuth.ready);
  assert.equal(reads,0);
  await env.tick(30001);
  await Promise.all([env.context.fetch('/results'),env.context.fetch('/ips')]);
  assert.equal(authCalls,2);
  assert.equal(reads,2);
});

test('security screen initialization recovers after transient authentication failure', async()=>{
  let calls=0;
  const env=environment(async()=>{
    if(++calls===1) throw new Error('offline');
    return response(identity);
  });
  env.context.location.pathname='/login.html';
  vm.runInContext(fs.readFileSync('security_ui.js','utf8'),env.context);
  await drain();
  assert.equal(env.node('login-form').onsubmit,undefined);
  await env.tick(30001);
  assert.equal(typeof env.node('login-form').onsubmit,'function','login form must initialize after recovery');
  assert.equal(env.node('security-message').textContent,'','successful auth recovery must clear its banner');
  const recoveredCalls=calls;
  await env.tick(30001);
  assert.equal(calls,recoveredCalls,'successful startup must stop retrying');
});

test('security startup does not repeatedly retry downstream permission or service errors', async()=>{
  for(const status of [403,503]){
    let calls=0, styles=0;
    const env=environment(async url=>{
      if(String(url).endsWith('/auth/me')) return response(identity);
      calls++; return {ok:false,status};
    });
    env.context.location.pathname='/account.html';
    env.context.document.head={append(){styles++;}};
    vm.runInContext(fs.readFileSync('security_ui.js','utf8'),env.context);
    await drain();
    for(let i=0;i<10;i++) await env.tick(30001);
    assert.equal(calls,1,'downstream errors must not replay startup reads forever');
    assert.equal(styles,1,'permissions decoration must not accumulate');
    assert.equal(env.timers.size,0);
  }
});

test('JSON deadline aborts pending fetch or body and permits a fresh read', async()=>{
  for(const stall of ['fetch','body']){
    let signal, calls=0;
    const env=environment(async (url,options)=>{
      if(String(url).endsWith('/auth/me')) return response(identity);
      signal=options.signal;
      if(++calls>1) return response({fresh:true});
      return stall==='fetch' ? pending() : {ok:true,status:200,json:pending};
    });
    await env.context.TraceAuth.ready;
    assert.equal(typeof env.context.TraceAuth.readJSON,'function','bounded JSON reader is required');
    let error;
    const first=env.context.TraceAuth.readJSON('/results',{timeoutMs:25}).catch(e=>{error=e;});
    await drain();
    await env.tick(26);
    assert.equal(error?.name,'TimeoutError',stall+' must settle by the deadline');
    assert.equal(signal.aborted,true,'abort the actual transport, not only a race');
    await first;
    assert.equal((await env.context.TraceAuth.readJSON('/results')).fresh,true);
    assert.equal(env.timers.size,0,'dispose lifetime timers');
  }
});

test('caller abort interrupts auth wait without cancelling other waiters', async()=>{
  let resolveAuth, reads=0;
  const env=environment(url=>String(url).endsWith('/auth/me') ? new Promise(resolve=>{resolveAuth=resolve;}) : (reads++,Promise.resolve(response({}))));
  const controller=new AbortController();
  let error;
  env.context.fetch('/results',{signal:controller.signal}).catch(e=>{error=e;});
  const other=env.context.fetch('/ips');
  await drain();
  controller.abort();
  await drain();
  assert.equal(error?.name,'AbortError','auth wait must obey caller abort');
  resolveAuth(response(identity));
  await other;
  await drain();
  assert.equal(reads,1,'cancelled request must never dispatch after auth settles');
});

test('stalled auth fetch and body time out then reinitialize without stale identity publication', async()=>{
  for(const stall of ['fetch','body']){
    let authCalls=0, oldResolve, oldSignal;
    const env=environment((url,options)=>{
      if(++authCalls>1) return Promise.resolve(response(identity));
      oldSignal=options.signal;
      const stuck=new Promise(resolve=>{oldResolve=resolve;});
      return stall==='fetch' ? stuck : Promise.resolve({ok:true,status:200,json:()=>stuck});
    });
    let error;
    env.context.TraceAuth.ready.catch(e=>{error=e;});
    await drain();
    await env.tick(15001);
    assert.equal(error?.name,'TimeoutError','auth initialization must be bounded');
    assert.equal(oldSignal.aborted,true);
    await env.tick(30001);
    await env.context.TraceAuth.ready;
    oldResolve(stall==='fetch' ? response({user:{role:'viewer'}}) : {user:{role:'viewer'}});
    await drain();
    assert.equal(env.context.TraceAuth.user.role,'admin');
    assert.equal(authCalls,2);
  }
});

test('401 is terminal for auth initialization and expired sessions, never bypassed', async()=>{
  for(const atStartup of [true,false]){
    let authCalls=0, requests=0;
    const env=environment(async url=>{
      if(String(url).endsWith('/auth/me')){authCalls++; return atStartup ? {ok:false,status:401} : response(identity);}
      requests++; return {ok:false,status:401};
    });
    if(atStartup) await assert.rejects(env.context.TraceAuth.ready);
    else {await env.context.TraceAuth.ready; await assert.rejects(env.context.fetch('/results'));}
    await env.tick(30001);
    await assert.rejects(env.context.fetch('/results'));
    assert.equal(authCalls,1,'401 must not restart auth');
    assert.equal(requests,atStartup?0:1,'no requests after session expiry');
    assert.equal(env.redirects[0],'/login.html');
  }
});

test('all four refreshes release stalled requests, preserve rows and recover independently', async()=>{
  for(const [fn,section,table] of [
    ['refreshResults','status','#resultsTable tbody'],['refreshIPs','ips','#ipsTable tbody'],
    ['refreshValidIPs','validips','#validIpsTable tbody'],['refreshDomainAnalysis','domainanalysis',null],
  ]){
    for(const stall of ['fetch','body']){
      let calls=0, signal;
      const env=environment(async (url,options)=>{
        if(String(url).endsWith('/auth/me')) return response(identity);
        signal=options.signal;
        if(++calls>1) return response({ips:[],domains:[],results_agg:{}});
        return stall==='fetch' ? pending() : {ok:true,status:200,json:pending};
      });
      await env.context.TraceAuth.ready;
      vm.runInContext(fs.readFileSync('dns_frontend.js','utf8'),env.context);
      let settled=false;
      const first=env.context[fn]().then(()=>{settled=true;});
      await drain();
      await env.tick(15001);
      assert.equal(settled,true,fn+' must release its in-flight guard');
      assert.equal(signal.aborted,true);
      if(table) assert.equal(env.node(table).innerHTML,'retained');
      assert.match(env.node(section+'-refresh-status').textContent,/retry/i);
      await first;
      await env.context[fn]();
      assert.equal(calls,2,fn+' must fetch again on a later tick');
      assert.match(env.node(section+'-refresh-status').textContent,/Snapshot from/i);
    }
  }
});

test('hidden tabs cancel reads, resume without stale publication or old-owner cleanup', async()=>{
  let calls=0, oldResolve, newResolve, oldSignal;
  const env=environment(async (url,options)=>{
    if(String(url).endsWith('/auth/me')) return response(identity);
    calls++;
    if(calls===1){oldSignal=options.signal;return {ok:true,status:200,json:()=>new Promise(resolve=>{oldResolve=resolve;})};}
    return {ok:true,status:200,json:()=>new Promise(resolve=>{newResolve=resolve;})};
  });
  await env.context.TraceAuth.ready;
  vm.runInContext(fs.readFileSync('dns_frontend.js','utf8'),env.context);
  env.node('.section.active').id='status';
  env.context.refreshResults();
  await drain();
  assert.equal(typeof env.listeners.get('visibilitychange'),'function','visibility changes must cancel active reads');
  env.context.document.hidden=true;
  env.listeners.get('visibilitychange')();
  assert.equal(oldSignal.aborted,true);
  await env.context.refreshIPs();
  assert.equal(calls,1,'hidden refreshes cannot dispatch');
  env.context.document.hidden=false;
  env.listeners.get('visibilitychange')();
  await drain();
  assert.equal(calls,2,'visible tab must resume');
  await env.context.refreshResults();
  assert.equal(calls,2,'old finally must not clear the newer owner');
  oldResolve({results_agg:{stale:{values:[]}}});
  await drain();
  assert.equal(env.node('#resultsTable tbody').innerHTML,'retained');
  newResolve({results_agg:{}});
  await drain();
  assert.match(env.node('status-refresh-status').textContent,/Snapshot from/i);
});

test('section navigation cancels obsolete reads without blocking independent resources', async()=>{
  const signals=[];
  const env=environment(async (url,options)=>{
    if(String(url).endsWith('/auth/me')) return response(identity);
    signals.push(options.signal); return pending();
  });
  await env.context.TraceAuth.ready;
  vm.runInContext(fs.readFileSync('dns_frontend.js','utf8'),env.context);
  env.context.refreshResults(); env.context.refreshIPs(); env.context.refreshValidIPs(); env.context.refreshDomainAnalysis();
  await drain();
  assert.equal(signals.length,4,'each resource has an independent owner');
  env.context.showSection('query');
  assert.equal(signals.every(s=>s.aborted),true,'section navigation must invalidate obsolete generations');
  await drain();
  env.context.showSection('status');
  await drain();
  assert.equal(signals.length,5,'new section can immediately start a fresh generation');
});

test('cancelled requests cannot process a late 401 after a fresh request succeeds', async()=>{
  let resolveOld, calls=0;
  const env=environment(async url=>{
    if(String(url).endsWith('/auth/me')) return response(identity);
    if(++calls===1) return new Promise(resolve=>{resolveOld=resolve;});
    return response({ok:true});
  });
  await env.context.TraceAuth.ready;
  const expired=env.context.TraceAuth.readJSON('/results',{timeoutMs:10}).catch(()=>{});
  await drain(); await env.tick(11); await expired;
  await env.context.TraceAuth.readJSON('/results');
  resolveOld({ok:false,status:401}); await drain();
  assert.equal(env.redirects.length,0,'abandoned fetch must not revoke current state');
  assert.equal(env.context.TraceAuth.user.role,'admin');
});

test('auth recovery clears only its own transient status message', async()=>{
  let calls=0;
  const env=environment(async()=>{
    if(++calls===1) throw new Error('offline');
    return response(identity);
  });
  await assert.rejects(env.context.TraceAuth.ready);
  assert.match(env.node('security-message').textContent,/unavailable/i);
  await env.tick(30001); await env.context.TraceAuth.ready;
  assert.equal(env.node('security-message').textContent,'','recovered identity must not retain a failure banner');
});

// Preservation checks: these contracts must stay green through recovery changes.
test('writes are dispatched once and never replayed after a transport failure', async()=>{
  let writes=0;
  const env=environment(async (url,options)=>{
    if(String(url).endsWith('/auth/me')) return response(identity);
    if(options.method==='POST'){writes++; throw new Error('connection lost after send');}
    return response({ok:true});
  });
  await env.context.TraceAuth.ready;
  await assert.rejects(env.context.TraceAuth.json('/config',{value:'test'}));
  await env.tick(60000);
  await env.context.TraceAuth.readJSON('/results');
  assert.equal(writes,1);
});

test('a read deadline includes auth wait and never sends the abandoned request later', async()=>{
  let resolveAuth, reads=0;
  const env=environment(url=>String(url).endsWith('/auth/me') ? new Promise(resolve=>{resolveAuth=resolve;}) : (reads++,Promise.resolve(response({}))));
  let error;
  env.context.TraceAuth.readJSON('/results',{timeoutMs:10}).catch(e=>{error=e;});
  await drain(); await env.tick(11);
  assert.equal(error?.name,'TimeoutError');
  resolveAuth(response(identity)); await drain();
  assert.equal(reads,0);
  await env.context.TraceAuth.readJSON('/results');
  assert.equal(reads,1);
});

test('JSON decode and HTTP failures release all refresh owners for future ticks', async()=>{
  for(const failure of ['json','http']){
    let fail=true, calls=0;
    const env=environment(async url=>{
      if(String(url).endsWith('/auth/me')) return response(identity);
      calls++;
      if(fail) return failure==='http' ? {ok:false,status:503} : {ok:true,status:200,json:async()=>{throw new SyntaxError('invalid JSON');}};
      return response({ips:[],domains:[],results_agg:{}});
    });
    await env.context.TraceAuth.ready;
    vm.runInContext(fs.readFileSync('dns_frontend.js','utf8'),env.context);
    const refresh=()=>Promise.all(['refreshResults','refreshIPs','refreshValidIPs','refreshDomainAnalysis'].map(fn=>env.context[fn]()));
    await refresh();
    assert.equal(calls,4);
    assert.equal(env.node('#resultsTable tbody').innerHTML,'retained');
    fail=false;
    await refresh();
    assert.equal(calls,8);
    assert.match(env.node('status-refresh-status').textContent,/Snapshot from/i);
  }
});

test('polling uses background VT mode and distinguishes pending enrichment', async()=>{
  const urls=[];
  const env=environment(async url=>{
    if(String(url).endsWith('/auth/me')) return response(identity);
    urls.push(new URL(url));
    return response({ips:[],domains:[],enrichment:{status:'pending'}});
  });
  await env.context.TraceAuth.ready;
  vm.runInContext(fs.readFileSync('dns_frontend.js','utf8'),env.context);
  await env.context.refreshIPs();
  await env.context.refreshDomainAnalysis();
  assert.equal(urls.length,2);
  assert(urls.every(url=>url.searchParams.get('vt_mode')==='background'));
  assert.match(env.node('domainanalysis-refresh-status').textContent,/VT: pending/);
});

test('clean VT completion replaces pending context and later ASN changes render', async()=>{
  let vt=null;
  const env=environment(async url=>String(url).endsWith('/auth/me') ? response(identity) : response({
    ips:[{ip:'8.8.8.8',count:1,last_ts:1,domains:['example.test'],vt}],ips_total_count:1,
    enrichment:{status:vt?'ready':'pending'}
  }));
  await env.context.TraceAuth.ready;
  vm.runInContext(fs.readFileSync('dns_frontend.js','utf8'),env.context);
  env.node('ips_include_vt').checked=true;
  const rows=[];
  env.node('#ipsTable tbody').appendChild=row=>rows.push(row);
  const original=env.context.document.createElement;
  env.context.document.createElement=()=>{const n=original();n.children=[];n.appendChild=c=>n.children.push(c);return n;};
  await env.context.refreshIPs();
  vt={malicious:0,suspicious:0,asn:15169,country:'US'};
  await env.context.refreshIPs();
  assert.equal(rows.length,2,'clean reports are not equivalent to absent reports');
  assert.match(rows[1].children[5].textContent,/15169/);
  vt={...vt,asn:1234};
  await env.context.refreshIPs();
  assert.match(rows[2].children[5].textContent,/1234/);
});

test('native fetch aborts a real partial JSON body and closes the response socket', async()=>{
  const http=require('http');
  let headersReady, socketClosed;
  const headers=new Promise(resolve=>{headersReady=resolve;});
  const closed=new Promise(resolve=>{socketClosed=resolve;});
  const server=http.createServer((request,response)=>{
    response.writeHead(200,{'Content-Type':'application/json'});
    response.write('{');
    response.on('close',socketClosed);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const base=`http://127.0.0.1:${server.address().port}`;
    const env=environment(async (url,options)=>{
      if(String(url).endsWith('/auth/me')) return response(identity);
      const result=await fetch(base+new URL(url).pathname,options);
      headersReady(); return result;
    });
    await env.context.TraceAuth.ready;
    let error;
    const read=env.context.TraceAuth.readJSON('/partial',{timeoutMs:10}).catch(e=>{error=e;});
    await headers; await drain(); await env.tick(11); await read;
    assert.equal(error?.name,'TimeoutError');
    await closed;
    assert.equal(env.timers.size,0);
  }finally{
    server.closeAllConnections();
    await new Promise(resolve=>server.close(resolve));
  }
});

(async()=>{
  const watchdog=setTimeout(()=>{console.error('FAIL unresolved test promise');process.exit(1);},3000);
  let failures=0;
  for(const {name,run} of tests){
    try{await run(); console.log('PASS '+name);}
    catch(error){failures++; console.error('FAIL '+name+'\n'+error.stack);}
  }
  console.log(`${tests.length-failures} passed, ${failures} failed`);
  clearTimeout(watchdog);
  process.exitCode=failures?1:0;
})();
