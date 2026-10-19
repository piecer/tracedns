// Execute the shipped diagnostics controller in the existing Node/VM style.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const corpus = JSON.parse(fs.readFileSync(0, 'utf8'));
const input = corpus.fixture;
const file = 'delivery_diagnostics.js';
assert(fs.existsSync(file), 'separate diagnostics controller must exist');
class Element {
  constructor(){ this.textContent = ''; this.children = []; this.hidden = false; this.disabled = false; this.events = {}; }
  appendChild(child){ this.children.push(child); }
  replaceChildren(fragment){ this.children = fragment ? fragment.children : []; }
  addEventListener(name, callback){ this.events[name] = callback; }
  click(){ this.clicked = true; }
  remove(){}
}
const ids = ['deliveryDiagnostics','diagnosticsRead','diagnosticsCancel','diagnosticsDownload','diagnosticsStatus','diagnosticsDetails'];
const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
const events = {};
let downloaded;
const urls = new Set();
const context = {TextDecoder, AbortController, Response, Blob, setTimeout, clearTimeout,
  URL:{createObjectURL:blob => {downloaded = blob; urls.add('blob:test'); return 'blob:test';}, revokeObjectURL:url => urls.delete(url)},
  document:{hidden:false, getElementById:id => elements[id], createDocumentFragment:() => new Element(),
    createElement:() => new Element(), addEventListener:(name, fn) => { events[name] = fn; }},
  window:{TraceAuth:{ready:Promise.resolve({role:'admin'})}, addEventListener:(name, fn) => {events[name] = fn;}},
  fetch:async () => { throw new Error('No automatic diagnostics request'); }};
vm.createContext(context);
const source = fs.readFileSync(file, 'utf8');
vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.diagTest = {readDiagnostics, render};\n})();'), context);
(async () => {
  const result = await context.diagTest.readDiagnostics(new Response(JSON.stringify(input)), new AbortController().signal);
  context.diagTest.render(result);
  const text = elements.diagnosticsDetails.children.map(x => x.textContent).join('\n');
  for(const label of ['latest result', 'latest terminal failure', 'oldest blocked', 'not automatically replayed', '302', 'lower bound', '1025', '1024', 'not necessarily active', 'sqlite_full', 'transaction_commit']) assert(text.includes(label), label);
  assert(elements.diagnosticsStatus.textContent.includes('stale'));
  assert(!elements.diagnosticsDownload.disabled);
  assert.equal(typeof elements.diagnosticsRead.events.click, 'function', 'manual read is wired');
  let requests = 0;
  context.fetch = async (url, options) => {
    requests++;
    assert.equal(url, '/delivery-diagnostics');
    assert.equal(options.cache, 'no-store');
    return new Response(JSON.stringify(input));
  };
  await elements.diagnosticsRead.events.click();
  assert.equal(requests, 1);
  assert.equal(elements.diagnosticsRead.disabled, false);
  assert.equal(typeof elements.diagnosticsDownload.events.click, 'function', 'download is wired');
  elements.diagnosticsDownload.events.click();
  assert.deepEqual(JSON.parse(await downloaded.text()), input);
  for(const wire of corpus.valid){
    const item = await context.diagTest.readDiagnostics(new Response(wire), new AbortController().signal);
    context.diagTest.render(item);
    assert(!elements.diagnosticsDetails.children.some(e => e.textContent.includes('PRIVATE-CANARY')));
    assert(elements.diagnosticsDetails.children.length <= 155);
  }
  for(const wire of corpus.invalid) await assert.rejects(context.diagTest.readDiagnostics(new Response(wire), new AbortController().signal));
  const exact = JSON.stringify(input).replace('"observed_at":101', '"observed_at":9223372036854775807');
  const precise = await context.diagTest.readDiagnostics(new Response(exact), new AbortController().signal);
  context.diagTest.render(precise);
  assert(elements.diagnosticsStatus.textContent.includes('precision unavailable'));
  elements.diagnosticsDownload.events.click();
  assert((await downloaded.text()).includes('9223372036854775807'));
  assert(!(await downloaded.text()).includes('9223372036854776000'));
  const duplicate = JSON.stringify(input).replace('"version":1', '"version":"PRIVATE-CANARY","version":1');
  const clean = await context.diagTest.readDiagnostics(new Response(duplicate), new AbortController().signal);
  assert(!clean.json.includes('PRIVATE-CANARY'));
  await assert.rejects(context.diagTest.readDiagnostics(new Response(' '.repeat(32769)), new AbortController().signal));
  // Real timer watchdog prevents an unresolved fake-deadline test from exiting green.
  const watchdog = setTimeout(() => { console.error('Lifecycle did not settle'); process.exit(1); }, 5000);
  try {
    const timers = new Map(); let timerId = 0;
    context.setTimeout = (fn, ms) => { const id = ++timerId; timers.set(id, {fn, ms}); return id; };
    context.clearTimeout = id => timers.delete(id);
    const flush = () => new Promise(setImmediate);
    const expire = () => { for(const [id, t] of timers) if(t.ms === 10000) {timers.delete(id); t.fn();} };
    let resolveFetch, signal;
    context.fetch = (_, options) => { requests++; signal = options.signal; return new Promise(resolve => {resolveFetch = resolve;}); };
    const before = requests;
    const pending = elements.diagnosticsRead.events.click();
    await flush();
    await elements.diagnosticsRead.events.click();
    assert.equal(requests, before + 1, 'one active read only');
    elements.diagnosticsCancel.events.click();
    await pending;
    assert(signal.aborted);
    assert(elements.diagnosticsStatus.textContent.includes('stale'));
    const cancelledStatus = elements.diagnosticsStatus.textContent;
    resolveFetch(new Response(JSON.stringify(input)));
    await flush();
    assert.equal(elements.diagnosticsStatus.textContent, cancelledStatus, 'late response cannot render');
    assert.equal(elements.diagnosticsRead.disabled, false);

    let releaseAuth;
    context.window.TraceAuth.ready = new Promise(resolve => {releaseAuth = resolve;});
    const authWait = elements.diagnosticsRead.events.click();
    await flush(); expire(); await authWait;
    const noAuthRequest = requests;
    releaseAuth({role:'admin'}); await flush();
    assert.equal(requests, noAuthRequest, 'late auth does not issue I/O');
    assert(elements.diagnosticsStatus.textContent.includes('stale'));

    context.window.TraceAuth.ready = Promise.reject(new Error('PRIVATE-CANARY'));
    await elements.diagnosticsRead.events.click();
    assert(!elements.diagnosticsStatus.textContent.includes('PRIVATE-CANARY'));
    context.window.TraceAuth.ready = Promise.resolve({role:'admin'});
    context.fetch = async () => new Response(JSON.stringify(input));
    await elements.diagnosticsRead.events.click();
    assert(!elements.diagnosticsDownload.disabled, 'explicit retry recovers');

    let bodyCancelled = false;
    context.fetch = async (_, options) => {
      signal = options.signal;
      return new Response(new ReadableStream({start(c){ c.enqueue(new TextEncoder().encode('{')); }, cancel(){bodyCancelled = true;}}));
    };
    const stalledBody = elements.diagnosticsRead.events.click();
    await flush(); expire(); await stalledBody; await flush();
    assert(signal.aborted && bodyCancelled);
    assert(elements.diagnosticsStatus.textContent.includes('stale'));

    context.fetch = async () => { throw new Error('Permission denied for this action.'); };
    await elements.diagnosticsRead.events.click();
    assert(elements.deliveryDiagnostics.hidden);
    assert.equal(elements.diagnosticsDetails.children.length, 0);
    assert(elements.diagnosticsDownload.disabled);
    context.fetch = async () => new Response(JSON.stringify(input));
    await elements.diagnosticsRead.events.click();
    assert(!elements.deliveryDiagnostics.hidden);
    context.window.TraceAuth.ready = Promise.resolve({role:'viewer'});
    context.fetch = async () => { throw new Error('viewer must not fetch'); };
    await elements.diagnosticsRead.events.click();
    assert(elements.deliveryDiagnostics.hidden);
    assert(elements.diagnosticsDownload.disabled);
    context.window.TraceAuth.ready = Promise.resolve({role:'operator'});
    context.fetch = async () => new Response('{}', {status:401});
    await elements.diagnosticsRead.events.click();
    assert(elements.diagnosticsDownload.disabled);

    context.fetch = (_, options) => { signal = options.signal; return new Promise(() => {}); };
    const hidden = elements.diagnosticsRead.events.click(); await flush();
    context.document.hidden = true; events.visibilitychange(); await hidden;
    assert(signal.aborted);
    context.document.hidden = false;
    const leaving = elements.diagnosticsRead.events.click(); await flush();
    events.pagehide(); await leaving;
    assert(signal.aborted);
    events.pageshow();
    context.fetch = async () => new Response(JSON.stringify(input));
    await elements.diagnosticsRead.events.click();
    assert.equal(elements.diagnosticsRead.disabled, false);
    assert.equal([...timers.values()].filter(t => t.ms === 10000).length, 0);
  } finally { clearTimeout(watchdog); }
  console.log('diagnostics schema, precision, rendering, refresh, download and lifecycle passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
