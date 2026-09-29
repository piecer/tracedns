// Canonical contract gate executes the shipped closure, not a copied parser.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('dns_frontend.js', 'utf8');
const start = source.indexOf('// Delivery health owns its lifecycle');
const end = source.indexOf('\nconst uiOverview', start);
assert(start >= 0 && end > start);
class Element {
  constructor() { this.textContent = ''; this.children = []; }
  appendChild(child) { this.children.push(child); }
  replaceChildren(fragment) { this.children = fragment.children; }
}
const elements = Object.fromEntries(['deliveryHealth','deliveryStatus','deliveryDetails','deliveryChecked'].map(id => [id, new Element()]));
const context = {TextDecoder, AbortController, Response, setTimeout, clearTimeout, performance,
  document:{getElementById:id => elements[id], createDocumentFragment:() => new Element(),
    createElement:() => new Element(), addEventListener:() => {}},
  window:{TraceAuth:{}, addEventListener:() => {}}};
vm.createContext(context);
vm.runInContext(source.slice(start, end).replace(/\}\)\(\);\s*$/, '  globalThis.healthTest = {validate, readHealth, render};\n})();'), context);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  for(const data of input.valid) {
    const h = await context.healthTest.readHealth(new Response(JSON.stringify(data)), new AbortController().signal);
    context.healthTest.render(h);
    assert(elements.deliveryDetails.children.length <= 13);
    assert(!elements.deliveryDetails.children.some(el => el.textContent.includes('PRIVATE-CANARY')));
  }
  for(const data of input.invalid) {
    await assert.rejects(context.healthTest.readHealth(new Response(JSON.stringify(data)), new AbortController().signal));
  }
  // Signed-64 maximum is legal on the wire but cannot be shown rounded in JS.
  const text = JSON.stringify(input.valid[0]).replace('"missed_total":0', '"missed_total":9223372036854775807');
  const h = await context.healthTest.readHealth(new Response(text), new AbortController().signal);
  context.healthTest.render(h);
  const rendered = elements.deliveryDetails.children.map(el => el.textContent).join('\n');
  assert(rendered.includes('precision unavailable'));
  assert(rendered.includes('lower bound'));
  assert(!rendered.includes('9223372036854776000'));
  console.log(JSON.stringify({valid:input.valid.length, invalid:input.invalid.length, precision:true}));
})().catch(e => { console.error(e); process.exitCode = 1; });
