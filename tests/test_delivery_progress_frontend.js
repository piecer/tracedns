// Execute the shipped bounded stream parser and renderer on exact Python bytes.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('dns_frontend.js', 'utf8');
const start = source.indexOf('// Delivery health owns its lifecycle');
const end = source.indexOf('\nconst uiOverview', start);
class Element {
  constructor(){ this.textContent = ''; this.children = []; }
  appendChild(child){ this.children.push(child); }
  replaceChildren(fragment){ this.children = fragment.children; }
}
const elements = Object.fromEntries(['deliveryHealth','deliveryStatus','deliveryDetails','deliveryChecked'].map(id => [id,new Element()]));
const context = {TextDecoder, AbortController, Response, setTimeout, clearTimeout, performance,
  document:{getElementById:id => elements[id], createDocumentFragment:() => new Element(),
    createElement:() => new Element(), addEventListener:() => {}},
  window:{TraceAuth:{},addEventListener:() => {}}};
vm.createContext(context);
vm.runInContext(source.slice(start,end).replace(/\}\)\(\);\s*$/, 'globalThis.healthTest={readHealth,validate,render};\n})();'),context);
(async () => {
  const input = JSON.parse(fs.readFileSync(0,'utf8'));
  for(const item of input){
    let parsed;
    try { parsed = await context.healthTest.readHealth(new Response(item.wire),new AbortController().signal); }
    catch(error){ if(item.accept) throw error; continue; }
    assert(item.accept, 'accepted malformed wire');
    context.healthTest.render(parsed);
    const text = elements.deliveryStatus.textContent + '\n' + elements.deliveryDetails.children.map(e=>e.textContent).join('\n');
    for(const expected of item.contains || []) assert(text.includes(expected), `missing ${expected}: ${text}`);
    assert(!text.includes('PRIVATE-CANARY'));
    assert(elements.deliveryDetails.children.length <= 19);
  }
  console.log(JSON.stringify({cases:input.length}));
})().catch(e=>{console.error(e); process.exitCode=1;});
