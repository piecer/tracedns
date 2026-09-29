// Exercise the actual shipped renderer with an isolated document per sequence.
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
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = Object.fromEntries(['deliveryHealth', 'deliveryStatus', 'deliveryDetails', 'deliveryChecked'].map(id => [id, new Element()]));
const context = {TextDecoder, AbortController, Response, setTimeout, clearTimeout, performance,
  document: {getElementById: id => elements[id], createDocumentFragment: () => new Element(),
    createElement: () => new Element(), addEventListener: () => {}},
  window: {TraceAuth: {}, addEventListener: () => {}}};
vm.createContext(context);
vm.runInContext(source.slice(start, end).replace(/\}\)\(\);\s*$/, '  globalThis.healthTest = {validate, render};\n})();'), context);
for (const health of input.sequence) context.healthTest.render(context.healthTest.validate(health));
const headline = elements.deliveryStatus.textContent;
for (const expected of input.contains) assert(headline.includes(expected), JSON.stringify({headline, expected}));
for (const unexpected of input.excludes || []) assert(!headline.includes(unexpected), JSON.stringify({headline, unexpected}));
assert(headline.length <= 600, 'live-region summary must remain bounded');
console.log(JSON.stringify({headline}));
