const {test, expect} = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {withViewServer, loginView} = require('./view-helpers');

// Real frontend and isolated HTTP/prepared producer. Faults gate only the
// transport; visibility schedules are synthetic, not native tab/BFCache tests.
async function openView(page, origin, testInfo) {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await loginView(page, origin);
  const bytes = await (await page.request.get(origin + '/dns_frontend.js')).body();
  expect(bytes.equals(fs.readFileSync(path.resolve(__dirname, '../../dns_frontend.js')))).toBe(true);
  await testInfo.attach('served-source', {body: JSON.stringify({
    path: path.resolve(__dirname, '../../dns_frontend.js'),
    sha256: crypto.createHash('sha256').update(bytes).digest('hex')
  }), contentType: 'application/json'});
  await page.click('#pauseRefreshBtn');
  return errors;
}
const history = {history: {meta: {}, events: Array.from({length: 51}, (_, i) => ({
  ts: i + 1, type: 'A', server: 'fixture', values: ['192.0.2.' + (i + 1)]
}))}};
async function selectTarget(page, index = 0) {
  await page.locator('#resultsTable tbody tr').nth(index).getByRole('button', {name: 'Details', exact: true}).click();
  await page.click('#targetHistory');
  await expect(page.locator('.history-event')).toHaveCount(50);
}
async function gateHistory(page) {
  await page.evaluate(() => {
    const original = window.fetch;
    window.fetch = (url, options) => String(url).includes('/history?')
      ? new Promise((resolve, reject) => { window.historyGate = {resolve, reject, signal: options.signal}; })
      : original(url, options);
    window.historyPending = loadHistory(selectedTarget.domain);
  });
  await expect.poll(() => page.evaluate(() => !!window.historyGate)).toBe(true);
}
async function releaseHistory(page, body, status = 200) {
  await page.evaluate(async ({body, status}) => {
    // The auth fetch adapter normally rejects non-2xx. Model that rejection
    // as well as a body that completes after abort (the adversarial schedule).
    if(status >= 400) window.historyGate.reject(Object.assign(new Error('fixture read failed'), {status}));
    else window.historyGate.resolve(new Response(JSON.stringify(body), {status}));
    await window.historyPending;
  }, {body, status});
}
async function pageHistory(page, direction, count, focus) {
  const button = page.locator(direction === 'next' ? '#historyNext' : '#historyPrev');
  await button.focus();
  await button.press('Enter');
  await expect(page.locator('.history-event')).toHaveCount(count);
  if(focus) await expect(page.locator(focus)).toBeFocused();
}

for(const pending of [false, true]) test(`F1 History ${pending ? 'pending refresh then paging' : 'failed refresh then paging'} retains failure until accepted recovery`, async ({page}, testInfo) => {
  await withViewServer({delivery: 'disabled'}, async origin => {
    const errors = await openView(page, origin, testInfo);
    let reads = 0;
    await page.route('**/history?**', route => { reads++; return route.fulfill({json: history}); });
    await selectTarget(page);
    await gateHistory(page);
    if(pending) await pageHistory(page, 'next', 1);
    await releaseHistory(page, {error: 'unavailable'}, 503);
    await expect(page.locator('#historyStatus')).toContainText('History read failed');
    await expect(page.locator('#historyStatus')).toContainText('Previous history is stale');
    const identity = await page.locator('#historyBox').getAttribute('data-feedback-id');
    if(pending) await pageHistory(page, 'previous', 50, '#historyNext');
    else await pageHistory(page, 'next', 1, '#historyPrev');
    await expect(page.locator('#historyStatus')).toContainText('History read failed');
    await expect(page.locator('#historyStatus')).toContainText('Previous history is stale');
    await pageHistory(page, pending ? 'next' : 'previous', pending ? 1 : 50, pending ? '#historyPrev' : '#historyNext');
    expect(await page.locator('#historyBox').getAttribute('data-feedback-id')).toBe(identity);
    // A retry and its cancellation must not silently recover the failed owner.
    await page.evaluate(() => { window.historyGate = null; window.historyPending = loadHistory(selectedTarget.domain); });
    await expect.poll(() => page.evaluate(() => !!window.historyGate)).toBe(true);
    await expect(page.locator('#historyStatus')).toContainText('History read failed');
    await page.evaluate(() => cancelHistoryRead());
    await releaseHistory(page, history);
    await pageHistory(page, pending ? 'previous' : 'next', pending ? 50 : 1);
    await expect(page.locator('#historyStatus')).toContainText('History read failed');
    // Malformed success is a failure, not recovery.
    await page.evaluate(() => { window.historyPending = loadHistory(selectedTarget.domain); });
    await releaseHistory(page, {history: {events: 'invalid'}});
    await expect(page.locator('#historyStatus')).toContainText('History read failed');
    await page.evaluate(() => { window.historyPending = loadHistory(selectedTarget.domain); });
    await releaseHistory(page, history);
    await expect(page.locator('#historyStatus')).not.toContainText(/failed|stale|Loading/);
    await expect(page.locator('#historyBox')).not.toHaveAttribute('data-feedback-id');
    expect(reads).toBe(1); // Other responses were gated at the real fetch boundary.
    expect(errors).toEqual([]);
  });
});

test('F1 History A/B/A selection rejects cancelled completions and detached cached controls', async ({page}, testInfo) => {
  await withViewServer({delivery: 'disabled'}, async origin => {
    const errors = await openView(page, origin, testInfo);
    await page.route('**/history?**', route => route.fulfill({json: history}));
    await selectTarget(page);
    await page.evaluate(() => {
      window.oldNext = document.getElementById('historyNext').onclick;
      window.oldEvent = document.querySelector('.history-event');
    });
    await gateHistory(page);
    await page.locator('#resultsTable tbody tr').nth(1).getByRole('button', {name: 'Details', exact: true}).click();
    expect(await page.evaluate(() => window.historyGate.signal.aborted)).toBe(true);
    await releaseHistory(page, history);
    await page.evaluate(() => { window.oldNext(); window.oldEvent.open = true; });
    await expect(page.locator('#targetDetailHeading')).toHaveText('target-001.test');
    await expect(page.locator('#historyBox')).toHaveCount(0);
    await page.locator('#resultsTable tbody tr').first().getByRole('button', {name: 'Details', exact: true}).click();
    await page.evaluate(() => { window.historyPending = loadHistory(selectedTarget.domain); });
    await releaseHistory(page, {error: 'unavailable'}, 503);
    const before = await page.locator('#historyBox').innerText();
    await page.evaluate(() => window.oldNext());
    expect(await page.locator('#historyBox').innerText()).toBe(before);
    await expect(page.locator('#historyStatus')).toContainText('No successful history read for this target');
    expect(errors).toEqual([]);
  });
});

function relationshipResult() {
  return JSON.parse(execFileSync(process.env.PYTHON || path.resolve(__dirname, '../../.venv/bin/python'),
    [path.join(__dirname, 'view_relationship_fixture.py'), '50', 'incomplete'],
    {encoding: 'utf8', maxBuffer: 16 * 1024 * 1024}));
}
async function acceptRelationship(page, result) {
  await page.route('**/ip-relationship-jobs', route => route.fulfill({status: 202, json: {status: 'queued', job_id: 'review-job'}}));
  await page.route('**/ip-relationship-jobs/review-job?result=1', route => route.fulfill({json: {status: 'completed', status_code: 200, result}}));
  await page.click('#menuIpIntel');
  await page.fill('#ipIntelInput', Object.keys(result.ip_features).join('\n'));
  await page.click('#runIpRelationshipBtn');
  await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state', 'complete');
  await expect(page.locator('#ipRelQualityBanner')).toContainText('Incomplete analysis');
}
async function lifecycle(page, kind, hidden) {
  await page.evaluate(({kind, hidden}) => {
    if(kind === 'visibility') {
      Object.defineProperty(document, 'hidden', {configurable: true, value: hidden});
      document.dispatchEvent(new Event('visibilitychange'));
    } else window.dispatchEvent(new PageTransitionEvent(hidden ? 'pagehide' : 'pageshow', {persisted: true}));
  }, {kind, hidden});
}
async function expectRelationshipView(page, view, result) {
  await expect(page.locator(`#ipRelView${view}Btn`)).toHaveAttribute('aria-selected', 'true');
  if(view === 'Table') await expect(page.locator('#ipRelClustersTable tbody tr')).toHaveCount(result.clusters.length);
  if(view === 'Graph') {
    await expect.poll(() => page.evaluate(() => window.IP_REL_GRAPH?.nodes().length || 0)).toBe(result.graph.nodes.length);
    await expect(page.locator('#ipRelGraph canvas').first()).toBeVisible();
  }
  if(view === 'Map') {
    await expect(page.locator('#ipRelMap circle')).toHaveCount(result.country_summary.length);
    await expect.poll(() => page.locator('#ipRelMap path').count()).toBeGreaterThan(100);
  }
}
function observeAnalysisRequests(page) {
  const requests = [];
  page.on('request', request => {
    if(request.method() === 'POST' || /\/(ip-relationship-jobs|ip-list-analysis|misp|ips|domain-analysis|results)([/?]|$)/.test(new URL(request.url()).pathname))
      requests.push({method: request.method(), url: request.url()});
  });
  return requests;
}

for(const view of ['Table', 'Graph', 'Map']) for(const paused of [false, true])
  test(`F2 ${view} cached view resumes after visibility and persisted pageshow with auto-refresh ${paused ? 'paused' : 'enabled'}`, async ({page}, testInfo) => {
    const result = relationshipResult();
    await withViewServer({delivery: 'disabled'}, async origin => {
      const errors = await openView(page, origin, testInfo);
      await acceptRelationship(page, result);
      await page.click(`#ipRelView${view}Btn`);
      await expectRelationshipView(page, view, result);
      await page.evaluate(paused => { manualPause = paused; hoverPause = false; }, paused);
      const quality = await page.locator('#ipRelQualityBanner').innerText();
      const requests = observeAnalysisRequests(page);
      for(const kind of ['visibility', 'bfcache']) {
        const focus = view === 'Table' ? page.locator('#ipRelClustersTable button').first()
          : view === 'Map' ? page.locator('#ipRelMap circle').first() : page.locator('#ipRelViewGraphBtn');
        await focus.focus();
        await lifecycle(page, kind, true);
        await expect(page.locator('#ipRelClustersTable tbody tr, #ipRelGraph canvas, #ipRelMap svg')).toHaveCount(0);
        await lifecycle(page, kind, false);
        await expectRelationshipView(page, view, result);
        await expect(page.locator(`#ipRelView${view}Btn`)).toBeFocused();
        expect(await page.locator('#ipRelQualityBanner').innerText()).toBe(quality);
        await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state', 'complete');
        expect(await page.evaluate(() => window.IP_REL_LAST_SUCCESS)).toEqual(result);
      }
      // A stable input keeps its own focus rather than being replaced by a tab.
      await page.focus('#ipIntelInput');
      await lifecycle(page, 'visibility', true); await lifecycle(page, 'visibility', false);
      await expectRelationshipView(page, view, result);
      await expect(page.locator('#ipIntelInput')).toBeFocused();
      expect(requests).toEqual([]);
      expect(errors).toEqual([]);
    });
  });

for(const kind of ['visibility', 'bfcache']) test(`F2 ${kind} detaches active job truthfully and restores only previous accepted evidence`, async ({page}, testInfo) => {
  const result = relationshipResult();
  await withViewServer({delivery: 'disabled'}, async origin => {
    const errors = await openView(page, origin, testInfo);
    await acceptRelationship(page, result);
    await page.evaluate(() => {
      const original = window.fetch;
      window.fetch = (url, options) => String(url).includes('/ip-relationship-jobs/review-job?')
        ? new Promise(resolve => { window.jobGate = {resolve, signal: options.signal}; }) : original(url, options);
    });
    await page.click('#runIpRelationshipBtn');
    await expect.poll(() => page.evaluate(() => !!window.jobGate)).toBe(true);
    const requests = observeAnalysisRequests(page);
    await lifecycle(page, kind, true);
    expect(await page.evaluate(() => window.jobGate.signal.aborted)).toBe(true);
    await lifecycle(page, kind, false);
    await expectRelationshipView(page, 'Table', result);
    await expect(page.locator('#ipRelRunStatus')).toContainText('Server work may continue; cancellation was not requested');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Previous successful result');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Incomplete analysis');
    await page.evaluate(() => window.jobGate.resolve(new Response(JSON.stringify({status: 'completed', status_code: 200,
      result: {status: 'ok', pairs: [], clusters: [], ip_features: {}}}))));
    await expect(page.locator('#runIpRelationshipBtn')).toBeEnabled();
    expect(await page.evaluate(() => window.IP_REL_CACHE)).toEqual(result);
    await expectRelationshipView(page, 'Table', result);
    await expect(page.locator('#ipRelRunStatus')).toContainText('Server work may continue');
    expect(requests).toEqual([]);
    expect(errors).toEqual([]);
  });
});

test('F2 access invalidation cannot restore private cached relationship evidence on resume', async ({page}, testInfo) => {
  const result = relationshipResult();
  await withViewServer({delivery: 'disabled'}, async origin => {
    const errors = await openView(page, origin, testInfo);
    await acceptRelationship(page, result);
    await page.click('#ipRelViewMapBtn'); await expectRelationshipView(page, 'Map', result);
    await page.evaluate(() => { window.oldCountry = document.querySelector('#ipRelMap circle'); });
    await lifecycle(page, 'visibility', true);
    await page.route('**/config', route => route.fulfill({status: 403, body: 'Forbidden'}));
    await page.evaluate(() => fetch('/config').catch(() => {}));
    expect(await page.evaluate(() => TraceAuth.accessInvalidated)).toBe(true);
    const requests = observeAnalysisRequests(page);
    await lifecycle(page, 'visibility', false);
    await lifecycle(page, 'bfcache', true); await lifecycle(page, 'bfcache', false);
    await page.evaluate(() => window.oldCountry.dispatchEvent(new MouseEvent('click')));
    expect(await page.evaluate(() => [window.IP_REL_CACHE, window.IP_REL_LAST_SUCCESS])).toEqual([null, null]);
    await expect(page.locator('#ipRelClustersTable tbody tr, #ipRelPairsTable tbody tr, #ipRelGraph canvas, #ipRelMap svg')).toHaveCount(0);
    await expect(page.locator('#exportIpRelationshipBtn')).toBeDisabled();
    expect(requests).toEqual([]);
    expect(errors).toEqual([]);
  });
});

for(const [section, menu, table, refresh] of [
  ['ips', 'menuIPs', 'ipsTable', 'refreshIPs'],
  ['validips', 'menuValidIPs', 'validIpsTable', 'refreshValidIPs']
]) {
  test(`F3 ${section} timestamp-only accepted refresh keeps row and focus but new detail/raw use current data`, async ({page}, testInfo) => {
    await withViewServer({delivery: 'disabled'}, async origin => {
      const errors = await openView(page, origin, testInfo);
      await page.click('#' + menu);
      const rows = page.locator(`#${table} tbody tr`), first = rows.first();
      await expect(first).toContainText('11.0.');
      const initial = await page.evaluate(section => TraceAuth.readJSON(preparedQuery(section)), section);
      expect(initial.ips.length).toBeGreaterThan(0);
      const accepted = structuredClone(initial);
      accepted.ips[0].last_ts += 3600;
      accepted.view_version += '-timestamp-only'; delete accepted.unchanged;
      const button = first.getByRole('button', {name: 'Details', exact: true});
      await button.focus();
      await page.evaluate(table => {
        window.savedIpRow = document.querySelector(`#${table} tbody tr`);
        window.savedIpButton = document.activeElement;
      }, table);
      let payload = accepted;
      await page.route('**/ips?**', route => route.fulfill({json: payload}));
      await page.evaluate(refresh => window[refresh](), refresh);
      expect(await page.evaluate(table => window.savedIpRow === document.querySelector(`#${table} tbody tr`), table)).toBe(true);
      await expect(button).toBeFocused();
      const observed = await first.locator('td').nth(2).textContent();
      await button.press('Enter');
      await expect(page.locator('#ipDetail')).toContainText('Last observed: ' + observed);
      await page.locator('#ipDetail summary').click();
      await expect(page.locator('#ipDetail details pre')).toBeVisible();
      expect(JSON.parse(await page.locator('#ipDetail details pre').textContent())).toEqual(accepted.ips[0]);
      await page.getByRole('button', {name: 'Close IP details', exact: true}).click();
      await expect(button).toBeFocused();
      // Changed row removes the old control; its captured handler cannot open
      // either the previous value or the new same-key replacement.
      await page.evaluate(() => { window.oldIpClick = window.savedIpButton.onclick; });
      payload = structuredClone(accepted); payload.ips[0].count += 1; payload.view_version += '-content';
      await page.evaluate(refresh => window[refresh](), refresh);
      expect(await page.evaluate(() => window.savedIpButton.isConnected)).toBe(false);
      await page.evaluate(() => window.oldIpClick());
      await expect(page.locator('#ipDetail')).toHaveCount(0);
      // A still-connected control in a now-hidden workspace is not an owner.
      await page.evaluate(table => { window.hiddenIpClick = document.querySelector(`#${table} tbody tr button`).onclick; }, table);
      await page.click('#menuIpIntel');
      await page.evaluate(() => window.hiddenIpClick());
      await expect(page.locator('#ipDetail')).toHaveCount(0);
      expect(errors).toEqual([]);
    });
  });

  test(`F3 ${section} invalidated IP detail entrypoint and lazy controls cannot publish`, async ({page}, testInfo) => {
    await withViewServer({delivery: 'disabled'}, async origin => {
      const errors = await openView(page, origin, testInfo);
      await page.click('#' + menu);
      const button = page.locator(`#${table} tbody tr`).first().getByRole('button', {name: 'Details', exact: true});
      await expect(button).toBeVisible();
      await page.evaluate(table => { window.invalidIpClick = document.querySelector(`#${table} tbody tr button`).onclick; }, table);
      await button.click();
      await page.evaluate(() => {
        window.invalidIpRaw = document.querySelector('#ipDetail details');
        window.invalidIpQuery = document.querySelector('#ipDetail button[data-access]').onclick;
      });
      await page.route('**/config', route => route.fulfill({status: 403, body: 'Forbidden'}));
      await page.evaluate(() => fetch('/config').catch(() => {}));
      expect(await page.evaluate(() => TraceAuth.accessInvalidated)).toBe(true);
      const requests = observeAnalysisRequests(page);
      await page.evaluate(() => { window.invalidIpRaw.open = true; window.invalidIpRaw.dispatchEvent(new Event('toggle')); window.invalidIpQuery(); });
      expect(await page.evaluate(() => window.invalidIpRaw.querySelectorAll('pre').length)).toBe(0);
      await page.evaluate(() => { document.getElementById('ipDetail')?.remove(); window.invalidIpClick(); });
      await expect(page.locator('#ipDetail')).toHaveCount(0);
      expect(await page.evaluate(() => getActiveSectionId())).toBe(section);
      expect(requests).toEqual([]);
      expect(errors).toEqual([]);
    });
  });
}
