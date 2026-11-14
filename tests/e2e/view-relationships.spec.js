const {test,expect}=require('@playwright/test');
const {execFileSync}=require('node:child_process');
const path=require('node:path');
const {withViewServer,loginView}=require('./view-helpers');
// Actual producer bytes; only provider observations and asynchronous transport
// are fixtures. This does not claim real VT or worker-process acceptance.
const result=JSON.parse(execFileSync(process.env.PYTHON || path.resolve(__dirname,'../../.venv/bin/python'),[path.join(__dirname,'view_relationship_fixture.py')],{encoding:'utf8'}));
async function installResult(page,payload=result){
  let posts=0;
  await page.route('**/ip-relationship-jobs',r=>{posts++;return r.fulfill({json:{status:'queued',job_id:'fixture-job'}});});
  await page.route('**/ip-relationship-jobs/fixture-job?result=1',r=>r.fulfill({json:{status:'completed',status_code:200,result:payload}}));
  await page.click('#menuIpIntel');
  await page.fill('#ipIntelInput',Object.keys(payload.ip_features).join('\n'));
  await page.click('#runIpRelationshipBtn');
  await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state','complete');
  return ()=>posts;
}

test('relationship evidence is selected, bounded and lazy without external reads',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); const posts=await installResult(page);
    await expect(page.locator('#ipRelQualityBanner')).toBeVisible();
    await expect(page.locator('#ipRelJobDetails')).not.toHaveAttribute('open');
    await expect(page.locator('#ipRelPairsTable tbody tr')).toHaveCount(0);
    await page.click('#ipRelPairsToggleBtn');
    await expect(page.locator('#ipRelPairsTable tbody tr')).toHaveCount(result.pairs.length);
    await expect(page.locator('#ipRelPairsTable .evidence-cell .evidence-sub')).toHaveCount(0);
    await expect(page.locator('#ipRelPairsTable .evidence-sub')).toHaveCount(result.pairs.length);
    for(let i=0;i<20;i++){
      const button=page.locator('#ipRelPairsTable').getByRole('button',{name:/Inspect pair/}).nth(i%result.pairs.length);
      await button.click();
      await expect(page.locator('#ipRelEvidence')).toBeVisible();
      expect(await page.locator('#ipRelEvidence *').count()).toBeLessThanOrEqual(500);
      expect(JSON.parse(await page.locator('#ipRelEvidence pre').textContent())).toEqual(result.pairs[i%result.pairs.length]);
      await page.locator('#ipRelEvidence').getByRole('button',{name:'Close evidence'}).click();
      await expect(button).toBeFocused();
      await expect(page.locator('#ipRelEvidence *')).toHaveCount(0);
    }
    await page.click('#ipRelPairsToggleBtn');
    await expect(page.locator('#ipRelPairsTable tbody tr')).toHaveCount(0);
    expect(posts()).toBe(1);
  });
});

test('real Graph and Map pixels, cached selection and keyboard country reanalysis remain usable',async({page},testInfo)=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); const posts=await installResult(page);
    await page.click('#ipRelViewGraphBtn');
    await expect.poll(()=>page.evaluate(()=>window.IP_REL_GRAPH?.nodes().length || 0)).toBeGreaterThan(1);
    await expect.poll(()=>page.locator('#ipRelGraph canvas').evaluateAll(canvases=>canvases.reduce((n,canvas)=>{
      const ctx=canvas.getContext('2d'); if(!ctx || !canvas.width || !canvas.height) return n;
      const bytes=ctx.getImageData(0,0,canvas.width,canvas.height).data;
      for(let i=3;i<bytes.length;i+=4) if(bytes[i]) n++;
      return n;
    },0))).toBeGreaterThan(100);
    await page.locator('#ipRelGraph').scrollIntoViewIfNeeded();
    // Let native scroll/layout events reach the canvas before hit-testing it.
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const target=await page.evaluate(()=>{
      const node=window.IP_REL_GRAPH.nodes()[0], pos=node.renderedPosition(), box=document.getElementById('ipRelGraph').getBoundingClientRect();
      return {x:pos.x+box.x,y:pos.y+box.y,ip:node.id()};
    });
    await page.mouse.click(target.x,target.y);
    await expect(page.locator('#ipRelGraphDetails')).toContainText(target.ip);
    await page.screenshot({path:testInfo.outputPath('relationship-graph.png'),fullPage:true,animations:'disabled'});
    await page.click('#ipRelViewMapBtn');
    await expect.poll(()=>page.locator('#ipRelMap path').count()).toBeGreaterThan(100);
    await expect(page.locator('#ipRelMap circle')).toHaveCount(2);
    expect(await page.locator('#ipRelMap circle').evaluateAll(nodes=>new Set(nodes.map(node=>node.getAttribute('fill'))).size)).toBe(2);
    await expect(page.locator('#ipRelGraph canvas')).toHaveCount(0);
    await page.screenshot({path:testInfo.outputPath('relationship-map.png'),fullPage:true,animations:'disabled'});
    expect(posts()).toBe(1);
    let selected;
    await page.route('**/ip-relationship-jobs',route=>{
      selected=route.request().postDataJSON();return route.fulfill({status:503,json:{error:'Unavailable'}});
    });
    const bubble=page.locator('#ipRelMap circle[aria-label^="US:"]');
    await bubble.focus(); await bubble.press('Enter');
    await expect.poll(()=>!!selected).toBe(true);
    expect(selected.ips.split('\n').sort()).toEqual(Object.keys(result.ip_features).filter(ip=>result.ip_features[ip].country==='US').sort());
    await expect(page.locator('#ipRelViewTableBtn')).toBeFocused();
    await expect(page.locator('#ipRelMap svg')).toHaveCount(0);
  });
});

test('Per-IP evidence pages actual API results without hidden bulk DOM or new POSTs',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await page.click('#menuIpIntel');
    await page.locator('.ipintel-enrichment-settings > summary').click();
    await page.uncheck('#ipIntelIncludeVt');
    await page.fill('#ipIntelInput',Array.from({length:123},(_,i)=>`11.0.0.${i+1}`).join('\n'));
    let posts=0; page.on('request',request=>{if(request.method()==='POST') posts++;});
    const received=page.waitForResponse(response=>response.url().endsWith('/ip-list-analysis'));
    await page.click('#runIpIntelBtn'); const payload=await (await received).json();
    expect(payload.ips).toHaveLength(123);
    await expect(page.locator('#ipIntelEvidence')).toBeVisible();
    await expect(page.locator('#ipIntelEvidence')).not.toHaveAttribute('open');
    await expect(page.locator('#ipIntelResultTable tbody tr')).toHaveCount(0);
    await page.locator('#ipIntelEvidence > summary').click();
    const seen=[];
    while(true){
      expect(await page.locator('#ipIntelResultsContent *').count()).toBeLessThanOrEqual(500);
      const rows=await page.locator('#ipIntelResultTable tbody tr td:first-child').allTextContents();
      seen.push(...rows);
      if(await page.locator('#ipIntelEvidenceNext').isDisabled()) break;
      await page.click('#ipIntelEvidenceNext');
    }
    expect(seen).toEqual(payload.ips.map(row=>row.ip));
    await page.locator('#ipIntelRaw > summary').click();
    await expect(page.locator('#ipIntelRaw pre')).toContainText('"ips"');
    expect(JSON.parse(await page.locator('#ipIntelRaw pre').textContent())).toEqual(payload);
    await page.locator('#ipIntelEvidence > summary').click();
    await expect(page.locator('#ipIntelResultsContent tbody tr')).toHaveCount(0);
    await expect(page.locator('#ipIntelRaw pre')).toHaveText('');
    expect(posts).toBe(1);
  });
});

for(const failure of ['admission','worker']) test(`relationship ${failure} failure stays local and never reflects provider errors`,async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await installResult(page);
    if(failure==='admission') await page.route('**/ip-relationship-jobs',r=>r.fulfill({status:503,body:'PRIVATE-PROVIDER-TOKEN'}));
    else await page.route('**/ip-relationship-jobs/fixture-job?result=1',r=>r.fulfill({json:{status:'failed',status_code:502,result:{error:'PRIVATE-PROVIDER-TOKEN'}}}));
    await page.click('#runIpRelationshipBtn');
    await expect(page.locator('#ipRelRunStatus')).toHaveAttribute('data-state','error');
    await expect(page.locator('#security-message')).toBeHidden();
    expect(await page.locator('body').evaluate(el=>el.textContent.includes('PRIVATE-PROVIDER-TOKEN'))).toBe(false);
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Previous successful result');
    await expect(page.locator('#exportIpRelationshipBtn')).toBeEnabled();
  });
});

test('role loss discards analysis caches and fences late admission without a new mutation',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await installResult(page);
    await page.click('#ipRelPairsToggleBtn');
    await page.evaluate(()=>{
      window.oldInspect=document.querySelector('#ipRelPairsTable .evidence-cell button').onclick;
      const original=window.fetch;
      window.fetch=(url,options)=>url==='/ip-relationship-jobs'
        ? new Promise(resolve=>{window.pendingAdmission={resolve,options};}) : original(url,options);
    });
    await page.click('#runIpRelationshipBtn');
    await expect.poll(()=>page.evaluate(()=>!!window.pendingAdmission)).toBe(true);
    await page.route('**/config',r=>r.fulfill({status:403,body:'Forbidden'}));
    await page.evaluate(()=>fetch('/config').catch(()=>{}));
    let writes=0;page.on('request',request=>{if(request.method()==='POST') writes++;});
    await expect(page.locator('#exportIpRelationshipBtn')).toBeDisabled();
    await page.evaluate(()=>{
      window.pendingAdmission.resolve(new Response(JSON.stringify({job_id:'late-job'}),{status:202}));
      window.oldInspect();
    });
    await expect.poll(()=>page.evaluate(()=>ipRelAnalyzeController===null)).toBe(true);
    expect(await page.evaluate(()=>window.IP_REL_LAST_SUCCESS)).toBeNull();
    expect(await page.evaluate(()=>exportLastIpRelationshipResult())).toBe(false);
    await expect(page.locator('#ipRelEvidence *')).toHaveCount(0);
    await expect(page.locator('#ipRelClustersTable tbody tr')).toHaveCount(0);
    expect(writes).toBe(0);
  });
});

test('leaving analysis stops browser publication without cancelling server work or losing previous export',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await installResult(page);
    await page.evaluate(()=>{
      const original=window.fetch;
      window.fetch=(url,options)=>url==='/ip-relationship-jobs'
        ? new Promise(resolve=>{window.pendingAdmission={resolve,options};}) : original(url,options);
    });
    await page.click('#runIpRelationshipBtn');
    await expect.poll(()=>page.evaluate(()=>!!window.pendingAdmission)).toBe(true);
    await page.click('#menuStatus');
    expect(await page.evaluate(()=>ipRelAnalyzeController===null)).toBe(true);
    let writes=0;page.on('request',request=>{if(request.method()==='POST') writes++;});
    await page.evaluate(()=>window.pendingAdmission.resolve(new Response(JSON.stringify({job_id:'late-job'}),{status:202})));
    await page.click('#menuIpIntel');
    await expect(page.locator('#exportIpRelationshipBtn')).toBeEnabled();
    expect(await page.evaluate(()=>window.IP_REL_LAST_SUCCESS)).toEqual(result);
    await expect(page.locator('#ipRelRunStatus')).toContainText('may continue');
    expect(writes).toBe(0);
  });
});

test('cancel distinguishes a pending server decision from confirmed cancellation',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await installResult(page);
    await page.route('**/ip-relationship-jobs/fixture-job?result=1',r=>r.fulfill({json:{status:'running'}}));
    let release,requested=false;const gate=new Promise(resolve=>{release=resolve;});
    await page.route('**/ip-relationship-jobs/fixture-job/cancel',async r=>{requested=true;await gate;await r.fulfill({json:{status:'cancelled',cancelled:true,job_id:'fixture-job'}});});
    await page.click('#runIpRelationshipBtn');
    await expect.poll(()=>page.evaluate(()=>ipRelActiveJobId)).toBe('fixture-job');
    await page.click('#cancelIpRelationshipBtn'); await expect.poll(()=>requested).toBe(true);
    await expect(page.locator('#ipRelRunStatus')).toContainText('not yet confirmed');
    release();
    await expect(page.locator('#ipRelRunStatus')).toContainText('Server cancellation confirmed');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Previous successful result');
    await expect(page.locator('#exportIpRelationshipBtn')).toBeEnabled();
  });
});

for(const kind of ['perip','misp']) test(`${kind} error payload is not an empty success or raw provider text`,async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await page.click('#menuIpIntel');
    await page.fill('#ipIntelInput','11.0.0.1'); await page.fill('#ipIntelMispEventId','123');
    await page.route(kind==='perip'?'**/ip-list-analysis':'**/misp/event-ips',r=>r.fulfill({json:{status:'error',error:'PRIVATE-PROVIDER-TOKEN'}}));
    await page.click(kind==='perip'?'#runIpIntelBtn':'#loadIpIntelMispBtn');
    await expect(page.locator(kind==='perip'?'#ipIntelResultsEmpty':'#ipIntelMispStatus')).toContainText(/failed/i);
    expect(await page.locator('body').evaluate(el=>el.textContent.includes('PRIVATE-PROVIDER-TOKEN'))).toBe(false);
    await expect(page.locator('#security-message')).toBeHidden();
  });
});

test('Per-IP input edits fence a delayed real response even when the fetch adapter ignores abort',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await page.click('#menuIpIntel');
    await page.locator('.ipintel-enrichment-settings > summary').click(); await page.uncheck('#ipIntelIncludeVt');
    await page.evaluate(()=>{
      const original=window.fetch;
      window.fetch=async(url,options)=>{
        if(url!=='/ip-list-analysis') return original(url,options);
        const data=await (await original(url,options)).json();
        return new Promise(resolve=>{window.releaseEnrichment=()=>resolve(new Response(JSON.stringify(data),{status:200}));});
      };
    });
    await page.fill('#ipIntelInput','11.0.0.1'); await page.click('#runIpIntelBtn');
    await expect.poll(()=>page.evaluate(()=>!!window.releaseEnrichment)).toBe(true);
    await page.fill('#ipIntelInput','11.0.0.2'); await page.evaluate(()=>window.releaseEnrichment());
    await expect(page.locator('#runIpIntelBtn')).toBeEnabled();
    expect(await page.evaluate(()=>window.IP_INTEL_LAST_RESULT || null)).toBeNull();
    await expect(page.locator('#ipIntelResultTable tbody tr')).toHaveCount(0);
  });
});

test('stale and failed reruns keep actual producer coverage warnings visible',async({page})=>{
  const partial=JSON.parse(execFileSync(process.env.PYTHON || path.resolve(__dirname,'../../.venv/bin/python'),[path.join(__dirname,'view_relationship_fixture.py'),'50','incomplete'],{encoding:'utf8',maxBuffer:16*1024*1024}));
  expect(partial.quality.analysis_complete).toBe(false);
  await withViewServer({},async origin=>{
    await loginView(page,origin);await installResult(page,partial);
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Incomplete analysis');
    await page.fill('#ipIntelInput',Object.keys(partial.ip_features).join('\n')+'\n11.0.0.51');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Inputs changed');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Incomplete analysis');
    await page.route('**/ip-relationship-jobs',r=>r.fulfill({status:503,json:{error:'Unavailable'}}));
    await page.click('#runIpRelationshipBtn');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Previous successful result');
    await expect(page.locator('#ipRelQualityBanner')).toContainText('Incomplete analysis');
    await expect(page.locator('#ipRelQualityBanner')).toBeVisible();
  });
});

test('late map assets cannot mount a hidden predecessor view',async({page})=>{
  await withViewServer({},async origin=>{
    await loginView(page,origin); await installResult(page);
    let release,started=false; const gate=new Promise(resolve=>{release=resolve;});
    await page.route('**/world_countries_110m.geojson',async route=>{started=true;await gate;await route.continue();});
    await page.evaluate(()=>{
      const render=renderIpRelMapFromCache;
      renderIpRelMapFromCache=()=>{window.mapFinished=render();return window.mapFinished;};
    });
    await page.click('#ipRelViewMapBtn'); await expect.poll(()=>started).toBe(true);
    await page.click('#ipRelViewTableBtn'); release();
    await page.evaluate(()=>window.mapFinished);
    await expect(page.locator('#ipRelMap *')).toHaveCount(0);
    await expect(page.locator('#ipRelMapSummary *')).toHaveCount(0);
    await page.click('#ipRelViewMapBtn');
    await expect(page.locator('#ipRelMap circle')).toHaveCount(2);
  });
});
