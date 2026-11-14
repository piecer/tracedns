const {test,expect}=require('@playwright/test');
const {withViewServer,loginView}=require('./view-helpers');
const sizes=[
  {label:'desktop',viewport:{width:1366,height:768},deviceScaleFactor:1},
  {label:'mobile',viewport:{width:390,height:844},deviceScaleFactor:1},
  // Equivalent CSS layout + physical pixels for 200% browser magnification.
  // This is not a physical-device or browser-chrome zoom-key test.
  {label:'200-percent-reflow',viewport:{width:Math.round(1366/2),height:Math.round(768/2)},deviceScaleFactor:2}
];
for(const role of ['admin','operator','viewer']) for(const size of sizes){
  test(`${role} whole-view geometry and keyboard access at ${size.label}`,async({page,browser},info)=>{
    await withViewServer({delivery:'disabled',documentation:true},async origin=>{
      await loginView(page,origin);
      if(role!=='admin') await page.evaluate(role=>TraceAuth.json('/admin/users',{username:role,password:'temporary-password',role}),role);
      const context=await browser.newContext({viewport:size.viewport,deviceScaleFactor:size.deviceScaleFactor});
      try{
        const actor=await context.newPage(),errors=[],requests=[];
        actor.on('pageerror',error=>errors.push(error.message));
        actor.on('request',r=>requests.push({path:new URL(r.url()).pathname,origin:new URL(r.url()).origin,method:r.method()}));
        if(role==='admin') await loginView(actor,origin);
        else{
          await loginView(actor,origin,role,'temporary-password',false);
          await expect(actor.locator('#password-submit')).toBeEnabled();
          await actor.fill('#current-password','temporary-password');
          await actor.fill('#new-password','changed-password');await actor.fill('#confirm-password','changed-password');
          await actor.click('#password-submit');await expect(actor).toHaveURL(/login\.html/);
          await loginView(actor,origin,role,'changed-password');
        }
        expect(await actor.evaluate(()=>document.body.dataset.role)).toBe(role);
        await actor.locator('.skip-link').focus();await actor.keyboard.press('Enter');
        await expect(actor.locator('#workspace')).toBeFocused();
        const before=requests.length;
        const views=['Status','IPs','ValidIPs','Query','DomainAnalysis','IpIntel',...(role==='viewer'?[]:['DomainVerify','Settings'])];
        const geometry=[];
        for(const view of views){
          await actor.click('#menu'+view);
          await expect(actor.locator('.section.active')).toHaveCount(1);
          await expect(actor.locator('#menu'+view)).toHaveAttribute('aria-current','page');
          await expect(actor.locator('.section.active > h3')).toBeVisible();
          if(view==='Status') await expect(actor.locator('#resultsTable tbody tr')).toHaveCount(12);
          if(view==='DomainAnalysis') await expect(actor.locator('#domainDomainStatsTable tbody tr')).toHaveCount(12);
          await actor.evaluate(()=>window.scrollTo(0,0));
          const bounds=await actor.evaluate(()=>{
            const box=document.querySelector('.section.active').getBoundingClientRect();
            return {left:box.left,right:box.right,width:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth};
          });
          expect(bounds.overflow,view).toBe(false);
          expect(bounds.left>=0 && bounds.right<=bounds.width,JSON.stringify({view,...bounds})).toBe(true);
          geometry.push({view,...bounds});
          await actor.screenshot({path:info.outputPath(view+'.png'),animations:'disabled'});
        }
        await actor.locator('#accountMenu > summary').focus();await actor.keyboard.press('Enter');
        await expect(actor.locator('#accountMenu')).toHaveAttribute('open');
        await expect(actor.locator('#security-nav')).toBeVisible();
        await actor.keyboard.press('Space');await expect(actor.locator('#accountMenu')).not.toHaveAttribute('open');
        const cdp=await context.newCDPSession(actor);
        const tree=await cdp.send('Accessibility.getFullAXTree');
        const accessible=tree.nodes.filter(n=>!n.ignored).map(n=>({role:n.role?.value,name:n.name?.value}));
        expect(accessible.some(n=>n.role==='main')).toBe(true);
        expect(accessible.some(n=>n.role==='navigation' && n.name==='Workspaces')).toBe(true);
        await cdp.detach();
        expect(requests.filter(r=>r.origin!==origin)).toEqual([]);
        expect(requests.slice(before).filter(r=>r.method==='POST')).toEqual([]);
        expect(errors).toEqual([]);
        await info.attach('whole-view-evidence',{body:JSON.stringify({role,size,geometry,requests,accessible}),contentType:'application/json'});
        // Server RBAC, not just hidden client controls. This denial is last so
        // the resulting intentional permission invalidation cannot mask reflow.
        if(role!=='admin'){
          const status=await actor.evaluate(async role=>{
            try{await TraceAuth.json(role==='viewer'?'/config':'/settings',{});return 200;}
            catch(error){return error.status;}
          },role);
          expect(status).toBe(403);
          await expect(actor.locator('#security-message')).toBeVisible();
        }
      }finally{await context.close();}
    });
  });
}
