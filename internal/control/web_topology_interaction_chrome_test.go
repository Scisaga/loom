package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func topologyMouseChrome(t *testing.T, debug *chromeDevTools, kind string, point map[string]any, offset float64) {
	t.Helper()
	params := map[string]any{"type": kind, "x": point["x"].(float64), "y": point["y"].(float64) + offset}
	if kind != "mouseMoved" {
		params["button"], params["clickCount"] = "left", 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := debug.call(ctx, "Input.dispatchMouseEvent", params, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWebChromeTopologyRealPointerPreviewAndPinStayStable(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for real topology pointer acceptance")
	}
	p := relayProjectionFixture(t)
	link := webRelayLink(t, p, "demo-entry", "demo-exit")
	reverse := webRelayLink(t, p, "demo-exit", "demo-entry")
	root, config, genesis := authorityFixture(t)
	authority, err := InitializeAuthority(root, config, genesis)
	if err != nil {
		t.Fatal(err)
	}
	authority.projection = p
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: &Runtime{Config: config, Authority: authority, Reports: store}}
	var holdOverviewHistory atomic.Bool
	overviewRequested, resumeOverview := make(chan struct{}), make(chan struct{})
	handler := server.AdminHandler()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/ui/traffic-history" && r.URL.Query().Get("network") != "" && holdOverviewHistory.Swap(false) {
			close(overviewRequested)
			select {
			case <-resumeOverview:
			case <-r.Context().Done():
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	defer func() {
		select {
		case <-resumeOverview:
		default:
			close(resumeOverview)
		}
	}()
	debug := openCommandChrome(t, httpServer.URL+"/topology")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1600, "height": 1100, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
		t.Fatal(err)
	}
	waitChromeEvaluation(t, debug, `document.querySelectorAll('#topology [data-topology-link]').length===2&&document.querySelectorAll('.link-hour').length===48`)
	chromeDo(t, debug, `(async()=>{
	 await document.fonts.ready;
	 await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
	 window.demoTopologySVG=document.querySelector('#topology svg');
	 window.demoTopologyEdges=[...demoTopologySVG.querySelectorAll('[data-topology-link]')];
	 window.demoTopologyDetached=0;
	 window.demoTopologyObserver=new MutationObserver(records=>{
	  for(const record of records)for(const node of record.removedNodes){
	   if(node===demoTopologySVG||node.contains?.(demoTopologySVG)||demoTopologyEdges.some(edge=>node===edge||node.contains?.(edge)))demoTopologyDetached++;
	  }
	 });
	 demoTopologyObserver.observe(document.querySelector('#app'),{subtree:true,childList:true});
	 return true;
	})()`)
	pointFor := func(id string) map[string]any {
		t.Helper()
		point := chromeDo(t, debug, `(()=>{const edge=document.querySelector('[data-topology-link="`+id+`"]'),path=edge.querySelector('.edge-hit');for(const fraction of [.5,.4,.6,.3,.7]){const p=path.getPointAtLength(path.getTotalLength()*fraction).matrixTransform(path.getScreenCTM());if([0,3,-3].every(offset=>document.elementFromPoint(p.x,p.y+offset)?.closest('.topology-edge')===edge))return {x:p.x,y:p.y}}return {error:'No independently hittable section of the current relay curve'}})()`)
		value := point.(map[string]any)
		if value["error"] != nil {
			t.Fatalf("derived relay cannot be selected by a real pointer: %s: %#v", id, point)
		}
		return value
	}
	for _, id := range []string{reverse.ID, link.ID} {
		point := pointFor(id)
		for _, offset := range []float64{0, 3, -3, 0} {
			topologyMouseChrome(t, debug, "mouseMoved", point, offset)
		}
		waitChromeEvaluation(t, debug, `document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+id+`'`)
		result := chromeDo(t, debug, `(async()=>{
		 await new Promise(resolve=>setTimeout(resolve,250));
		 const edge=demoTopologyEdges.find(edge=>edge.dataset.topologyLink==='`+id+`');
		 return {detached:demoTopologyDetached,sameSVG:document.querySelector('#topology svg')===demoTopologySVG,sameEdge:document.querySelector('[data-topology-link="`+id+`"]')===edge,related:edge.classList.contains('is-related'),unpinned:!new URLSearchParams(location.search).has('link')};
		})()`)
		value := result.(map[string]any)
		if value["detached"] != float64(0) || value["sameSVG"] != true || value["sameEdge"] != true || value["related"] != true || value["unpinned"] != true {
			t.Fatalf("real hovering detaches or loses the same LinkID: %#v", result)
		}
	}
	// Keep the real pointer on the edge while an independent history refresh
	// completes through the SPA's normal asynchronous redraw path.
	chromeDo(t, debug, `window.demoTopologyHistoryAsOf=document.querySelector('[data-link-history="`+link.ID+`"] small[title]').title;document.querySelector('[data-link-history-retry="`+link.ID+`"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-history="`+link.ID+`"] small[title]')?.title!==undefined&&document.querySelector('[data-link-history="`+link.ID+`"] small[title]').title!==demoTopologyHistoryAsOf`)
	if chromeDo(t, debug, `demoTopologyDetached===0&&document.querySelector('#topology svg')===demoTopologySVG&&demoTopologyEdges.every(edge=>edge.isConnected)&&document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+link.ID+`'&&document.querySelector('[data-topology-link="`+link.ID+`"]').classList.contains('is-related')`) != true {
		t.Fatal("asynchronous history refresh detached the hovered topology or changed its LinkID")
	}
	point := pointFor(link.ID)
	topologyMouseChrome(t, debug, "mousePressed", point, 0)
	topologyMouseChrome(t, debug, "mouseReleased", point, 0)
	waitChromeEvaluation(t, debug, `new URLSearchParams(location.search).get('link')==='`+link.ID+`'&&document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+link.ID+`'`)
	topologyMouseChrome(t, debug, "mouseMoved", pointFor(reverse.ID), 0)
	if chromeDo(t, debug, `document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+link.ID+`'&&document.querySelector('[data-link-row="`+link.ID+`"]').classList.contains('selected-link')&&document.querySelector('[data-topology-link="`+link.ID+`"]').classList.contains('is-related')&&document.querySelector('[data-topology-link="`+reverse.ID+`"]').classList.contains('is-muted')`) != true {
		t.Fatal("hover over another direction changed the pinned LinkID")
	}
	chromeDo(t, debug, `demoTopologyObserver.disconnect();document.querySelector('[data-topology-filter] [name=q]').value='`+reverse.ID+`';document.querySelector('[data-topology-filter] [name=q]').dispatchEvent(new Event('change',{bubbles:true}));true`)
	waitChromeEvaluation(t, debug, `!document.querySelector('#topology [data-topology-link="`+link.ID+`"]')&&document.querySelector('.topology-traffic-card').dataset.selectedLink===''&&new URLSearchParams(location.search).get('link')==='`+link.ID+`'`)
	chromeDo(t, debug, `document.querySelector('[data-topology-filter] [name=q]').value='';document.querySelector('[data-topology-filter] [name=q]').dispatchEvent(new Event('change',{bubbles:true}));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#topology [data-topology-link="`+link.ID+`"]')&&document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+link.ID+`'`)
	chromeDo(t, debug, `document.querySelector('[data-topology-link="`+link.ID+`"]').focus();true`)
	keysContext, keysCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer keysCancel()
	for _, kind := range []string{"keyDown", "keyUp"} {
		if err := debug.call(keysContext, "Input.dispatchKeyEvent", map[string]any{"type": kind, "key": "Escape", "code": "Escape", "windowsVirtualKeyCode": 27}, nil); err != nil {
			t.Fatal(err)
		}
	}
	waitChromeEvaluation(t, debug, `!new URLSearchParams(location.search).has('link')`)
	holdOverviewHistory.Store(true)
	chromeDo(t, debug, `history.pushState({},'','/');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('.overview-topology-card svg')!==null`)
	select {
	case <-overviewRequested:
	case <-time.After(5 * time.Second):
		t.Fatal("Overview did not request its original network traffic history")
	}
	chromeDo(t, debug, `window.demoOverviewSVG=document.querySelector('.overview-topology-card svg');window.demoOverviewDetached=0;window.demoOverviewObserver=new MutationObserver(records=>{for(const record of records)for(const node of record.removedNodes)if(node===demoOverviewSVG||node.contains?.(demoOverviewSVG))demoOverviewDetached++});demoOverviewObserver.observe(document.querySelector('#app'),{subtree:true,childList:true});true`)
	close(resumeOverview)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-traffic-scope^="network:"] .wg-traffic-hour').length===24`)
	if chromeDo(t, debug, `demoOverviewObserver.disconnect();demoOverviewDetached===0&&document.querySelector('.overview-topology-card svg')===demoOverviewSVG`) != true {
		t.Fatal("Overview's first asynchronous history read detached the original topology")
	}
}

func TestWebChromeTopologyParallelEdgesAndRouteHaveIndependentHits(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for real topology lane acceptance")
	}
	fixture, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	server := httptest.NewServer(fixture.AdminHandler())
	defer server.Close()
	debug := openCommandChrome(t, server.URL+"/")
	waitChromeEvaluation(t, debug, `document.querySelector('#app h1')&&document.querySelector('#connection').title.includes('local writes available')`)
	for _, width := range []int{1600, 390} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 1100, "deviceScaleFactor": 1, "mobile": width == 390}, nil); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		result := chromeDo(t, debug, `(async()=>{
	 const {topologyHTML,bindTopology}=await import('/assets/topology.js');
	 const nodes=Array.from({length:6},(_,i)=>({ID:'demo-node-'+i,Name:'Demo node '+i,Runtime:'running',Roles:['forward','internet_egress']}));
	 const from=nodes[0].ID,to=nodes[1].ID;
	 const links=[
	  {ID:'demo-link-forward',From:from,To:to,Kind:'tunnel',Transport:'wireguard',State:'available'},
	  {ID:'demo-link-reverse',From:to,To:from,Kind:'tunnel',Transport:'wireguard',State:'available'},
	  {ResourceID:'demo-resource-wg',From:from,To:to,Kind:'first_hop',Transport:'wireguard',State:'available'},
	  {ResourceID:'demo-resource-hy2',From:from,To:to,Kind:'first_hop',Transport:'hysteria2',State:'available'}
	 ];
	 const views=[
	  {route:{Chain:[from,to],FirstTransport:'hysteria2',FirstResourceID:'demo-resource-hy2',LinkIDs:[]},key:'data-route-resource',id:'demo-resource-hy2'},
	  {route:{Chain:[from,to],LinkIDs:['demo-link-forward']},key:'data-route-link',id:'demo-link-forward'}
	 ];
	 const results=[];
	 for(const scenario of views){
	  const app=document.querySelector('#app');app.className='network-page page-topology';
	  app.innerHTML='<section class="card topology-stage"><div id="demo-topology">'+topologyHTML({Nodes:nodes,Links:links,SelectedLink:''},[scenario.route])+'</div></section>';
	  const container=document.querySelector('#demo-topology'),svg=container.querySelector('svg');bindTopology(container);
	  await document.fonts.ready;
	  const edges=[...svg.querySelectorAll('.topology-edge')];
		  for(const edge of edges){
		   const hit=getComputedStyle(edge.querySelector('.edge-hit'));
		   if(hit.strokeWidth!=='18px'||hit.strokeDasharray!=='none'||hit.pointerEvents!=='stroke')return {error:'candidate hit area changed with visible stroke',scenario:scenario.id};
		   const line=edge.querySelector('.tunnel');
		   if(line&&!edge.classList.contains('has-route')){
		    const style=getComputedStyle(line),channels=style.stroke.match(/\d+/g).map(Number);
		    if(style.strokeWidth!=='1px'||Math.min(...channels)<180||Number(style.opacity)>=.85)return {error:'ordinary relay candidate remains visually heavy',scenario:scenario.id};
		   }
		  }
	  const points=edges.map(edge=>{const path=edge.querySelector('.edge-hit');return path.getPointAtLength(path.getTotalLength()/2).matrixTransform(path.getScreenCTM())});
	  for(let i=0;i<points.length;i++)for(let j=i+1;j<points.length;j++){
	   if(Math.hypot(points[i].x-points[j].x,points[i].y-points[j].y)<1)return {error:'parallel LinkIDs or first-hop transports overlap',scenario:scenario.id,a:i,b:j};
	  }
	  for(let i=0;i<edges.length;i++){
	   const point=points[i];
	   if(document.elementFromPoint(point.x,point.y)?.closest('.topology-edge')!==edges[i])return {error:'edge cannot be hit independently',scenario:scenario.id,index:i};
	  }
	  const route=svg.querySelector('.topology-route['+scenario.key+'="'+scenario.id+'"]');
	  if(!route)return {error:'selected route lost its exact original edge',scenario:scenario.id};
	  const midpoint=route.getPointAtLength(route.getTotalLength()/2).matrixTransform(route.getScreenCTM()),target=document.elementFromPoint(midpoint.x,midpoint.y),edge=target?.closest('.topology-edge');
	  if(!edge||target.closest('.topology-route')||(edge.dataset.topologyLink||edge.dataset.resource)!==scenario.id)return {error:'route decoration intercepts the original edge',scenario:scenario.id};
	  const visible=edge.querySelector('path:not(.edge-hit)'),style=getComputedStyle(visible);
	  if(style.visibility!=='hidden'&&style.display!=='none'&&style.opacity!=='0'&&style.strokeOpacity!=='0')return {error:'selected dashed route still paints the underlying transport color',scenario:scenario.id};
	  let clicked='';container.addEventListener('click',event=>{const edge=event.target.closest('.topology-edge');clicked=edge?.dataset.topologyLink||edge?.dataset.resource||''});
	  target.dispatchEvent(new MouseEvent('click',{bubbles:true}));
	  if(clicked!==scenario.id)return {error:'click did not select the actual edge under the route',scenario:scenario.id};
	  results.push({scenario:scenario.id,independentHits:edges.length});
	 }
	 return {passed:true,results};
	})()`)
		value, ok := result.(map[string]any)
		if !ok || value["passed"] != true {
			t.Fatalf("parallel topology edges or observed route are not independently usable at %d px: %#v", width, result)
		}
	}
}
