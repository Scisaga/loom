package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func topologyEscapeChrome(t *testing.T, debug *chromeDevTools) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, kind := range []string{"keyDown", "keyUp"} {
		if err := debug.call(ctx, "Input.dispatchKeyEvent", map[string]any{"type": kind, "key": "Escape", "code": "Escape", "windowsVirtualKeyCode": 27}, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func topologyDemoScreenshotChrome(t *testing.T, debug *chromeDevTools) {
	t.Helper()
	// Screenshot pixels exceed the DevTools library's default text-message cap.
	debug.connection.SetReadLimit(8 << 20)
	defer debug.connection.SetReadLimit(32768)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1600, "height": 1400, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
		t.Fatal(err)
	}
	clip := chromeDo(t, debug, `(async()=>{scrollTo(0,0);await document.fonts.ready;await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));const r=document.querySelector('#app').getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,scale:1}})()`)
	var screenshot struct {
		Data string `json:"data"`
	}
	if err := debug.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true, "clip": clip}, &screenshot); err != nil {
		t.Fatal(err)
	}
	content, err := base64.StdEncoding.DecodeString(screenshot.Data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "out", "topology-correction", "demo-bidirectional-details.png")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func topologyObservationArrowPixelsChrome(t *testing.T, debug *chromeDevTools) {
	t.Helper()
	for _, direction := range []string{"forward", "reverse"} {
		geometry := chromeDo(t, debug, `(async()=>{
		 const {topologyHTML}=await import('/assets/topology.js');
		 const nodes=Array.from({length:6},(_,i)=>({ID:'demo-node-'+i,Name:'Demo node '+i,Runtime:'running',Roles:['forward']}));
		 const reverse='`+direction+`'==='reverse',links=[
		  {ID:'demo-forward',From:nodes[0].ID,To:nodes[1].ID,FromResourceID:'demo-resource-a',ResourceID:'demo-resource-b',Kind:'tunnel',Transport:'wireguard',State:reverse?'unavailable':'available'},
		  {ID:'demo-reverse',From:nodes[1].ID,To:nodes[0].ID,FromResourceID:'demo-resource-b',ResourceID:'demo-resource-a',Kind:'tunnel',Transport:'wireguard',State:reverse?'available':'unavailable'}
		 ];
		 const app=document.querySelector('#app');app.className='network-page page-topology';app.innerHTML=topologyHTML({Nodes:nodes,Links:links});scrollTo(0,0);
		 await document.fonts.ready;await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
		 const svg=app.querySelector('svg'),node=svg.querySelector('[data-node="'+nodes[reverse?0:1].ID+'"] .node'),r=node.getBoundingClientRect(),scale=node.getScreenCTM().a,padding=30*scale;
		 return {cx:r.x+r.width/2,cy:r.y+r.height/2,radius:r.width/2+Number.parseFloat(getComputedStyle(node).strokeWidth)*scale/2,clip:{x:Math.floor(r.x-padding),y:Math.floor(r.y-padding),width:Math.ceil(r.width+padding*2),height:Math.ceil(r.height+padding*2),scale:1}};
		})()`).(map[string]any)
		capture := func() image.Image {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var result struct {
				Data string `json:"data"`
			}
			if err := debug.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true, "clip": geometry["clip"]}, &result); err != nil {
				t.Fatal(err)
			}
			content, err := base64.StdEncoding.DecodeString(result.Data)
			if err != nil {
				t.Fatal(err)
			}
			pixels, err := png.Decode(bytes.NewReader(content))
			if err != nil {
				t.Fatal(err)
			}
			return pixels
		}
		withArrow := capture()
		chromeDo(t, debug, `document.querySelector('.edge-stroke').removeAttribute('marker-start');document.querySelector('.edge-stroke').removeAttribute('marker-end');true`)
		withoutArrow := capture()
		clip := geometry["clip"].(map[string]any)
		cx, cy, radius := geometry["cx"].(float64), geometry["cy"].(float64), geometry["radius"].(float64)
		visible := 0
		for y := 0; y < withArrow.Bounds().Dy(); y++ {
			for x := 0; x < withArrow.Bounds().Dx(); x++ {
				r1, g1, b1, a1 := withArrow.At(x, y).RGBA()
				r2, g2, b2, a2 := withoutArrow.At(x, y).RGBA()
				if r1 == r2 && g1 == g2 && b1 == b2 && a1 == a2 {
					continue
				}
				dx, dy := float64(x)+clip["x"].(float64)+.5-cx, float64(y)+clip["y"].(float64)+.5-cy
				if dx*dx+dy*dy > radius*radius {
					visible++
				}
			}
		}
		if visible == 0 {
			t.Fatalf("%s WG DNS observation arrow paints no visible pixels outside the node and its white border", direction)
		}
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
	waitChromeEvaluation(t, debug, `document.querySelectorAll('#topology [data-topology-link]').length===1&&document.querySelectorAll('.link-hour').length===48`)
	if chromeDo(t, debug, `(()=>{const edge=document.querySelector('#topology [data-topology-links]');return JSON.parse(edge.dataset.topologyLinks).includes('`+link.ID+`')&&JSON.parse(edge.dataset.topologyLinks).includes('`+reverse.ID+`')})()`) != true {
		t.Fatal("one relay connection lost an original direction")
	}
	primary := chromeDo(t, debug, `document.querySelector('#topology [data-topology-link]').dataset.topologyLink`).(string)
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
		point := chromeDo(t, debug, `(()=>{const edge=[...document.querySelectorAll('#topology [data-topology-links]')].find(edge=>JSON.parse(edge.dataset.topologyLinks).includes('`+id+`')),path=edge.querySelector('.edge-hit');for(const fraction of [.5,.4,.6,.3,.7]){const p=path.getPointAtLength(path.getTotalLength()*fraction).matrixTransform(path.getScreenCTM());if([0,3,-3].every(offset=>document.elementFromPoint(p.x,p.y+offset)?.closest('.topology-edge')===edge))return {x:p.x,y:p.y}}return {error:'No independently hittable section of the current relay curve'}})()`)
		value := point.(map[string]any)
		if value["error"] != nil {
			t.Fatalf("derived relay cannot be selected by a real pointer: %s: %#v", id, point)
		}
		return value
	}
	for _, id := range []string{primary} {
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
	chromeDo(t, debug, `window.demoTopologyHistoryAsOf=document.querySelector('[data-link-history="`+primary+`"] small[title]').title;document.querySelector('[data-link-history-retry="`+primary+`"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-history="`+primary+`"] small[title]')?.title!==undefined&&document.querySelector('[data-link-history="`+primary+`"] small[title]').title!==demoTopologyHistoryAsOf`)
	if chromeDo(t, debug, `demoTopologyDetached===0&&document.querySelector('#topology svg')===demoTopologySVG&&demoTopologyEdges.every(edge=>edge.isConnected)&&document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+primary+`'&&document.querySelector('[data-topology-link="`+primary+`"]').classList.contains('is-related')`) != true {
		t.Fatal("asynchronous history refresh detached the hovered topology or changed its LinkID")
	}
	point := pointFor(primary)
	topologyMouseChrome(t, debug, "mousePressed", point, 0)
	topologyMouseChrome(t, debug, "mouseReleased", point, 0)
	waitChromeEvaluation(t, debug, `new URLSearchParams(location.search).get('link')==='`+primary+`'&&document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+primary+`'`)
	// Direction buttons are real controls for the original LinkID, not another
	// curve competing for the same pointer. Their change keeps the group DOM.
	for _, id := range []string{reverse.ID, link.ID} {
		button := chromeDo(t, debug, `(()=>{const button=document.querySelector('button[data-topology-direction="`+id+`"]');button.scrollIntoView({block:'nearest'});const r=button.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`).(map[string]any)
		topologyMouseChrome(t, debug, "mouseMoved", button, 0)
		topologyMouseChrome(t, debug, "mousePressed", button, 0)
		topologyMouseChrome(t, debug, "mouseReleased", button, 0)
		waitChromeEvaluation(t, debug, `new URLSearchParams(location.search).get('link')==='`+id+`'&&document.querySelector('button[data-topology-direction="`+id+`"]').getAttribute('aria-pressed')==='true'&&document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+primary+`'`)
		if chromeDo(t, debug, `demoTopologyDetached===0&&document.querySelector('#topology svg')===demoTopologySVG&&demoTopologyEdges[0]===document.querySelector('#topology [data-topology-link]')&&demoTopologyEdges[0].dataset.topologyLink==='`+id+`'&&demoTopologyEdges[0].classList.contains('is-related')&&document.querySelectorAll('.topology-selected-observation [data-link-direction]').length===2`) != true {
			t.Fatal("direction selection replaced the connection or lost bidirectional detail")
		}
	}
	node := chromeDo(t, debug, `(()=>{const node=document.querySelector('#topology [data-node="demo-entry"] .node');node.scrollIntoView({block:'nearest'});const r=node.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`).(map[string]any)
	topologyMouseChrome(t, debug, "mouseMoved", node, 0)
	topologyMouseChrome(t, debug, "mousePressed", node, 0)
	topologyMouseChrome(t, debug, "mouseReleased", node, 0)
	waitChromeEvaluation(t, debug, `document.querySelector('#topology').dataset.locked==='demo-entry'`)
	button := chromeDo(t, debug, `(()=>{const button=document.querySelector('button[data-topology-direction="`+reverse.ID+`"]');button.scrollIntoView({block:'nearest'});const r=button.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`).(map[string]any)
	topologyMouseChrome(t, debug, "mouseMoved", button, 0)
	topologyMouseChrome(t, debug, "mousePressed", button, 0)
	topologyMouseChrome(t, debug, "mouseReleased", button, 0)
	waitChromeEvaluation(t, debug, `document.querySelector('#topology').dataset.locked===''&&document.querySelector('#topology [data-topology-link]').classList.contains('is-inspected')&&document.activeElement.dataset.topologyDirection==='`+reverse.ID+`'`)
	topologyEscapeChrome(t, debug)
	waitChromeEvaluation(t, debug, `!new URLSearchParams(location.search).has('link')&&document.querySelector('#topology').dataset.locked===''`)
	chromeDo(t, debug, `history.pushState({},'','/topology?link=`+reverse.ID+`');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('button[data-topology-direction="`+reverse.ID+`"]').getAttribute('aria-pressed')==='true'&&document.querySelector('#topology [data-topology-link]').dataset.topologyLink==='`+reverse.ID+`'`)
	chromeDo(t, debug, `history.pushState({},'','/topology?link=`+link.ID+`');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('button[data-topology-direction="`+link.ID+`"]').getAttribute('aria-pressed')==='true'`)
	chromeDo(t, debug, `demoTopologyObserver.disconnect();document.querySelector('[data-topology-filter] [name=q]').value='demo-absent-connection';document.querySelector('[data-topology-filter] [name=q]').dispatchEvent(new Event('change',{bubbles:true}));true`)
	waitChromeEvaluation(t, debug, `!document.querySelector('#topology [data-topology-link="`+link.ID+`"]')&&document.querySelector('.topology-traffic-card').dataset.selectedLink===''&&new URLSearchParams(location.search).get('link')==='`+link.ID+`'`)
	chromeDo(t, debug, `document.querySelector('[data-topology-filter] [name=q]').value='';document.querySelector('[data-topology-filter] [name=q]').dispatchEvent(new Event('change',{bubbles:true}));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#topology [data-topology-link="`+link.ID+`"]')&&document.querySelector('button[data-topology-direction="`+link.ID+`"]').getAttribute('aria-pressed')==='true'`)
	chromeDo(t, debug, `document.querySelector('[data-topology-link="`+link.ID+`"]').focus();true`)
	topologyEscapeChrome(t, debug)
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

func TestWebChromeTopologyConnectionsKeepDirectionAndIndependentHits(t *testing.T) {
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
	 const {topologyHTML,bindTopology,topologyConnections,topologyConnectionAppearance}=await import('/assets/topology.js');
	 const nodes=Array.from({length:6},(_,i)=>({ID:'demo-node-'+i,Name:'Demo node '+i,Runtime:'running',Roles:['forward','internet_egress']}));
	 const from=nodes[0].ID,to=nodes[1].ID;
	 const links=[
	  {ID:'demo-link-forward',From:from,To:to,FromResourceID:'demo-native-a',ResourceID:'demo-native-b',Kind:'tunnel',Transport:'wireguard',State:'available'},
	  {ID:'demo-link-reverse',From:to,To:from,FromResourceID:'demo-native-b',ResourceID:'demo-native-a',Kind:'tunnel',Transport:'wireguard',State:'unavailable'},
	  {ID:'demo-link-other-resource',From:from,To:to,FromResourceID:'demo-other-a',ResourceID:'demo-other-b',Kind:'tunnel',Transport:'wireguard',State:'unknown'},
	  {ResourceID:'demo-resource-wg',From:from,To:to,Kind:'first_hop',Transport:'wireguard',State:'available'},
	  {ResourceID:'demo-resource-hy2',From:from,To:to,Kind:'first_hop',Transport:'hysteria2',State:'available'}
	 ];
	 const connection=topologyConnections(links).find(group=>group.links.some(link=>link.ID==='demo-link-forward'));
	 if(connection.links.length!==2||topologyConnections(links).length!==4)return {error:'reciprocal original resources did not share exactly one connection'};
	 for(const patch of [{FromResourceID:'demo-other-a'},{ResourceID:'demo-other-b'},{Kind:'first_hop'},{Transport:'hysteria2'},{FromResourceID:''}]){
	  const distinct={...links[0],...patch,ID:'demo-link-distinct'};
	  if(topologyConnections([links[0],links[1],distinct]).length!==2)return {error:'different resource, Kind or transport was folded into the shared WG connection',patch};
	 }
	 const missing=topologyConnections([links[1]])[0];
	 if(missing.key!==connection.key||missing.links.length!==1||missing.links[0].ID!=='demo-link-reverse')return {error:'one-direction connection invented or lost a direction'};
	 if(JSON.stringify(topologyConnections(links))!==JSON.stringify(topologyConnections([...links].reverse())))return {error:'connection identity depends on input order'};
	 const appearances=[
	  {states:['available','available'],pattern:'solid'},
	  {states:['available','unavailable'],pattern:'dashed',arrow:'end'},
	  {states:['unavailable','available'],pattern:'dashed',arrow:'start'},
	  {states:['unavailable','unavailable'],pattern:'dotted'},
	  {states:['available','unknown'],pattern:'unknown'},
	  {states:['unknown','unavailable'],pattern:'unknown'},
	  {states:['unknown','unknown'],pattern:'unknown'},
	  {states:['available'],pattern:'dashed',arrow:'end'},
	  {states:['unavailable'],pattern:'dotted'},
	  {states:['unknown'],pattern:'unknown'}
	 ];
	 const patterns=new Map();let stableHit='';
	 for(const appearance of appearances){
	  const values=appearance.states.map((state,index)=>({...links[index],State:state})),group=topologyConnections(values)[0],style=topologyConnectionAppearance(group);
	  if(style.pattern!==appearance.pattern||style.singleDirection!==(values.length===1)||JSON.stringify(style.directions.map(value=>value.state))!==JSON.stringify(appearance.states))return {error:'original directional observations were reduced to the wrong display pattern',appearance,style};
	  if(!!style.direction!==!!appearance.arrow||style.direction&&style.direction.from!==(appearance.arrow==='end'?from:to))return {error:'measurement direction borrowed missing or unsuccessful reverse evidence',appearance,style};
	  const app=document.querySelector('#app');app.className='network-page page-topology';app.innerHTML=topologyHTML({Nodes:nodes,Links:values});
	  const svg=app.querySelector('svg'),edge=svg.querySelector('.topology-edge'),line=edge.querySelector('.edge-stroke'),hit=edge.querySelector('.edge-hit'),computed=getComputedStyle(line);
	  if(line.dataset.observationPattern!==appearance.pattern||line.dataset.singleDirection!==String(values.length===1)||!line.classList.contains('observation-'+appearance.pattern)||svg.querySelector('.topology-edge circle'))return {error:'line pattern did not replace the old state circle',appearance};
	  if(['start','end'].some(end=>line.hasAttribute('marker-'+end)!==(appearance.arrow===end))||appearance.arrow&&!line.getAttribute('marker-'+appearance.arrow).includes('network-observation-arrow'))return {error:'grey measurement arrow has the wrong direction or scope',appearance};
	  if(values.length===1&&!edge.querySelector('title').textContent.includes('Only this relay candidate; no reverse candidate'))return {error:'one authorized direction was represented as a failed reverse',appearance};
	  const d=hit.getAttribute('d');if(stableHit&&stableHit!==d)return {error:'changing results or removing reverse candidate moved the hit curve',appearance};stableHit=d;
	  if(computed.strokeDasharray==='none'!==(appearance.pattern==='solid')||getComputedStyle(hit).strokeWidth!=='18px'||getComputedStyle(hit).strokeDasharray!=='none'||getComputedStyle(hit).pointerEvents!=='stroke')return {error:'computed observation pattern changed the stable hit area',appearance,dashes:computed.strokeDasharray};
	  patterns.set(appearance.pattern,{dash:computed.strokeDasharray,opacity:Number(computed.opacity)});
	 }
	 if(new Set([...patterns.values()].map(value=>value.dash)).size!==4||patterns.get('unknown').opacity>=patterns.get('solid').opacity)return {error:'unknown, dotted and confirmed directional patterns are not visibly distinct',patterns:[...patterns]};
	 const views=[
	  {routes:[{Chain:[from,to],FirstTransport:'hysteria2',FirstResourceID:'demo-resource-hy2',LinkIDs:[]}],resource:'demo-resource-hy2',id:'demo-resource-hy2'},
	  {routes:[{Chain:[from,to],LinkIDs:['demo-link-forward']}],ids:['demo-link-forward'],id:'demo-link-forward',arrow:'end'},
	  {routes:[{Chain:[to,from],LinkIDs:['demo-link-reverse']}],ids:['demo-link-reverse'],id:'demo-link-reverse',arrow:'start'},
	  {routes:[{Chain:[from,to],LinkIDs:['demo-link-forward']},{Chain:[to,from],LinkIDs:['demo-link-reverse']}],ids:['demo-link-forward','demo-link-reverse'],id:'demo-both-directions',arrow:'both'}
	 ];
	 const results=[];
	 for(const scenario of views){
	  const app=document.querySelector('#app');app.className='network-page page-topology';
	  app.innerHTML='<section class="card topology-stage"><div id="demo-topology">'+topologyHTML({Nodes:nodes,Links:links,SelectedLink:''},scenario.routes)+'</div></section>';
	  const container=document.querySelector('#demo-topology'),svg=container.querySelector('svg');bindTopology(container);
	  await document.fonts.ready;
	  const edges=[...svg.querySelectorAll('.topology-edge')];
	  if(edges.length!==4)return {error:'drawing still duplicates a reciprocal WG connection',scenario:scenario.id};
	  if(svg.querySelector('.topology-edge circle'))return {error:'a state circle still replaces the requested line pattern',scenario:scenario.id};
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
	   if(Math.hypot(points[i].x-points[j].x,points[i].y-points[j].y)<1)return {error:'different resources or first-hop transports overlap',scenario:scenario.id,a:i,b:j};
	  }
	  for(let i=0;i<edges.length;i++){
	   const point=points[i];
	   if(document.elementFromPoint(point.x,point.y)?.closest('.topology-edge')!==edges[i])return {error:'edge cannot be hit independently',scenario:scenario.id,index:i};
	  }
	  const routes=[...svg.querySelectorAll('.topology-route')],route=routes[0];
	  if(routes.length!==1||!route||scenario.resource&&route.dataset.routeResource!==scenario.resource||scenario.ids&&JSON.stringify(JSON.parse(route.dataset.routeLinks).sort())!==JSON.stringify([...scenario.ids].sort()))return {error:'actual directions did not retain one route layer with the exact original identities',scenario:scenario.id};
	  if(scenario.arrow&&['start','end'].some(end=>route.hasAttribute('marker-'+end)!==(scenario.arrow==='both'||scenario.arrow===end)))return {error:'actual path arrow points in the wrong business direction',scenario:scenario.id};
	  if(scenario.ids&&(route.dataset.observationPattern!=='dashed'||getComputedStyle(route).strokeDasharray!==getComputedStyle(edges.find(edge=>JSON.parse(edge.dataset.topologyLinks||'[]').includes('demo-link-forward')).querySelector('.edge-stroke')).strokeDasharray||['start','end'].some(end=>route.hasAttribute('marker-'+end)&&!route.getAttribute('marker-'+end).includes('network-arrow'))))return {error:'blue reported route hid the observation pattern or borrowed the grey availability direction',scenario:scenario.id};
	  const midpoint=route.getPointAtLength(route.getTotalLength()/2).matrixTransform(route.getScreenCTM()),target=document.elementFromPoint(midpoint.x,midpoint.y),edge=target?.closest('.topology-edge');
	  if(!edge||target.closest('.topology-route')||scenario.resource&&edge.dataset.resource!==scenario.resource||scenario.ids&&!scenario.ids.every(id=>JSON.parse(edge.dataset.topologyLinks).includes(id)))return {error:'route decoration intercepts the original connection',scenario:scenario.id};
	  const visible=edge.querySelector('path:not(.edge-hit)'),style=getComputedStyle(visible);
	  if(style.visibility!=='hidden'&&style.display!=='none'&&style.opacity!=='0'&&style.strokeOpacity!=='0')return {error:'selected dashed route still paints the underlying transport color',scenario:scenario.id};
	  let clicked='';container.addEventListener('click',event=>{const edge=event.target.closest('.topology-edge');clicked=edge?.dataset.topologyLink||edge?.dataset.resource||''});
	  target.dispatchEvent(new MouseEvent('click',{bubbles:true}));
	  if(clicked!==(edge.dataset.topologyLink||edge.dataset.resource))return {error:'click did not select the original identity under the route',scenario:scenario.id};
	  const ordinary=edges.filter(edge=>!edge.classList.contains('has-route')),widths=ordinary.map(edge=>getComputedStyle(edge.querySelector('.edge-stroke')).strokeWidth);
	  svg.querySelector('[data-node="'+from+'"]').dispatchEvent(new PointerEvent('pointerover',{bubbles:true}));
	  if(ordinary.some((edge,i)=>getComputedStyle(edge.querySelector('.edge-stroke')).strokeWidth!==widths[i]))return {error:'node hover thickened relay candidates',scenario:scenario.id};
	  const oneDirection=new DOMParser().parseFromString(topologyHTML({Nodes:nodes,Links:links.filter(link=>link.ID!=='demo-link-forward'),SelectedLink:'demo-link-reverse'},[scenario.routes.find(route=>route.LinkIDs.includes('demo-link-reverse'))].filter(Boolean)),'text/html');
	  const oneEdge=[...oneDirection.querySelectorAll('[data-topology-links]')].find(edge=>JSON.parse(edge.dataset.topologyLinks).includes('demo-link-reverse'));
	  const original=[...edges].find(edge=>JSON.parse(edge.dataset.topologyLinks||'[]').includes('demo-link-reverse'));
	  if(!oneEdge||JSON.parse(oneEdge.dataset.topologyLinks).length!==1||oneEdge.dataset.key!==original.dataset.key||oneEdge.querySelector('.edge-hit').getAttribute('d')!==original.querySelector('.edge-hit').getAttribute('d')||oneEdge.querySelector('.edge-stroke').dataset.singleDirection!=='true'||oneEdge.querySelector('.edge-stroke').dataset.observationPattern!=='dotted')return {error:'removing one direction moved the shared connection or manufactured reverse data'};
	  results.push({scenario:scenario.id,independentHits:edges.length});
	 }
	 return {passed:true,results};
	})()`)
		value, ok := result.(map[string]any)
		if !ok || value["passed"] != true {
			t.Fatalf("relay connections or actual directional route are not independently usable at %d px: %#v", width, result)
		}
		topologyObservationArrowPixelsChrome(t, debug)
	}
}
