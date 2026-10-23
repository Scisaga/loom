package control

import (
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromeTopologyLongNamesReadableAndInteractive(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for native topology layout acceptance")
	}
	fixture, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	server := httptest.NewServer(fixture.AdminHandler())
	defer server.Close()
	debug := openCommandChrome(t, server.URL+"/")
	waitChromeEvaluation(t, debug, `document.querySelector('#app h1')&&document.querySelector('#connection').title.includes('local writes available')`)
	result := chromeDo(t, debug, `(async()=>{
	 const {topologyHTML,bindTopology,topologyViewport}=await import('/assets/topology.js');
	 const {topologyPositions}=await import('/assets/model.js');
	 const results=[];
	 const scenarios=[{count:6,compact:true},{count:17,compact:true},
	  ...[6,17].flatMap(count=>[786,560].flatMap(width=>[476,604].map(height=>({count,compact:false,width,height}))))];
	 for(const {count,compact,width,height} of scenarios) {
	  const nodes=Array.from({length:count},(_,i)=>({ID:'demo-node-'+String(i).padStart(2,'0'),Name:i%2?'demo connection name fills width '+i:'演示节点名称较长时仍保留完整内容 '+i,Roles:['access','control','forward','internet_egress'],Location:'demo-location',Direction:i%3?'reverse_only':'',Control:i%2===0,Runtime:i%3?'unknown':'running'}));
	  const before=[...topologyPositions(nodes)],after=[...topologyPositions([...nodes].reverse().map(n=>({...n,Direction:n.Direction?'':'reverse_only',Control:!n.Control})))];
	  if(JSON.stringify(before)!==JSON.stringify(after))return {error:'rings depend on roles, direction or input order'};
	  if(!compact&&count===6)for(const [i,node] of nodes.entries())Object.assign(node,{Name:['demo-alpha','demo-bravo','demo-charlie','demo-delta','demo-echo','demo-foxtrot'][i],Roles:i===3?['access','control','forward']:['forward','internet_egress'],Location:''});
	  const id=compact?'overview-topology':'network';
	  const link={ID:'demo-link',From:nodes[0].ID,To:nodes[1].ID,FromResourceID:'demo-native-a',ResourceID:'demo-native-b',Kind:'tunnel',State:'available',Transport:'wireguard',Metrics:['WG DNS RTT: 29 ms','15m Δ P95−P50: 2 ms']};
	  const reverse={...link,ID:'demo-link-reverse',From:link.To,To:link.From,FromResourceID:link.ResourceID,ResourceID:link.FromResourceID,State:'unavailable'};
	  const view={Nodes:nodes,SelectedLink:'demo-link',Links:[link,reverse]};
	  const app=document.querySelector('#app');app.className='network-page '+(compact?'page-overview':'page-topology');
	  app.innerHTML='<div class="'+(compact?'overview-primary':'topology-layout')+'"><section class="card '+(compact?'overview-topology-card':'topology-stage')+'"><div id="demo-topology" '+(compact?'':'data-topology-layout="adaptive" style="width:'+width+'px;height:'+height+'px;--topology-viewport-height:'+height+'px"')+'>'+topologyHTML(view,[{Chain:[nodes[0].ID,nodes[1].ID]}],id,compact?undefined:{width,height})+'</div></section><aside></aside></div>';
	  const container=document.querySelector('#demo-topology'),svg=container.querySelector('svg');
	  if(!compact){container.style.width=width+'px';container.style.height=height+'px';container.style.setProperty('--topology-viewport-height',height+'px');}
	  bindTopology(container);
	  await document.fonts.ready;
	  const boxes=[...svg.querySelectorAll('.topology-label')].map(n=>n.getBBox()),bounds=svg.viewBox.baseVal;
	  const drawing=svg.getBoundingClientRect();
	  if(drawing.height+1<drawing.width*bounds.height/bounds.width)return {error:'fixed height shrinks actual text',count,compact};
	  if(!compact){
	   const name=svg.querySelector('.node-label:not(.sub)'),detail=svg.querySelector('.node-label.sub');
	   if(Math.abs(svg.getScreenCTM().a-1)>.01||getComputedStyle(name).fontSize!=='14px'||getComputedStyle(detail).fontSize!=='12px'||svg.querySelector('.node').getAttribute('r')!=='6')return {error:'adaptive view scales text or node size',count,width,height};
	   if(bounds.width!==width||count===6&&bounds.height!==height)return {error:'normal six-node diagram does not fill independent viewport',width,height,actualWidth:bounds.width,actualHeight:bounds.height};
	  }
	  if(boxes.length!==count)return {error:'missing node text',count};
	  for(let i=0;i<boxes.length;i++) {
	   const a=boxes[i];
	   if(a.x<0||a.y<0||a.x+a.width>bounds.width||a.y+a.height>bounds.height)return {error:'node text outside diagram',count,index:i};
	   for(let j=i+1;j<boxes.length;j++) {
	    const b=boxes[j];
	    if(a.x<b.x+b.width&&b.x<a.x+a.width&&a.y<b.y+b.height&&b.y<a.y+a.height)return {error:'node texts overlap',count,a:i,b:j};
	   }
	  }
	  const first=svg.querySelector('[data-node="'+nodes[0].ID+'"]');
	  first.focus();first.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
	  if(container.dataset.locked!==nodes[0].ID||first.getAttribute('aria-pressed')!=='true'||!first.querySelector('title').textContent.includes(nodes[0].Name))return {error:'node focus or complete identity lost'};
	  first.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
	  if(container.dataset.locked)return {error:'node lock cannot be cleared'};
	  let clicked=0;container.addEventListener('click',event=>{if(event.target.closest('[data-topology-link="demo-link"]'))clicked++});
	  svg.querySelector('[data-topology-link="demo-link"]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
	  if(clicked!==1||svg.dataset.selectedLink!=='demo-link'||svg.querySelectorAll('.topology-route').length!==1)return {error:'selected link or original route interaction lost'};
	  if(svg.textContent.includes('reverse_only')||svg.textContent.includes('inner: accepts'))return {error:'rings still express access authority'};
	  if(!compact&&count===6&&width===786&&height===476){
	   first.focus();first.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
	   const edge=svg.querySelector('.topology-edge'),hit=edge.querySelector('.edge-hit'),route=svg.querySelector('.topology-route');
	   const previousPath=hit.getAttribute('d'),ring=svg.querySelector('.topology-ring.outer'),rx=Number(ring.getAttribute('rx')),ry=Number(ring.getAttribute('ry'));
	   const nodesBefore=[...svg.querySelectorAll('.topology-node')];
	   container.style.width='640px';
	   await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
	   if(container.querySelector('svg')!==svg||svg.querySelector('.topology-edge')!==edge||edge.querySelector('.edge-hit')!==hit||svg.querySelector('.topology-route')!==route||nodesBefore.some(node=>!node.isConnected)||document.activeElement!==first||container.dataset.locked!==nodes[0].ID)return {error:'resize loses SVG, edge, focus or node identity'};
	   if(Number(ring.getAttribute('rx'))>=rx||Number(ring.getAttribute('ry'))!==ry||hit.getAttribute('d')===previousPath||route.getAttribute('d')!==hit.getAttribute('d')||getComputedStyle(hit).strokeWidth!=='18px'||edge.querySelector('.edge-stroke').dataset.observationPattern!=='dashed')return {error:'resize loses independent radii, shared route or directional line style'};
	   const resizedPath=hit.getAttribute('d');
	   container.parentElement.nextElementSibling.style.height='900px';
	   svg.dataset.selectedLink='demo-link-reverse';bindTopology(container);
	   edge.dispatchEvent(new PointerEvent('pointerover',{bubbles:true}));
	   await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
	   if(hit.getAttribute('d')!==resizedPath||container.dataset.locked!==nodes[0].ID||topologyViewport(container).width!==640)return {error:'detail height, hover or directional choice moves topology'};
	   container.style.height='604px';container.style.setProperty('--topology-viewport-height','604px');
	   await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
	   if(Number(ring.getAttribute('rx'))!==160||Number(ring.getAttribute('ry'))<=ry||svg.viewBox.baseVal.height!==604)return {error:'vertical viewport cannot grow independently of width'};
	  }
	  results.push({count,compact,width,height,passed:true});
	 }
	 return {passed:true,results};
	})()`)
	value, ok := result.(map[string]any)
	if !ok || value["passed"] != true {
		t.Fatalf("actual topology rendering is unreadable or changes interaction: %#v", result)
	}
}
