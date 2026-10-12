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
	 const {topologyHTML,bindTopology}=await import('/assets/topology.js');
	 const {topologyPositions}=await import('/assets/model.js');
	 const results=[];
	 for(const count of [6,17]) for(const compact of [false,true]) {
	  const nodes=Array.from({length:count},(_,i)=>({ID:'demo-node-'+String(i).padStart(2,'0'),Name:i%2?'demo connection name fills width '+i:'演示节点名称较长时仍保留完整内容 '+i,Roles:['access','control','forward','internet_egress'],Location:'demo-location',Direction:i%3?'reverse_only':'',Control:i%2===0,Runtime:i%3?'unknown':'running'}));
	  const before=[...topologyPositions(nodes)],after=[...topologyPositions([...nodes].reverse().map(n=>({...n,Direction:n.Direction?'':'reverse_only',Control:!n.Control})))];
	  if(JSON.stringify(before)!==JSON.stringify(after))return {error:'rings depend on roles, direction or input order'};
	  const id=compact?'overview-topology':'network';
	  const view={Nodes:nodes,SelectedLink:'demo-link',Links:[{ID:'demo-link',From:nodes[0].ID,To:nodes[1].ID,Kind:'tunnel',State:'unknown',Transport:'wireguard',Metrics:['WG DNS RTT: Unknown','15m Δ P95−P50: Unknown']}]};
	  const app=document.querySelector('#app');app.className='network-page '+(compact?'page-overview':'page-topology');
	  app.innerHTML='<div class="'+(compact?'overview-primary':'topology-layout')+'"><section class="card '+(compact?'overview-topology-card':'topology-stage')+'"><div id="demo-topology">'+topologyHTML(view,[{Chain:[nodes[0].ID,nodes[1].ID]}],id)+'</div></section><aside></aside></div>';
	  const container=document.querySelector('#demo-topology'),svg=container.querySelector('svg');
	  bindTopology(container);
	  await document.fonts.ready;
	  const boxes=[...svg.querySelectorAll('.topology-label')].map(n=>n.getBBox()),bounds=svg.viewBox.baseVal;
	  const drawing=svg.getBoundingClientRect();
	  if(drawing.height+1<drawing.width*bounds.height/bounds.width)return {error:'fixed height shrinks actual text',count,compact};
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
	  results.push({count,compact,passed:true});
	 }
	 return {passed:true,results};
	})()`)
	value, ok := result.(map[string]any)
	if !ok || value["passed"] != true {
		t.Fatalf("actual topology rendering is unreadable or changes interaction: %#v", result)
	}
}
