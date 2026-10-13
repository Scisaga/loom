package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromeLivePathsPrototypeScopeAndLayout(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for Live paths prototype acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		server.AdminHandler().ServeHTTP(w, r)
	}))
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/routing")
	waitChromeEvaluation(t, debug, `document.querySelector('.paths-layout')`)
	// Fixed public inputs exercise only the one-way rendering, never authority.
	if chromeDo(t, debug, `(async()=>{
	 const {routingHTML,routingContext,routingSummary}=await import('/assets/routing.js');
	 const now=Date.now(),service={id:'demo-media',name:'media',kind:'internet',matchers:[{kind:'domain',value:'media.example'}]},other={...service,id:'demo-office',name:'office'};
	 const policy=id=>({id:'demo-policy-'+id,name:'media access',service_id:id,action:'allow',entry_scope:{mode:'any'},relay_scope:{mode:'any'},exit_scope:{mode:'any'},allow_direct:true});
	 const path=(device,transport='wireguard',chain=['demo-entry','demo-exit'])=>({device,service_id:service.id,candidate_id:'demo-path-'+device,spec_digest:'demo-spec-'+device,first_transport:transport,first_resource_id:'demo-entry-wg',chain,link_ids:chain.length>1?['demo-link']:[],final_exit:chain.at(-1)||'direct',targets:['https://media.example/health'],selected:true,availability:'unknown'});
	 const devices=['a','b','c','d'].map(id=>({id:'demo-'+id,name:'device '+id,authorized:true,roles:['access'],policy_ids:['demo-policy-demo-media',...(id==='a'?['demo-policy-demo-office']:[])],evidence:{freshness:'current',current_until:now+60000,reported_at:new Date(now).toISOString(),network_generation:'demo-net',runtime:{state:'unknown'},measurements:[]}}));
	 const paths=devices.map(d=>path(d.id));paths[2]={...paths[2],chain:[],first_resource_id:'',link_ids:[],final_exit:'direct'};paths[3].selected=false;
	 devices[0].evidence.measurements=[{level:'service',service_id:service.id,candidate_id:paths[0].candidate_id,spec_digest:paths[0].spec_digest,network_generation:'demo-net',target:paths[0].targets[0],current_until:now+60000,result:'available',duration_ms:0}];
	 devices[1].evidence.measurements=[{...devices[0].evidence.measurements[0],candidate_id:paths[1].candidate_id,spec_digest:paths[1].spec_digest,result:'unavailable'}];
	 const snapshot={services:[service,other],policies:[policy(service.id),policy(other.id)],devices,paths,links:[{id:'demo-link',spec_digest:'demo-link-spec'}],targets:[{target_kind:'service',target_id:'demo-suspended',conflicted:true,deleted:false}]},params=new URLSearchParams({service:service.id});
	 const summary=routingSummary(routingContext(snapshot,params,now).records,snapshot),doc=new DOMParser().parseFromString(routingHTML(snapshot,params,now),'text/html');
	 if(summary.groups.length!==2||summary.groups.find(g=>g.path.final_exit!=='direct')?.count!==2||summary.unconfirmed!==1||summary.failed!==1||summary.unknown!==2||!doc.querySelector('[data-service=demo-suspended]')||doc.querySelector('.paths-layout .card')||doc.querySelectorAll('[data-paths-device]').length!==4||!doc.querySelector('[data-routing-total]').textContent.includes('4 devices')||!doc.querySelector('[data-routing-total]').textContent.includes('5 access records'))return false;
	 const wgGroup=summary.groups.find(g=>g.count===2),filtered=new DOMParser().parseFromString(routingHTML(snapshot,new URLSearchParams({service:service.id,filter:'route:'+wgGroup.key}),now),'text/html');if(filtered.querySelectorAll('[data-paths-device]').length!==2)return false;
	 paths[1].first_transport='hysteria2';if(routingSummary(routingContext(snapshot,params,now).records,snapshot).groups.length!==3)return false;
	 paths[1].first_transport='wireguard';paths[1].chain=['demo-exit'];paths[1].link_ids=[];if(routingSummary(routingContext(snapshot,params,now).records,snapshot).groups.length!==3)return false;
	 const detail=new DOMParser().parseFromString(routingHTML(snapshot,new URLSearchParams({service:service.id,device:devices[0].id,q:'device',filter:'failed'}),now),'text/html');
	 if(detail.querySelector('.paths-detail.card')||detail.querySelectorAll('.paths-identity>div').length!==4||!detail.querySelector('.paths-hop .icon')||!detail.querySelector('[data-end-to-end]').textContent.includes('0 ms')||!detail.querySelector('[data-paths-runtime]').textContent.includes('unknown')||new URL(detail.querySelector('[data-paths-back]').href,'https://example.test').searchParams.get('filter')!=='failed')return false;
	 window.demoRoutingScope=structuredClone(snapshot);devices[0].evidence.current_until=now-1;const expired=routingContext(snapshot,new URLSearchParams({service:service.id,device:devices[0].id}),now).detail;if(expired.current||expired.targetState!=='unknown')return false;
	 return true;
	})()`) != true {
		t.Fatal("prototype layout or actual scoped route/target counts drifted")
	}
	if chromeDo(t, debug, `(async()=>{const {routingHTML}=await import('/assets/routing.js');const s=window.demoRoutingScope,p=s.paths[0];p.first_resource_id='demo-long-shared-first-hop-resource';p.link_ids=['demo-long-shared-link-with-its-original-direction-and-specification'];s.links[0].id=p.link_ids[0];document.querySelector('#app').innerHTML=routingHTML(s,new URLSearchParams({service:'demo-media',device:p.device}),Date.now());await document.fonts.ready;return true})()`) != true {
		t.Fatal("long scoped path could not render")
	}
	if chromeDo(t, debug, `(()=>{const box=document.querySelector('.paths-route').getBoundingClientRect(),nodes=[...document.querySelectorAll('.paths-node-icon')].map(n=>n.getBoundingClientRect());return document.querySelectorAll('.paths-route [style]').length===0&&[...document.querySelectorAll('.paths-edge-metrics')].every(n=>{const r=n.getBoundingClientRect();return r.top>=box.top&&r.bottom<=Math.min(...nodes.map(v=>v.top))})&&document.documentElement.scrollWidth<=innerWidth})()`) != true {
		t.Fatal("long Link metrics were clipped or overlapped the route nodes")
	}

}
