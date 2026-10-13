package control

import (
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromeReleasesPrototypeAndScopedComponentResults(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for release prototype acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	source, _ := expectedReleaseFixture()
	set, body := source.original, []byte("demo package")
	set.Catalog.Entries[0].Artifact.Size = U64(len(body))
	set.Packages[0].Entry.Artifact.Size = U64(len(body))
	server.Releases = &demoReleaseSource{set: set, body: body}
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/releases?platform=linux")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-release-file]')`)
	if chromeDo(t, debug, `(async()=>{const row=document.querySelector('[data-release-file]'),link=row.querySelector('a[download]'),response=await fetch(link.href),raw=await response.arrayBuffer(),digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(v=>v.toString(16).padStart(2,'0')).join(''),snapshot=await(await fetch('/api/control/ui/snapshot')).json(),file=snapshot.releases[0];return response.ok&&digest===file.sha256&&row.querySelector('[data-copy-release-link]').dataset.copyReleaseLink===link.href.replace(location.origin,'')&&document.querySelectorAll('.release-file-head>span').length===4&&!document.querySelector('.package-grid')&&file.audience==='public'&&Number(file.catalog_generation)>0})()`) != true {
		t.Fatal("formal file download lost its verified exact URL, trust input or prototype rows")
	}
	if chromeDo(t, debug, `(async()=>{Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async text=>{window.demoCopiedRelease=text}});document.querySelector('[data-copy-release-link]').click();await Promise.resolve();return demoCopiedRelease===document.querySelector('[data-release-file] a[download]').href&&!new URL(demoCopiedRelease).search})()`) != true {
		t.Fatal("normal Copy link action changed the exact URL or added credentials")
	}

	// Fixed renderer inputs cover component scope independently of download trust.
	if chromeDo(t, debug, `(async()=>{
	 const {releasesHTML,deviceVersionsHTML}=await import('/assets/releases.js'),now=Date.now(),wanted={component_id:'demo-agent',platform:'linux-amd64',version:'demo-v1',artifact_digest:'sha256:'+'a'.repeat(64)},file={path:'demo-file',name:'demo-linux.tar.gz',title:'Demo Linux',platform:'linux',arch:'amd64',variant:'Mixed',version:'demo-v1',sha256:'b'.repeat(64),size:4,url:'/api/control/releases/demo/download',catalog_digest:'sha256:'+'c'.repeat(64),manifest_digest:'sha256:'+'d'.repeat(64),catalog_generation:'42',audience:'public',components:[wanted]};
	 const device=(id,actual,until=now+60000)=>({id,name:id,platform:'linux',authorized:true,expected_components:[wanted],expected_component_references:[{component_id:wanted.component_id,platform:wanted.platform,catalog_digest:file.catalog_digest,manifest_digest:file.manifest_digest}],evidence:{freshness:'current',current_until:until,reported_at:new Date(now).toISOString(),view_digest:'demo-view',runtime:{state:'running',applied_view_digest:'demo-view'},components:actual}});
	 const devices=[device('demo-match',[wanted]),device('demo-different',[{...wanted,artifact_digest:'sha256:'+'e'.repeat(64)}]),device('demo-expired',[wanted],now-1),device('demo-missing',[]),device('demo-other-platform',[{...wanted,platform:'linux-arm64'}])],s={releases:[file],devices,members:[]},doc=new DOMParser().parseFromString(deviceVersionsHTML(s,new URLSearchParams(),now),'text/html');
	 if(doc.querySelectorAll('.version-table-head>span').length!==3||doc.querySelector('[data-version-device=demo-match]').dataset.versionResult!=='matching'||doc.querySelector('[data-version-device=demo-different]').dataset.versionResult!=='different'||['demo-expired','demo-missing','demo-other-platform'].some(id=>doc.querySelector('[data-version-device='+id+']').dataset.versionResult!=='unknown'))return false;
	 const filtered=new DOMParser().parseFromString(deviceVersionsHTML(s,new URLSearchParams({result:'different'}),now),'text/html');if(filtered.querySelectorAll('[data-version-device]').length!==1)return false;
	 const page=new DOMParser().parseFromString(releasesHTML(s,new URLSearchParams({platform:'linux',device:'demo-match'}),now),'text/html');if(!page.querySelector('[data-file-application]').textContent.includes('Matching target')||page.querySelector('.release-workflow'))return false;
	 devices[0].expected_component_references=[];const unassigned=new DOMParser().parseFromString(releasesHTML(s,new URLSearchParams({platform:'linux',device:'demo-match'}),now),'text/html');return unassigned.querySelector('[data-file-application]').textContent.includes('Selected file is not this device’s target');
	})()`) != true {
		t.Fatal("file or device comparison mixed platform, stale report, archive hash or another expectation")
	}
}
