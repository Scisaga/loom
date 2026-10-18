package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestWebChromeLiveDeltasAndReconnect(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for live delta browser acceptance")
	}
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	server.Now = time.Now
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices/"+invite.DeviceID)
	script := `window.demoLiveFrames=[];window.demoLiveSockets=[];const DemoLiveSocket=WebSocket;window.WebSocket=class extends DemoLiveSocket{constructor(...args){super(...args);demoLiveSockets.push(this);this.addEventListener('message',event=>demoLiveFrames.push(JSON.parse(event.data)))}};`
	if err := debug.call(t.Context(), "Page.enable", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := debug.call(t.Context(), "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": script}, nil); err != nil {
		t.Fatal(err)
	}
	chromeDo(t, debug, `location.reload();true`)
	waitChromeEvaluation(t, debug, `window.demoLiveFrames!==undefined`)
	waitChromeEvaluation(t, debug, `demoLiveFrames[0]?.snapshot?.schema===3`)
	if chromeDo(t, debug, `demoLiveSockets[0].extensions.includes('permessage-deflate')`) != true {
		t.Fatal("real browser did not negotiate independent message compression")
	}
	first, second, delta := webDeltaFixture(t)
	expression := `(async()=>{const {applyLive}=await import('/assets/live.js'),first=` + string(first) + `,next=` + string(second) + `,delta=` + string(delta) + `,before=JSON.stringify(first),result=applyLive(first,delta),equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 if(!equal(result,next)||JSON.stringify(first)!==before)return false;
 const bad=[{schema:3,changes:[]},{schema:3,changes:[{path:['devices','01','name'],value:'bad'}]},{schema:3,changes:[{path:['devices','999','name'],value:'bad'}]},{schema:3,changes:[{path:['constructor','prototype','polluted'],value:true}]},{schema:3,changes:[{path:['devices','0'],remove:true}]},{schema:3,changes:[{path:['missing','name'],value:1}]},{schema:3,changes:[{path:['missing'],remove:true}]},{schema:3,changes:[{path:[],value:{schema:2}}]},{schema:3,changes:[{path:['nullable'],value:1,remove:false}]},first];
 for(const item of bad){try{applyLive(first,item);return false}catch{if(JSON.stringify(first)!==before)return false}}
 try{applyLive(null,delta);return false}catch{}
 return equal(applyLive(null,{schema:3,snapshot:next}),next)&&!({}).polluted;
 })()`
	if chromeDo(t, debug, expression) != true {
		t.Fatal("live difference lost exact fields, mutated its base, or accepted invalid paths")
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	report := DeviceReport{Schema: 3, NetworkID: view.View.NetworkID, DeviceID: invite.DeviceID, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped", AppliedViewDigest: view.ViewDigest}}
	send := func(state string) {
		t.Helper()
		report.ReportSequence++
		report.ReportedAt = time.Now().UnixMilli()
		report.Runtime.State = state
		report.Signature = ""
		signed, err := SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		response := enrollmentHTTP(t, server, "/device/report", signed, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID})
		if response.Code != 200 {
			t.Fatal("formal report upload failed", response.Code, response.Body.String())
		}
	}
	send("stopped")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-runtime-state]')?.textContent==='stopped'&&demoLiveFrames.some(v=>v.changes)`)
	chromeDo(t, debug, `(()=>{history.pushState({},'','/services?service=demo-service');dispatchEvent(new PopStateEvent('popstate'));window.demoLiveForm=document.querySelector('#service-form');window.demoLiveName=demoLiveForm.elements.name;demoLiveName.value='Unsaved demo delta';demoLiveName.focus();demoLiveName.setSelectionRange(2,5);return true})()`)
	send("running")
	waitChromeEvaluation(t, debug, `demoLiveFrames.some(v=>v.changes?.some(c=>c.path.at(-1)==='report_sequence'&&c.value==='2'))`)
	if chromeDo(t, debug, `demoLiveForm===document.querySelector('#service-form')&&document.activeElement===demoLiveName&&demoLiveName.value==='Unsaved demo delta'&&demoLiveName.selectionStart===2&&demoLiveName.selectionEnd===5`) != true {
		t.Fatal("incremental report replaced the active draft")
	}
	chromeDo(t, debug, `demoLiveSockets.at(-1).close();true`)
	waitChromeEvaluation(t, debug, `demoLiveSockets.length>=2&&demoLiveFrames.filter(v=>v.snapshot).length>=2`)
	chromeDo(t, debug, `(()=>{demoLiveName.blur();history.pushState({},'','/devices/`+invite.DeviceID+`');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-runtime-state]')?.textContent==='running'`)
	send("stopped")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-runtime-state]')?.textContent==='stopped'&&demoLiveFrames.at(-1).changes?.some(c=>c.path.at(-1)==='report_sequence'&&c.value==='3')`)
	// A fresh HTTP read must not replace the connection's untrimmed patch base.
	if chromeDo(t, debug, `(async()=>{const s=await(await fetch('/api/control/ui/snapshot')).json();return s.devices.some(v=>v.evidence?.report_sequence==='3')&&demoLiveFrames.filter(v=>v.snapshot).length===2})()`) != true {
		t.Fatal("HTTP/live interleave lost report or forced full frames")
	}
	encoded, _ := json.Marshal(len(second))
	t.Log("browser applied changes to full projection bytes", string(encoded))
}
