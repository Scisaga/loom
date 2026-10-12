package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWebChromeNodeRuntimeUsesSignedStateAcrossPages(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for runtime presentation acceptance")
	}
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	server.Now = func() time.Time { return time.Now().UTC() }
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("normal join failed")
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices")
	waitChromeEvaluation(t, debug, `document.querySelector('.node-inventory')`)
	for index, state := range []string{"running", "error", "stopped", "missing", "expired", "future"} {
		want, at := state, server.now()
		if state == "expired" {
			at, want = at.Add(-webReportLifetime-time.Second), "unknown"
		} else if state == "future" {
			at, want = at.Add(10*time.Second), "unknown"
		} else if state == "missing" {
			want = "unknown"
		}
		reported := state
		if state == "expired" || state == "future" {
			reported = "running"
		} else if state == "missing" {
			reported = "unknown"
		}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: server.Config.NetworkID, DeviceID: invite.DeviceID,
			ReportSequence: U64(index + 1), ViewDigest: view.ViewDigest, NetworkGeneration: "demo-network", ReportedAt: at.UnixMilli(),
			Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: reported, AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
		if err != nil || server.Runtime.Reports.Put(report, claim.DevicePublicKey) != nil {
			t.Fatal("signed report persistence failed", err)
		}
		for _, page := range []string{"/", "/devices", "/devices/" + invite.DeviceID, "/topology"} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := debug.call(ctx, "Page.navigate", map[string]any{"url": host.URL + page}, nil)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			waitChromeEvaluation(t, debug, `location.pathname==='`+page+`'&&document.querySelector('#connection').title.includes('local writes available')&&document.querySelector('#app h1')`)
			result := chromeDo(t, debug, `(async()=>{const {nodeRuntimeState}=await import('/assets/model.js'),snapshot=await(await fetch('/api/control/ui/snapshot')).json(),device=snapshot.devices.find(d=>d.id==='`+invite.DeviceID+`');return nodeRuntimeState(device,Date.now())==='`+want+`'&&!document.querySelector('.overview-health').textContent.includes('0 available')&&!document.body.innerText.includes('current available evidence')})()`)
			if result != true {
				t.Fatal("page consumed global availability instead of the signed runtime", state, page)
			}
			if page == "/devices" && chromeDo(t, debug, `document.querySelector('[data-runtime-history="`+invite.DeviceID+`"]')?.closest('tr').textContent.includes('Runtime: `+want+`')`) != true {
				t.Fatal("inventory runtime row disagrees with the summary", state)
			}
			if page == "/devices/"+invite.DeviceID && chromeDo(t, debug, `document.querySelector('.overview-health').textContent.includes('Runtime: `+want+`')`) != true {
				t.Fatal("device detail uses a different status", state)
			}
			if strings.HasSuffix(page, "topology") || page == "/" {
				if chromeDo(t, debug, `document.querySelector('.topology [data-node="`+invite.DeviceID+`"] title')?.textContent.includes('Runtime: `+want+`')`) != true {
					t.Fatal("topology circle uses a different runtime", state, page)
				}
			}
		}
	}
}

func TestWebChromeRuntimeAndDifferentServiceResultsRemainSeparate(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for scoped status acceptance")
	}
	fixture, _, projection := deviceContractFixture(t)
	projection.NetworkIntent.Services = append(projection.NetworkIntent.Services, materialTestService("demo-service-b"))
	projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, materialTestPolicy("demo-policy-b", "demo-service-b"))
	projection.DeviceAuthorizations[0].PolicyIDs = []string{"demo-policy", "demo-policy-b"}
	projection.NetworkIntent.BusinessProbeTargets = []BusinessProbeTarget{{ID: "demo-probe-a", URL: "https://demo-service.example/probe"}, {ID: "demo-probe-b", URL: "https://demo-service-b.example/probe"}}
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil || len(view.Routes) != 2 || len(view.BusinessProbeTargets) != 2 {
		t.Fatal("fixture needs two independently authorized Services", err)
	}
	digest, _ := DeviceViewDigest(view)
	now := time.Now().UTC().Truncate(time.Millisecond)
	report := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1, ViewDigest: digest, NetworkGeneration: "demo-network", ReportedAt: now.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
	for _, route := range view.Routes {
		result := "available"
		if route.ServiceID == "demo-service-b" {
			result = "unavailable"
		}
		report.Selections = append(report.Selections, ReportSelection{ServiceID: route.ServiceID, CandidateID: route.ID})
		report.Observations = append(report.Observations, Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: "https://" + route.ServiceID + ".example/probe", Action: "https_request", SpecDigest: route.SpecDigest, NetworkGeneration: report.NetworkGeneration, Result: result, ObservedAt: now.UnixMilli(), ValidUntil: now.Add(30 * time.Second).UnixMilli()})
	}
	sort.Slice(report.Selections, func(i, j int) bool { return report.Selections[i].ServiceID < report.Selections[j].ServiceID })
	sort.Slice(report.Observations, func(i, j int) bool {
		return observationOrder(report.Observations[i]) < observationOrder(report.Observations[j])
	})
	report, err = SignDeviceReport(report, fixture.keys[0])
	if err != nil || verifyCurrentReport(report, projection) != nil {
		t.Fatal("two scoped outcomes must obey actual report authentication", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil || store.Put(report, projection.DeviceAuthorizations[0].DevicePublicKey) != nil {
		t.Fatal("signed scoped report persistence failed", err)
	}
	defer store.Close()
	server := &Server{Runtime: &Runtime{Authority: &Authority{root: root, projection: projection}, Reports: store}, Now: func() time.Time { return now }}
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-node-service="demo-service-b"]')`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-node-row="demo-access"]');return row.textContent.includes('Runtime: running')&&row.querySelector('[data-node-service="demo-service"] .badge').textContent==='available'&&row.querySelector('[data-node-service="demo-service-b"] .badge').textContent==='unavailable'&&document.querySelector('.overview-health').textContent.includes('1 running')})()`) != true {
		t.Fatal("one Service failure changed the runtime or erased the other Service's success")
	}
	if chromeDo(t, debug, `(async()=>{const {appliedReadback}=await import('/assets/model.js'),snapshot=await(await fetch('/api/control/ui/snapshot')).json(),device=snapshot.devices.find(d=>d.id==='demo-access');return device.availability==='unknown'&&device.presence==='unknown'&&appliedReadback(device,Date.now())==='unknown'})()`) != true {
		t.Fatal("runtime or business results fabricated global health or an unconfigured component match")
	}
}
