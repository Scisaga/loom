package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebChromeHY2TransferHasOwnCurrentScopeAndUnknownExpiry(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for real browser acceptance")
	}
	p := hy2ProjectionFixture(t)
	key := testKey(t)
	p.DeviceAuthorizations[0].DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	view, err := ProjectDeviceView(p, p.DeviceAuthorizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	probes, err := FirstHopProbes(view)
	if err != nil || len(probes) != 1 {
		t.Fatal("fixture needs one actual first-hop scope", err)
	}
	digest, _ := DeviceViewDigest(view)
	now := time.Now().UTC().Truncate(time.Millisecond)
	sample := Observation{Level: "resource", ResourceID: probes[0].Resource.ID, Target: probes[0].Target(), Action: probes[0].Action(), SpecDigest: probes[0].SpecDigest,
		NetworkGeneration: "demo-generation", Result: "available", ObservedAt: now.UnixMilli(), ValidUntil: now.Add(10 * time.Minute).UnixMilli(),
		DurationMS: new(int64(30)), HY2Transfer: &HY2Transfer{DurationNS: 20_000_000, RXBytes: 2000, TXBytes: 1000}}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, ReportSequence: 1, ReportedAt: now.UnixMilli(), NetworkGeneration: sample.NetworkGeneration,
		Selections: []ReportSelection{}, Observations: []Observation{sample}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}, key)
	if err != nil || verifyCurrentReport(report, p) != nil {
		t.Fatal("fixture must obey current authentication and report rules", err)
	}
	root := t.TempDir()
	os.Chmod(root, 0o700)
	testSetObservationReports(t, root, []DeviceReport{report})
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now.UnixMilli())
	a := &Authority{root: root, projection: p}
	server := &Server{Runtime: &Runtime{Authority: a, Reports: store}, Now: func() time.Time { return time.UnixMilli(clock.Load()) }}
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/topology")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-hy2-resource="demo-hy2"]')?.textContent.includes('Hy2 probe TX: 0.400 Mbps · RX: 0.800 Mbps')`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-hy2-resource="demo-hy2"]');return row.textContent.includes('TX 1000 B · RX 2000 B · 20.000 ms')&&row.textContent.includes('not capacity')&&row.textContent.includes('demo-generation')&&row.textContent.includes('Service outcomes remain separate')&&document.querySelectorAll('[data-topology-link]').length===0})()`) != true {
		t.Fatal("Hy2 borrowed a WG Link, omitted raw inputs or claimed capacity")
	}
	chromeDo(t, debug, `document.querySelector('[data-hy2-resource="demo-hy2"] a').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-measurements')?.textContent.includes('Hy2 probe TX: 0.400 Mbps · RX: 0.800 Mbps')`)
	clock.Store(now.Add(4 * time.Minute).UnixMilli())
	waitChromeEvaluation(t, debug, `document.querySelector('#device-measurements')?.textContent.includes('Hy2 authentication probe rate: Unknown')`)
	if chromeDo(t, debug, `document.querySelector('#device-measurements').textContent.includes('Reported TX 1000 B · RX 2000 B')`) != true {
		t.Fatal("expiry erased the original diagnostic measurement")
	}
	// An older signed sample with no optional field remains unknown on both pages.
	report.ReportSequence++
	report.ReportedAt = clock.Load()
	report.Observations[0].ObservedAt = clock.Load()
	report.Observations[0].ValidUntil = clock.Load() + time.Minute.Milliseconds()
	report.Observations[0].HY2Transfer = nil
	report, _ = SignDeviceReport(report, key)
	if err := store.Put(report, p.DeviceAuthorizations[0].DevicePublicKey); err != nil {
		t.Fatal(err)
	}
	waitChromeEvaluation(t, debug, `(()=>{const row=document.querySelector('#device-measurements');return row.textContent.includes('Hy2 authentication probe rate: Unknown')&&!row.textContent.includes('Reported TX')})()`)
}
