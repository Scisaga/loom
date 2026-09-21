//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientcomponent"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

func windowsReportTestView(t *testing.T) control.DeviceView {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-ca"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := clientmodel.CanonicalizeRuntimeConfig([]byte(`{
		"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],
		"outbounds":[{"type":"direct","tag":"route-a"},{"type":"direct","tag":"route-b"},{"type":"selector","tag":"policy:a","outbounds":["route-a"]},{"type":"selector","tag":"policy:b","outbounds":["route-b"]}],
		"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	return control.DeviceView{Schema: 2, DeviceID: "demo-windows", Name: "Demo Windows", Platform: "windows",
		Roles: []string{"access"}, DevicePublicKey: base64.RawURLEncoding.EncodeToString(public), Floor: 1,
		Endpoints: []control.EndpointReference{{EndpointID: "demo-endpoint", Generation: 1, Transport: "tls_tunnel",
			Address: "192.0.2.1:443", ServerName: "control.example", SPKISHA256: strings.Repeat("0", 64), State: "serving"}},
		Routes: []control.RouteCandidate{{ID: "route-a", FinalExit: "direct", Scope: "policy:a"},
			{ID: "route-b", FinalExit: "direct", Scope: "policy:b"}},
		Runtime:           &control.RuntimeProfile{Kind: "sing_box", Config: raw},
		PublicDataPlaneCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func TestWindowsComponentReadbacksOnlyReportCertifiedExpectations(t *testing.T) {
	view := control.DeviceView{ExpectedComponents: []control.ComponentExpectation{
		{Name: "agent", Version: "0.1.0"},
		{Name: "sing-box", Version: "v1.11.4"},
	}}
	components := clientcomponent.RuntimePaths{Manifest: clientcomponent.Manifest{
		SingBox: clientcomponent.Component{Version: "v1.11.4", SHA256: strings.Repeat("1", 64)},
		Wintun:  clientcomponent.Component{Version: "0.14.1", SHA256: strings.Repeat("2", 64)},
	}}
	readbacks := windowsComponentReadbacks(view, components)
	if len(readbacks) != 2 || readbacks[0].Name != "agent" || readbacks[1].Name != "sing-box" ||
		readbacks[1].Version != "1.11.4" || readbacks[1].Digest != "sha256:"+strings.Repeat("1", 64) {
		t.Fatalf("readbacks=%+v", readbacks)
	}
}

func TestWindowsSchema2ReportUsesEveryCurrentScope(t *testing.T) {
	view := windowsReportTestView(t)
	activation := clientadapter.Activation{State: clientadapter.State{NetworkGeneration: "demo-generation",
		Observations: []clientmodel.Observation{}}, Selections: []clientadapter.SelectionStatus{
		{Scope: "policy:b", CandidateID: "route-b"}, {Scope: "policy:a", CandidateID: "route-a"},
	}}
	report, err := windowsDeviceReport(&control.DeviceViewEnvelope{View: view}, activation, nil,
		"2026-09-20T12:00:00Z", time.Date(2026, 9, 20, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.Runtime == nil || !report.Runtime.Exact || len(report.Selections) != 2 ||
		report.Selections[0].Scope != "policy:a" || report.Selections[1].Scope != "policy:b" || report.Selection != "" {
		t.Fatalf("schema-2 report=%+v", report)
	}
	first := windowsRuntimeFactsDigest(activation, nil)
	activation.Selections[0].CandidateID = "route-a"
	if second := windowsRuntimeFactsDigest(activation, nil); second == first {
		t.Fatal("selection change did not change the immediate-report fact digest")
	}
}
