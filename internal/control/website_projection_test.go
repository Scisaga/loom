package control

import (
	"testing"
	"time"
)

func TestWebsiteConcurrentPortsHaveNoDNSWinner(t *testing.T) {
	f := newMaterialFixture(t)
	trust := testWebsiteTrust(t, time.Now())
	grant := f.sign(t, 0, 1, nil, "demo-root", "public_trust.put", "public_trust", trust.ID, trust)
	first := EndpointGeneration{ID: "demo-web-a", Generation: 1, OwnerControlID: f.members[0].ControlID,
		Host: "192.0.2.10", Port: 8443, ServerName: "control.loom", SPKISHA256: endpointByteDigest([]byte("demo-spki")),
		CertificateDigest: endpointByteDigest([]byte("demo-leaf")), WebsiteTrustID: trust.ID, Modes: []string{"web"}, State: "prepared"}
	prepareA := f.sign(t, 0, 2, &grant, "demo-prepare-a", "endpoint.put", "endpoint", first.ID, first, materialTestID(t, grant))
	first.State = "serving"
	serveA := f.sign(t, 0, 3, &prepareA, "demo-serve-a", "endpoint.put", "endpoint", first.ID, first, materialTestID(t, prepareA))
	second := first
	second.ID, second.OwnerControlID, second.Host, second.Port, second.State = "demo-web-b", f.members[1].ControlID, "192.0.2.11", 9443, "prepared"
	prepareB := f.sign(t, 1, 1, nil, "demo-prepare-b", "endpoint.put", "endpoint", second.ID, second, materialTestID(t, grant))
	second.State = "serving"
	serveB := f.sign(t, 1, 2, &prepareB, "demo-serve-b", "endpoint.put", "endpoint", second.ID, second, materialTestID(t, prepareB))
	projection, err := Project(f.genesis, nil, []Material{grant, prepareA, serveA, prepareB, serveB})
	if err != nil || len(projection.InvalidMaterials) != 0 {
		t.Fatal("concurrent facts did not remain valid", err)
	}
	if endpoints, err := WebsiteEndpoints(projection); err == nil || endpoints != nil {
		t.Fatal("concurrent client ports chose an arbitrary DNS winner")
	}
	web := buildWebSnapshot(projection, true, true, true)
	if len(web.WebEndpoints) != 0 || len(web.UIState.Warnings) == 0 {
		t.Fatal("website conflict was hidden from management")
	}
	known := f.sign(t, 1, 2, &prepareB, "demo-known-conflict", "endpoint.put", "endpoint", second.ID, second, materialTestID(t, prepareB), materialTestID(t, serveA))
	projection, err = Project(f.genesis, nil, []Material{grant, prepareA, serveA, prepareB, known})
	if err != nil || len(projection.InvalidMaterials) != 1 {
		t.Fatal("known conflicting client port was accepted", err)
	}
}
