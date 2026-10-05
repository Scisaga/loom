package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Archive/signature verification is the existing independent ReleaseSource
// boundary; this fixture exercises control references without a second signer.
type retainedReleaseSource struct {
	original, current ReleaseSet
	unavailable       bool
}

func (s *retainedReleaseSource) Read() (ReleaseSet, error) { return s.current, nil }
func (s *retainedReleaseSource) ReadCatalog(id string) (ReleaseSet, error) {
	if !s.unavailable && id == s.original.ID {
		return s.original, nil
	}
	return ReleaseSet{}, errors.New("demo unavailable release")
}
func (*retainedReleaseSource) Open(string, ReleaseArtifact) (io.ReadCloser, error) {
	return nil, errors.New("demo download not exercised")
}

func expectedReleaseFixture() (*retainedReleaseSource, ExpectedComponent) {
	catalog := demoReleaseCatalog()
	set := ReleaseSet{ID: ReleaseDigest([]byte("demo exact catalog")), Catalog: catalog, Packages: []ReleasePackage{{Entry: catalog.Entries[0],
		Components: []ComponentReadback{{ComponentID: "agent", Platform: "linux-amd64", Version: "demo-version", ArtifactDigest: ReleaseDigest([]byte("demo actual program"))}}}}}
	value := ExpectedComponent{NodeID: "demo-access", ComponentID: "agent", Platform: "linux-amd64", CatalogDigest: set.ID, ManifestDigest: catalog.Entries[0].ManifestDigest}
	value.ID, _ = ExpectedComponentID(value.NodeID, value.ComponentID, value.Platform)
	return &retainedReleaseSource{original: set, current: set}, value
}

func expectedOperation(projection Projection, value ExpectedComponent, request string) Operation {
	node, _ := projection.CurrentTarget("device", value.NodeID)
	previous, _ := projection.CurrentTarget("expected_component", value.ID)
	return Operation{Schema: 3, RequestID: request, Operation: "expected_component.put", TargetKind: "expected_component", TargetID: value.ID,
		Dependencies: sortedUniqueDependencies(append(append([]string{}, node.MaterialIDs...), previous.MaterialIDs...)), Payload: value}
}

func TestExpectedComponentCanonicalReference(t *testing.T) {
	_, value := expectedReleaseFixture()
	body, err := CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ExpectedComponent
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}); err != nil || decoded != value {
		t.Fatal("expected reference did not round trip", err)
	}
	for _, bad := range [][]byte{
		append([]byte(" "), body...),
		bytes.Replace(body, []byte(`"component_id":"agent"`), []byte(`"component_id":"sing_box"`), 1),
		bytes.Replace(body, []byte(value.ID), []byte("demo-ambiguous-id"), 1),
		append(append([]byte{}, body[:len(body)-1]...), []byte(`,"version":"demo-invented"}`)...),
	} {
		if DecodeCanonical(bad, &decoded, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}) == nil {
			t.Fatal("noncanonical or independently editable expected coordinate accepted")
		}
	}
	initial := EmptyNetworkIntent()
	empty, _ := CanonicalEncode(initial)
	if !bytes.Contains(empty, []byte(`"expected_components":[]`)) {
		t.Fatal("existing empty authority bytes changed")
	}
	initial.ExpectedComponents = []ExpectedComponent{value}
	if initial.Validate() == nil {
		t.Fatal("genesis invented an ordinary device authorization")
	}
}

func TestExpectedComponentFormalWriteRestartAndIndependentResolution(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("fixture claim failed")
	}
	source, value := expectedReleaseFixture()
	server.Releases = source
	before := server.Runtime.Authority.Snapshot()
	op := expectedOperation(before, value, "demo-expect-program")
	for _, field := range []string{"catalog", "manifest", "platform", "node"} {
		bad := value
		switch field {
		case "catalog":
			bad.CatalogDigest = ReleaseDigest([]byte("demo other catalog"))
		case "manifest":
			bad.ManifestDigest = ReleaseDigest([]byte("demo other manifest"))
		case "platform":
			bad.Platform = "linux-arm64"
		case "node":
			bad.NodeID = "demo-missing-node"
		}
		bad.ID, _ = ExpectedComponentID(bad.NodeID, bad.ComponentID, bad.Platform)
		if _, _, err := server.HandleOperation(context.Background(), expectedOperation(before, bad, "demo-bad-"+field)); err == nil {
			t.Fatal("invalid expected reference was signed", field)
		}
	}
	if !reflect.DeepEqual(before.Frontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("failed reference validation advanced the fact chain")
	}
	accepted, _, err := server.HandleOperation(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := server.Runtime.Authority.Material(accepted.MaterialID)
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.View.ExpectedComponents, source.original.Packages[0].Components) {
		t.Fatal("signed view did not resolve exact program coordinates", err)
	}
	if view.View.ExpectedComponents[0].ArtifactDigest == source.original.Packages[0].Entry.Artifact.Digest {
		t.Fatal("package digest substituted for actual program")
	}
	stale := op
	stale.RequestID = "demo-stale-expectation"
	if _, _, err := server.HandleOperation(context.Background(), stale); err == nil {
		t.Fatal("stale reviewed expectation accepted")
	}
	// Download selection changes independently from the already signed reference.
	source.current.ID = ReleaseDigest([]byte("demo newly selected catalog"))
	after, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || after.ViewDigest != view.ViewDigest {
		t.Fatal("download pointer changed a device expectation", err)
	}
	reports, err := OpenObservationStore(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: server.Config.NetworkID, DeviceID: invite.DeviceID, ReportSequence: 1, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-network", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Components: view.View.ExpectedComponents, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}}, key)
	if err != nil || reports.Put(report, claim.DevicePublicKey) != nil || len(reports.Verified(accepted.Projection, server.expectedReleaseSets(accepted.Projection)...)) != 1 {
		t.Fatal("exact current-view report was rejected", err)
	}
	source.unavailable = true
	if _, err := server.deviceEnvelope(invite.DeviceID); err == nil || len(reports.Verified(accepted.Projection, server.expectedReleaseSets(accepted.Projection)...)) != 0 {
		t.Fatal("missing independent release became an empty or accepted expectation")
	}
	if retry, _, err := server.HandleOperation(context.Background(), op); err != nil || retry.MaterialID != accepted.MaterialID {
		t.Fatal("same-request retry lost its original signed reference", err)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	restarted, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	server.Runtime = restarted
	stored, _ := restarted.Authority.Material(accepted.MaterialID)
	if !bytes.Equal(raw, stored) || len(restarted.Authority.Snapshot().NetworkIntent.ExpectedComponents) != 1 {
		t.Fatal("missing release erased or changed persistent signed facts")
	}
	source.unavailable = false
	if restored, err := server.deviceEnvelope(invite.DeviceID); err != nil || restored.ViewDigest != view.ViewDigest {
		t.Fatal("restoring original release did not recover the original view", err)
	}
	device, _ := restarted.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	_, _, err = server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-revoke-expected-device", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: device.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.deviceEnvelope(invite.DeviceID); err == nil {
		t.Fatal("expectation restored a revoked device authorization")
	}
	cleared, _, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-clear-expectation", Operation: "expected_component.delete", TargetKind: "expected_component", TargetID: value.ID, Dependencies: []string{accepted.MaterialID}, Payload: DeleteTarget{ID: value.ID}})
	if err != nil || len(cleared.Projection.NetworkIntent.ExpectedComponents) != 0 {
		t.Fatal("revoked device expectation could not be cleared", err)
	}
}

func TestExpectedComponentConflictAndUnavailableUIFailClosed(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	source, value := expectedReleaseFixture()
	projection.NetworkIntent.ExpectedComponents = []ExpectedComponent{value}
	for _, conflict := range []bool{false, true} {
		p := projection
		p.Targets = append([]TargetState{}, projection.Targets...)
		if conflict {
			p.NetworkIntent.ExpectedComponents = []ExpectedComponent{}
			p.Targets = append(p.Targets, TargetState{TargetKind: "expected_component", TargetID: value.ID, MaterialIDs: []string{}, Conflicted: true})
		}
		if _, err := ProjectDeviceView(p, value.NodeID); err == nil {
			t.Fatal("unavailable expectation became an empty view")
		}
		devices := projectWebDevices(p)
		for _, device := range devices {
			if device.ID == value.NodeID && (device.ComponentError == "" || len(device.ExpectedComponents) != 0) {
				t.Fatal("unverified or conflicted expectation manufactured UI coordinates")
			}
		}
		if conflict {
			if _, err := ProjectDeviceView(p, value.NodeID, source.original); err == nil || !strings.Contains(err.Error(), "conflicted") {
				t.Fatal("valid release chose a winner for conflicting intent")
			}
		}
	}
}
