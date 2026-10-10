package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestWireGuardCountersPreserveOriginalReportsAndSignedPrecision(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-access", ReportSequence: 1, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}}
	original := map[string]any{"schema": 3, "network_id": report.NetworkID, "device_id": report.DeviceID, "report_sequence": report.ReportSequence, "view_digest": digest, "network_generation": report.NetworkGeneration, "reported_at": report.ReportedAt, "selections": report.Selections, "observations": report.Observations, "runtime": report.Runtime, "components": report.Components}
	message, err := signedContractBytes(reportDomain, original)
	if err != nil {
		t.Fatal(err)
	}
	report.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	before, _ := CanonicalEncode(report)
	var decoded DeviceReport
	if report.Verify(public) != nil || decodeStoredReport(before, &decoded) != nil || bytes.Contains(before, []byte("wireguard_counters")) {
		t.Fatal("absent field reinterpreted original report")
	}
	after, _ := CanonicalEncode(decoded)
	if !bytes.Equal(before, after) {
		t.Fatal("original bytes changed")
	}
	p := wireGuardAccessFixture(t)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	tag, peers, err := WireGuardCounterBindings(view)
	if err != nil || tag == "" || len(peers) == 0 {
		t.Fatal("shared endpoint missing", err)
	}
	report.WireGuardCounters = &WireGuardCounters{Interface: tag, Epoch: strings.Repeat("a", 32), ObservedAt: 1, Peers: peers}
	report.WireGuardCounters.Peers[0].TXBytes = 18446744073709551615
	report, err = SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := CanonicalEncode(report)
	if decodeStoredReport(body, &decoded) != nil || !reflect.DeepEqual(decoded, report) || decoded.Verify(public) != nil {
		t.Fatal("counter report lost original precision or signature")
	}
	changed := report
	changed.WireGuardCounters = nil
	if changed.Verify(public) == nil {
		t.Fatal("counter value outside signature")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, []DeviceReport{report})
	old := testObservationBytes(t, root)
	for i := 0; i < 2; i++ {
		store, err := testOpenObservationStore(t, root)
		if err != nil || !reflect.DeepEqual(store.History(), []DeviceReport{report}) {
			t.Fatal("counter original lost on restart", err)
		}
		if !bytes.Equal(old, testObservationBytes(t, store)) {
			t.Fatal("restart rewrote original")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*WireGuardCounters){
		func(v *WireGuardCounters) { v.Epoch = strings.Repeat("A", 32) },
		func(v *WireGuardCounters) { v.Peers = nil },
		func(v *WireGuardCounters) { v.Peers = append(v.Peers, v.Peers[0]) },
		func(v *WireGuardCounters) { v.Peers[0].Links = nil },
		func(v *WireGuardCounters) { v.Peers[0].PublicKey = "demo-not-key" },
		func(v *WireGuardCounters) { v.Interface = "demo-not-endpoint" },
	} {
		var bad DeviceReport
		if decodeStoredReport(body, &bad) != nil {
			t.Fatal("fixture")
		}
		mutate(bad.WireGuardCounters)
		if bad.validateFields() == nil {
			t.Fatal("invalid counter accepted")
		}
	}
	for _, replacement := range []string{`"18446744073709551616"`, `18446744073709551615`, `"01"`} {
		bad := bytes.Replace(body, []byte(`"18446744073709551615"`), []byte(replacement), 1)
		if decodeStoredReport(bad, &decoded) == nil {
			t.Fatal("noncanonical U64 accepted")
		}
	}
	for _, value := range []string{`null`, `{}`} {
		bad := bytes.Replace(before, []byte(`"view_digest"`), []byte(`"wireguard_counters":`+value+`,"view_digest"`), 1)
		if decodeStoredReport(bad, &decoded) == nil {
			t.Fatal("invalid optional counter accepted")
		}
	}
}

func TestWireGuardCounterBindingsKeepSharedPeerAndCurrentLinkScope(t *testing.T) {
	p := wireGuardAccessFixture(t)
	for _, node := range []string{"demo-access", "demo-entry", "demo-exit"} {
		view, err := ProjectDeviceView(p, node)
		if err != nil {
			t.Fatal(node, err)
		}
		tag, peers, err := WireGuardCounterBindings(view)
		if err != nil {
			t.Fatal(node, err)
		}
		if tag == "" {
			continue
		}
		value := WireGuardCounters{Interface: tag, Epoch: strings.Repeat("a", 32), ObservedAt: 1, Peers: peers}
		if value.Validate() != nil || verifyWireGuardCounters(&value, view) != nil {
			t.Fatal("actual peer binding rejected", node)
		}
		for i := range value.Peers {
			if len(value.Peers[i].Links) > 0 {
				value.Peers[i].Links[0].SpecDigest = "sha256:" + strings.Repeat("0", 64)
				if verifyWireGuardCounters(&value, view) == nil {
					t.Fatal("old Link specification counted as current")
				}
				break
			}
		}
	}
}

func TestReciprocalLinksKeepOnePhysicalPeerCounter(t *testing.T) {
	p := wireGuardAccessFixture(t)
	reverse := p.NetworkIntent.Links[0]
	reverse.ID = "demo-reverse"
	reverse.FromNodeID, reverse.ToNodeID = reverse.ToNodeID, reverse.FromNodeID
	reverse.FromResourceID, reverse.ResourceID = reverse.ResourceID, reverse.FromResourceID
	for _, resource := range p.NetworkIntent.Resources {
		if resource.ID == reverse.ResourceID {
			address, err := WireGuardAccessAddress(resource, "")
			if err != nil {
				t.Fatal(err)
			}
			reverse.ProbeTarget.ResourceID = resource.ID
			reverse.ProbeTarget.Host = address.String()
		}
	}
	p.NetworkIntent.Links = append(p.NetworkIntent.Links, reverse)
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	tag, peers, err := WireGuardCounterBindings(view)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, peer := range peers {
		if len(peer.Links) == 2 {
			count++
		}
	}
	if count != 1 {
		t.Fatal("reciprocal links duplicated their physical peer", tag, peers)
	}
}
