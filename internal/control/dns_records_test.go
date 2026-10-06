package control

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"testing"
)

func TestOverlayDNSCanonicalAndConcurrentNamespace(t *testing.T) {
	record := DNSRecord{ID: "demo-record", Name: "demo-service.loom", Addresses: []string{"192.0.2.10", "2001:db8::10"}}
	encoded, err := CanonicalEncode(record)
	var decoded DNSRecord
	if err != nil || DecodeCanonical(encoded, &decoded, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}) != nil || !reflect.DeepEqual(record, decoded) {
		t.Fatal("record round trip", err)
	}
	for _, name := range []string{"control.loom", "demo.example", "Demo.loom", "demo.loom.", "*.loom", "demo..loom", "loom"} {
		bad := record
		bad.Name = name
		if bad.Validate() == nil {
			t.Fatal("accepted noncanonical or reserved name", name)
		}
	}
	for _, addresses := range [][]string{nil, {}, {"0.0.0.0"}, {"224.0.0.1"}, {"::ffff:192.0.2.1"}, {"fe80::1%demo"}, {"192.0.2.1", "192.0.2.1"}, {"2001:db8::1", "192.0.2.1"}} {
		bad := record
		bad.Addresses = addresses
		if bad.Validate() == nil {
			t.Fatal("accepted invalid address set")
		}
	}
	f := newMaterialFixture(t)
	a := f.sign(t, 0, 1, nil, "demo-left", "dns_record.put", "dns_record", record.ID, record)
	other := record
	other.ID = "demo-other"
	b := f.sign(t, 1, 1, nil, "demo-right", "dns_record.put", "dns_record", other.ID, other)
	if err := ValidateAdmission(b, f.genesis, nil, []Material{a}); err != nil {
		t.Fatal("concurrent fact was rejected", err)
	}
	for _, facts := range [][]Material{{a, b}, {b, a}} {
		p, err := Project(f.genesis, nil, facts)
		if err != nil || len(p.NetworkIntent.DNSRecords) != 2 || len(projectDNSRecords(p.NetworkIntent.DNSRecords)) != 0 {
			t.Fatal("namespace collision chose a winner", err)
		}
	}
	// An already observed collision is an invalid normal write, not concurrency.
	known := f.sign(t, 0, 2, &a, "demo-known", "dns_record.put", "dns_record", other.ID, other)
	if ValidateAdmission(known, f.genesis, nil, []Material{a}) == nil {
		t.Fatal("accepted an already assigned name")
	}
	deletion := f.sign(t, 1, 2, &b, "demo-delete", "dns_record.delete", "dns_record", other.ID, DeleteTarget{ID: other.ID}, materialTestID(t, b))
	p, err := Project(f.genesis, nil, []Material{deletion, b, a})
	if err != nil || !reflect.DeepEqual(projectDNSRecords(p.NetworkIntent.DNSRecords), []DNSRecord{record}) {
		t.Fatal("delete did not resolve namespace", err)
	}
	raw, _, err := EncodeMaterial(a)
	round, decodeErr := DecodeMaterial(raw)
	again, _, againErr := EncodeMaterial(round)
	if err != nil || decodeErr != nil || againErr != nil || !bytes.Equal(raw, again) {
		t.Fatal("signed DNS bytes changed", err, decodeErr, againErr)
	}
}

func TestOverlayDNSFormalWriteRestartViewAndDeletion(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("claim failed")
	}
	original, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(original.View)
	if bytes.Contains(before, []byte(`"dns_records"`)) {
		t.Fatal("empty overlay changed existing View bytes")
	}
	record := DNSRecord{ID: "demo-dns", Name: "demo-private.loom", Addresses: []string{"192.0.2.20"}}
	op := Operation{Schema: 3, RequestID: "demo-create-dns", Operation: "dns_record.put", TargetKind: "dns_record", TargetID: record.ID, Dependencies: []string{}, Payload: record}
	result := submitAuthority(t, server.Runtime, op)
	if submitAuthority(t, server.Runtime, op).MaterialID != result.MaterialID {
		t.Fatal("retry created a fact")
	}
	raw, err := server.Runtime.Authority.Material(result.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.View.DNSRecords, []DNSRecord{record}) {
		t.Fatal("DNS did not reach signed device projection after restart", err)
	}
	if !reflect.DeepEqual(view.View.Routes, original.View.Routes) {
		t.Fatal("unrelated record changed Service candidate")
	}
	if got, _ := server.Runtime.Authority.Material(result.MaterialID); !bytes.Equal(got, raw) {
		t.Fatal("restart changed signed record")
	}
	if got := buildWebSnapshot(server.Runtime.Authority.Snapshot(), true, false, true).DNSRecords; !reflect.DeepEqual(got, []DNSRecord{record}) {
		t.Fatal("management readback lost DNS")
	}
	op.RequestID = "demo-stale-dns"
	record.Addresses = []string{"192.0.2.21"}
	op.Payload = record
	body, _ := EncodeOperation(op)
	if _, err := server.Runtime.Submit(context.Background(), body); err == nil {
		t.Fatal("stale update accepted")
	}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-delete-dns", Operation: "dns_record.delete", TargetKind: "dns_record", TargetID: record.ID, Dependencies: []string{result.MaterialID}, Payload: DeleteTarget{ID: record.ID}})
	view, err = server.deviceEnvelope(invite.DeviceID)
	if err != nil || view.View.DNSRecords != nil {
		t.Fatal("deleted record still projected", err)
	}
	oldView, _ := CanonicalEncode(original.View)
	restored, _ := CanonicalEncode(view.View)
	if !bytes.Equal(oldView, restored) {
		t.Fatal("empty DNS altered preexisting View contract")
	}
	// Null/empty/unknown fields cannot be a second encoding for absence.
	for _, field := range []string{`"dns_records":[],`, `"dns_records":null,`} {
		var invalid DeviceView
		bad := append([]byte("{"+field), oldView[1:]...)
		if DecodeCanonical(bad, &invalid, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 128, MaxItems: 10000}) == nil {
			t.Fatal("ambiguous absent DNS accepted")
		}
	}
}

func TestOverlayDNSOnlyInvalidatesRelevantBusiness(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Services[0].Matchers = []ServiceMatcher{{Kind: "dns_exact", Value: "demo-business.loom"}}
	before, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkIntent.DNSRecords = []DNSRecord{{ID: "demo-dns", Name: "demo-business.loom", Addresses: []string{"192.0.2.10"}}}
	after, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if before.Routes[0].ID != after.Routes[0].ID || before.Routes[0].SpecDigest == after.Routes[0].SpecDigest {
		t.Fatal("record did not invalidate exactly the candidate specification")
	}
	receiver, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || !reflect.DeepEqual(receiver.DNSRecords, after.DNSRecords) {
		t.Fatal("Hy2 receiver lost overlay", err)
	}
	p.NetworkIntent.DNSRecords = append(p.NetworkIntent.DNSRecords, DNSRecord{ID: "demo-other", Name: "demo-unrelated.loom", Addresses: []string{"192.0.2.30"}})
	unrelated, err := ProjectDeviceView(p, "demo-access")
	if err != nil || !reflect.DeepEqual(after.Routes, unrelated.Routes) {
		t.Fatal("unrelated DNS invalidated routes", err)
	}
}
