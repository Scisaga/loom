//go:build windows

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"loom/internal/control"
)

func windowsFixture(t *testing.T) (control.BootstrapInvite, func(string, uint64, ...func(*control.DeviceView)) control.DeviceViewEnvelope) {
	t.Helper()
	members := []control.Member{}
	keys := []ed25519.PrivateKey{}
	for _, suffix := range []string{"a", "b"} {
		seed := sha256.Sum256([]byte("demo-device-control-" + suffix))
		key := ed25519.NewKeyFromSeed(seed[:])
		keys = append(keys, key)
		members = append(members, control.Member{ControlID: "demo-control-" + suffix, NodeID: "demo-node-" + suffix, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	}
	keyID, _ := control.KeyID(members[1].PublicKey)
	config := control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: members, SealedKeys: []control.ControlSealedKey{}}
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: config, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{}}}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := control.MaterialID(genesis)
	configID, _ := control.ConfigID(config)
	endpoint := control.EndpointGeneration{ID: "demo-entry", Generation: 1, OwnerControlID: members[1].ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("1", 64), CertificateDigest: "sha256:" + strings.Repeat("2", 64), Modes: []string{"bootstrap", "device"}, State: "serving"}
	invitation := control.Invite{ID: "demo-transaction", GenesisDigest: anchor, IssuerControlID: members[1].ControlID, DeviceID: "demo-windows", Name: "Demo access", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Medium: "qr", Endpoint: endpoint, ExpiresAt: 1893456000000}
	material, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, ControlConfigID: configID, Sequence: 1, PreviousMaterialID: control.EmptyMaterialChainID(), Dependencies: []string{}, RequestID: "demo-issue", TargetKind: "invite", TargetID: invitation.ID, Operation: "invite.issue", Payload: invitation}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	invite := control.BootstrapInvite{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, ControlProof: control.ControlProof{Genesis: genesis, Successors: []control.ControlCertificate{}}, Material: material}
	if err := invite.Validate(); err != nil {
		t.Fatal(err)
	}
	makeEnvelope := func(public string, sequence uint64, changes ...func(*control.DeviceView)) control.DeviceViewEnvelope {
		p, err := control.Project(genesis, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		scope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
		p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}}}
		p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: scope, AllowDirect: true, LocalEgressDevices: []string{}}}
		inviteID, _ := control.MaterialID(material)
		p.DeviceAuthorizations = []control.DeviceAuthorization{{ID: invitation.DeviceID, Name: invitation.Name, Platform: "windows", DevicePublicKey: public, Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, DistributionURLs: []string{}, RuntimeKey: members[0].PublicKey, TransactionID: invitation.ID, InviteMaterialID: inviteID, BindingMaterialID: anchor}}
		p.EndpointGenerations = []control.EndpointGeneration{endpoint}
		view, err := control.ProjectDeviceView(p, invitation.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range changes {
			change(&view)
		}
		view.Routes, view.RuntimeProfile, err = control.ProjectAccessRuntime(view)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("demo-prefix-%d", sequence)))
		result, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, ControlProof: invite.ControlProof, FactFrontier: []control.FactFrontier{{KeyID: keyID, Sequence: control.U64(sequence), TipMaterialID: "sha256:" + hex.EncodeToString(sum[:])}}, View: view}, keys[1])
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	return invite, makeEnvelope
}

func brokerTestInvite(t *testing.T) control.BootstrapInvite {
	invite, _ := windowsFixture(t)
	return invite
}

func TestBrokerAcceptsCompleteBootstrapInviteDepth(t *testing.T) {
	body, err := control.CanonicalEncode(brokerRequest{Operation: "join_profile", Name: "Demo Installed", Invite: func() *control.BootstrapInvite {
		invite := brokerTestInvite(t)
		return &invite
	}()})
	if err != nil {
		t.Fatal(err)
	}
	request, err := decodeBrokerRequest(body)
	if err != nil {
		t.Fatalf("complete BootstrapInvite rejected by broker: %v", err)
	}
	if request.Invite == nil || request.Invite.Material.Payload.(control.Invite).ID != "demo-transaction" {
		t.Fatal("broker dropped the complete BootstrapInvite")
	}
}

func TestBrokerInviteDepthStillRejectsDuplicateAndOverdeepJSON(t *testing.T) {
	invite := brokerTestInvite(t)
	body, err := control.CanonicalEncode(brokerRequest{Operation: "join_profile", Name: "Demo Installed", Invite: &invite})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(body, []byte(`"control_id":"demo-control-a"`), []byte(`"control_id":"demo-control-a","CONTROL_ID":"demo-other"`), 1)
	if bytes.Equal(duplicate, body) {
		t.Fatal("test did not locate the member field")
	}
	if _, err := decodeBrokerRequest(duplicate); err == nil {
		t.Fatal("broker accepted a case-folded duplicate inside the complete invite")
	}

	overdeep := json.NewDecoder(strings.NewReader(strings.Repeat(`{"demo":`, 13) + `1` + strings.Repeat(`}`, 13)))
	if err := rejectJSONDuplicateFields(overdeep, 0, 12); err == nil {
		t.Fatal("broker duplicate scanner accepted content beyond its wire depth")
	}
}
