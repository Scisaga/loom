//go:build windows

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/control"
)

func brokerTestInvite(t *testing.T) control.BootstrapInvite {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	member := control.Member{ID: "demo-member", Node: "demo-node",
		PublicKey: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))}
	config := control.ControlConfig{Mode: "stable", Members: []control.Member{member}, Quorum: 1}
	digest := "sha256:" + strings.Repeat("0", 64)
	capability, err := control.SignBootstrapCapability(control.BootstrapCapability{
		Schema: 1, TransactionID: "demo-transaction", IssuedHead: digest, ConfigMaterial: digest,
		ControlConfig: config, ExpiresAt: "2030-01-01T00:00:00Z", Actions: []string{"claim", "resume"},
		Endpoints: []control.EndpointReference{{EndpointID: "demo-endpoint", Generation: 1, Transport: "tls_tunnel",
			Address: "127.0.0.1:443", ServerName: "127.0.0.1", SPKISHA256: strings.Repeat("0", 64), State: "serving"}},
		ConstraintDigest: digest, IssuerMemberID: member.ID,
	}, control.NodeConfig{MemberID: member.ID, IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(privateKey)})
	if err != nil {
		t.Fatal(err)
	}
	return control.BootstrapInvite{Schema: 1, Capability: capability}
}

func TestBrokerAcceptsCompleteBootstrapInviteDepth(t *testing.T) {
	body, err := json.Marshal(brokerRequest{Operation: "join_profile", Name: "Demo Installed", Invite: func() *control.BootstrapInvite {
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
	if request.Invite == nil || request.Invite.Capability.TransactionID != "demo-transaction" {
		t.Fatal("broker dropped the complete BootstrapInvite")
	}
}

func TestBrokerInviteDepthStillRejectsDuplicateAndOverdeepJSON(t *testing.T) {
	invite := brokerTestInvite(t)
	body, err := json.Marshal(brokerRequest{Operation: "join_profile", Name: "Demo Installed", Invite: &invite})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(body, []byte(`"id":"demo-member"`), []byte(`"id":"demo-member","ID":"demo-other"`), 1)
	if bytes.Equal(duplicate, body) {
		t.Fatal("test did not locate the member field")
	}
	if _, err := decodeBrokerRequest(duplicate); err == nil {
		t.Fatal("broker accepted a case-folded duplicate inside the complete invite")
	}

	overdeep := json.NewDecoder(strings.NewReader(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}}`))
	if err := rejectJSONDuplicateFields(overdeep, 0, 6); err == nil {
		t.Fatal("broker duplicate scanner accepted content beyond its wire depth")
	}
}
