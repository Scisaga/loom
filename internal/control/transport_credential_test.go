package control

import (
	"bytes"
	"strings"
	"testing"
)

func demoTransportCredentialBinding() TransportCredentialBinding {
	return TransportCredentialBinding{NetworkID: "demo-network",
		ResourceID:         "demo-resource",
		ResourceAuthDigest: "sha256:" + strings.Repeat("ab", 32), ReceiverNodeID: "demo-receiver", Purpose: "transport-auth", SenderID: "demo-device"}
}

func TestTransportCredentialCanonicalVectorAndIsolation(t *testing.T) {
	// Independent RFC 5869 extract/expand vector, using the public demo bytes
	// 00..1f and an explicitly reviewed canonical info object.
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	savedRoot := bytes.Clone(root)
	binding := demoTransportCredentialBinding()
	info, err := CanonicalEncode(binding)
	const expectedInfo = `{"network_id":"demo-network","purpose":"transport-auth","receiver_node_id":"demo-receiver","resource_auth_digest":"sha256:abababababababababababababababababababababababababababababababab","resource_id":"demo-resource","sender_id":"demo-device"}`
	if err != nil || string(info) != expectedInfo {
		t.Fatalf("credential context bytes differ from the contract: %v", err)
	}
	value, err := DeriveTransportCredential(root, binding)
	if err != nil || value != "bVajZ6x3E1fs3vn1BibCsedzmWFvrri_ZIpRc7m0JLQ" {
		t.Fatalf("credential does not match independent public demo vector: %v", err)
	}
	if !bytes.Equal(root, savedRoot) {
		t.Fatal("derivation mutated its caller's root key")
	}
	for name, change := range map[string]func(*TransportCredentialBinding){
		"network":        func(b *TransportCredentialBinding) { b.NetworkID = "demo-other-network" },
		"device":         func(b *TransportCredentialBinding) { b.SenderID = "demo-other-device" },
		"resource":       func(b *TransportCredentialBinding) { b.ResourceID = "demo-other-resource" },
		"authentication": func(b *TransportCredentialBinding) { b.ResourceAuthDigest = "sha256:" + strings.Repeat("cd", 32) },
		"recipient":      func(b *TransportCredentialBinding) { b.ReceiverNodeID = "demo-other-receiver" },
	} {
		t.Run(name, func(t *testing.T) {
			other := binding
			change(&other)
			got, err := DeriveTransportCredential(root, other)
			if err != nil || got == value {
				t.Fatalf("credential is not isolated by %s: %v", name, err)
			}
		})
	}
	root[0] ^= 1
	rotated, err := DeriveTransportCredential(root, binding)
	if err != nil || rotated == value {
		t.Fatalf("root rotation did not change the credential: %v", err)
	}
}

func TestTransportCredentialRejectsMissingOrInventedBinding(t *testing.T) {
	for _, size := range []int{0, 31, 33} {
		if got, err := DeriveTransportCredential(make([]byte, size), demoTransportCredentialBinding()); err == nil || got != "" {
			t.Fatal("wrong-length root produced a credential")
		}
	}
	for name, change := range map[string]func(*TransportCredentialBinding){
		"self sender":     func(b *TransportCredentialBinding) { b.SenderID = b.ReceiverNodeID },
		"no recipient":    func(b *TransportCredentialBinding) { b.ReceiverNodeID = "" },
		"direct receiver": func(b *TransportCredentialBinding) { b.ReceiverNodeID = "direct" },
		"wrong digest":    func(b *TransportCredentialBinding) { b.ResourceAuthDigest = strings.ToUpper(b.ResourceAuthDigest) },
		"other purpose":   func(b *TransportCredentialBinding) { b.Purpose = "local-api" },
	} {
		t.Run(name, func(t *testing.T) {
			binding := demoTransportCredentialBinding()
			change(&binding)
			if got, err := DeriveTransportCredential(make([]byte, 32), binding); err == nil || got != "" {
				t.Fatal("invalid binding produced a credential")
			}
		})
	}
}
