package control

import (
	"bytes"
	"strings"
	"testing"
)

func demoServiceCredentialBinding() ServiceCredentialBinding {
	return ServiceCredentialBinding{NetworkID: "demo-network", DeviceID: "demo-device",
		ServiceID: "demo-service", PolicyID: "demo-policy", ResourceID: "demo-resource",
		ResourceAuthDigest: "sha256:" + strings.Repeat("ab", 32), ReceiverNodeID: "demo-receiver", Purpose: "service-auth"}
}

func TestServiceCredentialCanonicalVectorAndIsolation(t *testing.T) {
	// Independent RFC 5869 extract/expand vector, using the public demo bytes
	// 00..1f and an explicitly reviewed canonical info object.
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	savedRoot := bytes.Clone(root)
	binding := demoServiceCredentialBinding()
	info, err := CanonicalEncode(binding)
	const expectedInfo = `{"device_id":"demo-device","network_id":"demo-network","policy_id":"demo-policy","purpose":"service-auth","receiver_node_id":"demo-receiver","resource_auth_digest":"sha256:abababababababababababababababababababababababababababababababab","resource_id":"demo-resource","service_id":"demo-service"}`
	if err != nil || string(info) != expectedInfo {
		t.Fatalf("credential context bytes differ from the contract: %v", err)
	}
	value, err := DeriveServiceCredential(root, binding)
	if err != nil || value != "-2GNLGfc6NOn2Y1bNFtB18lVz-mALsus_OAHKYJZaAI" {
		t.Fatalf("credential does not match independent public demo vector: %v", err)
	}
	if !bytes.Equal(root, savedRoot) {
		t.Fatal("derivation mutated its caller's root key")
	}
	for name, change := range map[string]func(*ServiceCredentialBinding){
		"network":        func(b *ServiceCredentialBinding) { b.NetworkID = "demo-other-network" },
		"device":         func(b *ServiceCredentialBinding) { b.DeviceID = "demo-other-device" },
		"service":        func(b *ServiceCredentialBinding) { b.ServiceID = "demo-other-service" },
		"policy":         func(b *ServiceCredentialBinding) { b.PolicyID = "demo-other-policy" },
		"resource":       func(b *ServiceCredentialBinding) { b.ResourceID = "demo-other-resource" },
		"authentication": func(b *ServiceCredentialBinding) { b.ResourceAuthDigest = "sha256:" + strings.Repeat("cd", 32) },
		"recipient":      func(b *ServiceCredentialBinding) { b.ReceiverNodeID = "demo-other-receiver" },
	} {
		t.Run(name, func(t *testing.T) {
			other := binding
			change(&other)
			got, err := DeriveServiceCredential(root, other)
			if err != nil || got == value {
				t.Fatalf("credential is not isolated by %s: %v", name, err)
			}
		})
	}
	root[0] ^= 1
	rotated, err := DeriveServiceCredential(root, binding)
	if err != nil || rotated == value {
		t.Fatalf("root rotation did not change the credential: %v", err)
	}
}

func TestServiceCredentialRejectsMissingOrInventedBinding(t *testing.T) {
	for _, size := range []int{0, 31, 33} {
		if got, err := DeriveServiceCredential(make([]byte, size), demoServiceCredentialBinding()); err == nil || got != "" {
			t.Fatal("wrong-length root produced a credential")
		}
	}
	for name, change := range map[string]func(*ServiceCredentialBinding){
		"no service":      func(b *ServiceCredentialBinding) { b.ServiceID = "" },
		"no policy":       func(b *ServiceCredentialBinding) { b.PolicyID = "" },
		"no recipient":    func(b *ServiceCredentialBinding) { b.ReceiverNodeID = "" },
		"direct receiver": func(b *ServiceCredentialBinding) { b.ReceiverNodeID = "direct" },
		"wrong digest":    func(b *ServiceCredentialBinding) { b.ResourceAuthDigest = strings.ToUpper(b.ResourceAuthDigest) },
		"other purpose":   func(b *ServiceCredentialBinding) { b.Purpose = "local-api" },
	} {
		t.Run(name, func(t *testing.T) {
			binding := demoServiceCredentialBinding()
			change(&binding)
			if got, err := DeriveServiceCredential(make([]byte, 32), binding); err == nil || got != "" {
				t.Fatal("invalid binding produced a credential")
			}
		})
	}
}
