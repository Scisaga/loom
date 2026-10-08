package control

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
)

func TestWireGuardKeyValidationReusePreservesRejection(t *testing.T) {
	publicKeys := make([]string, 300)
	for i := range publicKeys {
		seed := sha256.Sum256([]byte(fmt.Sprintf("demo-validation-%d", i)))
		private, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[i] = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	}
	zero, one := [32]byte{}, [32]byte{1}
	rejected := []string{"", publicKeys[0] + "=", publicKeys[0][:42],
		base64.RawURLEncoding.EncodeToString(zero[:]), base64.RawURLEncoding.EncodeToString(one[:])}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for round := range 2 {
				for i := range publicKeys {
					if err := validateWireGuardPublicKey(publicKeys[(i+round)%len(publicKeys)]); err != nil {
						t.Error("valid public key rejected after reuse or eviction", err)
					}
				}
				for _, key := range rejected {
					if validateWireGuardPublicKey(key) == nil {
						t.Error("noncanonical or low-order key acquired a cached success")
					}
				}
			}
		})
	}
	workers.Wait()
	projection := wireGuardAccessFixture(t)
	var resource TransportResource
	for _, candidate := range projection.NetworkIntent.Resources {
		if candidate.Kind == "wireguard" {
			resource = candidate
			break
		}
	}
	if err := resource.Validate(); err != nil {
		t.Fatal(err)
	}
	resource.OwnerNodeID = ""
	if resource.Validate() == nil {
		t.Fatal("valid public key bypassed resource identity validation")
	}
}

func BenchmarkRepeatedWireGuardPublicKeyValidation(b *testing.B) {
	private, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	key := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	b.ResetTimer()
	for b.Loop() {
		if err := validateWireGuardPublicKey(key); err != nil {
			b.Fatal(err)
		}
	}
}
