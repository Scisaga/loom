package main

import (
	"crypto"
	"crypto/ed25519"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestControlSoftwareCAReopensSameSealedSigner(t *testing.T) {
	dir := t.TempDir()
	material, err := openControlSoftwareMaterial(dir, "demo-control", true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	profile, err := material.prepareDeviceCA("demo-cluster", "demo-activation", now)
	if err != nil {
		t.Fatal(err)
	}
	material.Close()
	reopened, err := openControlSoftwareMaterial(dir, "demo-control", false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.prepareDeviceCA("demo-cluster", "demo-activation", now.Add(time.Hour))
	if err != nil || !wire.EqualCanonical(profile, again) {
		t.Fatal("retry replaced prepared CA", err)
	}
	signer, err := reopened.LoadSigner(profile.ProfileIntent.IssuerKeyArtifactHash, "ca_private_key", now)
	if err != nil {
		t.Fatal(err)
	}
	defer clearControlSigner(signer)
	if err := verifyControlDeviceIssuer(profile, signer); err != nil {
		t.Fatal(err)
	}
	message := []byte("demo actual signing after reload")
	signed, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil || !ed25519.Verify(signer.Public().(ed25519.PublicKey), message, signed) {
		t.Fatal("reopened CA cannot sign", err)
	}
	if _, err := reopened.LoadSigner(profile.ProfileIntent.IssuerKeyArtifactHash, "tls_private_key", now); err == nil {
		t.Fatal("CA signer released under wrong purpose")
	}
}
