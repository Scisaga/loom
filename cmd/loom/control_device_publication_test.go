package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

func controlPublicationFixture(t *testing.T) (*controlRuntime, string, wire.RuntimeDeviceMigrationLeafV1, controlPublishDevicePayloadV1) {
	t.Helper()
	var material *controlSoftwareMaterial
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapSPKI, _ := x509.MarshalPKIXPublicKey(wrapping.Public())
	wrapHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrapSPKI)
	runtime, admin, migration, _ := controlMigratedDeviceRuntime(t, func(application *controlApplicationV1, runtime *controlRuntime) {
		var err error
		material, err = openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, true)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := material.availabilityPolicy(application.ClusterID)
		if err != nil {
			t.Fatal(err)
		}
		application.ArtifactPolicies = []wire.ArtifactAvailabilityPolicyV1{policy}
		application.DeviceMigrations[0].WrappingKeyHash = wrapHash
		application.Authorizations[0].AllowedOperationKinds = append(application.Authorizations[0].AllowedOperationKinds, controlPublishDeviceKind)
		sort.Strings(application.Authorizations[0].AllowedOperationKinds)
	})
	defer material.Close()
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	previous, _ := wire.DeviceViewHash(&application.Devices[0].View)
	key, _ := enrollmentv2.MaterialAuthorityKey(wrapping.Public())
	sealing := wire.P256SealingPolicyV1()
	recipients := []wire.SealedBlobRecipientKeyRefV1{{RecipientID: migration.DeviceID, RecipientKeyGeneration: 1,
		RecipientKeyID: key.KeyID, RecipientKeyProfile: sealing.RecipientKeyProfile, RecipientPublicKey: key}}
	sealContext, err := wire.NewSealedSecretContext(application.ClusterID, "demo-publish", "demo-data", "data_plane_credential",
		wire.SecretArtifactOwnerV1{Kind: "device", Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: migration.DeviceID}}, 1, &sealing, recipients)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := enrollmentv2.CreateLocalSealedMaterial(material.store, sealContext, sealing, recipients, []byte("demo-private-credential"), nil,
		application.ArtifactPolicies[0], material.deviceID, material.reporter, runtime.now().UTC().Truncate(time.Second), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := material.store.Get(evidence.Ref.SealedBlob.CiphertextDigest)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := wire.MarshalCanonical(struct {
		Owner string            `json:"owner"`
		Files map[string]string `json:"files"`
	}{migration.DeviceID, map[string]string{"agent/config.json": `{"server":"demo-server"}`,
		"sing-box/config.json": `{"outbounds":[{"password":"${secret:demo-data}","type":"hysteria2"}]}`}})
	hash, _ := wire.DeviceConfigArtifactContentHash(raw)
	config := controlPublishedConfigV1{Ref: wire.DeviceConfigArtifactRefV1{ArtifactID: "android-runtime", Generation: 1,
		Platform: "android", MediaType: "application/vnd.loom.config+json", RenderContractID: "android-runtime-v1", SizeBytes: int64(len(raw)), ContentHash: hash}, Content: raw}
	return runtime, admin, migration, controlPublishDevicePayloadV1{Schema: 1,
		Publication: controlDevicePublicationV1{Schema: 1, DeviceID: migration.DeviceID, PreviousViewHash: previous,
			Configs: []controlPublishedConfigV1{config}, Secrets: []enrollmentv2.SealedMaterialEvidenceV1{evidence}},
		Envelopes: []wire.SealedSecretEnvelopeV1{envelope}}
}

func TestControlDevicePublicationCommitsOriginalIdentityAndReplaysAfterLostResponse(t *testing.T) {
	runtime, admin, migration, payload := controlPublicationFixture(t)
	before, err := runtime.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, client, _ := progressTestServer(t, runtime, admin)
	status, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := newControlDevicePublicationRequest(admin, endpoint, status, "demo-publish", payload, runtime.now())
	if err != nil {
		t.Fatal(err)
	}
	runtime.checkpoint = func(phase controlplane.Phase) error {
		if phase == controlplane.PhasePending {
			return errors.New("demo interrupted after durable request")
		}
		return nil
	}
	if _, err := submitControlOperation(context.Background(), admin, endpoint, client, status, request); err == nil {
		t.Fatal("interrupted operation returned success")
	}
	reopened, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, client, _ = progressTestServer(t, reopened, admin)
	result, err := submitControlOperation(context.Background(), admin, endpoint, client, status, request)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil || after.Record.IdentitySPKIHash != before.Record.IdentitySPKIHash || after.Record.CertificateHash != before.Record.CertificateHash ||
		!wire.EqualCanonical(after.CurrentDeviceView.Payload.Active.Responsibilities, before.CurrentDeviceView.Payload.Active.Responsibilities) ||
		!wire.EqualCanonical(after.CurrentDeviceView.Payload.Active.Grants, before.CurrentDeviceView.Payload.Active.Grants) ||
		after.CurrentDeviceView.Payload.DeviceGeneration != 2 || len(after.DeviceConfigUpdates) != 2 || len(after.DeviceSecretEnvelopes) != 1 {
		t.Fatal("publication did not preserve identity/authority or deliver config and sealed material", err)
	}
	if err := wire.VerifyDeviceViewSuccessor(&before.CurrentDeviceView, &after.CurrentDeviceView); err != nil {
		t.Fatal(err)
	}
	again, err := submitControlOperation(context.Background(), admin, endpoint, client, status, request)
	if err != nil || !wire.EqualCanonical(result, again) || len(reopened.journal.Records) != 2 {
		t.Fatal("retry changed result or duplicated publication", err)
	}
	for _, name := range []string{controlJournalName, controlRaftName, controlStateName} {
		raw, err := os.ReadFile(filepath.Join(runtime.dir, name))
		if err != nil || bytes.Contains(raw, []byte("demo-private-credential")) {
			t.Fatal("credential leaked into control state", err)
		}
	}
}

func TestControlDevicePublicationRejectsUnboundMaterialAndStaleDevice(t *testing.T) {
	runtime, admin, _, payload := controlPublicationFixture(t)
	endpoint, client, _ := progressTestServer(t, runtime, admin)
	status, _ := fetchControlStatus(context.Background(), endpoint, client)
	application, _ := runtime.certifiedApplicationLocked()
	for _, test := range []struct {
		name   string
		change func(*controlDevicePublicationV1)
	}{
		{"wrong-device", func(p *controlDevicePublicationV1) { p.DeviceID = "demo-other" }},
		{"stale-view", func(p *controlDevicePublicationV1) { p.PreviousViewHash = wire.EmptyHashV1 }},
		{"wrong-platform", func(p *controlDevicePublicationV1) { p.Configs[0].Ref.Platform = "windows-desktop" }},
		{"content-not-committed", func(p *controlDevicePublicationV1) { p.Configs[0].Content = []byte(`{}`) }},
		{"unapproved-policy", func(p *controlDevicePublicationV1) { p.Secrets[0].Policy.PolicyID = "demo-other-policy" }},
		{"forged-receipt", func(p *controlDevicePublicationV1) {
			p.Secrets[0].Receipts[0].Body.ObservedAt = runtime.now().Add(-time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
		}},
		{"wrong-proposal", func(p *controlDevicePublicationV1) { p.Secrets[0].Ref.ProposalID = "demo-other-op" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := controlClone(payload)
			test.change(&changed.Publication)
			hash, _ := controlDevicePublicationHash(changed.Publication)
			request, err := newControlSignedRequest(admin, endpoint, status, controlPublishDeviceKind, hash, "demo-publish", "demo rejection", runtime.now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := application.reduceDevicePublication(changed.Publication, request.Operation.Body, runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)); err == nil {
				t.Fatal("invalid publication accepted")
			}
		})
	}
}
