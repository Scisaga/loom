package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/controlplane"
	"loom/internal/model"
	"loom/internal/wire"
)

func controlPublicationFixture(t *testing.T) (*controlRuntime, string, wire.RuntimeDeviceMigrationLeafV1, controlPublishDevicePayloadV1) {
	t.Helper()
	runtime, admin, migration, input, _ := controlRenderedClientFixture(t, model.Android)
	state := runtime.store.Snapshot()
	payload, err := runtime.prepareClientConfigLocked(controlPrepareClientRequestV1{Schema: 1, RequestID: "demo-publish", ExpectedHead: state.CertifiedHead.HeadHash, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, admin, migration, payload
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
		after.CurrentDeviceView.Payload.DeviceGeneration != 2 || len(after.DeviceConfigUpdates) != 2 || len(after.DeviceSecretEnvelopes) != len(payload.Envelopes) {
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
		if err != nil || bytes.Contains(raw, []byte("demo-sealed-client-credential")) {
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
