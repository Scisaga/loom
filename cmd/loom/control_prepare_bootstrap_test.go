package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/certmanager"
	"loom/internal/model"
	"loom/internal/wire"
)

func testBootstrapPreparationFromCertificate(t *testing.T, binding certmanager.ExistingCertificateBindingV1, roots *x509.CertPool, now time.Time) controlPrepareBootstrapInputV1 {
	t.Helper()
	dir, _ := newAdminRotationFixture(t, false)
	runtime, err := openControlRuntime(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := runtime.store.Snapshot()
	qc, _ := wire.MarshalCanonical(state.CertifiedQC)
	status := controlStatusResponseV1{Schema: 1, ClusterID: runtime.config.ClusterID, Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet}
	resources := wire.ForwardServerListenerResourcesV1{Schema: 1, ClusterID: status.ClusterID, ServerID: binding.Identity.KeyOwnerDeviceID, Generation: 1,
		NginxLocalTCPPort: 443, HY2LocalUDPPortPool: []int64{24443}, WireGuardLocalUDPPorts: []int64{51820}, TrojanLocalTCPPortPool: []int64{24444}, Mappings: []wire.PortMappingIntentV1{}}
	resourceHash, _ := wire.ForwardServerListenerResourcesHash(&resources)
	profile := wire.ServerPublicAccessProfileV1{Schema: 1, ClusterID: status.ClusterID, ServerID: resources.ServerID, Generation: 1,
		FQDN: binding.Identity.DNSNames[0], DNSZoneRef: "demo-existing-zone", AddressFamilyPolicy: "ipv4_only", HTTPSPublicPort: 443,
		DeploymentKind: "direct_standard", PublicFrontendAddresses: []string{"203.0.113.10"}, CertificateProfileRef: binding.Identity.IssuerProfileRef, ForwardListenerResourcesHash: resourceHash}
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	id, _ := wire.ControlKeyID(public)
	policy := bootstrapaccess.BootstrapOuterEvidencePolicyV1{Schema: 1, ClusterID: status.ClusterID, PolicyID: "demo-external", MinimumExternalObservers: 1,
		MinimumExternalFailureDomains: 1, MaximumObservationAgeSeconds: 30, Observers: []bootstrapaccess.BootstrapOuterObserverV1{{ObserverID: "demo-observer", FailureDomain: "demo-external", ObserverKeyID: id, ObserverPublicKey: base64.RawURLEncoding.EncodeToString(public)}}}
	request := controlPrepareBootstrapInputV1{Schema: 1, OperationID: "demo-initial-bootstrap", ValidFrom: now.Format(time.RFC3339), ValidUntil: now.Add(time.Hour).Format(time.RFC3339),
		Listeners: []bootstrapaccess.InitialBootstrapListenerInputV1{
			{EndpointID: binding.Identity.EndpointIDs[0], Transport: "hysteria2", PublicPort: 24443, Profile: profile, Resources: resources, Certificate: binding, EvidencePolicy: policy},
			{EndpointID: binding.Identity.EndpointIDs[1], Transport: "trojan_tls", PublicPort: 24444, Profile: profile, Resources: resources, Certificate: binding, EvidencePolicy: policy}}}
	plan, err := prepareInitialBootstrapPlan(request, status, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Input.Parent.HeadHash != status.Head.HeadHash || len(plan.Plans) != 2 {
		t.Fatal("计划丢失原 Head 或独立 fallback")
	}
	if _, err := prepareInitialBootstrapPlan(request, status, x509.NewCertPool(), now); err == nil {
		t.Fatal("接受未受信任公开证书")
	}
	forged := controlClone(request)
	forged.Listeners[0].Certificate.NotAfter = now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := prepareInitialBootstrapPlan(forged, status, roots, now); err == nil {
		t.Fatal("允许公开绑定扩大证书有效期")
	}
	application, _ := controlInviteApplication(t, runtime)
	bindBootstrapFixtureSource(t, &application, binding.Identity.KeyOwnerDeviceID)
	application.BootstrapInstallation = &plan
	application.BootstrapCatalog = plan.Catalog
	if err := application.validate(); err != nil {
		t.Fatal(err)
	}
	application.BootstrapInstallation.Plans[0].Execution.TargetTuples[0].Port++
	if err := application.validate(); err == nil {
		t.Fatal("application 未重算安装计划")
	}
	return request
}

func bindBootstrapFixtureSource(t *testing.T, application *controlApplicationV1, device string) {
	t.Helper()
	source, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range source.Nodes {
		if node.Server != nil {
			application.LegacySSOT = strings.ReplaceAll(application.LegacySSOT, node.ID, device)
			return
		}
	}
	t.Fatal("缺 server fixture")
}
