package bootstrapaccess

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/certmanager"
	"loom/internal/rotation"
	"loom/internal/wire"
)

func initialInstallationFixture(t *testing.T, deployment string) InitialBootstrapInstallationInputV1 {
	t.Helper()
	f := newRuntimePlanFixture(t, "hysteria2", deployment)
	now := time.Now().UTC().Truncate(time.Second)
	root, tlsConfig, leaf := trojanCertificate(t, f.profile.FQDN)
	dir := t.TempDir()
	certificate := filepath.Join(dir, "certificate.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(tlsConfig.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	binding, err := certmanager.PrepareExistingCertificate(filepath.Join(dir, "materials"), certmanager.ExistingCertificateRequestV1{Schema: 1,
		RequestID: "demo-original-tls", ClusterID: f.profile.ClusterID, DeviceID: f.profile.ServerID, IdentityID: "demo-public-tls", IdentityGeneration: 1,
		CertificateGeneration: 1, EndpointIDs: []string{"demo-hy2", "demo-tcp"}, DNSNames: []string{f.profile.FQDN}, IssuerProfileRef: f.profile.CertificateProfileRef,
		CertificatePath: certificate, PrivateKeyPath: key}, root, now)
	if err != nil {
		t.Fatal(err)
	}
	observerKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := observerKey.Public().(ed25519.PublicKey)
	keyID, _ := wire.ControlKeyID(public)
	policy := BootstrapOuterEvidencePolicyV1{Schema: 1, ClusterID: f.profile.ClusterID, PolicyID: "demo-external", MinimumExternalObservers: 1,
		MinimumExternalFailureDomains: 1, MaximumObservationAgeSeconds: 30, Observers: []BootstrapOuterObserverV1{{ObserverID: "demo-observer", FailureDomain: "demo-external", ObserverKeyID: keyID, ObserverPublicKey: base64.RawURLEncoding.EncodeToString(public)}}}
	var qc wire.StableHeadReplicationQCV1
	if err := json.Unmarshal(f.catalog.BootstrapIngressSet.ConfigQC, &qc); err != nil {
		t.Fatal(err)
	}
	hy2, tcp := int64(24443), int64(24444)
	if deployment == "nat_mapped" {
		hy2, tcp = 30443, 30444
	}
	return InitialBootstrapInstallationInputV1{Schema: 1, ClusterID: f.profile.ClusterID, OperationID: "demo-bootstrap-installation", Parent: f.head, ParentQC: qc, ControlSet: f.controlSet,
		ValidFrom: now.Format(time.RFC3339), ValidUntil: now.Add(30 * time.Minute).Format(time.RFC3339), Listeners: []InitialBootstrapListenerInputV1{
			{EndpointID: "demo-hy2", Transport: "hysteria2", PublicPort: hy2, Profile: f.profile, Resources: f.resources, Certificate: binding, EvidencePolicy: policy},
			{EndpointID: "demo-tcp", Transport: "trojan_tls", PublicPort: tcp, Profile: f.profile, Resources: f.resources, Certificate: binding, EvidencePolicy: policy},
		}}
}

func TestInitialBootstrapPlanPreservesCertificateAndExactPortMappings(t *testing.T) {
	for _, deployment := range []string{"direct_standard", "nat_mapped"} {
		t.Run(deployment, func(t *testing.T) {
			input := initialInstallationFixture(t, deployment)
			installation, err := BuildInitialBootstrapInstallation(input)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := BuildInitialBootstrapInstallation(input)
			if err != nil || !wire.EqualCanonical(installation, retry) {
				t.Fatalf("non-deterministic plan: %v", err)
			}
			if err := ValidateInitialBootstrapInstallation(&installation); err != nil {
				t.Fatal(err)
			}
			for i, plan := range installation.Plans {
				if plan.Execution.TargetTuples[0].Port != []int64{24443, 24444}[i] {
					t.Fatal("映射 local port 漂移")
				}
				if plan.Intent.FrozenDependencies.CertificateIdentityProjectionHash != input.Listeners[i].Certificate.IdentityProjectionHash {
					t.Fatal("改变原证书身份")
				}
				transition := rotation.Transition{NextPhase: "prepared", CertifiedHeadHash: input.Parent.HeadHash, CertifiedAt: input.ValidFrom}
				verify := func(intent *rotation.IntentV1, current *rotation.StateV1, event *rotation.Transition) error {
					if current != nil || !wire.EqualCanonical(*intent, plan.Intent) || !wire.EqualCanonical(*event, transition) {
						return errors.New("wrong installation")
					}
					return nil
				}
				store, err := rotation.OpenStore(filepath.Join(t.TempDir(), "state.json"), verify)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.BeginPrepared(plan.Intent, transition); err != nil {
					t.Fatal(err)
				}
				plans, err := rotation.OpenExecutionPlanStore(filepath.Join(t.TempDir(), "plans.json"))
				if err != nil {
					t.Fatal(err)
				}
				frozen, err := plans.Freeze(plan.Intent, plan.Execution)
				if err != nil {
					t.Fatal(err)
				}
				authorized, err := rotation.AuthorizeRuntimePlan(store.Snapshot(), frozen, verify)
				if err != nil {
					t.Fatal(err)
				}
				spec := input.Listeners[i]
				now, _ := wire.ParseTimeZ(input.ValidFrom)
				runtime, err := BuildBootstrapIngressRuntimePlan(&installation.Catalog, &input.Parent, &input.ControlSet, nil, authorized, &spec.Profile, &spec.Resources, plan.EndpointID, 1, now, 2)
				if err != nil || len(runtime.Bindings()) != 1 {
					t.Fatalf("runtime plan: %v", err)
				}
			}
		})
	}
}

func TestInitialBootstrapRejectsUnboundInputsAndMutation(t *testing.T) {
	cases := map[string]func(*InitialBootstrapInstallationInputV1){
		"no_tcp_fallback":   func(i *InitialBootstrapInstallationInputV1) { i.Listeners = i.Listeners[:1] },
		"port_outside_pool": func(i *InitialBootstrapInstallationInputV1) { i.Listeners[0].PublicPort++ },
		"wrong_owner": func(i *InitialBootstrapInstallationInputV1) {
			i.Listeners[0].Certificate.Identity.KeyOwnerDeviceID = "demo-other"
		},
		"wrong_name": func(i *InitialBootstrapInstallationInputV1) { i.Listeners[0].Profile.FQDN = "different.example" },
		"past_certificate": func(i *InitialBootstrapInstallationInputV1) {
			at, _ := wire.ParseTimeZ(i.ValidUntil)
			i.ValidUntil = at.Add(24 * time.Hour).Format(time.RFC3339)
		},
		"self_observer": func(i *InitialBootstrapInstallationInputV1) {
			i.Listeners[0].EvidencePolicy.Observers[0].ObserverID = i.Listeners[0].Profile.ServerID
		},
		"wrong_parent_qc": func(i *InitialBootstrapInstallationInputV1) { i.Parent.HeadHash = runtimePlanHash("different-parent") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			input := initialInstallationFixture(t, "direct_standard")
			change(&input)
			if _, err := BuildInitialBootstrapInstallation(input); err == nil {
				t.Fatal("接受未绑定安装输入")
			}
		})
	}
	installation, err := BuildInitialBootstrapInstallation(initialInstallationFixture(t, "direct_standard"))
	if err != nil {
		t.Fatal(err)
	}
	installation.Plans[0].Execution.TargetTuples[0].Port++
	if err := ValidateInitialBootstrapInstallation(&installation); err == nil {
		t.Fatal("接受修改的 frozen plan")
	}
}
