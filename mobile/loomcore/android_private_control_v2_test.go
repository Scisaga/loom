package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPrepareAndroidV2PrivateControlPlanBindsSealedDirectoryAndKeystoreIdentity(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKI)
	profile, certificateDER, internalRootDER := androidDeviceCertificateProfileFixture(t, identity, now)

	inputs, preflight := androidEnrollmentCoreFixture(t)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	requestID := "android-private-control-request"
	csr, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: requestID}}, identity)
	core, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "p256-keystore-ecdh-v1", bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, baseEnvelope := androidV2EnvelopeFixture(t)
	if !wire.EqualCanonical(baseEnvelope.SignedCurrent.Head, inputs.head) {
		t.Fatal("private-control fixture base Head 不一致")
	}
	directory := wire.ControlServiceDirectoryV1{
		Schema: 1, ClusterID: inputs.set.ClusterID, Generation: 1,
		Services: []wire.PrivateControlServiceV1{
			{ServiceID: "device-config-1", Role: "device_config", OverlayIP: "10.31.0.2", Port: 7445,
				CertificateProfileRef:     "internal-device-config-v1",
				SPKIPins:                  []string{wire.HashRaw("android-private-control-test", []byte("config-spki"))},
				AuthorizedSubjectProfiles: []string{profile.ProfileID}},
			{ServiceID: "device-report-1", Role: "device_report", OverlayIP: "10.31.0.3", Port: 7446,
				CertificateProfileRef:     "internal-device-report-v1",
				SPKIPins:                  []string{wire.HashRaw("android-private-control-test", []byte("report-spki"))},
				AuthorizedSubjectProfiles: []string{profile.ProfileID}},
		},
		ControlSetHash: core.BaseControlSetHash, ParentHeadHash: core.BaseHeadHash,
		ConfigQC: append(json.RawMessage(nil), baseEnvelope.SignedCurrent.QuorumCertificate...),
	}
	directoryHash, err := wire.ControlServiceDirectoryHash(&directory)
	if err != nil {
		t.Fatal(err)
	}
	credential := wire.DevicePrivateControlCredentialV1{
		Schema: 1, ClusterID: inputs.set.ClusterID,
		DeviceID:   preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.DeviceID,
		ParentHead: inputs.head, ControlSet: inputs.set,
		ControlServiceDirectory: directory, ControlServiceDirectoryHash: directoryHash,
		InternalCARootsDER: []string{base64.RawURLEncoding.EncodeToString(internalRootDER)},
	}
	credentialJSON, err := wire.MarshalCanonical(credential)
	if err != nil {
		t.Fatal(err)
	}
	secretRef, sealedEnvelope, _ := androidSealedSecretFixtureFor(t, credential.DeviceID,
		androidPrivateControlCredentialSecretID, "device_credential", credentialJSON)
	secretRefJSON, _ := wire.MarshalCanonical(secretRef)
	sealedJSON, _ := wire.MarshalCanonical(sealedEnvelope)
	installedSecretJSON, err := PrepareAndroidInstalledSecretV2(secretRefJSON, sealedJSON, credentialJSON)
	if err != nil {
		t.Fatal(err)
	}
	var installedSecret androidInstalledSecretV1
	if err := decodeExactAndroidV2(installedSecretJSON, 1<<20, &installedSecret, "private installed secret"); err != nil {
		t.Fatal(err)
	}
	config, _ := wire.MarshalCanonical(bundleWire{Owner: credential.DeviceID, Files: map[string]string{
		"sing-box/config.json": `{"log":{"level":"warn"}}`,
	}})
	configHash, _ := wire.DeviceConfigArtifactContentHash(config)
	configRef := wire.DeviceConfigArtifactRefV1{
		ArtifactID: androidRuntimeArtifactID, Generation: 1, Platform: "android",
		MediaType: "application/vnd.loom.config+json", RenderContractID: androidRuntimeRenderContractID,
		SizeBytes: int64(len(config)), ContentHash: configHash,
	}
	configRefJSON, _ := wire.MarshalCanonical(configRef)
	installedConfigJSON, err := PrepareAndroidInstalledConfigV2(configRefJSON, config)
	if err != nil {
		t.Fatal(err)
	}
	var installedConfig androidInstalledConfigV1
	if err := decodeExactAndroidV2(installedConfigJSON, 1<<20, &installedConfig, "private installed config"); err != nil {
		t.Fatal(err)
	}
	set, currentEnvelope := androidV2EnvelopeFixtureForArtifacts(t, credential.DeviceID,
		identityHash, []wire.SecretArtifactRefV2{secretRef}, []wire.DeviceConfigArtifactRefV1{configRef})
	if !wire.EqualCanonical(set, inputs.set) {
		t.Fatal("private-control fixture ControlSet 不一致")
	}
	artifact := wire.EnrollmentResultArtifactV1{
		Schema: 1, ClusterID: inputs.set.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView:    currentEnvelope.Payload, SecretArtifactRefs: []wire.SecretArtifactRefV2{secretRef},
	}
	artifactHash, _ := wire.EnrollmentResultArtifactHash(&artifact)
	claimHash, _ := wire.EnrollmentClaimCoreHash(&core)
	_, expectedWrappingHash, _, _ := wire.EnrollmentClaimBinaryHashes(&core)
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	profileHash, _ := wire.DeviceCertificateProfileStateHash(&profile)
	issuance := wire.IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 2}
	installation := &androidEnrollmentInstallationV1{
		Schema: 1, ClaimCore: core, ClaimCoreHash: claimHash,
		IdentityKeyHash: identityHash, WrappingKeyHash: expectedWrappingHash,
		TransactionStateHash: wire.HashRaw("android-private-control-test", []byte("transaction")),
		ResultArtifactHash:   artifactHash, DeviceCertificateHash: certificateHash,
		DeviceProfileHash: profileHash, DeviceProfile: &profile, DeviceIssuance: &issuance,
		DeviceApprovedAt: now.Format(time.RFC3339), ResultArtifact: artifact,
		Credentials: []androidInstalledSecretV1{installedSecret},
		Configs:     []androidInstalledConfigV1{installedConfig},
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&currentEnvelope, &set)
	if err != nil {
		t.Fatal(err)
	}
	stateJSON, err := marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: floors, Envelope: currentEnvelope, ControlSet: &set, Enrollment: installation,
	})
	if err != nil {
		t.Fatal(err)
	}
	privateViewJSON, _ := wire.MarshalCanonical(currentEnvelope)
	replayedState, err := PrepareAndroidV2PrivateDeviceViewUpdate(stateJSON, privateViewJSON, identitySPKI)
	if err != nil || !bytes.Equal(replayedState, stateJSON) {
		t.Fatalf("private device_config exact LKG replay 失败: equal=%v err=%v", bytes.Equal(replayedState, stateJSON), err)
	}
	planJSON, err := PrepareAndroidV2PrivateControlPlan(stateJSON, identitySPKI,
		"device_config", "device-config-1", now.Add(time.Minute).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	var plan androidPrivateControlPlanV1
	if err := decodeExactAndroidV2(planJSON, 1<<20, &plan, "private control plan"); err != nil {
		t.Fatal(err)
	}
	if plan.Path != "/private/v2/device/config" || plan.OverlayIP != "10.31.0.2" ||
		plan.DirectoryHash != directoryHash || plan.IdentitySPKIHash != identityHash ||
		len(plan.ClientCertificateChainDER) != 3 || len(plan.InternalCARootsDER) != 1 {
		t.Fatalf("private control plan 投影不完整: %+v", plan)
	}
	otherIdentity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&otherIdentity.PublicKey)
	if _, err := PrepareAndroidV2PrivateControlPlan(stateJSON, otherSPKI,
		"device_config", "device-config-1", now.Add(time.Minute).Format(time.RFC3339)); err == nil {
		t.Fatal("其他 Keystore identity 取得了 private control plan")
	}
	if _, err := PrepareAndroidV2PrivateControlPlan(stateJSON, identitySPKI,
		"device_report", "device-config-1", now.Add(time.Minute).Format(time.RFC3339)); err == nil {
		t.Fatal("跨 role service ID 被接受")
	}

	payload := []byte(`{"healthy":true,"version":"android-test"}`)
	draftJSON, err := PrepareAndroidV2DeviceReportDraft(stateJSON, identitySPKI, "", 1,
		now.Add(2*time.Minute).Format(time.RFC3339), payload)
	if err != nil {
		t.Fatal(err)
	}
	var draft androidDeviceReportDraftV1
	if err := decodeExactAndroidV2(draftJSON, 4<<20, &draft, "Android report draft"); err != nil {
		t.Fatal(err)
	}
	message, err := base64.RawURLEncoding.DecodeString(draft.SigningMessage)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	rawSignature, err := ecdsa.SignASN1(rand.Reader, identity, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := NormalizeP256Signature(identitySPKI, message, rawSignature)
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := AssembleAndroidV2DeviceReport(stateJSON, identitySPKI, draftJSON,
		signature, now.Add(2*time.Minute).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAndroidV2DeviceReport(stateJSON, identitySPKI, envelopeJSON,
		now.Add(2*time.Minute).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	var report wire.DeviceReportEnvelopeV2
	if err := decodeExactAndroidV2(envelopeJSON, 4<<20, &report, "Android Device report"); err != nil {
		t.Fatal(err)
	}
	if report.Body.ReportSequence != 1 || report.Body.ReportID == "" ||
		!bytes.Equal(report.Payload, payload) || report.Signature.IdentitySPKIHash != identityHash {
		t.Fatalf("Android Device report 投影不完整: %+v", report)
	}
	tampered := append([]byte(nil), envelopeJSON...)
	tampered[len(tampered)-2] ^= 1
	if err := ValidateAndroidV2DeviceReport(stateJSON, identitySPKI, tampered,
		now.Add(2*time.Minute).Format(time.RFC3339)); err == nil {
		t.Fatal("篡改后的 pending Android report 被接受")
	}
}

func androidDeviceCertificateProfileFixture(t *testing.T, identity *ecdsa.PrivateKey,
	now time.Time,
) (wire.DeviceCertificateProfileStateV1, []byte, []byte) {
	t.Helper()
	rootPublic, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device issuer"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(14 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(issuerDER)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}
	policy, _ := x509.OIDFromASN1OID(policyOID)
	deviceURI, _ := url.Parse("spiffe://cluster.example/device/android-device-1")
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []x509.OID{policy}, URIs: []*url.URL{deviceURI}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &identity.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	chain := []string{base64.RawURLEncoding.EncodeToString(issuerDER), base64.RawURLEncoding.EncodeToString(rootDER)}
	issuerHash, _ := wire.HashBytes(wire.DomainDeviceIssuerCertificateDER, issuerDER)
	chainHash, _ := wire.HashObject(wire.DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: chain})
	extensionOrder := make([]string, len(leaf.Extensions))
	for index := range leaf.Extensions {
		extensionOrder[index] = leaf.Extensions[index].Id.String()
	}
	intent := wire.DeviceCertificateProfileIntentV1{
		Schema: 1, ClusterID: "demo-cluster", ProfileID: "android-device-certificate", Generation: 1,
		TargetStatus: "active", IssuerID: "device-issuer", IssuerGeneration: 1, IssuerFencingEpoch: 1,
		IssuanceNotBefore: now.Add(-time.Hour).Format(time.RFC3339),
		IssuanceNotAfter:  now.Add(12 * time.Hour).Format(time.RFC3339),
		ProfileKind:       "loom-device-x509-v1", IssuerCertificateDER: chain[0], IssuerCertificateHash: issuerHash,
		IssuerChainDER: chain, IssuerChainHash: chainHash,
		IssuerKeyArtifactHash: wire.HashRaw("android-private-control-test", []byte("issuer-key")),
		AllowedPlatforms:      []string{"android"}, AllowedResponsibilities: []string{"use_loom"},
		ValiditySeconds: 6 * 60 * 60, AllowedSubjectKeyAlgorithm: "p256", SignatureAlgorithm: "ed25519",
		SubjectMode: "empty", SANURIPrefix: "spiffe://cluster.example/device/",
		KeyUsageBits: []string{"digital_signature"}, BasicConstraintsCA: false,
		RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"}, RequiredPolicyOIDs: []string{policyOID.String()},
		ExtensionOrderOIDs: extensionOrder,
	}
	intentHash, _ := wire.DeviceCertificateProfileIntentHash(&intent)
	return wire.DeviceCertificateProfileStateV1{
		Schema: 1, ClusterID: intent.ClusterID, ProfileID: intent.ProfileID, Generation: 1,
		ProfileIntent: intent, DeviceCertificateProfileIntentHash: intentHash,
		Status: "active", StatusChangedAt: now.Add(-30 * time.Minute).Format(time.RFC3339),
	}, leafDER, rootDER
}
