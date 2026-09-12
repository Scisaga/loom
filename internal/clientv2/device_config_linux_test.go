//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestSyncLinuxDeviceViewUsesPinnedPrivateDirectoryAndDeviceMTLS(t *testing.T) {
	now := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	statePath, identityPath, set, envelope := installedDeviceConfigState(t, now)
	serverCertificate, roots, serverPin := privateEnrollmentCertificate(t, now, "10.50.0.2")
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/private/v2/device/config" || request.Host != "10.50.0.2:7445" ||
			request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 1 {
			t.Errorf("private request 未使用 exact route/Device mTLS: host=%q tls=%#v", request.Host, request.TLS)
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		body, err := wire.MarshalCanonical(envelope)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write(body)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	setHash, _ := wire.ControlSetHash(&set)
	directory := wire.ControlServiceDirectoryV1{
		Schema: 1, ClusterID: set.ClusterID, Generation: 1, ControlSetHash: setHash,
		ParentHeadHash: envelope.SignedCurrent.Head.HeadHash,
		ConfigQC:       append([]byte(nil), envelope.SignedCurrent.QuorumCertificate...),
		Services: []wire.PrivateControlServiceV1{{
			ServiceID: "device-config-primary", Role: "device_config", OverlayIP: "10.50.0.2", Port: 7445,
			CertificateProfileRef: "internal-device-config-server", SPKIPins: []string{serverPin},
			AuthorizedSubjectProfiles: []string{"device-profile"},
		}},
	}
	directoryHash, err := wire.ControlServiceDirectoryHash(&directory)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "10.50.0.2:7445" {
			t.Fatalf("dial 逃离 certified exact tuple: %s %s", network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	got, err := SyncLinuxDeviceView(context.Background(), LinuxDeviceViewSyncOptions{
		StatePath: statePath, IdentityPath: identityPath, Directory: directory,
		PinnedDirectoryHash: directoryHash, ControlSet: set, Roots: roots, Dial: dial,
		Now: func() time.Time { return now }, Timeout: 5 * time.Second,
	})
	if err != nil || got.HeadHash != envelope.SignedCurrent.Head.HeadHash || requests != 1 {
		t.Fatalf("private sync floors=%#v requests=%d err=%v", got, requests, err)
	}

	tampered := directory
	tampered.Services = append([]wire.PrivateControlServiceV1(nil), directory.Services...)
	tampered.Services[0].Port++
	if _, err := SyncLinuxDeviceView(context.Background(), LinuxDeviceViewSyncOptions{
		StatePath: statePath, IdentityPath: identityPath, Directory: tampered,
		PinnedDirectoryHash: directoryHash, ControlSet: set, Roots: roots, Dial: dial,
		Now: func() time.Time { return now }, Timeout: 5 * time.Second,
	}); err == nil || !strings.Contains(err.Error(), "hash pin") {
		t.Fatalf("篡改 directory 未在 dial 前被拒绝: %v", err)
	}
	if requests != 1 {
		t.Fatalf("失败的 directory pin 仍触发网络请求: %d", requests)
	}
}

func TestSyncLinuxDeviceViewRejectsWrongCertifiedSPKIPin(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	statePath, identityPath, set, envelope := installedDeviceConfigState(t, now)
	serverCertificate, roots, _ := privateEnrollmentCertificate(t, now, "10.50.0.3")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	setHash, _ := wire.ControlSetHash(&set)
	directory := wire.ControlServiceDirectoryV1{
		Schema: 1, ClusterID: set.ClusterID, Generation: 1, ControlSetHash: setHash,
		ParentHeadHash: envelope.SignedCurrent.Head.HeadHash,
		ConfigQC:       append([]byte(nil), envelope.SignedCurrent.QuorumCertificate...),
		Services: []wire.PrivateControlServiceV1{{
			ServiceID: "device-config-primary", Role: "device_config", OverlayIP: "10.50.0.3", Port: 7445,
			CertificateProfileRef:     "internal-device-config-server",
			SPKIPins:                  []string{wire.HashRaw("device-config-test", []byte("wrong pin"))},
			AuthorizedSubjectProfiles: []string{"device-profile"},
		}},
	}
	directoryHash, _ := wire.ControlServiceDirectoryHash(&directory)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	if _, err := SyncLinuxDeviceView(context.Background(), LinuxDeviceViewSyncOptions{
		StatePath: statePath, IdentityPath: identityPath, Directory: directory,
		PinnedDirectoryHash: directoryHash, ControlSet: set, Roots: roots, Dial: dial,
		Now: func() time.Time { return now }, Timeout: 5 * time.Second,
	}); err == nil || !strings.Contains(err.Error(), "SPKI") {
		t.Fatalf("错误 SPKI pin 未被 inner TLS 拒绝: %v", err)
	}
}

func TestSendLinuxDeviceReportSignsDurableFloorsOverPinnedMTLSRoute(t *testing.T) {
	now := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)
	statePath, identityPath, set, current := installedDeviceConfigState(t, now)
	serverCertificate, roots, serverPin := privateEnrollmentCertificate(t, now, "10.50.0.4")
	schemas := wire.DeviceReportSchemaRegistry{"health": 1}
	requests := 0
	var reportBodies [][]byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		body, _ := io.ReadAll(request.Body)
		reportBodies = append(reportBodies, append([]byte(nil), body...))
		var report wire.DeviceReportEnvelopeV2
		canonical, err := wire.DecodeStrict(body, 4<<20, &report)
		if err != nil || !bytes.Equal(canonical, body) || request.Method != http.MethodPost ||
			request.URL.Path != "/private/v2/device/report" || request.Host != "10.50.0.4:7446" ||
			request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
			t.Errorf("private report wire/route/mTLS 无效: err=%v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		identityPublic, ok := request.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
		identityHash := current.Payload.Active.IdentitySPKIHash
		if !ok || wire.VerifyDeviceReport(&report, identityPublic, current.Payload.DeviceID,
			identityHash, now, time.Minute, 30*time.Second, schemas) != nil ||
			!wire.EqualCanonical(report.Body.AcceptedFloors, mustDeviceFloors(t, &current, &set)) {
			t.Error("report 未绑定 durable floors/identity signature")
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		if requests == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	setHash, _ := wire.ControlSetHash(&set)
	directory := wire.ControlServiceDirectoryV1{
		Schema: 1, ClusterID: set.ClusterID, Generation: 1, ControlSetHash: setHash,
		ParentHeadHash: current.SignedCurrent.Head.HeadHash,
		ConfigQC:       append([]byte(nil), current.SignedCurrent.QuorumCertificate...),
		Services: []wire.PrivateControlServiceV1{{
			ServiceID: "device-report-primary", Role: "device_report", OverlayIP: "10.50.0.4", Port: 7446,
			CertificateProfileRef: "internal-device-report-server", SPKIPins: []string{serverPin},
			AuthorizedSubjectProfiles: []string{"device-profile"},
		}},
	}
	directoryHash, _ := wire.ControlServiceDirectoryHash(&directory)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.50.0.4:7446" {
			t.Fatalf("report dial 逃离 exact tuple: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	payload := json.RawMessage(`{"healthy":true,"version":"test"}`)
	options := LinuxDeviceReportOptions{
		StatePath: statePath, IdentityPath: identityPath, Directory: directory,
		PinnedDirectoryHash: directoryHash, ControlSet: set, Roots: roots, Dial: dial,
		Now: func() time.Time { return now }, Timeout: 5 * time.Second,
		ReportID: "report-linux-device-1-1", ReportSequence: 1,
		Kind: "health", PayloadSchema: 1, Payload: payload, Schemas: schemas,
	}
	report, err := SendLinuxDeviceReport(context.Background(), options)
	if err == nil || report.Body.ReportSequence != 1 || requests != 1 {
		t.Fatalf("private report=%#v requests=%d err=%v", report, requests, err)
	}
	options.Payload = nil
	options.ReportID = ""
	options.ReportSequence = 0
	options.RetryEnvelope = &report
	retried, err := SendLinuxDeviceReport(context.Background(), options)
	if err != nil || requests != 2 || !wire.EqualCanonical(report, retried) ||
		len(reportBodies) != 2 || !bytes.Equal(reportBodies[0], reportBodies[1]) {
		t.Fatalf("exact report retry 失败: requests=%d same=%v err=%v",
			requests, wire.EqualCanonical(report, retried), err)
	}
	brokenPayload := json.RawMessage(`{ "healthy":true}`)
	if _, err := SendLinuxDeviceReport(context.Background(), LinuxDeviceReportOptions{
		StatePath: statePath, IdentityPath: identityPath, Directory: directory,
		PinnedDirectoryHash: directoryHash, ControlSet: set, Roots: roots, Dial: dial,
		Now: func() time.Time { return now }, Timeout: 5 * time.Second,
		ReportID: "report-linux-device-1-2", ReportSequence: 2,
		Kind: "health", PayloadSchema: 1, Payload: brokenPayload, Schemas: schemas,
	}); err == nil {
		t.Fatal("接受了非 canonical report payload")
	}
	if requests != 2 {
		t.Fatalf("未签名的非 canonical payload 仍触发网络请求: %d", requests)
	}
}

func TestDurableLinuxDeviceReportJournalReplaysExactPendingBeforeAdvancing(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	statePath, identityPath, set, current := installedDeviceConfigState(t, now)
	serverCertificate, roots, serverPin := privateEnrollmentCertificate(t, now, "10.50.0.5")
	requests := 0
	var bodies [][]byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, append([]byte(nil), body...))
		if requests == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	setHash, _ := wire.ControlSetHash(&set)
	directory := wire.ControlServiceDirectoryV1{
		Schema: 1, ClusterID: set.ClusterID, Generation: 1, ControlSetHash: setHash,
		ParentHeadHash: current.SignedCurrent.Head.HeadHash,
		ConfigQC:       append([]byte(nil), current.SignedCurrent.QuorumCertificate...),
		Services: []wire.PrivateControlServiceV1{{
			ServiceID: "device-report-primary", Role: "device_report", OverlayIP: "10.50.0.5", Port: 7446,
			CertificateProfileRef: "internal-device-report-server", SPKIPins: []string{serverPin},
			AuthorizedSubjectProfiles: []string{"device-profile"},
		}},
	}
	directoryHash, _ := wire.ControlServiceDirectoryHash(&directory)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	options := LinuxDeviceReportOptions{
		StatePath: statePath, IdentityPath: identityPath, Directory: directory,
		PinnedDirectoryHash: directoryHash, ControlSet: set, Roots: roots, Dial: dial,
		Now: func() time.Time { return now }, Timeout: 5 * time.Second,
		Kind: "health", PayloadSchema: 1, Payload: json.RawMessage(`{"healthy":true}`),
		Schemas: wire.DeviceReportSchemaRegistry{"health": 1},
	}
	journalPath := filepath.Join(filepath.Dir(statePath), "device-report-journal.json")
	first, err := SendLinuxDeviceReportDurable(context.Background(), journalPath, options)
	if err == nil || first.Body.ReportSequence != 1 || requests != 1 {
		t.Fatalf("首次失败未保留 sequence 1: report=%#v requests=%d err=%v", first, requests, err)
	}
	journal, err := readLinuxDeviceReportJournal(journalPath)
	if err != nil || journal.Pending == nil || journal.NextSequence != 1 ||
		!wire.EqualCanonical(*journal.Pending, first) {
		t.Fatalf("首次失败后 journal=%#v err=%v", journal, err)
	}
	info, _ := os.Stat(journalPath)
	if info == nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode=%v", info)
	}

	// 即使本次观测已变，也必须先重放已落盘的 sequence 1，不能同序号重签。
	options.Payload = json.RawMessage(`{"healthy":false}`)
	second, err := SendLinuxDeviceReportDurable(context.Background(), journalPath, options)
	if err != nil || requests != 2 || !wire.EqualCanonical(first, second) ||
		len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("pending exact replay 失败: requests=%d same=%v err=%v",
			requests, wire.EqualCanonical(first, second), err)
	}
	journal, err = readLinuxDeviceReportJournal(journalPath)
	if err != nil || journal.Pending != nil || journal.LastAcceptedSequence != 1 || journal.NextSequence != 2 ||
		journal.LastAcceptedEnvelopeHash == "" {
		t.Fatalf("sequence 1 成功后 journal=%#v err=%v", journal, err)
	}
	third, err := SendLinuxDeviceReportDurable(context.Background(), journalPath, options)
	if err != nil || third.Body.ReportSequence != 2 || requests != 3 || bytes.Equal(bodies[1], bodies[2]) {
		t.Fatalf("sequence 2 未使用新 payload: report=%#v requests=%d err=%v", third, requests, err)
	}
}

func mustDeviceFloors(t *testing.T, envelope *wire.DeviceViewEnvelopeV2,
	set *wire.ControlSetV1) wire.ClientFloorsV2 {
	t.Helper()
	floors, err := wire.VerifyDeviceViewEnvelope(envelope, set)
	if err != nil {
		t.Fatal(err)
	}
	return floors
}

func installedDeviceConfigState(t *testing.T, now time.Time) (string, string, wire.ControlSetV1, wire.DeviceViewEnvelopeV2) {
	statePath, identityPath, set, envelope, _ := installedDeviceConfigStateWithKey(t, now)
	return statePath, identityPath, set, envelope
}

func installedDeviceConfigStateWithKey(t *testing.T, now time.Time) (string, string, wire.ControlSetV1,
	wire.DeviceViewEnvelopeV2, ed25519.PrivateKey) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(directory, "identity.json")
	identity, err := OpenOrCreateEnrollmentIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	identityKey, _, err := identity.keys()
	if err != nil {
		t.Fatal(err)
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		t.Fatal(err)
	}
	set, configKey := clientControlSet(t)
	envelope := clientEnvelopeWithIdentity(t, &set, configKey, identityHash)
	hash := func(value string) string { return wire.HashRaw("device-config-test", []byte(value)) }
	setHash, _ := wire.ControlSetHash(&set)
	claimCore, claimCoreHash, err := identity.PrepareClaimCore(ClaimCoreInputV2{
		ClusterID: set.ClusterID, InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash("record"), DeviceEnrollmentIntentCommitmentHash: hash("commitment"),
		DeviceEnrollmentIntentOpeningHash: hash("opening"), AcceptedDeviceEnrollmentIntentHash: hash("intent"),
		BaseRecoveryEpoch: 0, BaseControlEpoch: 0, BaseControlSetHash: setHash,
		BaseHeadHash: envelope.SignedCurrent.Head.HeadHash,
		ClientNonce:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateDER := deviceConfigClientCertificate(t, identityKey, now)
	artifact := wire.EnrollmentResultArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, InviteID: "invite", RequestID: "request",
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView:    envelope.Payload, SecretArtifactRefs: []wire.SecretArtifactRefV2{},
	}
	artifactHash, err := wire.EnrollmentResultArtifactHash(&artifact)
	if err != nil {
		t.Fatal(err)
	}
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	_, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&claimCore)
	if err != nil {
		t.Fatal(err)
	}
	installation := &EnrollmentInstallationV1{
		Schema: 1, ClaimCore: claimCore, ClaimCoreHash: claimCoreHash, IdentityKeyHash: identityHash,
		WrappingKeyHash: wrappingHash, TransactionStateHash: hash("completed"), ResultArtifactHash: artifactHash,
		DeviceCertificateHash: certificateHash, ResultArtifact: artifact, Credentials: []InstalledSecretV1{},
	}
	statePath := filepath.Join(directory, "state.json")
	store, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.acceptInitialInstallation(&envelope, &set, envelope.Payload.DeviceID,
		identityHash, installation); err != nil {
		t.Fatal(err)
	}
	return statePath, identityPath, set, envelope, configKey
}

func deviceConfigClientCertificate(t *testing.T, key *ecdsa.PrivateKey, now time.Time) []byte {
	t.Helper()
	if key == nil || key.Curve != elliptic.P256() {
		t.Fatal("Device identity 不是 P-256")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "linux-device-1"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
