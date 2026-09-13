package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

func TestControlRuntimeN1AdminCommitAndRestart(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 17444, 17445, clock); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	status := serveRuntimeStatus(t, runtime, peer)
	if status.Quorum != 1 || len(status.ControlSet.Members) != 1 ||
		status.Head.Body.Payload.HeadKind != "bootstrap" {
		t.Fatalf("unexpected bootstrap status: %#v", status)
	}
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		t.Fatal(err)
	}
	submitted, err := newControlPingRequest(adminDir, endpoint, status, "runtime integration", now)
	if err != nil {
		t.Fatal(err)
	}
	result := serveRuntimeOperation(t, runtime, peer, submitted, http.StatusOK)
	if result.Status != "certified" || result.RequestID != submitted.RequestID ||
		result.Head.Body.Payload.HeadKind != "ordinary" || result.OperationTreeSize != 1 {
		t.Fatalf("unexpected certified result: %#v", result)
	}
	if err := wire.VerifyConfigQCAuthority(result.Head.HeadHash, result.ConfigQC, &result.Head,
		&status.ControlSet, nil); err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyControlOperationInclusion(&result.OperationLeaf, result.OperationLeafIndex,
		result.OperationTreeSize, result.OperationAuditPath, &result.Head); err != nil {
		t.Fatal(err)
	}

	// Reopening must campaign again, commit/apply the barrier, and preserve the
	// exact certified operation head rather than synthesizing a second result.
	reopened, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	after := serveRuntimeStatus(t, reopened, peer)
	if after.Head.HeadHash != result.Head.HeadHash || after.Raft.Term <= status.Raft.Term ||
		after.Raft.CommitIndex != after.Raft.LastApplied {
		t.Fatalf("restart recovery changed authority or left prefix unapplied: %#v", after.Raft)
	}
}

func TestControlRuntimeRejectsWrongAdminCertificate(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 18444, 18445, clock); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongRoot, wrongRootKey, err := makeCertificateAuthority("wrong root",
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM, _, _, err := makeAdminCertificate("runtime-test", "wrong-admin",
		wrongRoot, wrongRootKey, now)
	if err != nil {
		t.Fatal(err)
	}
	wrong := certificateFromPEM(t, wrongPEM)
	request := httptest.NewRequest(http.MethodGet,
		"https://10.40.0.2:18444"+privateControlStatus, nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress("10.40.0.2:18444")))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{wrong}}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong admin certificate status=%d body=%s", response.Code, response.Body.String())
	}
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedHead.Body.Payload.HeadKind != "bootstrap" {
		t.Fatal("wrong admin certificate changed certified state")
	}
}

func serveRuntimeStatus(t *testing.T, runtime *controlRuntime,
	peer *x509.Certificate) controlStatusResponseV1 {
	t.Helper()
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	request := httptest.NewRequest(http.MethodGet, "https://"+address+privateControlStatus, nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress(address)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{peer}}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var status controlStatusResponseV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), controlMaxResponseSize, &status)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
		t.Fatalf("status response not canonical: %v", err)
	}
	return status
}

func serveRuntimeOperation(t *testing.T, runtime *controlRuntime, peer *x509.Certificate,
	submitted controlOperationRequestV1, wantStatus int) controlCertifiedOperationResultV1 {
	t.Helper()
	body, err := wire.MarshalCanonical(submitted)
	if err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	request := httptest.NewRequest(http.MethodPost,
		"https://"+address+controlplane.PrivateControlOperationPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress(address)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{peer}}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("operation status=%d body=%s", response.Code, response.Body.String())
	}
	var result controlCertifiedOperationResultV1
	if wantStatus == http.StatusOK {
		canonical, err := wire.DecodeStrict(response.Body.Bytes(), controlMaxResponseSize, &result)
		if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
			t.Fatalf("operation response not canonical: %v", err)
		}
	}
	return result
}

func readAdminTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return certificateFromPEM(t, body)
}

func certificateFromPEM(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	block, trailing := pem.Decode(body)
	if block == nil || len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

type controlTestAddress string

func (address controlTestAddress) Network() string { return "tcp" }
func (address controlTestAddress) String() string  { return string(address) }

var _ net.Addr = controlTestAddress("")
