//go:build linux

package clientv2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPrivateEnrollmentClientFetchesReleasedArtifactsInResultOrder(t *testing.T) {
	attempt, inputs, _ := linuxEnrollmentAttemptFixture(t)
	if _, err := runLinuxEnrollmentAttempt(context.Background(), attempt, inputs); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadEnrollmentIdentityForResume(attempt.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := readPendingClaim(attempt.PendingPath)
	if err != nil {
		t.Fatal(err)
	}
	result, envelope, _ := linuxCompletionResultFixture(t, identity, pending)
	ref := result.ResultArtifact.SecretArtifactRefs[0]

	now := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	certificate, roots, pin := privateEnrollmentCertificate(t, now, "10.30.0.1")
	requestedPath := "/v2/enrollment/artifacts/sha256/" + ref.SealedBlob.CiphertextDigest[len("sha256:"):]
	served := envelope
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != requestedPath ||
			request.Header.Get("Accept") != "application/json" || request.Header.Get("Authorization") != "" ||
			request.Header.Get("Cookie") != "" || request.ContentLength != 0 {
			t.Errorf("artifact request 越界: method=%s path=%s headers=%v length=%d",
				request.Method, request.URL.Path, request.Header, request.ContentLength)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := wire.MarshalCanonical(served)
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_, _ = response.Write(body)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	serviceRef := wire.PrivateEnrollmentServiceRefV1{
		Schema: 1, ServiceID: "enrollment-service", OverlayIP: "10.30.0.1", TCPPort: 7444,
		InternalCAProfileRef: "internal-ca-profile", ServerIdentitySPKIPins: []string{pin}, ServiceGeneration: 1,
	}
	client, err := NewPrivateEnrollmentClient(serviceRef, roots, dial, func() time.Time { return now }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	envelopes, err := client.FetchReleasedArtifacts(context.Background(), result)
	if err != nil || len(envelopes) != 1 || !wire.EqualCanonical(envelopes[0], envelope) {
		t.Fatalf("未按 result ref 拉取 exact envelope: values=%#v err=%v", envelopes, err)
	}

	served.CiphertextAndTag = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := client.FetchReleasedArtifacts(context.Background(), result); err == nil {
		t.Fatal("接受了与 result ref 不匹配的 artifact response")
	}

}
