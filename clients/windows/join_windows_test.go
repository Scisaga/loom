//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	qrcodeencoder "github.com/skip2/go-qrcode"

	"loom/internal/clientcomponent"
	"loom/internal/clientenroll"
	"loom/internal/clientjoin"
	"loom/internal/clientreport"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/publish"
)

func TestCleanWindowsClientWaitsForQRBeforeLoadingPackagedTrust(t *testing.T) {
	_, err := ensureWindowsJoined(context.Background(), t.TempDir(), clientsecret.UserProtector{}, "")
	if !errors.Is(err, errWindowsJoinInputRequired) {
		t.Fatalf("clean client startup error = %v, want QR input required", err)
	}
}

func TestWindowsQRJoinNativeReadyTransaction(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("unsupported native architecture")
	}
	singPath := os.Getenv("LOOM_SING_BOX_AMD64_ARCHIVE")
	if runtime.GOARCH == "arm64" {
		singPath = os.Getenv("LOOM_SING_BOX_ARM64_ARCHIVE")
	}
	wintunPath := os.Getenv("LOOM_WINTUN_ARCHIVE")
	if singPath == "" || wintunPath == "" {
		t.Skip("set official archive paths to run native Windows join")
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Skipf("required Portable Mixed loopback address %s is already in use: %v", address, err)
		}
		_ = listener.Close()
	}
	singArchive, err := os.ReadFile(singPath)
	if err != nil {
		t.Fatal(err)
	}
	wintunArchive, err := os.ReadFile(wintunPath)
	if err != nil {
		t.Fatal(err)
	}
	platformPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x67}, ed25519.SeedSize))
	artifact, err := clientcomponent.BuildOfficial(runtime.GOARCH, singArchive, wintunArchive, platformPrivate)
	if err != nil {
		t.Fatal(err)
	}
	localAppData := t.TempDir()
	t.Setenv("LocalAppData", localAppData)
	root := filepath.Join(localAppData, "LoomPortable")
	componentPath := filepath.Join(t.TempDir(), artifact.Name)
	if err := os.WriteFile(componentPath, artifact.Package, 0o600); err != nil {
		t.Fatal(err)
	}

	ca, caKey, caPEM := portableTestCA(t)
	current := publish.DeploymentCurrent{
		Schema: publish.DeploymentCurrentSchema, Generation: 1, Snapshot: "0123456789ab",
		PublishedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if err := current.Sign(platformPrivate); err != nil {
		t.Fatal(err)
	}
	authority, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	secretValue := "native-windows-join-secret"
	apiSecret := "native-portable-api-secret"
	distribution := servePortableTestDistribution(t, authority, platformPrivate,
		portableTestWindowsConfig("win-enroll"))
	defer distribution.Close()
	reports := make(chan clientreport.Observation, 16)
	var claimRequests, trustRequests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/loom-client/report" {
			var observation clientreport.Observation
			if err := json.NewDecoder(r.Body).Decode(&observation); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := verifyNativeReport(&observation, caPEM); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			reports <- observation
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/client/trust" {
			trustRequests++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schema":              1,
				"platform_public_key": base64.StdEncoding.EncodeToString(platformPrivate.Public().(ed25519.PublicKey)),
			})
			return
		}
		if r.URL.Path != "/loom-client/enroll" {
			http.NotFound(w, r)
			return
		}
		claimRequests++
		var claim struct {
			Token     string `json:"token"`
			Platform  string `json:"platform"`
			CSRPEM    string `json:"csr_pem"`
			RequestID string `json:"request_id"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&claim); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if claim.Platform != clientenroll.PlatformWindowsDesktop {
			t.Errorf("claim platform=%q", claim.Platform)
		}
		if claimRequests == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(clientenroll.Response{
				Schema: clientenroll.Schema, ClientID: "win-enroll", Status: "provisioning",
				ClaimedAt:     time.Now().UTC().Format(time.RFC3339),
				Configuration: "pending", Next: "wait_for_configuration",
			})
			return
		}
		certPEM, err := portableTestNodeCertificate(ca, caKey, claim.CSRPEM, "win-enroll")
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := clientenroll.Response{
			Schema: clientenroll.Schema, ClientID: "win-enroll", Status: "ready",
			ClaimedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
			Next:      "pull", Configuration: "ready",
			Bootstrap: &clientenroll.Bootstrap{
				NodeID: "win-enroll", DistributionURLs: []string{distribution.URL},
				DNS: []string{"1.1.1.1"}, SecretsEnv: "cred/win-enroll/best-egress=" + secretValue + "\napi/win-enroll=" + apiSecret + "\n",
				PlatformPublicKey: base64.StdEncoding.EncodeToString(platformPrivate.Public().(ed25519.PublicKey)),
				ReleaseAuthority:  string(authority), CACertPEM: string(caPEM), NodeCertPEM: string(certPEM),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	expiresAt := time.Now().Add(time.Minute).Format(time.RFC3339)
	joinPayload, err := json.Marshal(struct {
		Schema            int    `json:"schema"`
		Endpoint          string `json:"endpoint"`
		Token             string `json:"token"`
		ExpiresAt         string `json:"expires_at"`
		PlatformKeySHA256 string `json:"platform_key_sha256"`
	}{Schema: 1, Endpoint: server.URL + "/loom-client/enroll", Token: token, ExpiresAt: expiresAt,
		PlatformKeySHA256: fmt.Sprintf("%x", sha256.Sum256(platformPrivate.Public().(ed25519.PublicKey)))})
	if err != nil {
		t.Fatal(err)
	}
	joinURI := "loom://enroll#" + base64.RawURLEncoding.EncodeToString(joinPayload)
	joinQR, err := qrcodeencoder.Encode(joinURI, qrcodeencoder.Medium, 320)
	if err != nil {
		t.Fatal(err)
	}
	joinQRPath := filepath.Join(t.TempDir(), "control-device-join.png")
	if err := os.WriteFile(joinQRPath, joinQR, 0o600); err != nil {
		t.Fatal(err)
	}
	invite, err := clientjoin.Read(joinQRPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	var progress []string
	result, err := joinWindowsAt(context.Background(), windowsJoinOptions{
		Root: root, ComponentPath: componentPath, Client: server.Client(),
		Protector: clientsecret.UserProtector{}, Arch: runtime.GOARCH, RetryInterval: time.Millisecond,
		Invite: invite, PlatformKey: platformPrivate.Public().(ed25519.PublicKey),
		Progress: func(detail string) {
			progress = append(progress, detail)
			if _, err := os.Stat(filepath.Join(root, "config", "client.json")); !errors.Is(err, os.ErrNotExist) {
				t.Error("progress marked the join committed before verification and installation completed")
			}
			if strings.Contains(detail, token) || strings.Contains(detail, server.URL) {
				t.Error("join progress exposed a credential or endpoint")
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 加入已经固定 platform key，不再通过远端 trust 接口建立信任。
	if claimRequests != 2 || trustRequests != 0 || result.NodeID != "win-enroll" {
		t.Fatalf("join result=%+v claims=%d trust=%d", result, claimRequests, trustRequests)
	}
	if got := strings.Join(progress, "\n"); !strings.Contains(got, "等待配置发布") || !strings.Contains(got, "已收到中控配置") {
		t.Fatalf("pending and ready responses did not update join progress: %q", got)
	}
	config, err := clientupdate.ReadConfig(filepath.Join(root, "config", "client.json"))
	if err != nil || config.NodeID != "win-enroll" {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	vault, err := clientsecret.ReadVault(filepath.Join(root, "secrets", "vault.json.dpapi"), clientsecret.UserProtector{})
	if err != nil || vault["cred/win-enroll/best-egress"] != secretValue || vault["api/win-enroll"] != apiSecret {
		t.Fatalf("vault keys=%v err=%v", mapKeys(vault), err)
	}
	for _, path := range []string{
		filepath.Join(root, "join", "identity.json.dpapi"),
		filepath.Join(root, "secrets", "vault.json.dpapi"),
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte(secretValue)) {
			t.Fatalf("protected file %s contains plaintext join material", path)
		}
	}
	if _, err := readWindowsPendingInvite(root, clientsecret.UserProtector{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed join retained its pending QR credential: %v", err)
	}
	workload, err := prepareClientAt(root, clientsecret.UserProtector{}, editionPortableMixed, server.Client())
	if err != nil {
		t.Fatalf("prepare joined Portable Mixed client: %v", err)
	}
	runContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); done <- workload(runContext) }()
	defer func() { cancel(); <-finished }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", "127.0.0.1:1080", 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case runErr := <-done:
			t.Fatalf("joined Portable Mixed exited before opening its listener: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("joined Portable Mixed did not open 127.0.0.1:1080")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Let the activation manager cross its startup-grace commit. Seeing the
	// listener alone is insufficient: a child that dies inside this window is
	// deliberately rejected and rolled back.
	select {
	case runErr := <-done:
		t.Fatalf("joined Portable Mixed exited during startup grace: %v", runErr)
	case <-time.After(dataPlaneStartupGrace + 500*time.Millisecond):
	}
	select {
	case observation := <-reports:
		if observation.Applied != current.Snapshot || observation.SelfCheck.Healthy || len(observation.SelfCheck.Problems) == 0 {
			t.Fatal("native activation did not report its snapshot and missing end-to-end health evidence")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native activation did not send a signed report")
	}
	cancel()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("stop joined Portable Mixed: %v", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("joined Portable Mixed did not stop")
	}
	select {
	case <-reports:
		t.Fatal("native workload sent a report after stopping")
	case <-time.After(100 * time.Millisecond):
	}
	tamperedPackage := append([]byte(nil), artifact.Package...)
	tamperedPackage[len(tamperedPackage)/2] ^= 0x80
	tamperedPath := filepath.Join(t.TempDir(), "tampered-windows-dataplane.zip")
	if err := os.WriteFile(tamperedPath, tamperedPackage, 0o600); err != nil {
		t.Fatal(err)
	}
	failedRoot := filepath.Join(t.TempDir(), "LoomPortable")
	if _, err := joinWindowsAt(context.Background(), windowsJoinOptions{
		Root: failedRoot, ComponentPath: tamperedPath, Client: server.Client(),
		Protector: clientsecret.UserProtector{}, Arch: runtime.GOARCH, RetryInterval: time.Millisecond,
		Invite: invite, PlatformKey: platformPrivate.Public().(ed25519.PublicKey),
	}); err == nil {
		t.Fatal("tampered component package completed Windows join")
	}
	if _, err := os.Stat(filepath.Join(failedRoot, "config", "client.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed join published its commit marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(failedRoot, "join", "identity.json.dpapi")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local component preflight touched join identity: %v", err)
	}
	wrongPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	var wrongControlClaims int
	wrongControl := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrongControlClaims++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer wrongControl.Close()
	wrongInvite := invite
	wrongInvite.Endpoint = wrongControl.URL + "/loom-client/enroll"
	wrongDigest := sha256.Sum256(wrongPrivate.Public().(ed25519.PublicKey))
	wrongInvite.PlatformKeySHA256 = hex.EncodeToString(wrongDigest[:])
	wrongRoot := filepath.Join(t.TempDir(), "LoomPortable")
	if _, err := joinWindowsAt(context.Background(), windowsJoinOptions{
		Root: wrongRoot, ComponentPath: componentPath, Client: wrongControl.Client(),
		Protector: clientsecret.UserProtector{}, Arch: runtime.GOARCH, RetryInterval: time.Millisecond,
		Invite: wrongInvite, PlatformKey: platformPrivate.Public().(ed25519.PublicKey),
	}); err == nil || !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("mismatched control trust result=%v", err)
	}
	if wrongControlClaims != 0 {
		t.Fatalf("mismatched control consumed join request: %d", wrongControlClaims)
	}
	if _, err := os.Stat(filepath.Join(wrongRoot, "join", "identity.json.dpapi")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invite trust check touched join identity: %v", err)
	}
	recoveryRoot := filepath.Join(t.TempDir(), "LoomPortable")
	blockingTarget := filepath.Join(recoveryRoot, "trust", "platform.pub")
	if err := os.MkdirAll(blockingTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	requestsBeforeRecovery := claimRequests
	if _, err := joinWindowsAt(context.Background(), windowsJoinOptions{
		Root: recoveryRoot, ComponentPath: componentPath, Client: server.Client(),
		Protector: clientsecret.UserProtector{}, Arch: runtime.GOARCH, RetryInterval: time.Millisecond,
		Invite: invite, PlatformKey: platformPrivate.Public().(ed25519.PublicKey),
	}); err == nil {
		t.Fatal("forced local commit failure unexpectedly joined")
	}
	if claimRequests != requestsBeforeRecovery+1 {
		t.Fatalf("forced recovery join requests=%d, want %d", claimRequests, requestsBeforeRecovery+1)
	}
	if _, err := os.Stat(windowsJoinReadyPath(recoveryRoot)); err != nil {
		t.Fatalf("ready response was not protected for recovery: %v", err)
	}
	if err := os.Remove(blockingTarget); err != nil {
		t.Fatal(err)
	}
	recovered, resumed, err := resumeWindowsJoinAt(windowsJoinCommitOptions{
		Root: recoveryRoot, ComponentPath: componentPath, Protector: clientsecret.UserProtector{},
		Arch: runtime.GOARCH, PlatformKey: platformPrivate.Public().(ed25519.PublicKey),
	})
	if err != nil || !resumed || recovered.NodeID != "win-enroll" {
		t.Fatalf("ready recovery result=%+v resumed=%t err=%v", recovered, resumed, err)
	}
	if claimRequests != requestsBeforeRecovery+1 {
		t.Fatalf("ready recovery repeated the one-time HTTP claim: requests=%d", claimRequests)
	}
	if _, err := os.Stat(windowsJoinReadyPath(recoveryRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed recovery journal still exists: %v", err)
	}
	if _, err := joinWindowsAt(context.Background(), windowsJoinOptions{
		Root: root, ComponentPath: componentPath, Client: server.Client(), Protector: clientsecret.UserProtector{},
		Arch: runtime.GOARCH, RetryInterval: time.Millisecond,
		Invite: invite, PlatformKey: platformPrivate.Public().(ed25519.PublicKey),
	}); err == nil || !strings.Contains(err.Error(), "已经加入网络") {
		t.Fatalf("identity replacement result=%v", err)
	}
}

func TestWindowsInviteChecksEmbeddedDeploymentFingerprintWithoutHTTP(t *testing.T) {
	key := ed25519.PublicKey(bytes.Repeat([]byte{0x31}, ed25519.PublicKeySize))
	digest := sha256.Sum256(key)
	invite := clientenroll.Invite{Endpoint: "https://control.example/loom-client/enroll", PlatformKeySHA256: hex.EncodeToString(digest[:])}
	if err := verifyWindowsInviteTrust(invite, key); err != nil {
		t.Fatalf("matching invite fingerprint: %v", err)
	}
	wrongKey := ed25519.PublicKey(bytes.Repeat([]byte{0x32}, ed25519.PublicKeySize))
	if err := verifyWindowsInviteTrust(invite, wrongKey); err == nil {
		t.Fatal("mismatched deployment fingerprint was accepted")
	}
	withoutFingerprint := invite
	withoutFingerprint.PlatformKeySHA256 = ""
	if err := verifyWindowsInviteTrust(withoutFingerprint, key); err == nil {
		t.Fatal("invite without deployment fingerprint was accepted")
	}
	for _, endpoint := range []string{
		"http://control.example/loom-client/enroll", "https://control.example/api/client/enroll",
		"https://control.example/loom-client/enroll?token=demo-secret", "https://control.example/loom-client/enroll#fragment",
	} {
		invalid := invite
		invalid.Endpoint = endpoint
		if err := verifyWindowsInviteTrust(invalid, key); err == nil || strings.Contains(err.Error(), endpoint) {
			t.Fatal("invalid enrollment endpoint accepted or exposed in diagnostics")
		}
	}
}

func TestWindowsRejectedJoinDoesNotRetryOrChangePlatform(t *testing.T) {
	// §9.2：职责由中控邀请固定。旧码或平台不匹配被拒绝后，不能降级为 Linux 或补报 server。
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusGone} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var claim struct {
					Token, Platform string
					CSRPEM          string `json:"csr_pem"`
					RequestID       string `json:"request_id"`
				}
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&claim); err != nil || claim.Platform != clientenroll.PlatformWindowsDesktop ||
					r.Method != http.MethodPost || r.URL.Path != "/loom-client/enroll" {
					t.Error("Windows claim changed the platform or declared invitation responsibilities/server facts")
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			invite := clientenroll.Invite{
				Endpoint:  server.URL + "/loom-client/enroll",
				Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
				ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
			}
			identity, err := clientenroll.GeneratePreparedIdentity(clientenroll.PlatformWindowsDesktop, invite.Endpoint, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clearPreparedIdentity(&identity)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = waitForReadyJoin(ctx, windowsJoinOptions{Invite: invite, Client: server.Client(), RetryInterval: time.Millisecond}, identity)
			if err == nil || clientenroll.IsTransient(err) || calls.Load() != 1 || ctx.Err() != nil {
				t.Fatalf("rejected join was retried or accepted: requests=%d err=%v", calls.Load(), err)
			}
		})
	}
}

func TestWindowsJoinWaitProgress(t *testing.T) {
	for _, stopPending := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", stopPending), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if !stopPending && call == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"error":"demo-sensitive-response"}`))
					return
				}
				response := clientenroll.Response{
					Schema: clientenroll.Schema, ClientID: "demo-device", Status: "provisioning",
					ClaimedAt:     time.Now().UTC().Format(time.RFC3339),
					Configuration: "pending", Next: "wait_for_configuration",
				}
				status := http.StatusAccepted
				if call == 3 {
					status = http.StatusOK
					response.Status, response.Configuration, response.Next = "ready", "ready", "pull"
					response.Bootstrap = &clientenroll.Bootstrap{NodeID: "demo-device"}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			invite := clientenroll.Invite{
				Endpoint:  server.URL + "/loom-client/enroll",
				Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
				ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
			}
			identity, err := clientenroll.GeneratePreparedIdentity(clientenroll.PlatformWindowsDesktop, invite.Endpoint, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clearPreparedIdentity(&identity)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var progress []string
			response, err := waitForReadyJoin(ctx, windowsJoinOptions{
				Invite: invite, Client: server.Client(), RetryInterval: time.Millisecond,
				Progress: func(detail string) {
					progress = append(progress, detail)
					if stopPending && strings.Contains(detail, "等待配置发布") {
						cancel()
					}
				},
			}, identity)
			if stopPending {
				if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
					t.Fatalf("cancelled join kept polling: calls=%d err=%v", calls.Load(), err)
				}
			} else if err != nil || response.Configuration != "ready" || calls.Load() != 3 {
				t.Fatalf("join did not reach ready: calls=%d err=%v", calls.Load(), err)
			}
			joined := strings.Join(progress, "\n")
			if !strings.Contains(joined, "联系中控") || !strings.Contains(joined, "等待配置发布") ||
				(!stopPending && !strings.Contains(joined, "自动重试")) {
				t.Fatalf("missing wait feedback: %q", joined)
			}
			for _, secret := range []string{invite.Token, server.URL, "demo-sensitive-response", string(identity.PrivateKeyPEM)} {
				if strings.Contains(joined, secret) {
					t.Error("progress exposed enrollment material or server diagnostics")
				}
			}
		})
	}
}

func TestWindowsJoinIdentityIsBoundToOneJoinCode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "LoomPortable")
	first := clientenroll.Invite{
		Endpoint:  "https://control.example/api/client/enroll",
		Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
	}
	identity, err := loadOrCreateWindowsIdentity(root, first, clientsecret.UserProtector{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearPreparedIdentity(&identity)
	pending, err := readWindowsPendingInvite(root, clientsecret.UserProtector{})
	if err != nil || !sameWindowsInvite(pending, first) {
		t.Fatalf("protected pending join=%+v err=%v", pending, err)
	}
	second := first
	second.Token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	if _, err := loadOrCreateWindowsIdentity(root, second, clientsecret.UserProtector{}, rand.Reader); err == nil ||
		!strings.Contains(err.Error(), "another Device join code") {
		t.Fatalf("second join code identity result=%v", err)
	}
}

func TestWindowsPendingJoinCredentialCanBeScrubbedWithoutLosingIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "LoomPortable")
	invite := clientenroll.Invite{
		Endpoint:  "https://control.example/api/client/enroll",
		Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)),
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
	}
	identity, err := loadOrCreateWindowsIdentity(root, invite, clientsecret.UserProtector{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestID := identity.RequestID
	clearPreparedIdentity(&identity)
	if err := clearWindowsPendingInvite(root, clientsecret.UserProtector{}); err != nil {
		t.Fatal(err)
	}
	if _, err := readWindowsPendingInvite(root, clientsecret.UserProtector{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending QR credential survived scrub: %v", err)
	}
	identity, err = readWindowsJoinIdentity(root, clientsecret.UserProtector{})
	if err != nil || identity.RequestID != requestID {
		t.Fatalf("durable Device identity after scrub=%+v err=%v", identity, err)
	}
	clearPreparedIdentity(&identity)
}

func portableTestWindowsConfig(node string) string {
	return fmt.Sprintf(`{
  "log": {"level": "warn"},
  "dns": {"servers": [{"tag":"dns0","address":"1.1.1.1","detour":"dns-out"}]},
  "inbounds": [
    {"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"stack":"system"},
    {"type":"mixed","tag":"in-1080","listen":"127.0.0.1","listen_port":1080}
  ],
  "outbounds": [
    {"type":"direct","tag":"dns-out"},
    {"type":"hysteria2","tag":"cand:auto:edge","server":"edge.example.com","server_port":443,"password":"${secret:cred/%s/best-egress}","tls":{"enabled":true,"server_name":"edge.node.internal","certificate_path":"C:\\ProgramData\\Loom\\tls\\ca.crt","alpn":["h3"]}},
    {"type":"selector","tag":"decl:auto","outbounds":["cand:auto:edge"],"default":"cand:auto:edge"},
    {"type":"block","tag":"block"}
  ],
  "route": {"rules":[{"inbound":["tun-in","in-1080"],"outbound":"decl:auto"}],"final":"block"},
  "experimental": {"clash_api":{"external_controller":"127.0.0.1:61800","secret":"${secret:api/%s}"}}
}`, node, node)
}

func servePortableTestDistribution(t *testing.T, current []byte, private ed25519.PrivateKey, config string) *httptest.Server {
	t.Helper()
	const node = "win-enroll"
	files := map[string]string{"sing-box/config.json": config}
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s\x00%d\x00%s\x00", "sing-box/config.json", len(config), config)
	bundleHash := hex.EncodeToString(hash.Sum(nil))
	bundle, err := json.MarshalIndent(struct {
		Owner string            `json:"owner"`
		Files map[string]string `json:"files"`
	}{Owner: node, Files: files}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.MarshalIndent(struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		SSOTHash  string `json:"ssot_hash"`
		Bundles   []struct {
			Owner string `json:"owner"`
			Hash  string `json:"hash"`
		} `json:"bundles"`
		Components []struct {
			Node    string `json:"node"`
			SingBox string `json:"sing_box"`
		} `json:"components"`
	}{
		ID: "0123456789ab", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SSOTHash: strings.Repeat("0", 64),
		Bundles: []struct {
			Owner string `json:"owner"`
			Hash  string `json:"hash"`
		}{{Owner: node, Hash: bundleHash}},
		Components: []struct {
			Node    string `json:"node"`
			SingBox string `json:"sing_box"`
		}{{Node: node, SingBox: "v1.11.4"}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, manifest)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/current.json":
			body = current
		case "/0123456789ab/snapshot.json":
			body = manifest
		case "/0123456789ab/snapshot.sig":
			body = signature
		case "/0123456789ab/nodes/win-enroll.json":
			body = bundle
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
}

func portableTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Windows join test CA"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func portableTestNodeCertificate(ca *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM, nodeID string) ([]byte, error) {
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return nil, io.ErrUnexpectedEOF
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid test CSR")
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nodeID + ".node.internal"},
		DNSNames: []string{nodeID + ".node.internal"}, NotBefore: now, NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
