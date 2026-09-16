package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestControlAdminRotationPreservesAuthorityAndSurvivesRestart(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy-", legacy), func(t *testing.T) {
			dir, admin := newAdminRotationFixture(t, legacy)
			now := time.Now().UTC().Truncate(time.Second)
			runtime, err := openControlRuntime(dir, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			oldLeaf := readAdminTestCertificate(t, filepath.Join(admin, controlAdminCertName))
			oldHead := runtime.store.Snapshot().CertifiedHead
			configBefore, _ := os.ReadFile(filepath.Join(dir, controlConfigName))
			secretsBefore, _ := os.ReadFile(filepath.Join(dir, controlSecretsName))
			browserBefore, _ := os.ReadFile(filepath.Join(dir, controlBrowserTLSName))
			next := filepath.Join(t.TempDir(), "admin")
			if err := runtime.rotateAdminCertificate(admin, next, "demo certificate replacement"); err != nil {
				t.Fatal(err)
			}
			leaf := readAdminTestCertificate(t, filepath.Join(next, controlAdminCertName))
			root := readAdminTestCertificate(t, filepath.Join(next, controlAdminRootName))
			if leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
				root.PublicKeyAlgorithm != x509.ECDSA || root.SignatureAlgorithm != x509.ECDSAWithSHA256 {
				t.Fatal("未签发完整 P-256 链")
			}
			if err := verifyAdminPKCS12(next, leaf.Raw, root.Raw); err != nil {
				t.Fatal(err)
			}
			if !runtime.adminCertificateAuthorizedLocked(leaf.Raw) || runtime.adminCertificateAuthorizedLocked(oldLeaf.Raw) {
				t.Fatal("身份切换失败")
			}
			newHead := runtime.store.Snapshot().CertifiedHead
			if oldHead.HeadHash == newHead.HeadHash || oldHead.Body.Payload.AdminACLRoot == newHead.Body.Payload.AdminACLRoot {
				t.Fatal("未提交新 ACL")
			}
			for path, before := range map[string][]byte{controlConfigName: configBefore, controlSecretsName: secretsBefore, controlBrowserTLSName: browserBefore} {
				after, _ := os.ReadFile(filepath.Join(dir, path))
				if !bytes.Equal(before, after) {
					t.Fatalf("改变了既有 %s", path)
				}
			}
			packageBefore, _ := os.ReadFile(filepath.Join(next, "admin.p12"))
			if err := runtime.rotateAdminCertificate(admin, next, "retry"); err != nil {
				t.Fatal(err)
			}
			packageAfter, _ := os.ReadFile(filepath.Join(next, "admin.p12"))
			if !bytes.Equal(packageBefore, packageAfter) {
				t.Fatal("重试重签发了证书包")
			}
			reopened, err := openControlRuntime(dir, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if !reopened.adminCertificateAuthorizedLocked(leaf.Raw) || reopened.adminCertificateAuthorizedLocked(oldLeaf.Raw) {
				t.Fatal("重启丢失轮换结果")
			}
			status := serveRuntimeStatus(t, reopened, leaf)
			var endpoint controlAdminEndpointV1
			if err := readCanonicalFile(filepath.Join(next, controlEndpointName), 1<<20, &endpoint); err != nil {
				t.Fatal(err)
			}
			op, err := newControlPingRequest(next, endpoint, status, "demo P-256 operation", now)
			if err != nil {
				t.Fatal(err)
			}
			result := serveRuntimeOperation(t, reopened, leaf, op, http.StatusOK)
			if result.Status != "certified" {
				t.Fatal("P-256 操作未 certified")
			}
			if _, err := openControlRuntime(dir, func() time.Time { return now }); err != nil {
				t.Fatal(err)
			}
			verifyP256OnlyTLS(t, reopened, next)
			// 轮换是本机维护命令，不借此给旧 ACL 增加网络写权限。
			rotation := runtime.journal.Records[0]
			request := controlOperationRequestV1{Schema: 1, ExpectedHeadHash: status.Head.HeadHash,
				RequestID: rotation.Operation.Body.OperationID, Operation: rotation.Operation}
			serveRuntimeOperation(t, reopened, leaf, request, http.StatusForbidden)
			for _, mutation := range []func(*controlAdminRotationV1){
				func(r *controlAdminRotationV1) {
					r.Payload.NextAuthorization.AllowedOperationKinds = append(r.Payload.NextAuthorization.AllowedOperationKinds, "unapproved")
				},
				func(r *controlAdminRotationV1) {
					r.NewKeyProof.AuthorSignature.Signature = r.NewKeyProof.AuthorSignature.Signature[:12]
				},
				func(r *controlAdminRotationV1) {
					r.Payload.NextAuthorization.NotAfter = now.Add(730 * 24 * time.Hour).Format(time.RFC3339)
				},
			} {
				encoded, _ := json.Marshal(rotation.AdminRotation)
				var copy controlAdminRotationV1
				if err := json.Unmarshal(encoded, &copy); err != nil {
					t.Fatal(err)
				}
				mutation(&copy)
				runtime.journal.Records[0].AdminRotation = &copy
				if err := runtime.verifyAdminRotationRecord(0); err == nil {
					t.Fatal("接受了篡改/提权轮换")
				}
			}
		})
	}
}

func TestControlAdminBundleRejectsLegacyAndIncompleteChain(t *testing.T) {
	_, legacy := newAdminRotationFixture(t, true)
	if err := exportAdminPKCS12(legacy, time.Now()); err == nil {
		t.Fatal("再次交付了 Ed25519 浏览器证书")
	}
	_, admin := newAdminRotationFixture(t, false)
	leaf := readAdminTestCertificate(t, filepath.Join(admin, controlAdminCertName))
	root := readAdminTestCertificate(t, filepath.Join(admin, controlAdminRootName))
	if err := exportAdminPKCS12(admin, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("openssl", "pkcs12", "-export", "-inkey", filepath.Join(admin, controlAdminKeyName),
		"-in", filepath.Join(admin, controlAdminCertName), "-passout", "file:"+filepath.Join(admin, "admin.p12.password"))
	incomplete, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(admin, "admin.p12"), incomplete, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAdminPKCS12(admin, leaf.Raw, root.Raw); err == nil {
		t.Fatal("接受了缺少 issuer 的旧打包方式")
	}
}

func TestControlAdminRotationExplicitlyAddsOnlyBootstrapAdvertise(t *testing.T) {
	dir, admin := newAdminRotationFixture(t, false)
	runtime, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	previous := append([]string(nil), runtime.config.Authorizations[0].AllowedOperationKinds...)
	out := filepath.Join(t.TempDir(), "admin")
	if err := runtime.rotateAdminCertificate(admin, out, "enable certified bootstrap advertise", true); err != nil {
		t.Fatal(err)
	}
	next := runtime.config.Authorizations[0].AllowedOperationKinds
	want := append(previous, controlAdvertiseBootstrapKind)
	sort.Strings(want)
	if !wire.EqualCanonical(next, want) || !validAdminRotationOperationKinds(previous, next) {
		t.Fatalf("显式 ACL 升级超出唯一允许的 kind: got=%v want=%v", next, want)
	}
	forged := append(append([]string(nil), next...), "unapproved")
	sort.Strings(forged)
	if validAdminRotationOperationKinds(previous, forged) {
		t.Fatal("管理员轮换接受了 advertise_bootstrap 之外的权限扩张")
	}
	reopened, err := openControlRuntime(dir, time.Now)
	if err != nil || !wire.EqualCanonical(reopened.config.Authorizations[0].AllowedOperationKinds, want) {
		t.Fatalf("重启丢失显式 ACL 升级: %v", err)
	}
}

func TestControlAdminRotationRecoversPreparedRecordWithoutChangingDeliveredKey(t *testing.T) {
	dir, admin := newAdminRotationFixture(t, true)
	runtime, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	raftBefore, _ := os.ReadFile(filepath.Join(dir, controlRaftName))
	stateBefore, _ := os.ReadFile(filepath.Join(dir, controlStateName))
	out := filepath.Join(t.TempDir(), "admin")
	if err := runtime.rotateAdminCertificate(admin, out, "demo prepare recovery"); err != nil {
		t.Fatal(err)
	}
	packageBefore, _ := os.ReadFile(filepath.Join(out, "admin.p12"))
	// 模拟只写入准备日志就退出：Raft 尚未接收候选，交付 key 已落盘。
	runtime.journal.Records[0].Result = nil
	if err := writeCanonicalAtomic(filepath.Join(dir, controlJournalName), runtime.journal, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{controlRaftName: raftBefore, controlStateName: stateBefore} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := openControlRuntime(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.rotateAdminCertificate(admin, out, "demo resumed preparation"); err != nil {
		t.Fatal(err)
	}
	packageAfter, _ := os.ReadFile(filepath.Join(out, "admin.p12"))
	if !bytes.Equal(packageBefore, packageAfter) || len(reopened.journal.Records) != 1 {
		t.Fatal("恢复改变了交付 key 或重复提交")
	}
	if err := os.Remove(filepath.Join(out, "rotation-receipt.json")); err != nil {
		t.Fatal(err)
	}
	if err := reopened.rotateAdminCertificate(admin, out, "demo receipt recovery"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "rotation-receipt.json")); err != nil {
		t.Fatal(err)
	}
}

func newAdminRotationFixture(t *testing.T, legacy bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir, admin := filepath.Join(root, "state"), filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(dir, admin, "demo-cluster", "00000000000000000000000000",
		"demo-control", net.IPv4(10, 40, 0, 2).String(), 17444, 17445, clock); err != nil {
		t.Fatal(err)
	}
	if !legacy {
		return dir, admin
	}
	// 回归夹具重建升级前的 Ed25519 genesis，不触碰真实控制状态。
	rootPEM, issuer, key, err := makeCertificateAuthority("demo legacy admin CA", now.Add(-5*time.Minute), now.Add(5*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, keyPEM, der, err := makeAdminCertificate("demo-cluster", "admin-primary", issuer, key, now)
	if err != nil {
		t.Fatal(err)
	}
	profile, authorization, err := makeAdminAuthority("demo-cluster", issuer.Raw, der, now)
	if err != nil {
		t.Fatal(err)
	}
	var config controlDiskConfigV1
	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(dir, controlConfigName), 8<<20, &config); err != nil {
		t.Fatal(err)
	}
	if err := readCanonicalFile(filepath.Join(dir, controlSecretsName), 8<<20, &secrets); err != nil {
		t.Fatal(err)
	}
	config.AdminProfiles = map[string]wire.AdminCertificateProfileV1{profile.ProfileID: profile}
	config.Authorizations = []wire.AdminAuthorizationV1{authorization}
	rootKeyPEM, _ := privateKeyPKCS8PEM(key)
	secrets.AdminCAPrivateKeyPKCS8PEM = string(rootKeyPEM)
	for name, content := range map[string][]byte{controlAdminCertName: leafPEM, controlAdminKeyName: keyPEM, controlAdminRootName: rootPEM} {
		if err := os.WriteFile(filepath.Join(admin, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	aclRoot, _ := wire.AdminACLRoot(config.Authorizations, config.AdminProfiles)
	setHash, _ := wire.ControlSetHash(&config.ControlSet)
	directoryHash, _ := wire.ControlPeerDirectoryHash(&config.ControlSet, &config.PeerDirectory)
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(admin, controlEndpointName), 1<<20, &endpoint); err != nil {
		t.Fatal(err)
	}
	internalRoot, _ := base64.RawURLEncoding.DecodeString(endpoint.InternalRootDER)
	config.GenesisEvidence = makeControlGenesisEvidence(config.ClusterID, setHash, directoryHash, aclRoot, internalRoot, issuer.Raw)
	if err := writeCanonicalAtomic(filepath.Join(dir, controlConfigName), config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonicalAtomic(filepath.Join(dir, controlSecretsName), secrets, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{controlRaftName, controlStateName} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := openControlRuntime(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.commitGenesis(now, aclRoot, directoryHash); err != nil {
		t.Fatal(err)
	}
	return dir, admin
}

func verifyP256OnlyTLS(t *testing.T, runtime *controlRuntime, admin string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime.config.ControlPort = int64(listener.Addr().(*net.TCPAddr).Port)
	runtime.uiReadOnly = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "demo-read-only") })
	runtime.uiAdmin = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "demo-admin") })
	server := &http.Server{Handler: runtime.controlHandler(), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(tls.NewListener(listener, runtime.controlServerTLSConfig(runtime.browserTLS)))
	cmd := exec.Command("openssl", "s_client", "-connect", listener.Addr().String(), "-tls1_3",
		"-sigalgs", "ecdsa_secp256r1_sha256", "-CAfile", filepath.Join(admin, controlInternalRootName),
		"-verify_return_error", "-verify_ip", "127.0.0.1", "-cert", filepath.Join(admin, controlAdminCertName),
		"-key", filepath.Join(admin, controlAdminKeyName), "-cert_chain", filepath.Join(admin, controlAdminRootName), "-quiet")
	cmd.Stdin = bytes.NewBufferString("GET / HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\nConnection: close\r\n\r\n")
	output, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("demo-admin")) {
		t.Fatalf("仅 P-256 的真实 mTLS 认证失败: %v\n%s", err, output)
	}
}
