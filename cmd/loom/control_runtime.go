package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"os/signal"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"loom/internal/controlplane"
	"loom/internal/dnsprovider"
	"loom/internal/webui"
	"loom/internal/wire"
)

const (
	controlConfigName       = "config.json"
	controlSecretsName      = "secrets.json"
	controlJournalName      = "operations.json"
	controlRaftName         = "raft.json"
	controlStateName        = "control-state.json"
	controlBrowserTLSName   = "browser-tls.json"
	controlAdminCertName    = "admin.crt"
	controlAdminKeyName     = "admin.key"
	controlAdminRootName    = "admin-root.crt"
	controlInternalRootName = "control-root.crt"
	controlEndpointName     = "endpoint.json"
	privateControlStatus    = "/private/v2/control/status"
	controlPingKind         = "control_ping"
	controlMaxResponseSize  = 8 << 20
	controlLoopbackIP       = "127.0.0.1"
)

var controlOperationSchemas = wire.OperationSchemaRegistry{controlPingKind: 1, dnsprovider.BindingOperationKind: 1}

type controlDiskConfigV1 struct {
	Schema          int                                       `json:"schema"`
	ClusterID       string                                    `json:"cluster_id"`
	MemberID        string                                    `json:"member_id"`
	DeviceID        string                                    `json:"device_id"`
	OverlayIP       string                                    `json:"overlay_ip"`
	ControlPort     int64                                     `json:"control_port"`
	RaftPort        int64                                     `json:"raft_port"`
	ControlSet      wire.ControlSetV1                         `json:"control_set"`
	PeerDirectory   wire.ControlPeerDirectoryV1               `json:"peer_directory"`
	ControlService  wire.PrivateControlServiceV1              `json:"control_service"`
	AdminProfiles   map[string]wire.AdminCertificateProfileV1 `json:"admin_profiles"`
	Authorizations  []wire.AdminAuthorizationV1               `json:"authorizations"`
	GenesisEvidence controlGenesisEvidenceV1                  `json:"genesis_evidence"`
}

type controlGenesisEvidenceV1 struct {
	Schema                      int    `json:"schema"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	SnapshotHash                string `json:"snapshot_hash"`
	EffectiveSSOTHash           string `json:"effective_ssot_hash"`
	DeviceViewsRoot             string `json:"device_views_root"`
	CAProfileRoot               string `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string `json:"bootstrap_issuer_registry_root"`
	TransitionProofHash         string `json:"transition_proof_hash"`
}

type controlDiskSecretsV1 struct {
	Schema                       int    `json:"schema"`
	MembershipPrivateKey         string `json:"membership_private_key"`
	ConfigPrivateKey             string `json:"config_private_key"`
	EnrollmentPrivateKey         string `json:"enrollment_private_key"`
	ControlTLSCertificate        string `json:"control_tls_certificate"`
	ControlTLSPrivateKey         string `json:"control_tls_private_key"`
	PeerTLSCertificate           string `json:"peer_tls_certificate"`
	PeerTLSPrivateKey            string `json:"peer_tls_private_key"`
	InternalCAPrivateKeyPKCS8PEM string `json:"internal_ca_private_key_pkcs8_pem"`
	AdminCAPrivateKeyPKCS8PEM    string `json:"admin_ca_private_key_pkcs8_pem"`
}

type controlBrowserTLSV1 struct {
	Schema                 int    `json:"schema"`
	CertificateChainPEM    string `json:"certificate_chain_pem"`
	PrivateKeyPKCS8PEM     string `json:"private_key_pkcs8_pem"`
	RootPrivateKeyPKCS8PEM string `json:"root_private_key_pkcs8_pem"`
}

type controlOperationRecordV1 struct {
	Schema        int                                `json:"schema"`
	Operation     wire.ControlOperationV1            `json:"operation"`
	Payload       json.RawMessage                    `json:"payload,omitempty"`
	Leaf          wire.ControlOperationLeafV1        `json:"leaf"`
	Candidate     wire.HeadEntryV2                   `json:"candidate"`
	Result        *controlCertifiedOperationResultV1 `json:"result,omitempty"`
	AdminRotation *controlAdminRotationV1            `json:"admin_rotation,omitempty"`
}

type controlOperationJournalV1 struct {
	Schema  int                        `json:"schema"`
	Records []controlOperationRecordV1 `json:"records"`
}

type controlAdminEndpointV1 struct {
	Schema           int                          `json:"schema"`
	ClusterID        string                       `json:"cluster_id"`
	AdminID          string                       `json:"admin_id"`
	Service          wire.PrivateControlServiceV1 `json:"service"`
	InternalRootDER  string                       `json:"internal_root_der"`
	AdminCertificate string                       `json:"admin_certificate"`
	AdminPrivateKey  string                       `json:"admin_private_key"`
}

type controlStatusResponseV1 struct {
	Schema     int                          `json:"schema"`
	ClusterID  string                       `json:"cluster_id"`
	MemberID   string                       `json:"member_id"`
	Quorum     int                          `json:"quorum"`
	Head       wire.HeadEntryV2             `json:"head"`
	ConfigQC   json.RawMessage              `json:"config_qc"`
	ControlSet wire.ControlSetV1            `json:"control_set"`
	Raft       controlRaftStatusV1          `json:"raft"`
	Service    wire.PrivateControlServiceV1 `json:"service"`
}

type controlRaftStatusV1 struct {
	Term        int64 `json:"term"`
	CommitIndex int64 `json:"commit_index"`
	LastApplied int64 `json:"last_applied"`
}

type controlOperationRequestV1 struct {
	Schema           int                     `json:"schema"`
	ExpectedHeadHash string                  `json:"expected_head_hash"`
	RequestID        string                  `json:"request_id"`
	Operation        wire.ControlOperationV1 `json:"operation"`
	Payload          json.RawMessage         `json:"payload,omitempty"`
}

type controlCertifiedOperationResultV1 struct {
	Schema             int                         `json:"schema"`
	Status             string                      `json:"status"`
	RequestID          string                      `json:"request_id"`
	Head               wire.HeadEntryV2            `json:"head"`
	ConfigQC           json.RawMessage             `json:"config_qc"`
	OperationLeaf      wire.ControlOperationLeafV1 `json:"operation_leaf"`
	OperationLeafIndex int64                       `json:"operation_leaf_index"`
	OperationTreeSize  int64                       `json:"operation_tree_size"`
	OperationAuditPath []string                    `json:"operation_audit_path"`
}

type controlRuntime struct {
	mu         sync.Mutex
	dir        string
	config     controlDiskConfigV1
	journal    controlOperationJournalV1
	configKey  ed25519.PrivateKey
	controlTLS tls.Certificate
	browserTLS tls.Certificate
	peerTLS    tls.Certificate
	storage    *controlplane.RaftStorage
	store      *controlplane.Store
	leader     *controlplane.StableRaftLeader
	service    *controlplane.PrivateControlService
	uiReadOnly http.Handler
	uiAdmin    http.Handler
	now        func() time.Time
}

func cmdControl(args []string) error {
	if len(args) == 0 {
		return errors.New("control 需要 bootstrap、enable-loopback、rotate-admin、export-admin、serve、status 或 request")
	}
	switch args[0] {
	case "bootstrap":
		return cmdControlBootstrap(args[1:])
	case "enable-loopback":
		return cmdControlEnableLoopback(args[1:])
	case "rotate-admin":
		return cmdControlRotateAdmin(args[1:])
	case "export-admin":
		return cmdControlExportAdmin(args[1:])
	case "serve":
		return cmdControlServe(args[1:])
	case "status":
		return cmdControlStatus(args[1:])
	case "request":
		return cmdControlRequest(args[1:])
	default:
		return fmt.Errorf("未知 control 子命令 %q", args[0])
	}
}

func cmdControlEnableLoopback(args []string) error {
	fs := flag.NewFlagSet("control enable-loopback", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom-control", "控制面状态目录")
	adminDir := fs.String("admin-dir", "", "包含 endpoint.json 的管理员交付目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" {
		return errors.New("control enable-loopback 必须指定 -admin-dir，且不接受位置参数")
	}
	return enableControlLoopback(*dir, *adminDir, time.Now)
}

func cmdControlBootstrap(args []string) error {
	fs := flag.NewFlagSet("control bootstrap", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom-control", "root-only 控制面状态目录")
	adminOut := fs.String("admin-out", "", "管理员证书/私钥交付目录（默认 state-dir/admin）")
	clusterID := fs.String("cluster-id", "", "v2 cluster ID")
	memberID := fs.String("member-id", "", "初始 N=1 ULID member ID（默认安全随机生成）")
	deviceID := fs.String("device-id", "", "已入网 control Device ID")
	overlayIP := fs.String("overlay-ip", "", "private overlay IP")
	controlPort := fs.Int64("control-port", 7444, "private control_api TCP port")
	raftPort := fs.Int64("raft-port", 7445, "private Raft TCP port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *overlayIP == "" || *clusterID == "" || *deviceID == "" {
		return errors.New("control bootstrap 必须指定 -cluster-id、-device-id 和 -overlay-ip，且不能有位置参数")
	}
	if *adminOut == "" {
		*adminOut = filepath.Join(*dir, "admin")
	}
	if *memberID == "" {
		generated, err := newControlMemberID()
		if err != nil {
			return err
		}
		*memberID = generated
	}
	return bootstrapControlRuntime(*dir, *adminOut, *clusterID, *memberID, *deviceID,
		*overlayIP, *controlPort, *raftPort, time.Now)
}

func cmdControlServe(args []string) error {
	fs := flag.NewFlagSet("control serve", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom-control", "控制面状态目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control serve 不接受位置参数")
	}
	unlock, err := lockControlState(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	runtime, err := openControlRuntime(*dir, time.Now)
	if err != nil {
		return err
	}
	return runtime.serve()
}

func cmdControlStatus(args []string) error {
	fs := flag.NewFlagSet("control status", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "包含 endpoint.json 的管理员交付目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" {
		return errors.New("control status 必须指定 -admin-dir")
	}
	endpoint, client, err := loadControlAdminClient(*adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	status, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		return err
	}
	body, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(body))
	return nil
}

func cmdControlRequest(args []string) error {
	fs := flag.NewFlagSet("control request", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "包含 endpoint.json 的管理员交付目录")
	kind := fs.String("kind", controlPingKind, "已登记 operation kind")
	reason := fs.String("reason", "operator control-plane reachability check", "审计理由")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" || strings.TrimSpace(*reason) == "" {
		return errors.New("control request 必须指定 -admin-dir 和非空 -reason")
	}
	if *kind != controlPingKind {
		return fmt.Errorf("当前生产 reducer 只登记 %q；未实现的操作不会被假提交", controlPingKind)
	}
	endpoint, client, err := loadControlAdminClient(*adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	status, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		return err
	}
	request, err := newControlPingRequest(*adminDir, endpoint, status, *reason, time.Now())
	if err != nil {
		return err
	}
	result, err := submitControlOperation(context.Background(), *adminDir, endpoint, client, status, request)
	if err != nil {
		return err
	}
	body, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(body))
	return nil
}

func enableControlLoopback(dir, adminDir string, now func() time.Time) error {
	if now == nil {
		return errors.New("control loopback 证书迁移需要可信时间源")
	}
	var config controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(dir, controlConfigName), 8<<20, &config); err != nil {
		return err
	}
	if config.Schema != 1 || config.ClusterID == "" || config.OverlayIP != config.ControlService.OverlayIP ||
		config.ControlPort != config.ControlService.Port || net.ParseIP(config.OverlayIP) == nil {
		return errors.New("control config header/authority 不一致")
	}
	if err := wire.ValidatePrivateControlService(&config.ControlService); err != nil {
		return err
	}

	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(dir, controlSecretsName), 8<<20, &secrets); err != nil {
		return err
	}
	if secrets.Schema != 1 {
		return errors.New("control secrets schema 无效")
	}
	controlTLS, err := tls.X509KeyPair([]byte(secrets.ControlTLSCertificate),
		[]byte(secrets.ControlTLSPrivateKey))
	if err != nil || len(controlTLS.Certificate) != 2 {
		return errors.New("control TLS 必须是精确的 leaf + internal root chain")
	}
	leaf, err := x509.ParseCertificate(controlTLS.Certificate[0])
	if err != nil {
		return fmt.Errorf("control TLS leaf: %w", err)
	}
	issuer, err := x509.ParseCertificate(controlTLS.Certificate[1])
	if err != nil {
		return fmt.Errorf("control TLS internal root: %w", err)
	}
	issuerKey, err := parsePrivateKeyPKCS8PEM([]byte(secrets.InternalCAPrivateKeyPKCS8PEM))
	if err != nil {
		return fmt.Errorf("internal CA private key: %w", err)
	}
	issuerPublic, issuerIsEd25519 := issuer.PublicKey.(ed25519.PublicKey)
	_, leafIsEd25519 := leaf.PublicKey.(ed25519.PublicKey)
	if !issuer.IsCA || !issuerIsEd25519 || !leafIsEd25519 ||
		!bytes.Equal(issuerPublic, issuerKey.Public().(ed25519.PublicKey)) ||
		issuer.CheckSignatureFrom(issuer) != nil || leaf.CheckSignatureFrom(issuer) != nil {
		return errors.New("control TLS leaf/internal CA authority 不一致")
	}
	instant := now().UTC()
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: config.OverlayIP, Roots: roots,
		CurrentTime: instant, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("既有 control TLS leaf 无法验证 overlay identity: %w", err)
	}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(spki[:])
	if !containsText(config.ControlService.SPKIPins, pin) {
		return errors.New("既有 control TLS leaf 不在 certified service pin set")
	}

	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		return err
	}
	endpointRoot, err := base64.RawURLEncoding.DecodeString(endpoint.InternalRootDER)
	if err != nil || endpoint.Schema != 1 || endpoint.ClusterID != config.ClusterID ||
		!wire.EqualCanonical(endpoint.Service, config.ControlService) || !bytes.Equal(endpointRoot, issuer.Raw) {
		return errors.New("admin 交付目录与 control internal authority 不一致")
	}
	browserRootPath := filepath.Join(adminDir, controlInternalRootName)
	existingRoot, rootReadErr := readOwnerOnlyFile(browserRootPath, 1<<20)
	if rootReadErr != nil && !errors.Is(rootReadErr, os.ErrNotExist) {
		return rootReadErr
	}

	browserPath := filepath.Join(dir, controlBrowserTLSName)
	var browserRoot *x509.Certificate
	created := false
	if _, statErr := os.Lstat(browserPath); errors.Is(statErr, os.ErrNotExist) {
		browserState, _, generatedRoot, makeErr := makeControlBrowserTLS(config.ClusterID,
			config.OverlayIP, instant)
		if makeErr != nil {
			return makeErr
		}
		if len(existingRoot) > 0 {
			existingCertificate, parseErr := parseSingleCertificatePEM(existingRoot)
			if parseErr != nil || !bytes.Equal(existingCertificate.Raw, issuer.Raw) {
				return errors.New("既有浏览器 trust root 不是当前 internal root，拒绝覆盖")
			}
		}
		if _, raceErr := os.Lstat(browserPath); !errors.Is(raceErr, os.ErrNotExist) {
			return errors.New("browser TLS state 在迁移期间发生并发变化")
		}
		if err := writeCanonicalAtomic(browserPath, browserState, 0o600); err != nil {
			return err
		}
		browserRoot = generatedRoot
		created = true
	} else if statErr != nil {
		return statErr
	} else {
		_, _, loadedRoot, loadErr := loadControlBrowserTLS(browserPath, config.ClusterID,
			config.OverlayIP, instant)
		if loadErr != nil {
			return loadErr
		}
		browserRoot = loadedRoot
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: browserRoot.Raw})
	if len(existingRoot) == 0 || !bytes.Equal(existingRoot, rootPEM) {
		if len(existingRoot) > 0 {
			existingCertificate, parseErr := parseSingleCertificatePEM(existingRoot)
			if parseErr != nil || (!bytes.Equal(existingCertificate.Raw, issuer.Raw) &&
				!bytes.Equal(existingCertificate.Raw, browserRoot.Raw)) {
				return errors.New("浏览器 trust root 在迁移期间发生冲突，拒绝覆盖")
			}
		}
		if err := writeBytesAtomic(browserRootPath, rootPEM, 0o600); err != nil {
			return err
		}
		created = true
	}
	if created {
		fmt.Printf("✓ P-256 browser TLS identity 已就绪并更新 %s；重启 control 后生效\n",
			browserRootPath)
	} else {
		fmt.Printf("✓ P-256 browser TLS identity 已存在，未改写 authority\n")
	}
	return nil
}

func bootstrapControlRuntime(dir, adminOut, clusterID, memberID, deviceID, overlayIP string,
	controlPort, raftPort int64, now func() time.Time) error {
	address, err := netip.ParseAddr(overlayIP)
	if err != nil || address.String() != overlayIP || !address.IsPrivate() ||
		controlPort < 1 || controlPort > 65535 || raftPort < 1 || raftPort > 65535 ||
		controlPort == raftPort || clusterID == "" || !wire.ValidMemberID(memberID) || deviceID == "" {
		return errors.New("control bootstrap 的 identity/private overlay/port 无效")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("状态目录 %s 已存在；bootstrap 绝不覆盖既有 authority", dir)
		}
		return err
	}
	if _, err := os.Lstat(adminOut); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("admin 交付目录 %s 已存在；bootstrap 拒绝覆盖", adminOut)
		}
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(dir)
			_ = os.RemoveAll(adminOut)
		}
	}()
	instant := now().UTC().Truncate(time.Second)
	membershipPublic, membershipPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	configPublic, configPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	enrollmentPublic, enrollmentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	membershipID, _ := wire.ControlKeyID(membershipPublic)
	configID, _ := wire.ControlKeyID(configPublic)
	enrollmentID, _ := wire.ControlKeyID(enrollmentPublic)
	member := wire.ControlMemberV1{Schema: 1, ClusterID: clusterID, MemberID: memberID,
		MembershipKeyID: membershipID, MembershipPublicKey: base64.RawURLEncoding.EncodeToString(membershipPublic),
		ConfigKeyID: configID, ConfigPublicKey: base64.RawURLEncoding.EncodeToString(configPublic),
		EnrollmentKeyID: enrollmentID, EnrollmentPublicKey: base64.RawURLEncoding.EncodeToString(enrollmentPublic),
		MinimumControlProtocol: 2}
	set := wire.ControlSetV1{Schema: 1, ClusterID: clusterID, Members: []wire.ControlMemberV1{member}}
	setHash, err := wire.ControlSetHash(&set)
	if err != nil {
		return err
	}

	peerCertPEM, peerKeyPEM, peerDER, err := makeControlPeerCertificate(clusterID, memberID, overlayIP, instant)
	if err != nil {
		return err
	}
	peerCertificate, _ := x509.ParseCertificate(peerDER)
	peerSPKI, _ := wire.HashBytes(wire.DomainControlPeerIdentitySPKI, peerCertificate.RawSubjectPublicKeyInfo)
	peerCertHash, _ := wire.HashBytes(wire.DomainControlPeerCertificate, peerDER)
	peerArtifactHash := wire.HashRaw("loom-control-peer-artifact-v1", peerCertPEM)
	hidingNonce := make([]byte, 32)
	if _, err := rand.Read(hidingNonce); err != nil {
		return err
	}
	peerDirectory := wire.ControlPeerDirectoryV1{Schema: 1, ClusterID: clusterID, DirectoryGeneration: 1,
		HidingNonce: base64.RawURLEncoding.EncodeToString(hidingNonce),
		Members: []wire.ControlPeerDirectoryMemberV1{{Schema: 1, ClusterID: clusterID, MemberID: memberID,
			DeviceID: deviceID, PeerIdentitySPKIHash: peerSPKI, PeerIdentityArtifactHash: peerArtifactHash,
			PeerCertificateDER: base64.RawURLEncoding.EncodeToString(peerDER), PeerCertificateHash: peerCertHash,
			PeerEndpoints: []wire.ControlPeerEndpointV1{{EndpointID: "raft-" + memberID,
				URL: fmt.Sprintf("https://%s:%d", overlayIP, raftPort)}}, FaultDomain: "single-member"}}}
	peerDirectoryHash, err := wire.ControlPeerDirectoryHash(&set, &peerDirectory)
	if err != nil {
		return err
	}

	internalRootPEM, internalRoot, internalRootKey, err := makeCertificateAuthority(
		"Loom v2 internal control CA", instant.Add(-5*time.Minute), instant.Add(5*365*24*time.Hour))
	if err != nil {
		return err
	}
	controlCertPEM, controlKeyPEM, controlDER, err := makeControlServerCertificate(
		clusterID, overlayIP, internalRoot, internalRootKey, instant)
	if err != nil {
		return err
	}
	controlCertificate, _ := x509.ParseCertificate(controlDER)
	controlSPKISum := sha256.Sum256(controlCertificate.RawSubjectPublicKeyInfo)
	controlPin := "sha256:" + hex.EncodeToString(controlSPKISum[:])
	service := wire.PrivateControlServiceV1{ServiceID: "control-api-" + memberID, Role: "control_api",
		OverlayIP: overlayIP, Port: controlPort, CertificateProfileRef: "internal-control-api-server-v1",
		SPKIPins: []string{controlPin}, AuthorizedSubjectProfiles: []string{"admin-client-v1"}}
	if err := wire.ValidatePrivateControlService(&service); err != nil {
		return err
	}
	browserState, _, browserRoot, err := makeControlBrowserTLS(clusterID, overlayIP, instant)
	if err != nil {
		return err
	}

	adminRootPEM, adminRoot, adminRootKey, err := makeP256AdminCA(
		"Loom v2 admin root", instant.Add(-5*time.Minute), instant.Add(5*365*24*time.Hour))
	if err != nil {
		return err
	}
	adminCertPEM, adminKeyPEM, adminDER, err := makeAdminCertificate(
		clusterID, "admin-primary", adminRoot, adminRootKey, instant)
	if err != nil {
		return err
	}
	profile, authorization, err := makeAdminAuthority(clusterID, adminRoot.Raw, adminDER, instant)
	if err != nil {
		return err
	}
	profiles := map[string]wire.AdminCertificateProfileV1{profile.ProfileID: profile}
	aclRoot, err := wire.AdminACLRoot([]wire.AdminAuthorizationV1{authorization}, profiles)
	if err != nil {
		return err
	}
	evidence := makeControlGenesisEvidence(clusterID, setHash, peerDirectoryHash, aclRoot,
		internalRoot.Raw, adminRoot.Raw)
	config := controlDiskConfigV1{Schema: 1, ClusterID: clusterID, MemberID: memberID, DeviceID: deviceID,
		OverlayIP: overlayIP, ControlPort: controlPort, RaftPort: raftPort, ControlSet: set,
		PeerDirectory: peerDirectory, ControlService: service, AdminProfiles: profiles,
		Authorizations: []wire.AdminAuthorizationV1{authorization}, GenesisEvidence: evidence}
	internalCAKeyPEM, err := privateKeyPKCS8PEM(internalRootKey)
	if err != nil {
		return err
	}
	adminCAKeyPEM, err := privateKeyPKCS8PEM(adminRootKey)
	if err != nil {
		return err
	}
	secrets := controlDiskSecretsV1{Schema: 1,
		MembershipPrivateKey:  base64.RawURLEncoding.EncodeToString(membershipPrivate),
		ConfigPrivateKey:      base64.RawURLEncoding.EncodeToString(configPrivate),
		EnrollmentPrivateKey:  base64.RawURLEncoding.EncodeToString(enrollmentPrivate),
		ControlTLSCertificate: string(append(controlCertPEM, internalRootPEM...)),
		ControlTLSPrivateKey:  string(controlKeyPEM), PeerTLSCertificate: string(peerCertPEM),
		PeerTLSPrivateKey: string(peerKeyPEM), InternalCAPrivateKeyPKCS8PEM: string(internalCAKeyPEM),
		AdminCAPrivateKeyPKCS8PEM: string(adminCAKeyPEM)}
	if err := writeCanonicalAtomic(filepath.Join(dir, controlConfigName), config, 0o600); err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(dir, controlSecretsName), secrets, 0o600); err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(dir, controlBrowserTLSName), browserState, 0o600); err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(dir, controlJournalName),
		controlOperationJournalV1{Schema: 1, Records: []controlOperationRecordV1{}}, 0o600); err != nil {
		return err
	}
	if err := writeAdminDelivery(adminOut, config, internalRoot.Raw, browserRoot.Raw, adminCertPEM, adminKeyPEM,
		adminRootPEM, instant); err != nil {
		return err
	}
	runtime, err := openControlRuntime(dir, func() time.Time { return instant })
	if err != nil {
		return err
	}
	if runtime.store.Snapshot().CertifiedHead == nil {
		if err := runtime.commitGenesis(instant, aclRoot, peerDirectoryHash); err != nil {
			return err
		}
	}
	committed = true
	fmt.Printf("✓ v2 N=1 ControlSet 已初始化\n  state: %s\n  admin: %s\n  control: https://%s:%d\n",
		dir, adminOut, overlayIP, controlPort)
	return nil
}

func makeControlGenesisEvidence(clusterID, setHash, directoryHash, aclRoot string,
	internalRoot, adminRoot []byte) controlGenesisEvidenceV1 {
	preimage := struct {
		Schema        int    `json:"schema"`
		ClusterID     string `json:"cluster_id"`
		ControlSet    string `json:"control_set_hash"`
		PeerDirectory string `json:"peer_directory_hash"`
		AdminACL      string `json:"admin_acl_root"`
	}{1, clusterID, setHash, directoryHash, aclRoot}
	hash := func(domain string, value any) string {
		encoded, _ := wire.MarshalCanonical(value)
		return wire.HashRaw(domain, encoded)
	}
	return controlGenesisEvidenceV1{Schema: 1,
		RecoveryStatementHash: hash("loom-runtime-recovery-statement-v1", preimage),
		RecoveryPolicyHash: hash("loom-runtime-recovery-policy-v1", struct {
			Schema int    `json:"schema"`
			Root   string `json:"admin_root"`
		}{1, base64.RawURLEncoding.EncodeToString(adminRoot)}),
		SnapshotHash:      hash("loom-runtime-snapshot-v1", preimage),
		EffectiveSSOTHash: hash("loom-runtime-effective-ssot-v1", preimage),
		DeviceViewsRoot: hash("loom-runtime-device-views-v1", struct {
			Schema int `json:"schema"`
		}{1}),
		CAProfileRoot: hash("loom-runtime-ca-profiles-v1", struct {
			Schema   int    `json:"schema"`
			Internal string `json:"internal"`
			Admin    string `json:"admin"`
		}{1, base64.RawURLEncoding.EncodeToString(internalRoot), base64.RawURLEncoding.EncodeToString(adminRoot)}),
		BootstrapIssuerRegistryRoot: hash("loom-runtime-bootstrap-issuers-v1", struct {
			Schema int `json:"schema"`
		}{1}),
		TransitionProofHash: hash("loom-runtime-v1-v2-transition-anchor-v1", preimage)}
}

func openControlRuntime(dir string, now func() time.Time) (*controlRuntime, error) {
	if now == nil {
		return nil, errors.New("control runtime 需要可信时间源")
	}
	var config controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(dir, controlConfigName), 8<<20, &config); err != nil {
		return nil, err
	}
	if config.Schema != 1 || config.ClusterID != config.ControlSet.ClusterID ||
		config.OverlayIP != config.ControlService.OverlayIP || config.ControlPort != config.ControlService.Port {
		return nil, errors.New("control config header/authority 不一致")
	}
	if err := wire.ValidateControlSet(&config.ControlSet); err != nil {
		return nil, err
	}
	if len(config.ControlSet.Members) != 1 || config.ControlSet.Members[0].MemberID != config.MemberID ||
		len(config.PeerDirectory.Members) != 1 || config.PeerDirectory.Members[0].DeviceID != config.DeviceID ||
		len(config.PeerDirectory.Members[0].PeerEndpoints) != 1 ||
		config.PeerDirectory.Members[0].PeerEndpoints[0].URL !=
			fmt.Sprintf("https://%s:%d", config.OverlayIP, config.RaftPort) {
		return nil, errors.New("N=1 config 的 member/Device/Raft tuple 不一致")
	}
	if err := wire.ValidateControlPeerDirectoryAt(&config.ControlSet, &config.PeerDirectory, now().UTC()); err != nil {
		return nil, err
	}
	if err := wire.ValidatePrivateControlService(&config.ControlService); err != nil {
		return nil, err
	}
	aclRoot, err := wire.AdminACLRoot(config.Authorizations, config.AdminProfiles)
	if err != nil {
		return nil, err
	}
	if aclRoot == "" || len(config.Authorizations) != 1 {
		return nil, errors.New("control config 必须包含精确初始 admin authority")
	}
	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(dir, controlSecretsName), 8<<20, &secrets); err != nil {
		return nil, err
	}
	if secrets.Schema != 1 {
		return nil, errors.New("control secrets schema 无效")
	}
	member := config.ControlSet.Members[0]
	privateKeys := []struct {
		encoded string
		public  string
		purpose string
	}{{secrets.MembershipPrivateKey, member.MembershipPublicKey, "membership"},
		{secrets.ConfigPrivateKey, member.ConfigPublicKey, "config"},
		{secrets.EnrollmentPrivateKey, member.EnrollmentPublicKey, "enrollment"}}
	decodedKeys := make([]ed25519.PrivateKey, len(privateKeys))
	for index, candidate := range privateKeys {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(candidate.encoded)
		if decodeErr != nil || len(decoded) != ed25519.PrivateKeySize ||
			!bytes.Equal(ed25519.PrivateKey(decoded).Public().(ed25519.PublicKey), mustDecodeBase64(candidate.public)) {
			return nil, fmt.Errorf("control %s private key 与 ControlSet 不匹配", candidate.purpose)
		}
		decodedKeys[index] = ed25519.PrivateKey(decoded)
	}
	if _, err := parsePrivateKeyPKCS8PEM([]byte(secrets.InternalCAPrivateKeyPKCS8PEM)); err != nil {
		return nil, fmt.Errorf("internal CA private key: %w", err)
	}
	if _, err := parseAdminPrivateKey([]byte(secrets.AdminCAPrivateKeyPKCS8PEM)); err != nil {
		return nil, fmt.Errorf("admin CA private key: %w", err)
	}
	controlTLS, err := tls.X509KeyPair([]byte(secrets.ControlTLSCertificate), []byte(secrets.ControlTLSPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("control TLS keypair: %w", err)
	}
	_, browserTLS, _, err := loadControlBrowserTLS(filepath.Join(dir, controlBrowserTLSName),
		config.ClusterID, config.OverlayIP, now().UTC())
	if err != nil {
		return nil, fmt.Errorf("control browser TLS: %w", err)
	}
	peerTLS, err := tls.X509KeyPair([]byte(secrets.PeerTLSCertificate), []byte(secrets.PeerTLSPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("peer TLS keypair: %w", err)
	}
	var journal controlOperationJournalV1
	if err := readCanonicalFile(filepath.Join(dir, controlJournalName), 64<<20, &journal); err != nil {
		return nil, err
	}
	if journal.Schema != 1 {
		return nil, errors.New("control operation journal schema 无效")
	}
	storage, err := controlplane.OpenRaftStorage(filepath.Join(dir, controlRaftName), config.MemberID, config.ControlSet)
	if err != nil {
		return nil, err
	}
	store, err := controlplane.Open(filepath.Join(dir, controlStateName), config.ControlSet)
	if err != nil {
		return nil, err
	}
	runtime := &controlRuntime{dir: dir, config: config, journal: journal,
		configKey: decodedKeys[1], controlTLS: controlTLS, browserTLS: browserTLS, peerTLS: peerTLS,
		storage: storage, store: store, now: now}
	// A restart never reuses an old leadership assertion. N=1 still campaigns and
	// commits a current-term barrier before serving writes.
	leader, err := controlplane.CampaignStableRaft(context.Background(), storage, config.ControlSet,
		map[string]controlplane.RaftPeer{})
	if err != nil {
		return nil, err
	}
	runtime.leader = leader
	if err := runtime.recoverCommitted(); err != nil {
		return nil, err
	}
	service, err := controlplane.NewPrivateControlService(config.OverlayIP, config.ControlPort,
		runtime.readAuthority, runtime.resolveScope, runtime.commitOperation,
		controlOperationSchemas, now)
	if err != nil {
		return nil, err
	}
	runtime.service = service
	runtime.uiReadOnly = newControlUIProxy(webui.ReadOnlySocketPath)
	runtime.uiAdmin = newControlUIProxy(webui.AdminSocketPath)
	return runtime, nil
}

func (runtime *controlRuntime) commitGenesis(at time.Time, aclRoot, peerDirectoryHash string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.store.Snapshot().CertifiedHead != nil {
		return errors.New("genesis 已存在")
	}
	raft := runtime.storage.SnapshotRaft()
	if len(raft.Log) != 0 || raft.CurrentTerm < 1 {
		return errors.New("genesis Raft 坐标无效")
	}
	setHash, _ := wire.ControlSetHash(&runtime.config.ControlSet)
	operationRoot, err := wire.ControlOperationRoot(nil)
	if err != nil {
		return err
	}
	e := runtime.config.GenesisEvidence
	body := wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{Schema: 2, HeadKind: "bootstrap",
		ClusterID: runtime.config.ClusterID, RecoveryEpoch: 1,
		RecoveryStatementHash: e.RecoveryStatementHash, RecoveryPolicyHash: e.RecoveryPolicyHash,
		ControlEpoch: 1, ControlSetHash: setHash, ControlPeerDirectoryHash: peerDirectoryHash,
		RaftTerm: raft.CurrentTerm, RaftIndex: 1, PreviousLogEntryHash: wire.EmptyHashV1,
		ControlRevision: 1, ParentHeadHash: wire.EmptyHashV1, OperationRoot: operationRoot,
		SnapshotHash: e.SnapshotHash, EffectiveSSOTHash: e.EffectiveSSOTHash,
		DeviceViewsRoot: e.DeviceViewsRoot, AdminACLRoot: aclRoot, CAProfileRoot: e.CAProfileRoot,
		BootstrapIssuerRegistryRoot: e.BootstrapIssuerRegistryRoot, RenderContractVersion: 1,
		MinReaderVersion: 2, CommittedLogicalTime: at.UTC().Format(time.RFC3339), MaxClockSkewSeconds: 300,
		TransitionContext: json.RawMessage(fmt.Sprintf(
			`{"schema":1,"kind":"bootstrap","initial_v2_head_payload_hash":%q}`,
			wire.HashRaw("loom-runtime-initial-v2-payload-v1", []byte(runtime.config.ClusterID))))},
		TransitionProofHash: e.TransitionProofHash}
	head, err := wire.NewHeadEntry(body)
	if err != nil {
		return err
	}
	if _, err := runtime.leader.ReplicateHead(context.Background(), runtime.store, head); err != nil {
		return err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return err
	}
	return nil
}

func (runtime *controlRuntime) recoverCommitted() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.finishCommittedLocked()
}

func (runtime *controlRuntime) finishCommittedLocked() error {
	if _, err := controlplane.ApplyCommittedPrefix(context.Background(), runtime.storage, runtime.store,
		runtime.verifyCommittedHead); err != nil {
		return err
	}
	if err := runtime.store.RecoverCertification(map[string]ed25519.PrivateKey{
		runtime.config.MemberID: runtime.configKey}); err != nil {
		return err
	}
	state := runtime.store.Snapshot()
	if state.Active == nil {
		return runtime.projectAdminRotations()
	}
	if state.Active.Phase != controlplane.PhaseCertified || state.Active.QC == nil {
		return errors.New("N=1 committed Head 未形成 exact QC")
	}
	if state.Active.Entry.Body.Payload.HeadKind == "ordinary" {
		if err := runtime.finalizeJournalResultLocked(state.Active.Entry, state.Active.QC); err != nil {
			return err
		}
	}
	if err := runtime.store.MarkApplied(state.Active.Entry.EntryHash); err != nil {
		return err
	}
	return runtime.projectAdminRotations()
}

func (runtime *controlRuntime) verifyCommittedHead(_ context.Context, head wire.HeadEntryV2) error {
	if head.Body.Payload.HeadKind == "bootstrap" {
		if head.Body.Payload.RaftIndex != 1 {
			return errors.New("bootstrap Head index 无效")
		}
		return nil
	}
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Candidate.EntryHash == head.EntryHash && wire.EqualCanonical(record.Candidate, head) {
			leaves := make([]wire.ControlOperationLeafV1, index+1)
			for i := 0; i <= index; i++ {
				leaves[i] = runtime.journal.Records[i].Leaf
			}
			root, err := wire.ControlOperationRoot(leaves)
			if err != nil || root != head.Body.Payload.OperationRoot {
				return errors.New("operation journal 与 committed Head root 不匹配")
			}
			if record.AdminRotation != nil {
				return runtime.verifyAdminRotationRecord(index)
			}
			return nil
		}
	}
	return errors.New("committed ordinary Head 缺 durable operation preimage")
}

func (runtime *controlRuntime) finalizeJournalResultLocked(head wire.HeadEntryV2,
	qc *wire.StableHeadReplicationQCV1) error {
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Candidate.EntryHash != head.EntryHash {
			continue
		}
		if record.Result != nil {
			return nil
		}
		leaves := make([]wire.ControlOperationLeafV1, index+1)
		for i := 0; i <= index; i++ {
			leaves[i] = runtime.journal.Records[i].Leaf
		}
		leaf, leafIndex, treeSize, path, err := wire.ControlOperationInclusionProof(leaves,
			record.Operation.Body.OperationID)
		if err != nil {
			return err
		}
		encodedQC, err := wire.MarshalCanonical(qc)
		if err != nil {
			return err
		}
		record.Result = &controlCertifiedOperationResultV1{Schema: 1, Status: "certified",
			RequestID: record.Operation.Body.OperationID, Head: head, ConfigQC: encodedQC,
			OperationLeaf: leaf, OperationLeafIndex: leafIndex, OperationTreeSize: treeSize,
			OperationAuditPath: path}
		return runtime.persistJournalLocked()
	}
	return errors.New("certified ordinary Head 缺 operation journal record")
}

func (runtime *controlRuntime) readAuthority(_ context.Context) (controlplane.ControlAuthoritySnapshotV1, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil {
		return controlplane.ControlAuthoritySnapshotV1{}, errors.New("control authority 暂不可用")
	}
	qc, err := wire.MarshalCanonical(state.CertifiedQC)
	if err != nil {
		return controlplane.ControlAuthoritySnapshotV1{}, err
	}
	return controlplane.ControlAuthoritySnapshotV1{Head: *state.CertifiedHead, ConfigQC: qc,
		ControlSet: state.ControlSet, Authorizations: append([]wire.AdminAuthorizationV1(nil), runtime.config.Authorizations...),
		Profiles: cloneAdminProfiles(runtime.config.AdminProfiles)}, nil
}

func (runtime *controlRuntime) resolveScope(ctx context.Context,
	operation wire.ControlOperationV1) (wire.AdminResourceScopeV1, error) {
	if err := validateControlPayload(operation, controlplane.OperationPayload(ctx)); err != nil {
		return wire.AdminResourceScopeV1{}, err
	}
	return wire.AdminResourceScopeV1{ScopeKind: "cluster", Cluster: &struct{}{}}, nil
}

func (runtime *controlRuntime) commitOperation(ctx context.Context,
	verified wire.VerifiedAdminOperationV1) (controlplane.CertifiedControlOperationV1, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	operation := verified.Operation()
	payload := controlplane.OperationPayload(ctx)
	if err := validateControlPayload(operation, payload); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Operation.Body.OperationID != operation.Body.OperationID {
			continue
		}
		if !wire.EqualCanonical(record.Operation, operation) {
			return controlplane.CertifiedControlOperationV1{}, errors.New("request_id 与既有 operation 冲突")
		}
		if record.Result == nil {
			if err := runtime.finishCommittedLocked(); err != nil {
				return controlplane.CertifiedControlOperationV1{}, err
			}
		}
		return controlplaneResult(record.Result)
	}
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		state.CertifiedHead.HeadHash != verified.HeadHash() {
		return controlplane.CertifiedControlOperationV1{}, errors.New("operation base authority 已改变")
	}
	if operation.Body.Kind == dnsprovider.BindingOperationKind {
		if err := runtime.validateDNSBindingUpdateLocked(payload); err != nil {
			return controlplane.CertifiedControlOperationV1{}, err
		}
	}
	certificateDER, err := authorizedAdminCertificate(runtime.config.Authorizations,
		operation.Body.AdminCertDigest)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	certificate, _ := x509.ParseCertificate(certificateDER)
	objectID, err := wire.ControlOperationObjectID(&operation, certificate.RawSubjectPublicKeyInfo,
		runtime.now().UTC(), controlOperationSchemas)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	leaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: operation.Body.OperationID, ObjectID: objectID}
	leaves := make([]wire.ControlOperationLeafV1, len(runtime.journal.Records)+1)
	for i := range runtime.journal.Records {
		leaves[i] = runtime.journal.Records[i].Leaf
	}
	leaves[len(leaves)-1] = leaf
	operationRoot, err := wire.ControlOperationRoot(leaves)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	raft := runtime.storage.SnapshotRaft()
	if len(raft.Log) == 0 || raft.CurrentTerm < 1 {
		return controlplane.CertifiedControlOperationV1{}, errors.New("Raft leader coordinate 无效")
	}
	parent := *state.CertifiedHead
	last := raft.Log[len(raft.Log)-1]
	body := parent.Body
	body.Payload.HeadKind = "ordinary"
	body.Payload.RaftTerm = raft.CurrentTerm
	body.Payload.RaftIndex = int64(len(raft.Log)) + 1
	body.Payload.PreviousLogEntryHash = last.EntryHash
	body.Payload.ControlRevision = body.Payload.RaftIndex
	body.Payload.ParentHeadHash = parent.HeadHash
	body.Payload.OperationRoot = operationRoot
	body.Payload.CommittedLogicalTime = runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	body.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	candidate, err := wire.NewHeadEntry(body)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1,
		Operation: operation, Payload: payload, Leaf: leaf, Candidate: candidate})
	if err := runtime.persistJournalLocked(); err != nil {
		runtime.journal.Records = runtime.journal.Records[:len(runtime.journal.Records)-1]
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if _, err := runtime.leader.ReplicateHead(context.Background(), runtime.store, candidate); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	record := &runtime.journal.Records[len(runtime.journal.Records)-1]
	return controlplaneResult(record.Result)
}

func controlplaneResult(result *controlCertifiedOperationResultV1) (controlplane.CertifiedControlOperationV1, error) {
	if result == nil {
		return controlplane.CertifiedControlOperationV1{}, errors.New("operation 尚未 certified")
	}
	return controlplane.CertifiedControlOperationV1{Schema: result.Schema, Status: result.Status,
		Head: result.Head, ConfigQC: append(json.RawMessage(nil), result.ConfigQC...),
		OperationLeaf: result.OperationLeaf, OperationLeafIndex: result.OperationLeafIndex,
		OperationTreeSize:  result.OperationTreeSize,
		OperationAuditPath: append([]string(nil), result.OperationAuditPath...)}, nil
}

func (runtime *controlRuntime) persistJournalLocked() error {
	return writeCanonicalAtomic(filepath.Join(runtime.dir, controlJournalName), runtime.journal, 0o600)
}

func (runtime *controlRuntime) serve() error {
	controlAddress := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	loopbackAddress := net.JoinHostPort(controlLoopbackIP, fmt.Sprint(runtime.config.ControlPort))
	raftAddress := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.RaftPort))
	if len(runtime.browserTLS.Certificate) < 1 {
		return errors.New("control browser TLS leaf 缺失")
	}
	browserLeaf, err := x509.ParseCertificate(runtime.browserTLS.Certificate[0])
	if err != nil || browserLeaf.VerifyHostname(controlLoopbackIP) != nil {
		return errors.New("control browser TLS leaf 未授权 127.0.0.1；请先执行 control enable-loopback")
	}
	controlListener, err := net.Listen("tcp", controlAddress)
	if err != nil {
		return fmt.Errorf("listen control_api %s: %w", controlAddress, err)
	}
	defer controlListener.Close()
	loopbackListener, err := net.Listen("tcp4", loopbackAddress)
	if err != nil {
		return fmt.Errorf("listen control browser loopback %s: %w", loopbackAddress, err)
	}
	defer loopbackListener.Close()
	raftListener, err := net.Listen("tcp", raftAddress)
	if err != nil {
		return fmt.Errorf("listen Raft %s: %w", raftAddress, err)
	}
	defer raftListener.Close()
	controlTLSConfig := runtime.controlServerTLSConfig(runtime.controlTLS)
	loopbackTLSConfig := runtime.controlServerTLSConfig(runtime.browserTLS)
	raftTLSConfig, err := controlplane.NewControlPeerServerTLSConfig(runtime.config.MemberID,
		runtime.peerTLS, runtime.config.ControlSet, runtime.config.PeerDirectory, runtime.now)
	if err != nil {
		return err
	}
	raftHandler, err := controlplane.NewRaftHTTPHandler(runtime.storage, runtime.config.ControlSet,
		runtime.config.PeerDirectory, runtime.now,
		func(ctx context.Context, record controlplane.RaftLogRecordV1) error {
			if record.Kind == controlplane.RaftRecordHead && record.Head != nil {
				return runtime.verifyCommittedHead(ctx, *record.Head)
			}
			return nil
		})
	if err != nil {
		return err
	}
	controlHandler := runtime.controlHandler()
	controlServer := &http.Server{Handler: controlHandler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	loopbackServer := &http.Server{Handler: controlHandler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	raftServer := &http.Server{Handler: raftHandler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	errorsOut := make(chan error, 3)
	go func() { errorsOut <- controlServer.Serve(tls.NewListener(controlListener, controlTLSConfig)) }()
	go func() { errorsOut <- loopbackServer.Serve(tls.NewListener(loopbackListener, loopbackTLSConfig)) }()
	go func() { errorsOut <- raftServer.Serve(tls.NewListener(raftListener, raftTLSConfig)) }()
	fmt.Printf("✓ v2 control_api 监听 %s；浏览器转发入口监听 %s；Raft 监听 %s；ControlSet N=1 q=1\n",
		controlAddress, loopbackAddress, raftAddress)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = controlServer.Shutdown(ctx)
		_ = loopbackServer.Shutdown(ctx)
		_ = raftServer.Shutdown(ctx)
	}
	select {
	case sig := <-stop:
		shutdown()
		fmt.Printf("control runtime 收到 %s，已停止\n", sig)
		return nil
	case serveErr := <-errorsOut:
		shutdown()
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	}
}

func (runtime *controlRuntime) controlHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case privateControlStatus:
			runtime.serveStatus(writer, request)
		case controlplane.PrivateControlOperationPath:
			runtime.service.ServeHTTP(writer, request)
		default:
			runtime.serveControlUI(writer, request)
		}
	})
}

func (runtime *controlRuntime) controlServerTLSConfig(certificate tls.Certificate) *tls.Config {
	acceptable := x509.NewCertPool()
	for _, profile := range runtime.config.AdminProfiles {
		for _, encoded := range profile.IssuerChainDER {
			der, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				continue
			}
			certificate, err := x509.ParseCertificate(der)
			if err == nil {
				acceptable.AddCert(certificate)
			}
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequestClientCert,
		ClientCAs: acceptable}
}

func newControlUIProxy(socketPath string) http.Handler {
	transport := &http.Transport{Proxy: nil, DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
		}}
	return &httputil.ReverseProxy{
		Director: func(request *http.Request) {
			request.URL.Scheme = "http"
			request.URL.Host = "loom-control-ui.local"
			request.Host = "loom-control-ui.local"
			request.Header.Del("Authorization")
			request.Header.Del("Cookie")
			request.Header.Del("X-Forwarded-For")
			request.Header.Del("X-Forwarded-Host")
			request.Header.Del("X-Forwarded-Proto")
		},
		Transport: transport,
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			writer.Header().Set("Cache-Control", "no-store")
			http.Error(writer, "控制 UI 暂不可用", http.StatusServiceUnavailable)
		},
	}
}

func (runtime *controlRuntime) serveControlUI(writer http.ResponseWriter, request *http.Request) {
	address, exactListener := runtime.controlUIAddress(request)
	if request.URL.RawPath != "" || pathpkg.Clean(request.URL.Path) != request.URL.Path ||
		!controlUIPathAllowed(request.URL.Path) || !exactListener ||
		request.TLS == nil || !request.TLS.HandshakeComplete ||
		request.TLS.Version != tls.VersionTLS13 || request.Header.Get("Authorization") != "" {
		http.NotFound(writer, request)
		return
	}
	websocketUpgrade := controlUIWebSocketUpgrade(request)
	if websocketUpgrade {
		if request.Method != http.MethodGet || request.Header.Get("Origin") != "https://"+address ||
			(request.Header.Get("Sec-Fetch-Site") != "" && request.Header.Get("Sec-Fetch-Site") != "same-origin") {
			writeControlRuntimeError(writer, http.StatusForbidden, "[实时设备列表] WebSocket 的 same-origin 证据无效")
			return
		}
		// net/http 的请求级读写 deadline 在 Hijack 后不会自动清除。WebSocket
		// 若沿用 control server 的 15s/30s deadline，会被误断成周期重连。
		writer = &controlUIUpgradeResponseWriter{ResponseWriter: writer}
	}
	admin := false
	if len(request.TLS.PeerCertificates) > 0 {
		runtime.mu.Lock()
		admin = runtime.adminCertificateAuthorizedLocked(request.TLS.PeerCertificates[0].Raw)
		runtime.mu.Unlock()
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		if !admin {
			writeControlRuntimeError(writer, http.StatusForbidden, "需要有效的管理员客户端证书（admin.p12）")
			return
		}
		if request.Header.Get("Origin") != "https://"+address ||
			(request.Header.Get("Sec-Fetch-Site") != "" && request.Header.Get("Sec-Fetch-Site") != "same-origin") {
			writeControlRuntimeError(writer, http.StatusForbidden, "管理 UI 写请求的 same-origin 证据无效")
			return
		}
	}
	if admin {
		runtime.uiAdmin.ServeHTTP(writer, request)
		return
	}
	runtime.uiReadOnly.ServeHTTP(writer, request)
}

type controlUIUpgradeResponseWriter struct {
	http.ResponseWriter
}

func (w *controlUIUpgradeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return connection, buffered, nil
}

func controlUIWebSocketUpgrade(request *http.Request) bool {
	if request == nil || !strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, token := range strings.Split(request.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

func (runtime *controlRuntime) controlUIAddress(request *http.Request) (string, bool) {
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return "", false
	}
	for _, address := range []string{
		net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort)),
		net.JoinHostPort(controlLoopbackIP, fmt.Sprint(runtime.config.ControlPort)),
	} {
		if local.String() == address && request.Host == address {
			return address, true
		}
	}
	return "", false
}

func controlUIPathAllowed(path string) bool {
	switch path {
	case "/", "/favicon.svg", "/traffic.json", "/devices", "/clients", "/nodes", "/topology",
		"/services", "/routing", "/releases", "/deployments", "/events", "/events.csv", "/settings", "/ssot":
		return true
	}
	for _, prefix := range []string{"/assets/", "/devices/", "/clients/", "/nodes/", "/api/control/", "/act/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (runtime *controlRuntime) serveStatus(writer http.ResponseWriter, request *http.Request) {
	expectedAddress := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !ok || local.String() != expectedAddress ||
		request.Host != expectedAddress || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) < 1 || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Cookie") != "" {
		writeControlRuntimeError(writer, http.StatusForbidden, "private admin status transport 被拒绝")
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		!runtime.adminCertificateAuthorizedLocked(request.TLS.PeerCertificates[0].Raw) {
		writeControlRuntimeError(writer, http.StatusForbidden, "admin certificate 未获 certified ACL 授权")
		return
	}
	qc, _ := wire.MarshalCanonical(state.CertifiedQC)
	raft := runtime.storage.SnapshotRaft()
	quorum, _ := wire.Quorum(len(state.ControlSet.Members))
	response := controlStatusResponseV1{Schema: 1, ClusterID: runtime.config.ClusterID,
		MemberID: runtime.config.MemberID, Quorum: quorum, Head: *state.CertifiedHead, ConfigQC: qc,
		ControlSet: state.ControlSet, Raft: controlRaftStatusV1{Term: raft.CurrentTerm,
			CommitIndex: raft.CommitIndex, LastApplied: raft.LastApplied}, Service: runtime.config.ControlService}
	body, _ := wire.MarshalCanonical(response)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func (runtime *controlRuntime) adminCertificateAuthorizedLocked(raw []byte) bool {
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedQC == nil {
		return false
	}
	qc, err := wire.MarshalCanonical(state.CertifiedQC)
	if err != nil || wire.VerifyConfigQCAuthority(state.CertifiedHead.HeadHash, qc,
		state.CertifiedHead, &state.ControlSet, nil) != nil {
		return false
	}
	root, err := wire.AdminACLRoot(runtime.config.Authorizations, runtime.config.AdminProfiles)
	if err != nil || root != state.CertifiedHead.Body.Payload.AdminACLRoot {
		return false
	}
	for index := range runtime.config.Authorizations {
		authorization := &runtime.config.Authorizations[index]
		profile, found := runtime.config.AdminProfiles[authorization.CertificateProfileRef.ProfileID]
		der, decodeErr := base64.RawURLEncoding.DecodeString(authorization.AdminCertificateDER)
		if !found || decodeErr != nil || !bytes.Equal(der, raw) ||
			wire.ValidateAdminAuthorizationAt(authorization, &profile, runtime.now().UTC()) != nil ||
			authorization.Status != "active" {
			continue
		}
		return true
	}
	return false
}

func writeControlRuntimeError(writer http.ResponseWriter, status int, message string) {
	body, _ := wire.MarshalCanonical(struct {
		Schema int    `json:"schema"`
		Error  string `json:"error"`
	}{1, message})
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func loadControlAdminClient(adminDir string) (controlAdminEndpointV1, *http.Client, error) {
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		return endpoint, nil, err
	}
	if endpoint.Schema != 1 || endpoint.ClusterID == "" || endpoint.AdminID == "" ||
		endpoint.AdminCertificate != controlAdminCertName || endpoint.AdminPrivateKey != controlAdminKeyName {
		return endpoint, nil, errors.New("admin endpoint manifest 无效")
	}
	if err := wire.ValidatePrivateControlService(&endpoint.Service); err != nil || endpoint.Service.Role != "control_api" {
		return endpoint, nil, errors.New("admin endpoint service 无效")
	}
	certificatePEM, err := readOwnerOnlyFile(filepath.Join(adminDir, endpoint.AdminCertificate), 1<<20)
	if err != nil {
		return endpoint, nil, err
	}
	privateKeyPEM, err := readOwnerOnlyFile(filepath.Join(adminDir, endpoint.AdminPrivateKey), 1<<20)
	if err != nil {
		return endpoint, nil, err
	}
	adminTLS, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return endpoint, nil, err
	}
	rootDER, err := base64.RawURLEncoding.DecodeString(endpoint.InternalRootDER)
	if err != nil {
		return endpoint, nil, errors.New("internal root DER 编码无效")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return endpoint, nil, errors.New("internal root DER 无效")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{adminTLS}, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyControlServerTLS(state, endpoint.Service, root, time.Now().UTC())
		}}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	return endpoint, &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func verifyControlServerTLS(state tls.ConnectionState, service wire.PrivateControlServiceV1,
	root *x509.Certificate, now time.Time) error {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) < 1 || root == nil {
		return errors.New("control server TLS profile 无效")
	}
	leaf := state.PeerCertificates[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.VerifyHostname(service.OverlayIP) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("control server certificate role/IP/validity 无效")
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	if !containsText(service.SPKIPins, pin) {
		return errors.New("control server SPKI 不在交付 pin set")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: service.OverlayIP, Roots: roots,
		Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("control server 不属于 exact internal CA profile")
	}
	return nil
}

func fetchControlStatus(ctx context.Context, endpoint controlAdminEndpointV1,
	client *http.Client) (controlStatusResponseV1, error) {
	var status controlStatusResponseV1
	url := fmt.Sprintf("https://%s:%d%s", endpoint.Service.OverlayIP, endpoint.Service.Port, privateControlStatus)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	response, err := client.Do(request)
	if err != nil {
		return status, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, controlMaxResponseSize+1))
	if err != nil || len(body) > controlMaxResponseSize || response.StatusCode != http.StatusOK ||
		strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		return status, fmt.Errorf("control status HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	canonical, err := wire.DecodeStrict(body, controlMaxResponseSize, &status)
	if err != nil || !bytes.Equal(canonical, body) || status.Schema != 1 || status.ClusterID != endpoint.ClusterID ||
		!wire.EqualCanonical(status.Service, endpoint.Service) {
		return status, errors.New("control status response canonical/authority 无效")
	}
	if err := wire.VerifyConfigQCAuthority(status.Head.HeadHash, status.ConfigQC, &status.Head,
		&status.ControlSet, nil); err != nil {
		return status, fmt.Errorf("control status QC 无效: %w", err)
	}
	setHash, _ := wire.ControlSetHash(&status.ControlSet)
	if setHash != status.Head.Body.Payload.ControlSetHash {
		return status, errors.New("control status Head/ControlSet 不一致")
	}
	return status, nil
}

func newControlPingRequest(adminDir string, endpoint controlAdminEndpointV1,
	status controlStatusResponseV1, reason string, now time.Time) (controlOperationRequestV1, error) {
	certificatePEM, err := readOwnerOnlyFile(filepath.Join(adminDir, endpoint.AdminCertificate), 1<<20)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return controlOperationRequestV1{}, errors.New("admin certificate PEM 无效")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	privateKeyPEM, err := readOwnerOnlyFile(filepath.Join(adminDir, endpoint.AdminPrivateKey), 1<<20)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	keyBlock, _ := pem.Decode(privateKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return controlOperationRequestV1{}, errors.New("admin private key PEM 无效")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	privateKey, ok := parsedKey.(crypto.Signer)
	if err != nil || !ok {
		return controlOperationRequestV1{}, errors.New("admin private key 必须是 PKCS#8 signer")
	}
	digest, _ := wire.AdminCertificateDigest(certificate.Raw)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return controlOperationRequestV1{}, err
	}
	operationID := "op-" + hex.EncodeToString(nonce)
	payloadHash := wire.HashRaw("loom-control-ping-payload-v1", nonce)
	instant := now.UTC().Truncate(time.Second)
	body := wire.ControlOperationBodyV1{Schema: 1, ClusterID: status.ClusterID,
		OperationID: operationID, AuthorID: endpoint.AdminID, AdminCertDigest: digest,
		CreatedAt: instant.Format(time.RFC3339), ExpiresAt: instant.Add(5 * time.Minute).Format(time.RFC3339),
		BaseRecoveryEpoch:         status.Head.Body.Payload.RecoveryEpoch,
		BaseRecoveryStatementHash: status.Head.Body.Payload.RecoveryStatementHash,
		BaseRecoveryPolicyHash:    status.Head.Body.Payload.RecoveryPolicyHash,
		BaseControlEpoch:          status.Head.Body.Payload.ControlEpoch,
		BaseControlSetHash:        status.Head.Body.Payload.ControlSetHash,
		BaseControlRevision:       status.Head.Body.Payload.ControlRevision,
		ParentHeadHash:            status.Head.HeadHash, Kind: controlPingKind, PayloadSchema: 1,
		PayloadHash: payloadHash, Reason: reason}
	operation, err := wire.NewControlOperation(body, privateKey, controlOperationSchemas)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	return controlOperationRequestV1{Schema: 1, ExpectedHeadHash: status.Head.HeadHash,
		RequestID: operationID, Operation: operation}, nil
}

func submitControlOperation(ctx context.Context, adminDir string, endpoint controlAdminEndpointV1,
	client *http.Client, status controlStatusResponseV1,
	submitted controlOperationRequestV1) (controlCertifiedOperationResultV1, error) {
	var result controlCertifiedOperationResultV1
	body, err := wire.MarshalCanonical(submitted)
	if err != nil {
		return result, err
	}
	url := fmt.Sprintf("https://%s:%d%s", endpoint.Service.OverlayIP, endpoint.Service.Port,
		controlplane.PrivateControlOperationPath)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, controlMaxResponseSize+1))
	if err != nil || len(responseBody) > controlMaxResponseSize || response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("control operation HTTP %d: %s", response.StatusCode,
			strings.TrimSpace(string(responseBody)))
	}
	canonical, err := wire.DecodeStrict(responseBody, controlMaxResponseSize, &result)
	if err != nil || !bytes.Equal(canonical, responseBody) || result.Schema != 1 ||
		result.Status != "certified" || result.RequestID != submitted.RequestID {
		return result, errors.New("control operation response canonical/request binding 无效")
	}
	if err := wire.VerifyConfigQCAuthority(result.Head.HeadHash, result.ConfigQC, &result.Head,
		&status.ControlSet, nil); err != nil {
		return result, fmt.Errorf("control operation result QC 无效: %w", err)
	}
	if err := wire.ValidateHeadEntry(&result.Head, &status.Head); err != nil {
		return result, fmt.Errorf("control operation Head lineage 无效: %w", err)
	}
	certificatePEM, err := readOwnerOnlyFile(filepath.Join(adminDir, endpoint.AdminCertificate), 1<<20)
	if err != nil {
		return result, err
	}
	block, trailing := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(trailing)) != 0 {
		return result, errors.New("admin certificate PEM 无效")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return result, err
	}
	expectedObjectID, err := wire.ControlOperationObjectID(&submitted.Operation,
		certificate.RawSubjectPublicKeyInfo, time.Now().UTC(), controlOperationSchemas)
	if err != nil {
		return result, err
	}
	if result.OperationLeaf.OperationID != submitted.Operation.Body.OperationID ||
		result.OperationLeaf.ObjectID != expectedObjectID ||
		wire.VerifyControlOperationInclusion(&result.OperationLeaf, result.OperationLeafIndex,
			result.OperationTreeSize, result.OperationAuditPath, &result.Head) != nil {
		return result, errors.New("control operation inclusion proof 无效")
	}
	return result, nil
}

func makeCertificateAuthority(commonName string, notBefore, notAfter time.Time) ([]byte,
	*x509.Certificate, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC(), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, privateKey, nil
}

func makeControlServerCertificate(clusterID, overlayIP string, issuer *x509.Certificate,
	issuerKey ed25519.PrivateKey, now time.Time) ([]byte, []byte, []byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	ip := net.ParseIP(overlayIP)
	if ip == nil {
		return nil, nil, nil, errors.New("control overlay IP 无效")
	}
	certificatePEM, der, err := signControlServerCertificate(clusterID,
		[]net.IP{ip, net.ParseIP(controlLoopbackIP)}, issuer, issuerKey, privateKey, now)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return certificatePEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), der, nil
}

func signControlServerCertificate(clusterID string, ipAddresses []net.IP, issuer *x509.Certificate,
	issuerKey, privateKey ed25519.PrivateKey, now time.Time) ([]byte, []byte, error) {
	if clusterID == "" || issuer == nil || len(issuerKey) != ed25519.PrivateKeySize ||
		len(privateKey) != ed25519.PrivateKeySize || len(ipAddresses) == 0 {
		return nil, nil, errors.New("control server certificate authority/key/IP 无效")
	}
	addresses := make([]net.IP, len(ipAddresses))
	for index, ip := range ipAddresses {
		if ip == nil {
			return nil, nil, errors.New("control server certificate IP 无效")
		}
		addresses[index] = append(net.IP(nil), ip...)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, nil, err
	}
	notBefore := now.UTC().Add(-5 * time.Minute)
	if issuer.NotBefore.After(notBefore) {
		notBefore = issuer.NotBefore
	}
	notAfter := now.UTC().Add(365 * 24 * time.Hour)
	if issuer.NotAfter.Before(notAfter) {
		notAfter = issuer.NotAfter
	}
	if !notAfter.After(now.UTC()) {
		return nil, nil, errors.New("control server certificate issuer 已过期")
	}
	template := &x509.Certificate{SerialNumber: serial,
		Subject: pkix.Name{CommonName: "control-api." + clusterID}, NotBefore: notBefore,
		NotAfter: notAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: addresses}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, privateKey.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der, nil
}

func makeControlBrowserTLS(clusterID, overlayIP string, now time.Time) (controlBrowserTLSV1,
	tls.Certificate, *x509.Certificate, error) {
	var empty controlBrowserTLSV1
	overlay := net.ParseIP(overlayIP)
	if clusterID == "" || overlay == nil {
		return empty, tls.Certificate{}, nil, errors.New("browser TLS cluster/overlay identity 无效")
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	rootSerial, err := randomCertificateSerial()
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	instant := now.UTC()
	rootTemplate := &x509.Certificate{SerialNumber: rootSerial,
		Subject:   pkix.Name{CommonName: "Loom browser control CA " + clusterID},
		NotBefore: instant.Add(-5 * time.Minute), NotAfter: instant.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate,
		&rootKey.PublicKey, rootKey)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	serverSerial, err := randomCertificateSerial()
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	serverTemplate := &x509.Certificate{SerialNumber: serverSerial,
		Subject:   pkix.Name{CommonName: "control-browser." + clusterID},
		NotBefore: instant.Add(-5 * time.Minute), NotAfter: instant.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{overlay, net.ParseIP(controlLoopbackIP)}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root,
		&serverKey.PublicKey, rootKey)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	serverKeyPEM, err := ecdsaPrivateKeyPKCS8PEM(serverKey)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	rootKeyPEM, err := ecdsaPrivateKeyPKCS8PEM(rootKey)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	state := controlBrowserTLSV1{Schema: 1, CertificateChainPEM: string(chain),
		PrivateKeyPKCS8PEM: string(serverKeyPEM), RootPrivateKeyPKCS8PEM: string(rootKeyPEM)}
	pair, err := tls.X509KeyPair(chain, serverKeyPEM)
	if err != nil {
		return empty, tls.Certificate{}, nil, err
	}
	return state, pair, root, nil
}

func loadControlBrowserTLS(path, clusterID, overlayIP string, now time.Time) (controlBrowserTLSV1,
	tls.Certificate, *x509.Certificate, error) {
	var state controlBrowserTLSV1
	if err := readCanonicalFile(path, 4<<20, &state); err != nil {
		return state, tls.Certificate{}, nil, err
	}
	if state.Schema != 1 {
		return state, tls.Certificate{}, nil, errors.New("browser TLS state schema 无效")
	}
	pair, err := tls.X509KeyPair([]byte(state.CertificateChainPEM), []byte(state.PrivateKeyPKCS8PEM))
	if err != nil || len(pair.Certificate) != 2 {
		return state, tls.Certificate{}, nil, errors.New("browser TLS 必须是精确的 P-256 leaf + root chain")
	}
	leaf, leafErr := x509.ParseCertificate(pair.Certificate[0])
	root, rootErr := x509.ParseCertificate(pair.Certificate[1])
	if leafErr != nil || rootErr != nil {
		return state, tls.Certificate{}, nil, errors.New("browser TLS certificate chain 无效")
	}
	rootKey, rootKeyErr := parseECDSAPrivateKeyPKCS8PEM([]byte(state.RootPrivateKeyPKCS8PEM))
	serverKey, serverKeyErr := parseECDSAPrivateKeyPKCS8PEM([]byte(state.PrivateKeyPKCS8PEM))
	rootPublic, rootPublicOK := root.PublicKey.(*ecdsa.PublicKey)
	leafPublic, leafPublicOK := leaf.PublicKey.(*ecdsa.PublicKey)
	if rootKeyErr != nil || serverKeyErr != nil || !rootPublicOK || !leafPublicOK ||
		rootPublic.Curve != elliptic.P256() || leafPublic.Curve != elliptic.P256() ||
		!rootPublic.Equal(rootKey.Public()) || !leafPublic.Equal(serverKey.Public()) || !root.IsCA ||
		root.CheckSignatureFrom(root) != nil || leaf.CheckSignatureFrom(root) != nil ||
		root.Subject.CommonName != "Loom browser control CA "+clusterID ||
		leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.Subject.CommonName != "control-browser."+clusterID ||
		len(leaf.DNSNames) != 0 || !exactControlBrowserIPs(leaf.IPAddresses, overlayIP) {
		return state, tls.Certificate{}, nil, errors.New("browser TLS P-256 leaf/key/root authority 无效")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: overlayIP, Roots: roots,
		CurrentTime: now.UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil ||
		leaf.VerifyHostname(controlLoopbackIP) != nil {
		return state, tls.Certificate{}, nil, errors.New("browser TLS overlay/loopback identity 无效")
	}
	return state, pair, root, nil
}

func exactControlBrowserIPs(addresses []net.IP, overlayIP string) bool {
	if len(addresses) != 2 {
		return false
	}
	overlay := net.ParseIP(overlayIP)
	loopback := net.ParseIP(controlLoopbackIP)
	return (addresses[0].Equal(overlay) && addresses[1].Equal(loopback)) ||
		(addresses[0].Equal(loopback) && addresses[1].Equal(overlay))
}

func ecdsaPrivateKeyPKCS8PEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil || privateKey.Curve != elliptic.P256() {
		return nil, errors.New("browser TLS private key 必须是 P-256")
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseECDSAPrivateKeyPKCS8PEM(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, trailing := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, errors.New("必须是单一 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || privateKey.Curve != elliptic.P256() {
		return nil, errors.New("必须是 P-256 private key")
	}
	return privateKey, nil
}

func parseSingleCertificatePEM(encoded []byte) (*x509.Certificate, error) {
	block, trailing := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, errors.New("必须是单一 certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func makeControlPeerCertificate(clusterID, memberID, overlayIP string, now time.Time) ([]byte,
	[]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: memberID + "." + clusterID},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(overlayIP)}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), der, nil
}

func makeAdminCertificate(clusterID, adminID string, issuer *x509.Certificate,
	issuerKey crypto.Signer, now time.Time) ([]byte, []byte, []byte, error) {
	privateKey, err := generateAdminKey(issuerKey.Public())
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	policy := []uint64{1, 3, 6, 1, 4, 1, 55555, 1, 1}
	policyOID, err := x509.OIDFromInts(policy)
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: adminID + "." + clusterID},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Policies: []x509.OID{policyOID}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, privateKey.Public(), issuerKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), der, nil
}

func makeAdminAuthority(clusterID string, rootDER, adminDER []byte,
	now time.Time) (wire.AdminCertificateProfileV1, wire.AdminAuthorizationV1, error) {
	issuerChain := []string{base64.RawURLEncoding.EncodeToString(rootDER)}
	issuerHash, err := wire.HashObject(wire.DomainAdminIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{1, issuerChain})
	if err != nil {
		return wire.AdminCertificateProfileV1{}, wire.AdminAuthorizationV1{}, err
	}
	profile := wire.AdminCertificateProfileV1{Schema: 1, ClusterID: clusterID,
		ProfileID: "admin-client-v1", Generation: 1, IssuerChainDER: issuerChain,
		AdminIssuerChainHash: issuerHash, SubjectKeyAlgorithm: "ed25519",
		OperationSignatureAlgorithm: "ed25519", RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"},
		RequiredPolicyOIDs: []string{"1.3.6.1.4.1.55555.1.1"}, MaximumValiditySeconds: 366 * 24 * 60 * 60}
	adminLeaf, err := x509.ParseCertificate(adminDER)
	if err != nil {
		return profile, wire.AdminAuthorizationV1{}, err
	}
	if adminLeaf.PublicKeyAlgorithm == x509.ECDSA {
		profile.SubjectKeyAlgorithm, profile.OperationSignatureAlgorithm = "p256", "ecdsa-p256-sha256"
	}
	profileHash, err := wire.AdminCertificateProfileHash(&profile)
	if err != nil {
		return profile, wire.AdminAuthorizationV1{}, err
	}
	certificate, err := x509.ParseCertificate(adminDER)
	if err != nil {
		return profile, wire.AdminAuthorizationV1{}, err
	}
	digest, _ := wire.AdminCertificateDigest(adminDER)
	keyID, _ := wire.AdminKeyID(certificate.RawSubjectPublicKeyInfo)
	authorization := wire.AdminAuthorizationV1{Schema: 1, ClusterID: clusterID,
		AuthorizationID: "admin-primary-v1", Generation: 1, AdminID: "admin-primary",
		AdminCertificateDER: base64.RawURLEncoding.EncodeToString(adminDER), AdminCertificateDigest: digest,
		AdminKeyID: keyID, CertificateProfileRef: wire.AdminCertificateProfileRefV1{ProfileID: profile.ProfileID,
			Generation: profile.Generation, AdminCertificateProfileHash: profileHash},
		NotBefore: now.Add(-5 * time.Minute).Format(time.RFC3339),
		NotAfter:  now.Add(365 * 24 * time.Hour).Format(time.RFC3339), Status: "active",
		AllowedOperationKinds: []string{controlPingKind, dnsprovider.BindingOperationKind}, Capabilities: []string{},
		Scopes: []wire.AdminResourceScopeV1{{ScopeKind: "cluster", Cluster: &struct{}{}}}}
	if err := wire.ValidateAdminAuthorizationAt(&authorization, &profile, now); err != nil {
		return profile, authorization, err
	}
	return profile, authorization, nil
}

func randomCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func privateKeyPKCS8PEM(privateKey crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parsePrivateKeyPKCS8PEM(encoded []byte) (ed25519.PrivateKey, error) {
	block, trailing := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, errors.New("必须是单一 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("必须是 Ed25519 private key")
	}
	return privateKey, nil
}

func newControlMemberID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	number := new(big.Int).SetBytes(raw)
	encoded := make([]byte, 26)
	mask := big.NewInt(31)
	for index := len(encoded) - 1; index >= 0; index-- {
		component := new(big.Int).And(number, mask).Int64()
		encoded[index] = alphabet[component]
		number.Rsh(number, 5)
	}
	return string(encoded), nil
}

func writeAdminDelivery(dir string, config controlDiskConfigV1, internalRootDER, browserRootDER []byte,
	adminCertPEM, adminKeyPEM, adminRootPEM []byte, now time.Time) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("admin 交付目录 %s 已存在，拒绝覆盖", dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	endpoint := controlAdminEndpointV1{Schema: 1, ClusterID: config.ClusterID,
		AdminID: config.Authorizations[0].AdminID, Service: config.ControlService,
		InternalRootDER:  base64.RawURLEncoding.EncodeToString(internalRootDER),
		AdminCertificate: controlAdminCertName, AdminPrivateKey: controlAdminKeyName}
	if err := writeCanonicalAtomic(filepath.Join(dir, controlEndpointName), endpoint, 0o600); err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{{controlAdminCertName, adminCertPEM, 0o600}, {controlAdminKeyName, adminKeyPEM, 0o600},
		{controlInternalRootName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: browserRootDER}), 0o600},
		{controlAdminRootName, adminRootPEM, 0o600}} {
		if err := writeBytesAtomic(filepath.Join(dir, file.name), file.body, file.mode); err != nil {
			return err
		}
	}
	return exportAdminPKCS12(dir, now)
}

func readCanonicalFile(path string, limit int64, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s 必须是 owner-only regular file", path)
	}
	body, err := os.ReadFile(path)
	if err != nil || int64(len(body)) > limit {
		return fmt.Errorf("读取 %s 失败或过大", path)
	}
	canonical, err := wire.DecodeStrict(body, int(limit), value)
	if err != nil || !bytes.Equal(canonical, body) {
		return fmt.Errorf("%s 不是 exact canonical JSON: %w", path, err)
	}
	return nil
}

func readOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > limit {
		return nil, fmt.Errorf("%s 必须是有界 owner-only regular file", path)
	}
	body, err := os.ReadFile(path)
	if err != nil || int64(len(body)) != info.Size() {
		return nil, fmt.Errorf("读取 %s 失败或发生并发变化", path)
	}
	return body, nil
}

func writeCanonicalAtomic(path string, value any, mode os.FileMode) error {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return err
	}
	return writeBytesAtomic(path, body, mode)
}

func writeBytesAtomic(path string, body []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".loom-control-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dirFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

func authorizedAdminCertificate(authorizations []wire.AdminAuthorizationV1, digest string) ([]byte, error) {
	for _, authorization := range authorizations {
		if authorization.AdminCertificateDigest == digest {
			return base64.RawURLEncoding.DecodeString(authorization.AdminCertificateDER)
		}
	}
	return nil, errors.New("admin certificate digest 不在 ACL")
}

func cloneAdminProfiles(input map[string]wire.AdminCertificateProfileV1) map[string]wire.AdminCertificateProfileV1 {
	body, _ := json.Marshal(input)
	var output map[string]wire.AdminCertificateProfileV1
	_ = json.Unmarshal(body, &output)
	return output
}

func containsText(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mustDecodeBase64(value string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(value)
	return decoded
}
