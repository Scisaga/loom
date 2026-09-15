//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
	"loom/internal/clientcomponent"
	"loom/internal/clientmigration"
	"loom/internal/clientsecret"
	"loom/internal/clientv2"
	"loom/internal/windowsv2"
	"loom/internal/wire"
)

// 这些类型仅解释本机历史存储，不提供旧邀请、网络或配置执行功能。
type legacyWindowsIdentity struct {
	Schema        int             `json:"schema"`
	JoinCodeHash  string          `json:"join_code_sha256"`
	PendingInvite json.RawMessage `json:"pending_invite,omitempty"`
	Identity      struct {
		Schema        int    `json:"schema"`
		Platform      string `json:"platform"`
		Endpoint      string `json:"endpoint"`
		RequestID     string `json:"request_id"`
		PrivateKeyPEM []byte `json:"private_key_pem"`
		CSRPEM        []byte `json:"csr_pem"`
	} `json:"identity"`
}

type legacyWindowsConfig struct {
	Schema              int      `json:"schema"`
	NodeID              string   `json:"node_id"`
	DistributionURLs    []string `json:"distribution_urls"`
	DNS                 []string `json:"dns,omitempty"`
	PullIntervalSeconds int      `json:"pull_interval_seconds,omitempty"`
}

func readLegacyWindowsIdentity(root string, protector clientsecret.Protector,
	platform ed25519.PublicKey) (string, *ecdsa.PrivateKey, clientmigration.Floor, error) {
	var zero clientmigration.Floor
	configBytes, err := readWindowsMigrationFile(filepath.Join(root, "config", "client.json"), 64<<10)
	if err != nil {
		return "", nil, zero, err
	}
	var config legacyWindowsConfig
	if _, err := wire.DecodeStrict(configBytes, 64<<10, &config); err != nil || config.Schema != 1 || config.NodeID == "" {
		return "", nil, zero, errors.New("[Windows migration] 原设备配置身份无效")
	}
	floorBytes, err := readWindowsMigrationFile(filepath.Join(root, "state", "release-floor.json"), 64<<10)
	if err != nil {
		return "", nil, zero, err
	}
	floor, err := clientmigration.ParseFloor(floorBytes)
	if err != nil {
		return "", nil, zero, err
	}
	pinnedBytes, err := readWindowsMigrationFile(filepath.Join(root, "trust", "platform.pub"), 64<<10)
	if err != nil {
		return "", nil, zero, err
	}
	pinned, err := decodeWindowsPlatformKey(pinnedBytes)
	if err != nil || !bytes.Equal(pinned, platform) {
		return "", nil, zero, errors.New("[Windows migration] 安装包与原网络信任公钥不匹配")
	}
	var protected legacyWindowsIdentity
	if err := clientsecret.ReadJSONProtected(filepath.Join(root, "join", "identity.json.dpapi"),
		"network-join-identity-v1", &protected, protector); err != nil {
		return "", nil, zero, err
	}
	defer clear(protected.Identity.PrivateKeyPEM)
	if protected.Schema != 1 || protected.Identity.Schema != 1 || protected.Identity.Platform != "windows-desktop" {
		return "", nil, zero, errors.New("[Windows migration] 原受保护身份格式无效")
	}
	block, rest := pem.Decode(protected.Identity.PrivateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, zero, errors.New("[Windows migration] 原身份密钥格式无效")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return "", nil, zero, errors.New("[Windows migration] 原身份不是 P-256")
	}
	keep := false
	defer func() {
		if !keep {
			clear(key.D.Bits())
		}
	}()
	certBytes, err := readWindowsMigrationFile(filepath.Join(root, "tls", "node.crt"), 64<<10)
	if err != nil {
		return "", nil, zero, err
	}
	certBlock, rest := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, zero, errors.New("[Windows migration] 原设备证书无效")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	public, publicErr := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || publicErr != nil || !bytes.Equal(cert.RawSubjectPublicKeyInfo, public) {
		return "", nil, zero, errors.New("[Windows migration] 原证书与受保护密钥不匹配")
	}
	ca, err := readWindowsMigrationFile(filepath.Join(root, "tls", "ca.crt"), 64<<10)
	if err != nil {
		return "", nil, zero, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return "", nil, zero, errors.New("[Windows migration] 原 CA 无效")
	}
	// 这是历史身份验证；当前权限仍由 v2 迁移证明及当前 Head 决定。
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: config.NodeID + ".node.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: cert.NotBefore.Add(time.Second)}); err != nil {
		return "", nil, zero, errors.New("[Windows migration] 原证书不能证明此设备身份")
	}
	keep = true
	return config.NodeID, key, floor, nil
}

func readWindowsMigrationFile(path string, maximum int64) ([]byte, error) {
	if !localWindowsPath(path) {
		return nil, errors.New("[Windows migration] 原记录必须位于本机磁盘")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("[Windows migration] 原记录不是有界普通文件")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		return nil, errors.New("[Windows migration] 读取期间原记录发生变化")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != after.Size() {
		clear(body)
		return nil, errors.New("[Windows migration] 原记录大小发生变化")
	}
	return body, nil
}

func migrateWindowsDevice(ctx context.Context, root string, protector clientsecret.Protector,
	delivery wire.RuntimeDeviceMigrationPackageV1, progress windowsJoinProgress) (windowsJoinResult, error) {
	lock, err := acquireWindowsJoinLock()
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer lock.close()
	state, err := windowsV2Installed(root, protector)
	if err != nil {
		return windowsJoinResult{}, err
	}
	if state != nil {
		return windowsJoinResult{}, errors.New("设备已安装 v2，迁移包不能覆盖现有身份")
	}
	platform, err := embeddedWindowsPlatformKey()
	if err != nil {
		return windowsJoinResult{}, err
	}
	deviceID, original, floor, err := readLegacyWindowsIdentity(root, protector, platform)
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer clear(original.D.Bits())
	progress.report("正在验证原设备身份和迁移证明…")
	identity, err := windowsv2.ImportIdentity(windowsV2IdentityPath(root), protector, original, nil)
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer identity.Close()
	oldCurrent, err := base64.RawURLEncoding.DecodeString(delivery.LegacySignedCurrent)
	if err != nil || base64.RawURLEncoding.EncodeToString(oldCurrent) != delivery.LegacySignedCurrent {
		return windowsJoinResult{}, errors.New("原签名配置编码无效")
	}
	legacy, err := clientmigration.VerifyFloor(oldCurrent, platform, deviceID, floor)
	if err != nil {
		return windowsJoinResult{}, err
	}
	wrappingHash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, identity.WrappingSPKIDER())
	if err != nil {
		return windowsJoinResult{}, err
	}
	expected := wire.RuntimeDeviceMigrationExpectedV1{DeviceID: deviceID, Platform: "windows-desktop",
		IdentitySPKIDER: identity.IdentitySPKIDER(), WrappingKeyHash: wrappingHash, LegacyFloor: legacy}
	trust := wire.InviteProofTrustV2{V1PlatformKey: platform, V1PlatformKeyID: delivery.Activation.Proof.Statement.V1PlatformKeyID}
	verified, err := wire.VerifyRuntimeDeviceMigration(&delivery, expected, trust, time.Now().UTC())
	if err != nil {
		return windowsJoinResult{}, err
	}
	componentPath, err := bundledWindowsComponentPath()
	if err != nil {
		return windowsJoinResult{}, err
	}
	componentBody, _, err := prepareWindowsJoinComponent(windowsJoinCommitOptions{
		Root: root, ComponentPath: componentPath, Protector: protector, Arch: runtime.GOARCH, PlatformKey: platform, Progress: progress})
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer clear(componentBody)
	final := verified.Configuration().Envelope()
	progress.report("正在获取设备的认证 v2 配置…")
	configs, err := windowsv2.FetchConfigArtifacts(ctx, delivery.DistributionMirrors,
		final.Payload.Active.ConfigArtifactRefs, clientv2.MirrorFetcher{Timeout: 30 * time.Second})
	if err != nil {
		return windowsJoinResult{}, err
	}
	if _, err := clientcomponent.InstallWindows(root, componentBody, platform); err != nil {
		return windowsJoinResult{}, err
	}
	if _, err := windowsv2.InstallMigration(windowsv2.MigrationInstall{
		StatePath: windowsV2StatePath(root), IdentityPath: windowsV2IdentityPath(root), Protector: protector,
		Package: delivery, Expected: expected, LegacyFloor: floor, Trust: trust, Now: time.Now().UTC(), Configs: configs,
		ValidateCandidate: func(candidate *windowsv2.StateV1) error {
			return preflightWindowsV2InstallCandidate(ctx, root, candidate, platform)
		},
	}); err != nil {
		return windowsJoinResult{}, err
	}
	return windowsJoinResult{NodeID: deviceID}, nil
}

func exportWindowsMigrationRequest(edition clientEdition, args []string) error {
	options := flag.NewFlagSet("migration-request", flag.ContinueOnError)
	options.SetOutput(io.Discard)
	destination := options.String("out", "", "迁移请求输出文件")
	profileID := options.String("profile", "", "原连接配置 ID，默认当前配置")
	if err := options.Parse(args); err != nil || options.NArg() != 0 || *destination == "" {
		return errors.New("用法：--migration-request --out <文件> [--profile <配置 ID>]")
	}
	base, err := localAppDataRoot()
	var protector clientsecret.Protector = clientsecret.UserProtector{}
	if edition == editionInstalled {
		if !windows.GetCurrentProcessToken().IsElevated() {
			return errors.New("导出 Installed 原身份迁移请求需要管理员权限")
		}
		base, err = programDataRoot()
		protector = clientsecret.MachineProtector{}
	}
	if err != nil {
		return err
	}
	lock, err := acquireWindowsJoinLock()
	if err != nil {
		return err
	}
	defer lock.close()
	profiles, err := loadConnectionProfiles(base, writeWindowsJoinFile, checkWindowsProfilePath)
	if err != nil {
		return err
	}
	if *profileID == "" {
		*profileID = profiles.Snapshot().Selected
	}
	root, err := profiles.ResolveRoot(*profileID)
	if err != nil {
		return err
	}
	state, err := windowsV2Installed(root, protector)
	if err != nil {
		return err
	}
	if state != nil {
		return errors.New("当前设备已使用 v2，无需迁移")
	}
	platform, err := embeddedWindowsPlatformKey()
	if err != nil {
		return err
	}
	deviceID, original, floor, err := readLegacyWindowsIdentity(root, protector, platform)
	if err != nil {
		return err
	}
	defer clear(original.D.Bits())
	identity, err := windowsv2.ImportIdentity(windowsV2IdentityPath(root), protector, original, nil)
	if err != nil {
		return err
	}
	defer identity.Close()
	floorJSON, err := wire.MarshalCanonical(floor)
	if err != nil {
		return err
	}
	request, err := wire.SignRuntimeDeviceMigrationRequest(wire.RuntimeDeviceMigrationRequestBodyV1{
		Schema: 1, DeviceID: deviceID, Platform: "windows-desktop",
		PlatformKeyHash:    fmt.Sprintf("sha256:%x", sha256.Sum256(platform)),
		IdentitySPKIDER:    base64.RawURLEncoding.EncodeToString(identity.IdentitySPKIDER()),
		WrappingSPKIDER:    base64.RawURLEncoding.EncodeToString(identity.WrappingSPKIDER()),
		WrappingKeyProfile: windowsv2.WrappingKeyProfile, LegacyFloor: floorJSON,
	}, identity.Signer())
	if err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(*destination)
	if err != nil || !localWindowsPath(path) {
		return errors.New("迁移请求输出必须位于本机磁盘")
	}
	return writeWindowsJoinCommit(path, body)
}
