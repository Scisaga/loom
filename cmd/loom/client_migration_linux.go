//go:build linux

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
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/clientv2"
	"loom/internal/wire"
)

func cmdClientExportMigrationRequest(args []string) error {
	fs := flag.NewFlagSet("client export-migration-request", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom/client-v2", "本机 v2 身份目录")
	deviceID := fs.String("device", "", "原设备 ID")
	keyPath := fs.String("identity-key", "/etc/loom/tls/node.key", "原设备 P-256 私钥")
	certificatePath := fs.String("identity-cert", "/etc/loom/tls/node.crt", "原设备证书")
	caPath := fs.String("identity-ca", "/etc/loom/tls/ca.crt", "原设备 CA")
	platformPath := fs.String("platform-pubkey", "/etc/loom/platform-signing.pub", "原平台公钥")
	floorPath := fs.String("floor", "", "原 signed pull floor 文件")
	output := fs.String("out", "", "公共迁移请求文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *deviceID == "" || *floorPath == "" || *output == "" || !filepath.IsAbs(*dir) || filepath.Clean(*dir) != *dir {
		return errors.New("client export-migration-request 必须指定 -device、-floor、-out 和本机绝对 state-dir")
	}
	floorRaw, err := readOwnerOnlyFile(*floorPath, 64<<10)
	if err != nil {
		return err
	}
	floor, err := clientmigration.ParseFloor(floorRaw)
	if err != nil {
		return err
	}
	canonicalFloor, err := wire.MarshalCanonical(floor)
	if err != nil {
		return err
	}
	platform, err := readKey(*platformPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	keyPEM, err := readOwnerOnlyFile(*keyPath, 64<<10)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("[Linux migration] 原私钥 PEM 无效")
	}
	defer clear(block.Bytes)
	var key *ecdsa.PrivateKey
	if block.Type == "EC PRIVATE KEY" {
		key, err = x509.ParseECPrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*ecdsa.PrivateKey)
	}
	if err != nil || key == nil || key.Curve != elliptic.P256() {
		return errors.New("[Linux migration] 原设备私钥不是 P-256")
	}
	defer clear(key.D.Bits())
	certificatePEM, err := os.ReadFile(*certificatePath)
	if err != nil {
		return err
	}
	certificate, err := parseSingleCertificatePEM(certificatePEM)
	if err != nil {
		return err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(public, certificate.RawSubjectPublicKeyInfo) {
		return errors.New("[Linux migration] 原证书与身份 key 不一致")
	}
	ca, err := os.ReadFile(*caPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("[Linux migration] 原 CA 无效")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: *deviceID + ".node.internal",
		CurrentTime: certificate.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("[Linux migration] 原证书未证明指定设备身份")
	}
	identity, err := clientv2.ImportLinuxMigrationIdentity(filepath.Join(*dir, "identity.json"), key)
	if err != nil {
		return err
	}
	request, err := identity.SignMigrationRequest(wire.RuntimeDeviceMigrationRequestBodyV1{Schema: 1, DeviceID: *deviceID, Platform: "linux-server",
		PlatformKeyHash: fmt.Sprintf("sha256:%x", sha256.Sum256(platform)), IdentitySPKIDER: identity.IdentityPublicKeySPKI,
		WrappingSPKIDER: identity.WrappingPublicKeySPKI, WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1", LegacyFloor: canonicalFloor})
	if err != nil {
		return err
	}
	if err := writeCanonicalAtomic(*output, request, 0o600); err != nil {
		return err
	}
	fmt.Println("✓ 已导出原身份签名的迁移请求；原密钥和 floor 保留")
	return nil
}

func cmdClientImportMigration(args []string) error {
	fs := flag.NewFlagSet("client import-migration", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom/client-v2", "本机 v2 身份目录")
	deviceID := fs.String("device", "", "原设备 ID")
	packagePath := fs.String("file", "", "管理员导出的 certified 原身份迁移包")
	floorPath := fs.String("floor", "", "原 signed pull floor 文件")
	platformPath := fs.String("platform-pubkey", "/etc/loom/platform-signing.pub", "原平台公钥")
	peerPath := fs.String("control-peer-directory", "", "control 节点的 certified 私有 peer directory")
	dryRun := fs.Bool("dry-run", false, "验证完整迁移与运行配置，不安装身份或激活服务")
	timeout := fs.Duration("timeout", 2*time.Minute, "下载与激活各自的超时")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *deviceID == "" || *packagePath == "" || *floorPath == "" ||
		!filepath.IsAbs(*dir) || filepath.Clean(*dir) != *dir || *timeout < time.Second || *timeout > 10*time.Minute {
		return errors.New("client import-migration 必须指定 -device、-file、-floor 和规范绝对 state-dir")
	}
	if !*dryRun && os.Geteuid() != 0 {
		return errors.New("[Linux migration] 安装并激活必须由目标节点 root 执行")
	}
	var delivery wire.RuntimeDeviceMigrationPackageV1
	if err := readExactLinuxV2JSON(*packagePath, 32<<20, &delivery); err != nil {
		return err
	}
	floorRaw, err := readOwnerOnlyFile(*floorPath, 64<<10)
	if err != nil {
		return err
	}
	floor, err := clientmigration.ParseFloor(floorRaw)
	if err != nil {
		return err
	}
	platform, err := readKey(*platformPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	identityPath := filepath.Join(*dir, "identity.json")
	identity, err := clientv2.LoadEnrollmentIdentityForResume(identityPath)
	if err != nil {
		return err
	}
	public, err := base64.RawURLEncoding.DecodeString(identity.IdentityPublicKeySPKI)
	if err != nil {
		return err
	}
	wrapping, err := base64.RawURLEncoding.DecodeString(identity.WrappingPublicKeySPKI)
	if err != nil {
		return err
	}
	wrappingHash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrapping)
	if err != nil {
		return err
	}
	original, err := base64.RawURLEncoding.DecodeString(delivery.LegacySignedCurrent)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != delivery.LegacySignedCurrent {
		return errors.New("[Linux migration] 原 signed current 编码无效")
	}
	legacyFloor, err := clientmigration.VerifyFloor(original, platform, *deviceID, floor)
	if err != nil {
		return err
	}
	expected := wire.RuntimeDeviceMigrationExpectedV1{DeviceID: *deviceID, Platform: "linux-server",
		IdentitySPKIDER: public, WrappingKeyHash: wrappingHash, LegacyFloor: legacyFloor}
	trust := wire.InviteProofTrustV2{V1PlatformKey: platform,
		V1PlatformKeyID: delivery.Activation.Proof.Statement.V1PlatformKeyID}
	now := time.Now().UTC()
	verified, err := wire.VerifyRuntimeDeviceMigration(&delivery, expected, trust, now)
	if err != nil {
		return err
	}
	var peers *wire.ControlPeerDirectoryPrivateObjectV1
	if *peerPath != "" {
		peers = new(wire.ControlPeerDirectoryPrivateObjectV1)
		if err := readExactLinuxV2JSON(*peerPath, 4<<20, peers); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	envelope := verified.Configuration().Envelope()
	configs, err := clientv2.FetchLinuxDeviceConfigArtifacts(ctx, delivery.DistributionMirrors,
		envelope.Payload.Active.ConfigArtifactRefs, clientv2.MirrorFetcher{Timeout: linuxClientV2NetworkTimeout(*timeout)})
	if err != nil {
		return err
	}
	input := clientv2.LinuxMigrationInstall{StatePath: filepath.Join(*dir, "state.json"), IdentityPath: identityPath,
		Package: delivery, Expected: expected, LegacyFloor: floor, Trust: trust, Now: now, Configs: configs,
		ValidateCandidate: func(state *clientv2.State) error { return clientv2.ValidateLinuxMigrationRuntime(state, peers, now) }}
	if *dryRun {
		candidate, err := clientv2.PrepareLinuxMigration(input)
		if err != nil {
			return err
		}
		if err := input.ValidateCandidate(candidate); err != nil {
			return err
		}
		fmt.Println("✓ 迁移证明、原身份和完整运行配置已验证；未安装身份或激活服务")
		return nil
	}
	if _, err := clientv2.InstallLinuxMigration(input); err != nil {
		return err
	}
	runtimeArgs := []string{"-state-dir", *dir, "-apply", "-timeout", timeout.String()}
	if *peerPath != "" {
		runtimeArgs = append(runtimeArgs, "-control-peer-directory", *peerPath)
	}
	if err := cmdClientAcceptV2Runtime(runtimeArgs); err != nil {
		return fmt.Errorf("[Linux migration] 身份和 floors 已保存，运行配置尚未激活；修复后执行 client accept-v2-runtime -apply：%w", err)
	}
	fmt.Println("✓ 原设备身份已迁移到 v2，运行配置已事务激活")
	return nil
}
