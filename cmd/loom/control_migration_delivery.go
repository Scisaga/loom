package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/wire"
)

const privateControlMigrationPrefix = "/private/v2/control/migrations/"

// 迁移证书和旧 current 是生成器保存的不可变交付输入；只有实际日志中的
// activation/Head/QC 和当前 Device view 可以把它们组合成可安装交付物。
func (runtime *controlRuntime) migrationDeliveryLocked(deviceID string) (wire.RuntimeDeviceMigrationPackageV1, error) {
	var delivery wire.RuntimeDeviceMigrationPackageV1
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		return delivery, err
	}
	var activation *controlOperationRecordV1
	for i := range runtime.journal.Records {
		if runtime.journal.Records[i].Activation != nil {
			activation = &runtime.journal.Records[i]
			break
		}
	}
	if activation == nil || activation.Result == nil {
		return delivery, errors.New("[设备迁移] 原迁移尚未认证")
	}
	proof, err := wire.BuildRuntimeDeviceMigrationProof(activation.Activation.Application.DeviceMigrations, deviceID)
	if err != nil {
		return delivery, err
	}
	authority, err := runtime.readDeviceIdentityLocked(proof.Leaf.DeviceCertificateHash)
	if err != nil || authority.Record.IdentityStatus != "active" {
		return delivery, errors.New("[设备迁移] 当前 Device 不允许安装迁移")
	}
	certificate, err := readOwnerOnlyFile(filepath.Join(runtime.dir, "migration-certificates",
		strings.TrimPrefix(proof.Leaf.DeviceCertificateHash, "sha256:")+".der"), 1<<20)
	if err != nil {
		return delivery, errors.New("[设备迁移] 缺原迁移的证书材料")
	}
	hash, err := wire.DeviceCertificateHash(certificate)
	if err != nil || hash != proof.Leaf.DeviceCertificateHash {
		return delivery, errors.New("[设备迁移] 证书材料不匹配已认证迁移")
	}
	current, err := readOwnerOnlyFile(filepath.Join(runtime.dir, "migration-currents",
		strings.TrimPrefix(proof.Leaf.LegacyFloor.V1SignedCurrentHash, "sha256:")+".json"), 4<<20)
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(current)) != proof.Leaf.LegacyFloor.V1SignedCurrentHash {
		return delivery, errors.New("[设备迁移] 缺原签名 current 的 exact bytes")
	}
	var originalProfile *wire.DeviceCertificateProfileStateV1
	for _, profile := range activation.Activation.Application.CARegistry.DeviceProfiles {
		hash, err := wire.DeviceCertificateProfileStateHash(&profile)
		if err == nil && hash == proof.Leaf.DeviceCertificateProfileHash {
			copy := profile
			originalProfile = &copy
			break
		}
	}
	if originalProfile == nil {
		return delivery, errors.New("[设备迁移] 缺原迁移的 CA profile")
	}
	bundle := controlClone(activation.Activation.Bundle)
	bundle.Head = activation.Result.Head
	if _, err := wire.DecodeStrict(activation.Result.ConfigQC, 4<<20, &bundle.ConfigQC); err != nil {
		return delivery, err
	}
	delivery = wire.RuntimeDeviceMigrationPackageV1{Schema: 1, LegacySignedCurrent: base64.RawURLEncoding.EncodeToString(current),
		Activation: bundle, Migration: proof, DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificate),
		DeviceProfile: *originalProfile, AdminCertificateProfiles: authority.AdminCertificateProfiles,
		DeviceCertificateProfiles: authority.DeviceCertificateProfiles, DistributionMirrors: application.Mirrors,
		Configuration: wire.DeviceConfigDeliveryV1{Schema: 1, ClusterID: application.ClusterID, DeviceID: deviceID,
			Updates: authority.DeviceConfigUpdates, SecretEnvelopes: authority.DeviceSecretEnvelopes}}
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		return wire.RuntimeDeviceMigrationPackageV1{}, err
	}
	public, err := base64.RawURLEncoding.DecodeString(bundle.Proof.Statement.V1PlatformPublicKey)
	if err != nil {
		return wire.RuntimeDeviceMigrationPackageV1{}, err
	}
	if _, err := wire.VerifyRuntimeDeviceMigration(&delivery, wire.RuntimeDeviceMigrationExpectedV1{
		DeviceID: deviceID, Platform: proof.Leaf.Platform, IdentitySPKIDER: parsed.RawSubjectPublicKeyInfo,
		WrappingKeyHash: proof.Leaf.WrappingKeyHash, LegacyFloor: proof.Leaf.LegacyFloor,
	}, wire.InviteProofTrustV2{V1PlatformKey: public, V1PlatformKeyID: bundle.Proof.Statement.V1PlatformKeyID}, runtime.now().UTC()); err != nil {
		return wire.RuntimeDeviceMigrationPackageV1{}, err
	}
	return controlClone(delivery), nil
}

func (runtime *controlRuntime) serveMigrationDelivery(writer http.ResponseWriter, request *http.Request) {
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		!ok || local == nil || local.String() != address || request.Host != address || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) < 1 ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" ||
		request.Header.Get("Referer") != "" || request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		writeControlRuntimeError(writer, http.StatusForbidden, "[设备迁移] 私有管理员传输被拒绝")
		return
	}
	id := strings.TrimPrefix(request.URL.Path, privateControlMigrationPrefix)
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		http.NotFound(writer, request)
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	// 交付包含逐设备私有目录，需当前 certified cluster 管理权限。
	if !runtime.inviteAdminAuthorizedLocked(request.TLS.PeerCertificates[0].Raw) {
		writeControlRuntimeError(writer, http.StatusForbidden, "[设备迁移] 管理员未获交付权限")
		return
	}
	delivery, err := runtime.migrationDeliveryLocked(id)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusConflict, "[设备迁移] 当前迁移材料尚不可交付")
		return
	}
	body, err := wire.MarshalCanonical(delivery)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusInternalServerError, "[设备迁移] 交付编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(body)
}

func cmdControlExportMigration(args []string) error {
	fs := flag.NewFlagSet("control export-migration", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "管理员证书与 endpoint 目录")
	deviceID := fs.String("device", "", "原 Device ID")
	out := fs.String("out", "", "保存迁移文件的受保护目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" || *deviceID == "" || strings.ContainsAny(*deviceID, "/\\?#%") || *out == "" {
		return errors.New("control export-migration 需要 -admin-dir、-device 和 -out")
	}
	endpoint, client, err := loadControlAdminClient(*adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var delivery wire.RuntimeDeviceMigrationPackageV1
	if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlMigrationPrefix+*deviceID, &delivery); err != nil {
		return err
	}
	if delivery.Schema != 1 || delivery.Migration.Leaf.DeviceID != *deviceID || delivery.Activation.Head.Body.Payload.ClusterID != endpoint.ClusterID {
		return errors.New("[设备迁移] 管理面返回不同网络或 Device 的交付")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(*out)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[设备迁移] 交付目录必须是 0700 实体目录")
	}
	if err := writeCanonicalAtomic(filepath.Join(*out, "device.loom-migration"), delivery, 0o600); err != nil {
		return err
	}
	fmt.Println("✓ 原 Device 的认证迁移文件已导出")
	return nil
}
