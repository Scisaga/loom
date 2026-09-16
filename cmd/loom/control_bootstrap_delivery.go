package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
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

	"loom/internal/bootstrapaccess"
	"loom/internal/clientmigration"
	"loom/internal/wire"
)

const privateControlBootstrapPrefix = "/private/v2/control/bootstrap-installation/"

type bootstrapInstallationBundleV1 struct {
	Schema       int                                   `json:"schema"`
	DeviceID     string                                `json:"device_id"`
	Activation   wire.RuntimeActivationBundleV1        `json:"activation"`
	Installation wire.ControlApplicationSectionProofV2 `json:"installation"`
}

func verifyBootstrapInstallationBundle(bundle bootstrapInstallationBundleV1, public ed25519.PublicKey, deviceID string) (bootstrapaccess.InitialBootstrapInstallationV1, error) {
	var installation bootstrapaccess.InitialBootstrapInstallationV1
	if bundle.Schema != 1 || bundle.DeviceID == "" || bundle.DeviceID != deviceID {
		return installation, errors.New("[bootstrap] 安装交付不属于此设备")
	}
	trust, err := clientmigration.RuntimeActivationTrust(public)
	if err != nil {
		return installation, err
	}
	if _, err := wire.VerifyRuntimeActivationBundle(&bundle.Activation, trust, "", ""); err != nil {
		return installation, err
	}
	if err := wire.VerifyControlApplicationSectionProofV2(&bundle.Installation, bundle.Activation.Head.Body.Payload.SnapshotHash,
		bundle.Activation.Head.Body.Payload.ClusterID, "bootstrap_installation"); err != nil {
		return installation, err
	}
	if _, err := wire.DecodeStrict(bundle.Installation.Content, 16<<20, &installation); err != nil {
		return installation, err
	}
	if err := bootstrapaccess.ValidateInitialBootstrapInstallation(&installation); err != nil {
		return installation, err
	}
	if !wire.EqualCanonical(installation.Input.Parent, bundle.Activation.Parent) || !wire.EqualCanonical(installation.Input.ControlSet, bundle.Activation.ControlSet) {
		return installation, errors.New("[bootstrap] 初始计划与原认证 parent 不一致")
	}
	found := false
	for _, listener := range installation.Input.Listeners {
		found = found || listener.Profile.ServerID == deviceID
	}
	if !found {
		return installation, errors.New("[bootstrap] 安装计划未授权本设备监听")
	}
	return installation, nil
}

func (runtime *controlRuntime) bootstrapInstallationDeliveryLocked(deviceID string) (bootstrapInstallationBundleV1, error) {
	var empty bootstrapInstallationBundleV1
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		return empty, err
	}
	if application.BootstrapInstallation == nil {
		return empty, errors.New("[bootstrap] 尚无正式安装计划")
	}
	for _, record := range runtime.journal.Records {
		if record.Activation == nil || record.Result == nil {
			continue
		}
		original := record.Activation.Application
		if original.Schema != 2 || !wire.EqualCanonical(original.BootstrapInstallation, application.BootstrapInstallation) {
			return empty, errors.New("[bootstrap] 初始安装已改变，不能重放旧授权")
		}
		body, err := wire.MarshalCanonical(original)
		if err != nil {
			return empty, err
		}
		proof, err := wire.BuildControlApplicationSectionProofV2(body, "bootstrap_installation")
		if err != nil {
			return empty, err
		}
		activation := controlClone(record.Activation.Bundle)
		activation.Head = record.Result.Head
		if _, err := wire.DecodeStrict(record.Result.ConfigQC, 4<<20, &activation.ConfigQC); err != nil {
			return empty, err
		}
		delivery := bootstrapInstallationBundleV1{Schema: 1, DeviceID: deviceID, Activation: activation, Installation: proof}
		public, err := base64.RawURLEncoding.DecodeString(activation.Proof.Statement.V1PlatformPublicKey)
		if err != nil {
			return empty, err
		}
		if _, err := verifyBootstrapInstallationBundle(delivery, public, deviceID); err != nil {
			return empty, err
		}
		return delivery, nil
	}
	return empty, errors.New("[bootstrap] 安装计划尚未进入原认证日志")
}

func (runtime *controlRuntime) serveBootstrapInstallation(writer http.ResponseWriter, request *http.Request) {
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" || !ok || local == nil || local.String() != address || request.Host != address ||
		request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) < 1 || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Referer") != "" || request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		writeControlRuntimeError(writer, http.StatusForbidden, "[bootstrap] 私有管理员传输被拒绝")
		return
	}
	id := strings.TrimPrefix(request.URL.Path, privateControlBootstrapPrefix)
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		http.NotFound(writer, request)
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.inviteAdminAuthorizedLocked(request.TLS.PeerCertificates[0].Raw) {
		writeControlRuntimeError(writer, http.StatusForbidden, "[bootstrap] 管理员无交付权限")
		return
	}
	bundle, err := runtime.bootstrapInstallationDeliveryLocked(id)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusConflict, "[bootstrap] 安装材料尚不可交付")
		return
	}
	body, err := wire.MarshalCanonical(bundle)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusInternalServerError, "[bootstrap] 交付编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(body)
}

func cmdControlExportBootstrap(args []string) error {
	flags := flag.NewFlagSet("control export-bootstrap", flag.ContinueOnError)
	admin := flags.String("admin-dir", "", "原管理员交付目录")
	device := flags.String("device", "", "原 Device ID")
	out := flags.String("out", "", "受保护的交付文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *admin == "" || *device == "" || strings.ContainsAny(*device, "/\\?#%") || !filepath.IsAbs(*out) {
		return errors.New("export-bootstrap 需要 admin-dir、device 与 out 绝对路径")
	}
	parent, err := os.Lstat(filepath.Dir(*out))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("bootstrap 交付输出须位于已有的 0700 实体目录")
	}
	endpoint, client, err := loadControlAdminClient(*admin)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var bundle bootstrapInstallationBundleV1
	if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlBootstrapPrefix+*device, &bundle); err != nil {
		return err
	}
	if bundle.DeviceID != *device || bundle.Activation.Head.Body.Payload.ClusterID != endpoint.ClusterID {
		return errors.New("bootstrap 交付网络或设备不匹配")
	}
	if err := writeCanonicalAtomic(*out, bundle, 0600); err != nil {
		return err
	}
	fmt.Println("✓ 已导出认证安装计划及部分证明；不包含私有 application 的其他内容")
	return nil
}
