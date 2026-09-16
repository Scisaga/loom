package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/wire"
)

const privateControlPrepareClientPath = "/private/v2/control/device-config/prepare"

// 管理员仅提供公开隧道分配和现有数据面凭据；网络、职责和配置代从当前
// certified application 读取。秘密仅经管理员 mTLS 输入，日志只保存密文。
type controlClientConfigInputV1 struct {
	Schema         int                              `json:"schema"`
	DeviceID       string                           `json:"device_id"`
	Recipient      wire.SealedBlobRecipientKeyRefV1 `json:"recipient"`
	ControlTunnel  render.ClientControlTunnelV2     `json:"control_tunnel"`
	SingBoxVersion string                           `json:"sing_box_version"`
	ObservationCA  string                           `json:"observation_ca_pem"`
	Credentials    map[string]string                `json:"credentials"`
}

type controlPrepareClientRequestV1 struct {
	Schema       int                        `json:"schema"`
	RequestID    string                     `json:"request_id"`
	ExpectedHead string                     `json:"expected_head"`
	Input        controlClientConfigInputV1 `json:"input"`
}

type controlPreparedClientV1 struct {
	Schema    int                           `json:"schema"`
	InputHash string                        `json:"input_hash"`
	Payload   controlPublishDevicePayloadV1 `json:"payload"`
}

func (runtime *controlRuntime) prepareClientConfigLocked(request controlPrepareClientRequestV1) (controlPublishDevicePayloadV1, error) {
	var empty controlPublishDevicePayloadV1
	if request.Schema != 1 || request.Input.Schema != 1 || request.RequestID == "" || len(request.RequestID) > 128 ||
		request.Input.Credentials == nil || request.Input.DeviceID == "" {
		return empty, errors.New("[配置生成] 缺设备、请求 ID 或凭据输入")
	}
	inputHash, err := wire.HashObject("loom-control-client-config-input-v1", request)
	if err != nil {
		return empty, err
	}
	requestHash := wire.HashRaw("loom-control-client-config-request-v1", []byte(request.RequestID))
	root := filepath.Join(runtime.dir, "prepared-client-configs")
	path := filepath.Join(root, strings.TrimPrefix(requestHash, "sha256:")+".json")
	var retained controlPreparedClientV1
	if err := readCanonicalFile(path, 4<<20, &retained); err == nil {
		if retained.Schema != 1 || retained.InputHash != inputHash {
			return empty, errors.New("[配置生成] 请求 ID 已绑定另一份输入")
		}
		return retained.Payload, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedHead.HeadHash != request.ExpectedHead || state.Active != nil {
		return empty, errors.New("[配置生成] 当前 Head 与管理员读取的 base 不一致")
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		return empty, err
	}
	var device *controlDeviceStateV1
	for i := range application.Devices {
		if application.Devices[i].View.DeviceID == request.Input.DeviceID {
			device = &application.Devices[i]
		}
	}
	if device == nil || device.View.Active == nil || device.View.State != "active" || device.View.DeviceGeneration == math.MaxInt64 {
		return empty, errors.New("[配置生成] 设备未激活、已撤销或配置代耗尽")
	}
	platform, err := application.devicePlatform(request.Input.DeviceID)
	if err != nil || platform != "android" && platform != "windows-desktop" && platform != "linux-server" {
		return empty, errors.New("[配置生成] 本入口要求已认证的 Linux/Android/Windows 设备")
	}
	if platform != "linux-server" && !wire.EqualCanonical(device.View.Active.Responsibilities.Values, []string{"use_loom"}) {
		return empty, errors.New("[配置生成] Android/Windows 职责必须为 use_loom")
	}
	sealing, err := clientConfigSealingPolicy(application, *device, request.Input.Recipient, platform)
	if err != nil {
		return empty, err
	}
	if err := wire.ValidateRuntimeCABundle(request.Input.ObservationCA); err != nil {
		return empty, err
	}
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		return empty, err
	}
	artifactGeneration := int64(1)
	for _, ref := range device.View.Active.ConfigArtifactRefs {
		if ref.Generation == math.MaxInt64 {
			return empty, errors.New("[配置生成] 制品 generation 已耗尽")
		}
		if ref.Generation >= artifactGeneration {
			artifactGeneration = ref.Generation + 1
		}
	}
	var rendered render.ClientRuntimeV2
	var controlLink *wire.DeviceControlLinkV1
	configs := []controlPublishedConfigV1{}
	if platform == "linux-server" {
		if !wire.EqualCanonical(request.Input.ControlTunnel, render.ClientControlTunnelV2{}) {
			return empty, errors.New("[配置生成] Linux 从认证网络生成逐边隧道，不接收移动端隧道输入")
		}
		views := map[string]wire.DeviceViewPayloadV2{}
		for _, current := range application.Devices {
			views[current.View.DeviceID] = current.View
		}
		qc, err := wire.MarshalCanonical(state.CertifiedQC)
		if err != nil {
			return empty, err
		}
		linux, err := render.RenderLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: ssot, Views: views,
			Authority: wire.CertifiedHeadV1{Head: *state.CertifiedHead, QC: qc}, DeviceID: device.View.DeviceID,
			DeviceGeneration: device.View.DeviceGeneration + 1, ArtifactGeneration: artifactGeneration,
			DeviceControlLinks: application.deviceControlLinksFor(device.View.DeviceID)})
		if err != nil {
			return empty, err
		}
		rendered = linux.Runtime
		configs = append(configs, controlPublishedConfigV1{Ref: linux.Links.Ref, Content: linux.Links.Content})
	} else {
		tunnel := controlClone(request.Input.ControlTunnel)
		link, err := application.prepareDeviceControlLink(request.Input, device.View.DeviceGeneration+1)
		if err != nil {
			return empty, err
		}
		controlLink = &link
		// 客户端控制路由由认证目录限定，不接受管理员输入扩大到任意私网。
		allowed := map[string]bool{}
		for _, service := range application.Services {
			if service.Role != "device_config" && service.Role != "device_report" {
				continue
			}
			address, err := netip.ParseAddr(service.OverlayIP)
			if err != nil || !address.IsPrivate() {
				return empty, errors.New("[配置生成] 设备控制服务必须使用认证私网地址")
			}
			allowed[netip.PrefixFrom(address, address.BitLen()).String()] = true
		}
		tunnel.AllowedIPs = make([]string, 0, len(allowed))
		for prefix := range allowed {
			tunnel.AllowedIPs = append(tunnel.AllowedIPs, prefix)
		}
		sort.Strings(tunnel.AllowedIPs)
		if len(tunnel.AllowedIPs) == 0 {
			return empty, errors.New("[配置生成] 缺设备控制服务")
		}
		if len(request.Input.ControlTunnel.AllowedIPs) != 0 && !wire.EqualCanonical(request.Input.ControlTunnel.AllowedIPs, tunnel.AllowedIPs) {
			return empty, errors.New("[配置生成] 指定控制路由与认证服务目录不同")
		}
		rendered, err = render.RenderClientRuntimeV2(render.ClientRuntimeV2Input{SSOT: ssot, Grants: &device.View.Active.Grants, ClusterID: application.ClusterID,
			DeviceID: device.View.DeviceID, DeviceGeneration: device.View.DeviceGeneration + 1, ArtifactGeneration: artifactGeneration,
			SingBoxVersion: request.Input.SingBoxVersion, ObservationCA: request.Input.ObservationCA, ControlTunnel: tunnel})
		if err != nil {
			return empty, err
		}
	}
	configs = append(configs, controlPublishedConfigV1{Ref: rendered.Ref, Content: rendered.Content})
	if len(rendered.Skipped) != 0 {
		return empty, errors.New("[配置生成] 运行配置包含未实现的渲染项")
	}
	if rendered.Ref.Platform != platform || len(rendered.CredentialRefs) != len(request.Input.Credentials) {
		return empty, errors.New("[配置生成] 原网络平台或凭据集合与生成结果不一致")
	}
	privateControl, err := runtime.devicePrivateControlCredentialLocked(application, device.View.DeviceID)
	if err != nil {
		return empty, err
	}
	privateBody, err := wire.MarshalCanonical(privateControl)
	if err != nil {
		return empty, err
	}
	defer clear(privateBody)
	values := map[string]string{wire.DevicePrivateControlCredentialSecretIDV1: string(privateBody), wire.DeviceObservationCASecretIDV1: request.Input.ObservationCA}
	for _, ref := range rendered.CredentialRefs {
		value, found := request.Input.Credentials[ref]
		if !found || value == "" || ref == wire.DevicePrivateControlCredentialSecretIDV1 || ref == wire.DeviceObservationCASecretIDV1 {
			return empty, errors.New("[配置生成] 缺 exact 数据面凭据或与保留 ID 冲突")
		}
		values[ref] = value
	}
	material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, false)
	if err != nil {
		return empty, err
	}
	defer material.Close()
	policy, err := material.availabilityPolicy(application.ClusterID)
	if err != nil {
		return empty, err
	}
	approved := false
	for _, existing := range application.ArtifactPolicies {
		approved = approved || wire.EqualCanonical(existing, policy)
	}
	if !approved {
		return empty, errors.New("[配置生成] 本机 artifact reporter 尚未获当前 authority 授权")
	}
	previous, err := wire.DeviceViewHash(&device.View)
	if err != nil {
		return empty, err
	}
	payload := controlPublishDevicePayloadV1{Schema: 1, Publication: controlDevicePublicationV1{Schema: 1,
		DeviceID: device.View.DeviceID, PreviousViewHash: previous, Configs: configs,
		Secrets: []enrollmentv2.SealedMaterialEvidenceV1{}, ControlLink: controlLink}, Envelopes: []wire.SealedSecretEnvelopeV1{}}
	// Secret root 先按用途枚举排序：device_credential 在 data_plane_credential
	// 前；每个用途内按 ID 排序。renderer 已返回排序后的数据面 ref。
	ids := append([]string{wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1}, rendered.CredentialRefs...)
	for _, id := range ids {
		generation := int64(1)
		for _, ref := range device.SecretArtifactRefs {
			if ref.SecretID == id {
				if ref.Generation == math.MaxInt64 {
					return empty, errors.New("[配置生成] secret generation 已耗尽")
				}
				generation = ref.Generation + 1
			}
		}
		purpose := "data_plane_credential"
		if id == wire.DevicePrivateControlCredentialSecretIDV1 || id == wire.DeviceObservationCASecretIDV1 {
			purpose = "device_credential"
		}
		recipients := []wire.SealedBlobRecipientKeyRefV1{request.Input.Recipient}
		context, err := wire.NewSealedSecretContext(application.ClusterID, request.RequestID, id, purpose,
			wire.SecretArtifactOwnerV1{Kind: "device", Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: device.View.DeviceID}}, generation, &sealing, recipients)
		if err != nil {
			return empty, err
		}
		plaintext := []byte(values[id])
		evidence, err := enrollmentv2.CreateLocalSealedMaterial(material.store, context, sealing, recipients, plaintext, nil,
			policy, material.deviceID, material.reporter, runtime.now().UTC().Truncate(time.Second), rand.Reader)
		clear(plaintext)
		if err != nil {
			return empty, err
		}
		envelope, err := material.store.Get(evidence.Ref.SealedBlob.CiphertextDigest)
		if err != nil {
			return empty, err
		}
		payload.Publication.Secrets = append(payload.Publication.Secrets, evidence)
		payload.Envelopes = append(payload.Envelopes, envelope)
	}
	publicationHash, err := controlDevicePublicationHash(payload.Publication)
	if err != nil {
		return empty, err
	}
	if _, err := application.reduceDevicePublication(payload.Publication, wire.ControlOperationBodyV1{ClusterID: application.ClusterID,
		Kind: controlPublishDeviceKind, OperationID: request.RequestID, ParentHeadHash: request.ExpectedHead, PayloadHash: publicationHash},
		runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)); err != nil {
		return empty, err
	}
	// 在响应前固化第一次结果。重试返回相同密文，不会签名同代不同材料。
	if err := os.MkdirAll(root, 0o700); err != nil {
		return empty, err
	}
	if err := writeCanonicalAtomic(path, controlPreparedClientV1{Schema: 1, InputHash: inputHash, Payload: payload}, 0o600); err != nil {
		return empty, err
	}
	return payload, nil
}

func clientConfigSealingPolicy(application *controlApplicationV1, device controlDeviceStateV1,
	recipient wire.SealedBlobRecipientKeyRefV1, platform string) (wire.SealingPolicyV1, error) {
	var policy wire.SealingPolicyV1
	expected, err := application.deviceWrappingHash(device)
	if err != nil {
		return policy, err
	}
	spki, err := base64.RawURLEncoding.DecodeString(recipient.RecipientPublicKey.PublicKeySPKIDER)
	hash, hashErr := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, spki)
	if err != nil || hashErr != nil || hash != expected || recipient.RecipientID != device.View.DeviceID || recipient.RecipientKeyGeneration != 1 {
		return policy, errors.New("[配置生成] recipient 不是该设备已认证的 wrapping key")
	}
	switch recipient.RecipientKeyProfile {
	case "p256-root-only-pkcs8-ecdh-v1":
		if platform != "linux-server" {
			return policy, errors.New("[配置生成] root-only wrapping 仅用于 Linux")
		}
		policy = wire.P256RootOnlySealingPolicyV1()
	case "p256-keystore-ecdh-v1":
		if platform == "linux-server" {
			return policy, errors.New("[配置生成] Linux 必须使用原 root-only wrapping profile")
		}
		policy = wire.P256SealingPolicyV1()
	case "rsa2048-keystore-decrypt-v1":
		if platform != "android" {
			return policy, errors.New("[配置生成] RSA wrapping 仅用于已认证 Android profile")
		}
		policy = wire.RSASealingPolicyV1()
	default:
		return policy, errors.New("[配置生成] 客户端 wrapping profile 不支持")
	}
	return policy, nil
}

func (runtime *controlRuntime) servePrepareClientConfig(writer http.ResponseWriter, request *http.Request) {
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodPost || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		!ok || local == nil || local.String() != address || request.Host != address || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) == 0 ||
		request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Origin") != "" ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
		writeControlRuntimeError(writer, http.StatusForbidden, "[配置生成] 私有管理员传输被拒绝")
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.controlAdminOperationAuthorizedLocked(request.TLS.PeerCertificates[0].Raw, controlPublishDeviceKind) {
		writeControlRuntimeError(writer, http.StatusForbidden, "[配置生成] 管理员无配置发布权限")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, (3<<20)+1))
	defer clear(body)
	var input controlPrepareClientRequestV1
	canonical, decodeErr := wire.DecodeStrict(body, 3<<20, &input)
	defer clear(canonical)
	if err != nil || decodeErr != nil || !bytes.Equal(body, canonical) {
		writeControlRuntimeError(writer, http.StatusBadRequest, "[配置生成] 请求编码无效")
		return
	}
	payload, err := runtime.prepareClientConfigLocked(input)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusConflict, err.Error())
		return
	}
	encoded, err := wire.MarshalCanonical(payload)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusInternalServerError, "[配置生成] 发布材料编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(encoded)
}

func (runtime *controlRuntime) controlAdminOperationAuthorizedLocked(certificate []byte, kind string) bool {
	digest, err := wire.AdminCertificateDigest(certificate)
	if err != nil || !runtime.adminCertificateAuthorizedLocked(certificate) {
		return false
	}
	for _, authorization := range runtime.config.Authorizations {
		if authorization.AdminCertificateDigest != digest || !containsControlValue(authorization.AllowedOperationKinds, kind) {
			continue
		}
		for _, scope := range authorization.Scopes {
			if scope.ScopeKind == "cluster" {
				return true
			}
		}
	}
	return false
}
