package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/wire"
)

// 在 sequencer 持有 runtime.mu 且冻结日志坐标后调用。所有随机材料先进入
// DurableProvisionalService；失败恢复只能使用同一证书、配置和密文。
func (runtime *controlRuntime) prepareEnrollmentRuntime(ctx context.Context, operationID string, attempt enrollmentv2.VerifiedClaimAttemptV2,
	record enrollmentv2.DurableRecord, coordinate enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.PreparedProvisionalV1, error) {
	var empty enrollmentv2.PreparedProvisionalV1
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		return empty, err
	}
	if len(application.EnrollmentPlans) != 0 {
		return empty, errors.New("[首次配置] 先完成已有入网配置事务")
	}
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedHead.HeadHash != coordinate.ParentHeadHash {
		return empty, errors.New("[首次配置] 签发坐标与当前认证 Head 不一致")
	}
	var invite controlInviteStateV1
	for _, current := range application.Invites {
		if current.Record.InviteID == record.InviteID {
			invite = current
		}
	}
	if invite.Status != "reserved" || !wire.EqualCanonical(invite.Opening, record.ClaimEvidence.Opening) {
		return empty, errors.New("[首次配置] 缺本次已预留邀请")
	}
	core := attempt.Submission().ClaimCore
	public, err := wire.EnrollmentWireGuardPublicKey(&core)
	if err != nil {
		return empty, err
	}
	network, err := enrollmentNetwork(application, invite)
	if err != nil {
		return empty, err
	}
	qc, err := wire.MarshalCanonical(state.CertifiedQC)
	if err != nil {
		return empty, err
	}
	plan := controlEnrollmentRuntimePlanV1{Schema: 1, InviteID: record.InviteID, OperationID: operationID,
		Parent: wire.CertifiedHeadV1{Head: *state.CertifiedHead, QC: qc}, NetworkHash: wire.HashRaw("loom-enrollment-network-v1", []byte(application.LegacySSOT)),
		Network: string(network.Content), SingBoxVersion: "1.11.4", PreparedAt: coordinate.CommittedLogicalTime, Servers: []controlDevicePublicationV1{}}
	plan.ControlLink, err = allocateEnrollmentControlLink(application, runtime.config.DeviceID, invite.Opening.DeviceEnrollmentIntent.DeviceID, public)
	if err != nil {
		return empty, err
	}
	var clientRefs []string
	plan.ClientConfigs, clientRefs, err = renderEnrollmentClient(application, invite, plan)
	if err != nil {
		return empty, err
	}
	values := map[string]string{}
	defer clear(values)
	for _, id := range append(network.CredentialRefs, plan.ControlLink.Carrier.CredentialRef,
		"api/"+invite.Opening.DeviceEnrollmentIntent.DeviceID, "probe/"+invite.Opening.DeviceEnrollmentIntent.DeviceID) {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return empty, err
		}
		values[id] = base64.RawURLEncoding.EncodeToString(secret[:])
		clear(secret[:])
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
	for _, current := range application.ArtifactPolicies {
		approved = approved || wire.EqualCanonical(current, policy)
	}
	if !approved {
		return empty, errors.New("[首次配置] 本机制品回执没有当前认证授权")
	}
	recipient, err := enrollmentRecipient(record)
	if err != nil {
		return empty, err
	}
	private, err := runtime.devicePrivateControlCredentialLocked(application, invite.Opening.DeviceEnrollmentIntent.DeviceID)
	if err != nil {
		return empty, err
	}
	privateBytes, err := wire.MarshalCanonical(private)
	if err != nil {
		return empty, err
	}
	defer clear(privateBytes)
	values[wire.DevicePrivateControlCredentialSecretIDV1] = string(privateBytes)
	values[wire.DeviceObservationCASecretIDV1] = application.ObservationCAPEM
	clientRefs = append(clientRefs, wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1)
	plan.ClientSecrets, err = sealEnrollmentCredentials(material, policy, operationID, recipient, clientRefs, values, nil, coordinate.CommittedLogicalTime)
	if err != nil {
		return empty, err
	}
	for _, device := range application.Devices {
		if device.View.State != "active" || device.View.Active == nil || !containsControlValue(device.View.Active.Responsibilities.Values, "forward") {
			continue
		}
		configs, refs, err := renderEnrollmentServer(application, invite, plan, device)
		if err != nil {
			return empty, fmt.Errorf("[首次配置] 服务器渲染: %w", err)
		}
		recipient, err := retainedEnrollmentRecipient(device)
		if err != nil {
			return empty, err
		}
		// 既有服务身份、CA 及各设备的旧秘密引用保持原字节；只封装本次
		// 新增的客户端凭据，控制端无需解封已有服务器秘密。
		refs = append(refs, wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1)
		for _, id := range []string{wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1} {
			found := false
			for _, ref := range device.SecretArtifactRefs {
				found = found || ref.SecretID == id
			}
			if !found {
				return empty, errors.New("[首次配置] 原服务器缺已认证的私有服务凭据，必须先完成存量配置迁移")
			}
		}
		secrets, err := sealEnrollmentCredentials(material, policy, operationID, recipient, refs, values, device.SecretArtifactRefs, coordinate.CommittedLogicalTime)
		if err != nil {
			return empty, err
		}
		previous, err := wire.DeviceViewHash(&device.View)
		if err != nil {
			return empty, err
		}
		plan.Servers = append(plan.Servers, controlDevicePublicationV1{Schema: 1, DeviceID: device.View.DeviceID, PreviousViewHash: previous, Configs: configs, Secrets: secrets})
	}
	refs := make([]wire.SecretArtifactRefV2, len(plan.ClientSecrets))
	for i, evidence := range plan.ClientSecrets {
		refs[i] = evidence.Ref
	}
	view, err := enrollmentInitialView(record, plan.ClientConfigs, refs)
	if err != nil {
		return empty, err
	}
	if _, err := application.applyEnrollmentRuntimePlan(plan, record, view, coordinate.CommittedLogicalTime); err != nil {
		return empty, err
	}
	if err := runtime.persistEnrollmentRuntimePlan(plan, material.store); err != nil {
		return empty, err
	}
	var profile wire.DeviceCertificateProfileStateV1
	for _, candidate := range application.CARegistry.DeviceProfiles {
		if wire.ValidateDeviceCertificateProfileRef(&invite.Opening.DeviceEnrollmentIntent.DeviceCertificateProfileRef, &candidate) == nil {
			profile = candidate
		}
	}
	issuer, err := runtime.loadDeviceIssuer(profile)
	if err != nil {
		return empty, err
	}
	defer clearControlSigner(issuer)
	spki, err := base64.RawURLEncoding.DecodeString(core.DeviceIdentityPublicKey)
	if err != nil {
		return empty, err
	}
	_, lineage, err := runtime.enrollmentLineage(record.ReservationCertification.Head, state.CertifiedHead.HeadHash)
	if err != nil {
		return empty, err
	}
	input := enrollmentv2.DeviceIssuanceContext{Reservation: record, Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet,
		ReservationToHead: lineage, CARegistry: application.CARegistry, Profile: profile, Coordinate: coordinate, IdentitySPKIDER: spki}
	prepared, err := enrollmentv2.PrepareReservedDeviceIssuance(input, view, refs, application.IssuanceRegistry, issuer, rand.Reader)
	if err != nil {
		return empty, err
	}
	prepared.RuntimePlan, err = wire.MarshalCanonical(plan)
	return prepared, err
}

func enrollmentRecipient(record enrollmentv2.DurableRecord) (wire.SealedBlobRecipientKeyRefV1, error) {
	var recipient wire.SealedBlobRecipientKeyRefV1
	der, err := base64.RawURLEncoding.DecodeString(record.ClaimEvidence.WrappingPublicKey)
	if err != nil {
		return recipient, err
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return recipient, err
	}
	key, err := enrollmentv2.MaterialAuthorityKey(public)
	if err != nil {
		return recipient, err
	}
	return wire.SealedBlobRecipientKeyRefV1{RecipientID: record.ClaimEvidence.Opening.DeviceEnrollmentIntent.DeviceID,
		RecipientKeyID: key.KeyID, RecipientKeyGeneration: 1, RecipientKeyProfile: record.ClaimEvidence.WrappingKeyProfile, RecipientPublicKey: key}, nil
}

func retainedEnrollmentRecipient(device controlDeviceStateV1) (wire.SealedBlobRecipientKeyRefV1, error) {
	var result wire.SealedBlobRecipientKeyRefV1
	for _, ref := range device.SecretArtifactRefs {
		if ref.SealedBlob == nil || len(ref.SealedBlob.RecipientKeyVersions) != 1 {
			return result, errors.New("[首次配置] 原设备缺唯一已认证 wrapping recipient")
		}
		value := ref.SealedBlob.RecipientKeyVersions[0]
		if value.RecipientID != device.View.DeviceID || result.RecipientID != "" && !wire.EqualCanonical(value, result) {
			return result, errors.New("[首次配置] 原设备 wrapping recipient 不一致")
		}
		result = value
	}
	if result.RecipientID == "" {
		return result, errors.New("[首次配置] 原服务器尚未交付 v2 运行凭据")
	}
	return result, nil
}

func sealEnrollmentCredentials(material *controlSoftwareMaterial, policy wire.ArtifactAvailabilityPolicyV1, operationID string,
	recipient wire.SealedBlobRecipientKeyRefV1, ids []string, values map[string]string, retained []wire.SecretArtifactRefV2, atText string) ([]enrollmentv2.SealedMaterialEvidenceV1, error) {
	at, err := wire.ParseTimeZ(atText)
	if err != nil {
		return nil, err
	}
	var sealing wire.SealingPolicyV1
	switch recipient.RecipientKeyProfile {
	case "p256-keystore-ecdh-v1":
		sealing = wire.P256SealingPolicyV1()
	case "p256-root-only-pkcs8-ecdh-v1":
		sealing = wire.P256RootOnlySealingPolicyV1()
	case "rsa2048-keystore-decrypt-v1":
		sealing = wire.RSASealingPolicyV1()
	default:
		return nil, errors.New("[首次配置] 不支持的 wrapping profile")
	}
	sort.Strings(ids)
	result := []enrollmentv2.SealedMaterialEvidenceV1{}
	for i, id := range ids {
		if i > 0 && ids[i-1] == id {
			continue
		}
		if id == wire.LocalWireGuardKeySecretID {
			return nil, errors.New("[首次配置] 不允许服务端提供设备本地 WireGuard 私钥")
		}
		found := false
		for _, ref := range retained {
			if ref.SecretID == id {
				result = append(result, enrollmentv2.SealedMaterialEvidenceV1{Ref: ref})
				found = true
				break
			}
		}
		if found {
			continue
		}
		value, ok := values[id]
		if !ok || value == "" {
			return nil, fmt.Errorf("[首次配置] 缺所需的运行凭据 %q，不能用空值替代", id)
		}
		purpose := "data_plane_credential"
		if id == wire.DevicePrivateControlCredentialSecretIDV1 || id == wire.DeviceObservationCASecretIDV1 {
			purpose = "device_credential"
		}
		recipients := []wire.SealedBlobRecipientKeyRefV1{recipient}
		context, err := wire.NewSealedSecretContext(policy.ClusterID, operationID, id, purpose,
			wire.SecretArtifactOwnerV1{Kind: "device", Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: recipient.RecipientID}}, 1, &sealing, recipients)
		if err != nil {
			return nil, err
		}
		plaintext := []byte(value)
		evidence, err := enrollmentv2.CreateLocalSealedMaterial(material.store, context, sealing, recipients, plaintext, nil, policy, material.deviceID, material.reporter, at, rand.Reader)
		clear(plaintext)
		if err != nil {
			return nil, err
		}
		result = append(result, evidence)
	}
	order := map[string]int{"device_credential": 0, "data_plane_credential": 1}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Ref, result[j].Ref
		if a.Purpose != b.Purpose {
			return order[a.Purpose] < order[b.Purpose]
		}
		return a.SecretID < b.SecretID
	})
	return result, nil
}

// 地址与端口只分配在已有私有控制承载的命名空间，不探测或新开公网端口。
// 分配结果由 certified Head 认证；重复请求从 first-result 读取同一结果。
func allocateEnrollmentControlLink(application *controlApplicationV1, listener, device, public string) (wire.DeviceControlLinkV1, error) {
	var link wire.DeviceControlLinkV1
	if !enrollmentWireGuardPublicValid(public) {
		return link, errors.New("[首次配置] 缺客户端本地 WireGuard 公钥")
	}
	for _, current := range application.DeviceControlLinks {
		if current.Resource.ListenerDeviceID == listener {
			link = controlClone(current)
			break
		}
	}
	if link.Resource.ListenerDeviceID == "" {
		return link, errors.New("[首次配置] 控制成员缺已认证的私有 WireGuard 承载分配")
	}
	source, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		return link, err
	}
	server := source.NodeByID()[listener]
	if server == nil || server.Server == nil || server.PublicEndpoint == "" || server.Server.InboundProtocol.Or() != model.Hysteria2 {
		return link, errors.New("[首次配置] 私有控制承载缺现有 HY2 listener")
	}
	hash, err := wire.HashObject("loom-device-control-link-id-v1", struct{ Cluster, Device string }{application.ClusterID, device})
	if err != nil {
		return link, err
	}
	link.Resource.ResourceID = "device-control-" + strings.TrimPrefix(hash, "sha256:")[:24]
	link.Resource.LinkID = link.Resource.ResourceID
	link.Resource.DialerDeviceID, link.Resource.DialerPublicKey, link.Resource.ListenerGeneration = device, public, 1
	usedIPs := map[string]bool{}
	usedPorts := map[int64]bool{int64(server.Server.InboundPort): true}
	for _, service := range application.Services {
		usedIPs[service.OverlayIP] = true
		usedPorts[service.Port] = true
	}
	for _, current := range application.DeviceControlLinks {
		for _, text := range []string{current.Resource.DialerTunnelPrefix, current.Resource.ListenerTunnelPrefix} {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return link, err
			}
			usedIPs[prefix.Addr().String()] = true
		}
		if current.Resource.ListenerDeviceID == listener {
			usedPorts[current.Resource.EndpointPort] = true
		}
		if current.Resource.DialerPublicKey == public {
			return link, errors.New("[首次配置] WireGuard 公钥已属于另一设备")
		}
	}
	tunnels, err := source.ResolveAll()
	if err != nil {
		return link, err
	}
	for _, tunnel := range tunnels {
		for _, address := range []string{tunnel.InitiatorAddr, tunnel.AcceptorAddr} {
			prefix, err := netip.ParsePrefix(address)
			if err != nil {
				return link, err
			}
			usedIPs[prefix.Addr().String()] = true
		}
		if tunnel.Acceptor.ID == listener {
			usedPorts[int64(tunnel.ListenPort)] = true
		}
	}
	base, err := netip.ParsePrefix(link.Resource.DialerTunnelPrefix)
	if err != nil || !base.Addr().Is4() || !base.Addr().IsPrivate() {
		return link, errors.New("[首次配置] 本机控制承载缺 IPv4 私有分配空间")
	}
	seed := sha256.Sum256([]byte(application.ClusterID + "/" + device))
	a := base.Addr().As4()
	allocated := false
	for n := uint32(0); n < 65536; n++ {
		x := uint16(uint32(binary.BigEndian.Uint16(seed[:2])) + n)
		ip := netip.AddrFrom4([4]byte{a[0], a[1], byte(x >> 8), byte(x)})
		if !ip.IsPrivate() || usedIPs[ip.String()] {
			continue
		}
		link.Resource.DialerTunnelPrefix = ip.String() + "/32"
		allocated = true
		break
	}
	if !allocated {
		return link, errors.New("[首次配置] 私有控制地址分配空间已耗尽")
	}
	allocated = false
	for n := uint32(0); n < 16384; n++ {
		port := int64(49152 + (uint32(binary.BigEndian.Uint16(seed[2:4]))+n)%16384)
		if usedPorts[port] {
			continue
		}
		link.Resource.EndpointPort = port
		allocated = true
		break
	}
	if !allocated {
		return link, errors.New("[首次配置] 私有控制端口分配空间已耗尽")
	}
	link.Carrier = &wire.DeviceControlCarrierV1{Address: server.PublicEndpoint, Port: int64(server.Server.InboundPort), TLSServerName: server.ID + ".node.internal", CredentialRef: wire.DeviceControlCarrierCredentialRef(link)}
	return link, wire.ValidateDeviceControlLink(&link)
}

func (runtime *controlRuntime) persistEnrollmentRuntimePlan(plan controlEnrollmentRuntimePlanV1, store *enrollmentv2.SealedArtifactStore) error {
	publications := append([]controlDevicePublicationV1{{Configs: plan.ClientConfigs, Secrets: plan.ClientSecrets}}, plan.Servers...)
	for _, publication := range publications {
		payload := controlPublishDevicePayloadV1{Schema: 1, Publication: controlDevicePublicationV1{Configs: publication.Configs}, Envelopes: []wire.SealedSecretEnvelopeV1{}}
		for _, evidence := range publication.Secrets {
			if evidence.Ref.ProposalID != plan.OperationID {
				continue
			}
			envelope, err := store.Get(evidence.Ref.SealedBlob.CiphertextDigest)
			if err != nil {
				return err
			}
			payload.Envelopes = append(payload.Envelopes, envelope)
			payload.Publication.Secrets = append(payload.Publication.Secrets, evidence)
		}
		if err := runtime.persistDevicePublication(payload); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *controlRuntime) productionEnrollmentWorkflow() (*controlEnrollmentWorkflow, error) {
	artifacts, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(runtime.dir, "sealed-artifacts"))
	if err != nil {
		return nil, err
	}
	provision, err := enrollmentv2.OpenDurableProvisionalService(filepath.Join(runtime.dir, controlProvisionalResultsName), runtime.prepareEnrollmentRuntime)
	if err != nil {
		return nil, err
	}
	return runtime.newEnrollmentWorkflow(provision, artifacts)
}
