package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/wire"
)

const privateControlInvitePrefix = "/private/v2/control/invites/"

type controlBootstrapIssuerKeyV1 struct {
	Schema     int    `json:"schema"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key"`
}

// Descriptor 是一次性私有交付；只有 Proof/Catalog 可发布到静态 distribution。
type controlInviteDeliveryV1 struct {
	Schema     int                              `json:"schema"`
	Descriptor wire.InviteBootstrapDescriptorV2 `json:"descriptor"`
	Proof      wire.InviteProofBundleV2         `json:"proof"`
	Catalog    wire.BootstrapEndpointCatalogV1  `json:"catalog"`
}

func (runtime *controlRuntime) bootstrapIssuerKey(issuer wire.BootstrapIssuerAuthorizationV1) (ed25519.PrivateKey, error) {
	if issuer.Active == nil {
		return nil, errors.New("[D115 Invite] issuer 未激活")
	}
	id := issuer.Active.IssuerKeyID
	if _, err := wire.ParseHash(id); err != nil {
		return nil, err
	}
	var stored controlBootstrapIssuerKeyV1
	path := filepath.Join(runtime.dir, "bootstrap-issuers", strings.TrimPrefix(id, "sha256:")+".json")
	if err := readCanonicalFile(path, 8192, &stored); err != nil {
		return nil, errors.New("[D115 Invite] bootstrap issuer key 暂不可用")
	}
	key, err := base64.RawURLEncoding.DecodeString(stored.PrivateKey)
	if err != nil || stored.Schema != 1 || stored.KeyID != id || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("[D115 Invite] bootstrap issuer key 格式无效")
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	keyID, err := wire.ControlKeyID(public)
	if err != nil || keyID != id || base64.RawURLEncoding.EncodeToString(public) != issuer.Active.IssuerPublicKey {
		return nil, errors.New("[D115 Invite] issuer key 与当前 certified 授权不一致")
	}
	return ed25519.PrivateKey(key), nil
}

func (application *controlApplicationV1) issuerProof(authorizationHash string) (wire.BootstrapIssuerAuthorizationProofV1, error) {
	leaves, encoded, err := application.issuerLeaves()
	if err != nil {
		return wire.BootstrapIssuerAuthorizationProofV1{}, err
	}
	for index, leaf := range leaves {
		if leaf.AuthorizationHash != authorizationHash {
			continue
		}
		path, err := wire.MerkleInclusionPath(encoded, int64(index))
		if err != nil {
			return wire.BootstrapIssuerAuthorizationProofV1{}, err
		}
		audit := make([]string, len(path))
		for i, hash := range path {
			audit[i] = fmt.Sprintf("sha256:%x", hash)
		}
		return wire.BootstrapIssuerAuthorizationProofV1{Schema: 1, ClusterID: application.ClusterID,
			Authorization: application.BootstrapIssuers[index], AuthorizationHash: authorizationHash,
			Leaf: leaf, LeafIndex: int64(index), RegistryTreeSize: int64(len(leaves)), RegistryAuditPath: audit,
			RegistryRoot: fmt.Sprintf("sha256:%x", wire.MerkleRoot(encoded))}, nil
	}
	return wire.BootstrapIssuerAuthorizationProofV1{}, errors.New("[D115 Invite] 当前 registry 中没有对应 issuer")
}

func (runtime *controlRuntime) inviteDeliveryLocked(inviteID string) (controlInviteDeliveryV1, error) {
	var delivery controlInviteDeliveryV1
	material, err := runtime.readInviteMaterialLocked(runtime.config.ClusterID, inviteID)
	if err != nil {
		return delivery, err
	}
	now := runtime.now().UTC().Truncate(time.Second)
	expires, err := wire.ParseTimeZ(material.Record.ExpiresAt)
	if err != nil || !now.Before(expires) || material.Status != "available" {
		return delivery, errors.New("[D114 Invite] 邀请已过期、撤销或进入事务；不能重新交付 initial token")
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil || application == nil {
		return delivery, errors.New("[D114 Invite] 当前 application 不可用")
	}
	issuerProof, err := application.issuerProof(material.Record.BootstrapIssuerAuthorizationHash)
	if err != nil || issuerProof.RegistryRoot != material.Record.BootstrapIssuerRegistryRoot {
		return delivery, errors.New("[D115 Invite] 初始邀请的 issuer authority 已改变")
	}
	if err := wire.VerifyBootstrapIssuerAuthorizationProof(&issuerProof, now); err != nil {
		return delivery, err
	}
	issuerKey, err := runtime.bootstrapIssuerKey(issuerProof.Authorization)
	if err != nil {
		return delivery, err
	}
	token, err := runtime.readInviteToken(material.Record)
	if err != nil {
		return delivery, err
	}
	proof := wire.InviteProofBundleV2{Schema: 2, ClusterID: material.Record.ClusterID, InviteID: inviteID,
		AuthorityTransitions: []json.RawMessage{}, CertifiedInviteRecord: material.Record, InviteIssuancePolicy: material.Policy,
		DeviceEnrollmentIntentCommitment: material.Commitment, InviteOperationLeaf: material.InviteOperationLeaf,
		InviteLeafIndex: material.InviteLeafIndex, InviteOperationTreeSize: material.InviteTreeSize,
		InviteOperationAuditPath: material.InviteAuditPath, RecordHead: material.RecordHead, RecordHeadQC: material.RecordHeadQC,
		BootstrapIssuerAuthorizationProof: issuerProof, BootstrapCatalogHash: material.Record.BootstrapCatalogHash}
	for _, record := range runtime.journal.Records {
		if record.Candidate.HeadHash == material.RecordHead.HeadHash {
			break
		}
		if record.Result == nil {
			return delivery, errors.New("[D115 Invite] lineage 尚未认证")
		}
		if record.Activation != nil {
			activation := controlClone(record.Activation.Bundle)
			activation.Head = record.Candidate
			if _, err := wire.DecodeStrict(record.Result.ConfigQC, 4<<20, &activation.ConfigQC); err != nil {
				return delivery, err
			}
			proof.RuntimeActivationBundle = &activation
			continue
		}
		if proof.RuntimeActivationBundle == nil {
			continue
		}
		if record.Candidate.Body.Payload.HeadKind != "ordinary" {
			return delivery, errors.New("[D115 Invite] 缺非 ordinary authority transition bundle")
		}
		raw, err := wire.MarshalCanonical(wire.CertifiedHeadV1{Head: record.Candidate, QC: record.Result.ConfigQC})
		if err != nil {
			return delivery, err
		}
		proof.AuthorityTransitions = append(proof.AuthorityTransitions, raw)
	}
	if proof.RuntimeActivationBundle == nil {
		return delivery, errors.New("[D115 Invite] 缺已验证运行态迁移锚")
	}
	proofHash, err := wire.InviteProofBundleHash(&proof)
	if err != nil {
		return delivery, err
	}
	recordHash, err := wire.CertifiedInviteRecordHash(&material.Record, &material.Policy)
	if err != nil {
		return delivery, err
	}
	active, policy, service := issuerProof.Authorization.Active, material.Policy, material.EnrollmentServiceRef
	capIssued, err := wire.ParseTimeZ(material.Record.IssuedAt)
	if err != nil {
		return delivery, err
	}
	// 初始 capability 的 bytes 随 Invite 固定；读取或重试不能刷新有效期/重置预算。
	capExpiry := capIssued.Add(time.Duration(min(policy.MaximumInitialCapabilityTTLSeconds, active.MaximumCapabilityTTLSeconds)) * time.Second)
	if expires.Before(capExpiry) {
		capExpiry = expires
	}
	ip, err := netip.ParseAddr(service.OverlayIP)
	if err != nil {
		return delivery, err
	}
	body := wire.BootstrapTunnelCapabilityBodyV1{Schema: 1, ClusterID: runtime.config.ClusterID, InviteID: inviteID,
		CommittedInviteRecordHash: recordHash, InviteIssuancePolicyHash: material.Record.InviteIssuancePolicyHash,
		BootstrapIssuerAuthorizationHash: material.Record.BootstrapIssuerAuthorizationHash, BootstrapIssuerRegistryRoot: issuerProof.RegistryRoot,
		EnrollmentServiceRefHash: material.Record.EnrollmentServiceRefHash, Mode: "initial_claim", IssuedAt: capIssued.Format(time.RFC3339),
		NotBefore: capIssued.Format(time.RFC3339), ExpiresAt: capExpiry.Format(time.RFC3339),
		AllowedIngressSetHash: application.BootstrapCatalog.BootstrapIngressSetHash, AllowedServiceID: service.ServiceID,
		AllowedDestinationIP: service.OverlayIP, AllowedDestinationPrefixLength: int64(ip.BitLen()), AllowedDestinationPort: service.TCPPort, AllowedInsideTransport: "tcp",
		MaximumConnectionAttempts: min(policy.BootstrapConnectionAttempts, active.MaximumConnectionAttempts), MaximumConcurrentSessions: 1,
		MaximumSessionSeconds: min(policy.BootstrapSessionSeconds, active.MaximumSessionSeconds), MaximumTotalBytes: min(policy.BootstrapTotalBytes, active.MaximumTotalBytes),
		IssuerEpoch: active.IssuerEpoch, IssuerKeyID: active.IssuerKeyID}
	capability, err := wire.SignBootstrapCapability(body, issuerKey)
	if err != nil {
		return delivery, err
	}
	descriptor := wire.InviteBootstrapDescriptorV2{Schema: 2, ClusterID: runtime.config.ClusterID, InviteID: inviteID, ExpiresAt: material.Record.ExpiresAt,
		Token: token.Token, TokenCommitment: material.Record.TokenCommitment, BootstrapTunnelCapability: capability,
		BootstrapCatalogHash: material.Record.BootstrapCatalogHash, ProofBundleHash: proofHash, EnrollmentServiceRef: service,
		DistributionMirrors: controlClone(application.Mirrors), MinimumRecoveryEpoch: material.RecordHead.Body.Payload.RecoveryEpoch,
		TrustedCheckpointHash: proof.RuntimeActivationBundle.Head.HeadHash}
	if _, err := wire.VerifyInviteProofBundle(&proof, &descriptor, now, wire.InviteProofTrustV2{}); err != nil {
		return delivery, err
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&application.BootstrapCatalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash {
		return delivery, errors.New("[D115 Invite] catalog 已改变，不能用新旧输入拼接交付")
	}
	return controlInviteDeliveryV1{Schema: 1, Descriptor: descriptor, Proof: proof, Catalog: controlClone(application.BootstrapCatalog)}, nil
}

func (runtime *controlRuntime) serveInviteDelivery(writer http.ResponseWriter, request *http.Request) {
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		!ok || local == nil || local.String() != address || request.Host != address || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) < 1 ||
		request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
		writeControlRuntimeError(writer, http.StatusForbidden, "[D115 Invite] 私有管理员传输被拒绝")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, privateControlInvitePrefix), "/delivery")
	if id == "" || strings.Contains(id, "/") || request.URL.Path != privateControlInvitePrefix+id+"/delivery" {
		http.NotFound(writer, request)
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.inviteAdminAuthorizedLocked(request.TLS.PeerCertificates[0].Raw) {
		writeControlRuntimeError(writer, http.StatusForbidden, "[D115 Invite] 管理员无邀请交付权限")
		return
	}
	delivery, err := runtime.inviteDeliveryLocked(id)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusConflict, "[D115 Invite] 当前邀请无法交付")
		return
	}
	body, err := wire.MarshalCanonical(delivery)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusInternalServerError, "[D115 Invite] 交付编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(body)
}

func (runtime *controlRuntime) inviteAdminAuthorizedLocked(certificate []byte) bool {
	digest, err := wire.AdminCertificateDigest(certificate)
	if err != nil || !runtime.adminCertificateAuthorizedLocked(certificate) {
		return false
	}
	for _, authorization := range runtime.config.Authorizations {
		if authorization.AdminCertificateDigest != digest || !containsControlValue(authorization.AllowedOperationKinds, controlCreateInviteKind) {
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
