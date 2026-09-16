package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// capability 与原 Invite 的坐标/有效期固定，relay 重连不会刷新 token 或预算。
func (runtime *controlRuntime) initialBootstrapCapabilityLocked(application *controlApplicationV1,
	material enrollmentv2.InviteMaterialV2, proof wire.BootstrapIssuerAuthorizationProofV1) (wire.BootstrapTunnelCapabilityV1, error) {
	var empty wire.BootstrapTunnelCapabilityV1
	if proof.Authorization.Active == nil || proof.RegistryRoot != material.Record.BootstrapIssuerRegistryRoot ||
		proof.AuthorizationHash != material.Record.BootstrapIssuerAuthorizationHash {
		return empty, errors.New("[bootstrap relay] Invite issuer 已变化或被撤销")
	}
	key, err := runtime.bootstrapIssuerKey(proof.Authorization)
	if err != nil {
		return empty, err
	}
	defer clear(key)
	recordHash, err := wire.CertifiedInviteRecordHash(&material.Record, &material.Policy)
	if err != nil {
		return empty, err
	}
	active, policy, service := proof.Authorization.Active, material.Policy, material.EnrollmentServiceRef
	issued, err := wire.ParseTimeZ(material.Record.IssuedAt)
	if err != nil {
		return empty, err
	}
	expires, err := wire.ParseTimeZ(material.Record.ExpiresAt)
	if err != nil {
		return empty, err
	}
	capExpiry := issued.Add(time.Duration(min(policy.MaximumInitialCapabilityTTLSeconds, active.MaximumCapabilityTTLSeconds)) * time.Second)
	if expires.Before(capExpiry) {
		capExpiry = expires
	}
	ip, err := netip.ParseAddr(service.OverlayIP)
	if err != nil {
		return empty, err
	}
	body := wire.BootstrapTunnelCapabilityBodyV1{Schema: 1, ClusterID: runtime.config.ClusterID, InviteID: material.Record.InviteID,
		CommittedInviteRecordHash: recordHash, InviteIssuancePolicyHash: material.Record.InviteIssuancePolicyHash,
		BootstrapIssuerAuthorizationHash: material.Record.BootstrapIssuerAuthorizationHash, BootstrapIssuerRegistryRoot: proof.RegistryRoot,
		EnrollmentServiceRefHash: material.Record.EnrollmentServiceRefHash, Mode: "initial_claim", IssuedAt: issued.Format(time.RFC3339),
		NotBefore: issued.Format(time.RFC3339), ExpiresAt: capExpiry.Format(time.RFC3339),
		AllowedIngressSetHash: application.BootstrapCatalog.BootstrapIngressSetHash, AllowedServiceID: service.ServiceID,
		AllowedDestinationIP: service.OverlayIP, AllowedDestinationPrefixLength: int64(ip.BitLen()), AllowedDestinationPort: service.TCPPort, AllowedInsideTransport: "tcp",
		MaximumConnectionAttempts: min(policy.BootstrapConnectionAttempts, active.MaximumConnectionAttempts), MaximumConcurrentSessions: 1,
		MaximumSessionSeconds: min(policy.BootstrapSessionSeconds, active.MaximumSessionSeconds), MaximumTotalBytes: min(policy.BootstrapTotalBytes, active.MaximumTotalBytes),
		IssuerEpoch: active.IssuerEpoch, IssuerKeyID: active.IssuerKeyID}
	return wire.SignBootstrapCapability(body, key)
}

// 外层只接受当前认证 ingress Device 的 mTLS；随后恢复该次邀请的精确受限
// capability。真正的 claim 仍只由 relay 内的 Enrollment TLS reader 消费。
func (runtime *controlRuntime) authorizeBootstrapRelay(ctx context.Context, certificateDER []byte, capabilityID string) (wire.VerifiedBootstrapCapabilityV1, error) {
	var empty wire.VerifiedBootstrapCapabilityV1
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if _, err := wire.ParseHash(capabilityID); err != nil {
		return empty, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		return empty, err
	}
	var profiles []string
	for _, service := range application.Services {
		if service.Role == "enroll" {
			profiles = service.AuthorizedSubjectProfiles
		}
	}
	now := runtime.now().UTC()
	identity, err := controlplane.AuthenticateDeviceIdentity(ctx, certificateDER, now, profiles,
		func(_ context.Context, certificateHash string) (controlplane.DeviceIdentityAuthorityV1, error) {
			return runtime.readDeviceIdentityLocked(certificateHash)
		})
	if err != nil || identity.IdentityStatus() != "active" || !containsControlValue(identity.Responsibilities(), "forward") {
		return empty, errors.New("[bootstrap relay] 对端不是当前可转发的 Device")
	}
	if err := bootstrapIngressIdentityAllowed(application, identity); err != nil {
		return empty, errors.New("[bootstrap relay] 对端不属于当前 bootstrap ingress set")
	}
	return runtime.findBootstrapCapabilityLocked(application, now, func(verified wire.VerifiedBootstrapCapabilityV1,
		_ wire.BootstrapCapabilityLookupResponseV1) bool {
		return verified.CapabilityID() == capabilityID
	})
}

func bootstrapIngressIdentityAllowed(application *controlApplicationV1,
	identity controlplane.VerifiedDeviceIdentityV1) error {
	if application == nil || application.BootstrapInstallation != nil || identity.IdentityStatus() != "active" ||
		!containsControlValue(identity.Responsibilities(), "forward") {
		return errors.New("[bootstrap relay] ingress 尚未发布或 Device 职责无效")
	}
	for _, endpoint := range application.BootstrapCatalog.BootstrapIngressSet.Endpoints {
		if endpoint.LogicalServerID == identity.DeviceID() {
			return nil
		}
	}
	return errors.New("[bootstrap relay] Device 不属于当前 ingress set")
}

func (runtime *controlRuntime) resolveBootstrapCapability(ctx context.Context,
	identity controlplane.VerifiedDeviceIdentityV1,
	lookup wire.BootstrapCapabilityLookupRequestV1) (wire.BootstrapCapabilityLookupResponseV1, error) {
	var empty wire.BootstrapCapabilityLookupResponseV1
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := wire.ValidateBootstrapCapabilityLookupRequest(&lookup); err != nil {
		return empty, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	application, err := runtime.certifiedApplicationLocked()
	if err != nil || application == nil || lookup.IngressSetHash != application.BootstrapCatalog.BootstrapIngressSetHash ||
		bootstrapIngressIdentityAllowed(application, identity) != nil {
		return empty, errors.New("[capability lookup] ingress identity/set 未获当前 authority 授权")
	}
	current, err := runtime.readDeviceIdentityLocked(identity.CertificateHash())
	if err != nil || current.Record.DeviceID != identity.DeviceID() || current.Record.IdentityStatus != "active" ||
		!containsControlValue(current.Record.Responsibilities, "forward") {
		return empty, errors.New("[capability lookup] ingress identity 已变化或被撤销")
	}
	now := runtime.now().UTC()
	_, response, err := runtime.findBootstrapCapabilityResponseLocked(application, now,
		func(verified wire.VerifiedBootstrapCapabilityV1, response wire.BootstrapCapabilityLookupResponseV1) bool {
			_, verifyErr := wire.VerifyBootstrapCapabilityLookupResponse(&lookup, &response, now)
			return verifyErr == nil && verified.CapabilityID() == response.Capability.CapabilityID
		})
	return response, err
}

func (runtime *controlRuntime) findBootstrapCapabilityLocked(application *controlApplicationV1,
	now time.Time, match func(wire.VerifiedBootstrapCapabilityV1,
		wire.BootstrapCapabilityLookupResponseV1) bool) (wire.VerifiedBootstrapCapabilityV1, error) {
	verified, _, err := runtime.findBootstrapCapabilityResponseLocked(application, now, match)
	return verified, err
}

func (runtime *controlRuntime) findBootstrapCapabilityResponseLocked(application *controlApplicationV1,
	now time.Time, match func(wire.VerifiedBootstrapCapabilityV1,
		wire.BootstrapCapabilityLookupResponseV1) bool) (wire.VerifiedBootstrapCapabilityV1,
	wire.BootstrapCapabilityLookupResponseV1, error) {
	var empty wire.VerifiedBootstrapCapabilityV1
	var emptyResponse wire.BootstrapCapabilityLookupResponseV1
	for _, invite := range application.Invites {
		if invite.Status == "revoked" {
			continue
		}
		until, err := wire.ParseTimeZ(invite.Record.ExpiresAt)
		if err != nil || !now.Before(until) {
			continue
		}
		material, err := runtime.readInviteMaterialLocked(runtime.config.ClusterID, invite.Record.InviteID)
		if err != nil {
			return empty, emptyResponse, err
		}
		proof, err := application.issuerProof(material.Record.BootstrapIssuerAuthorizationHash)
		if err != nil {
			continue
		}
		capability, err := runtime.initialBootstrapCapabilityLocked(application, material, proof)
		if err != nil {
			continue
		}
		verified, err := wire.VerifyCapabilityAuthorizationEvidence(&capability, &proof, &material.Policy, now)
		response := wire.BootstrapCapabilityLookupResponseV1{Schema: 1, Capability: capability,
			IssuerProof: proof, Policy: material.Policy}
		if err == nil && match != nil && match(verified, response) {
			return verified, response, nil
		}
	}
	return empty, emptyResponse, errors.New("[bootstrap relay] capability 未获当前邀请授权或已过期")
}
