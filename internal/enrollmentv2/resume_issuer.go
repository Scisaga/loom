package enrollmentv2

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/wire"
)

const DomainEnrollmentResumeIssueRequest = "loom-enrollment-resume-issue-request-v1"

// ResumeIssueRequestV1 必须来自已经通过 admin mTLS/ACL 并进入 certified Head 的
// control operation。IssuedAt 只能取该 Head 的 committed logical time。
type ResumeIssueRequestV1 struct {
	Schema                       int    `json:"schema"`
	OperationID                  string `json:"operation_id"`
	ClusterID                    string `json:"cluster_id"`
	InviteID                     string `json:"invite_id"`
	RequestID                    string `json:"request_id"`
	DeviceID                     string `json:"device_id"`
	ExpectedTransactionStateHash string `json:"expected_transaction_state_hash"`
	IssuedAt                     string `json:"issued_at"`
	ExpiresAt                    string `json:"expires_at"`
}

// ResumeIssuanceMaterialV1 必须由一次线性化读取返回。issuer 不接受调用方分别提供
// transaction、Invite、catalog 或 authorization 的散装快照。
type ResumeIssuanceMaterialV1 struct {
	Transaction               DurableRecord                             `json:"transaction"`
	Invite                    InviteMaterialV2                          `json:"invite"`
	BootstrapCatalog          wire.BootstrapEndpointCatalogV1           `json:"bootstrap_catalog"`
	CatalogHead               wire.HeadEntryV2                          `json:"catalog_head"`
	CatalogControlSet         wire.ControlSetV1                         `json:"catalog_control_set"`
	CatalogPreviousControlSet *wire.ControlSetV1                        `json:"catalog_previous_control_set,omitempty"`
	IssuerAuthorizationProof  wire.BootstrapIssuerAuthorizationProofV1  `json:"issuer_authorization_proof"`
	ProofBundleHash           string                                    `json:"proof_bundle_hash"`
	DistributionMirrors       []wire.DistributionMirrorRefV1            `json:"distribution_mirrors"`
	DistributionEndpointSets  map[string]wire.DistributionEndpointSetV1 `json:"distribution_endpoint_sets"`
}

type ResumeIssuanceMaterialReader func(context.Context, string, string, string) (ResumeIssuanceMaterialV1, error)

type BootstrapCapabilitySigner func(context.Context, wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error)

type resumeFirstResultRecordV1 struct {
	OperationID     string                            `json:"operation_id"`
	RequestHash     string                            `json:"request_hash"`
	Request         ResumeIssueRequestV1              `json:"request"`
	IssuerPublicKey string                            `json:"issuer_public_key"`
	DescriptorHash  string                            `json:"descriptor_hash"`
	Descriptor      wire.EnrollmentResumeDescriptorV1 `json:"descriptor"`
}

type resumeFirstResultStateV1 struct {
	Schema  int                         `json:"schema"`
	Records []resumeFirstResultRecordV1 `json:"records"`
}

// DurableResumeIssuer 冻结每个 certified admin operation 的第一次合法 descriptor。
// journal 位于 control-private 存储，响应不得进入 public distribution/latest。
type DurableResumeIssuer struct {
	mu    sync.Mutex
	path  string
	read  ResumeIssuanceMaterialReader
	sign  BootstrapCapabilitySigner
	now   func() time.Time
	state resumeFirstResultStateV1
}

func OpenDurableResumeIssuer(path string, read ResumeIssuanceMaterialReader,
	sign BootstrapCapabilitySigner, now func() time.Time) (*DurableResumeIssuer, error) {
	if path == "" || read == nil || sign == nil || now == nil {
		return nil, errors.New("[resume] issuer path/dependencies 不能为空")
	}
	issuer := &DurableResumeIssuer{path: path, read: read, sign: sign, now: now,
		state: resumeFirstResultStateV1{Schema: 1, Records: []resumeFirstResultRecordV1{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return issuer, nil
	}
	if err != nil {
		return nil, err
	}
	var state resumeFirstResultStateV1
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		return nil, fmt.Errorf("[resume] first-result store 非规范或损坏: %w", err)
	}
	if err := validateResumeFirstResultState(&state); err != nil {
		return nil, err
	}
	issuer.state = state
	return issuer, nil
}

func (issuer *DurableResumeIssuer) Issue(ctx context.Context,
	request ResumeIssueRequestV1) (wire.EnrollmentResumeDescriptorV1, error) {
	if issuer == nil {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[resume] issuer 不能为空")
	}
	if err := ctx.Err(); err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	requestHash, err := resumeIssueRequestHash(&request)
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}

	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	index := sort.Search(len(issuer.state.Records), func(index int) bool {
		return issuer.state.Records[index].OperationID >= request.OperationID
	})
	if index < len(issuer.state.Records) && issuer.state.Records[index].OperationID == request.OperationID {
		existing := issuer.state.Records[index]
		if existing.RequestHash != requestHash || !wire.EqualCanonical(existing.Request, request) {
			return wire.EnrollmentResumeDescriptorV1{},
				errors.New("[resume] certified operation ID 已绑定不同 request")
		}
		if err := validateResumeFirstResultRecord(&existing); err != nil {
			return wire.EnrollmentResumeDescriptorV1{}, err
		}
		return cloneResumeDescriptor(existing.Descriptor), nil
	}

	material, err := issuer.read(ctx, request.ClusterID, request.InviteID, request.RequestID)
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[resume] transaction material 不可用")
	}
	trustedTime := issuer.now().UTC().Truncate(time.Second)
	issuedAt, _ := wire.ParseTimeZ(request.IssuedAt)
	if issuedAt.After(trustedTime) {
		trustedTime = issuedAt
	}
	publicKey, body, err := validateResumeIssuanceMaterial(&request, &material, trustedTime)
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	capability, err := issuer.sign(ctx, cloneCapabilityBody(body))
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	if !wire.EqualCanonical(capability.Body, body) ||
		wire.VerifyCapabilityAuthorization(&capability, &material.IssuerAuthorizationProof, &material.Invite.Policy, trustedTime) != nil {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[resume] signer 返回错误 capability first-result")
	}
	descriptor := wire.EnrollmentResumeDescriptorV1{
		Schema: 1, ClusterID: request.ClusterID, InviteID: request.InviteID, RequestID: request.RequestID,
		ExpiresAt: request.ExpiresAt, ResumeTunnelCapability: capability,
		ClaimCoreHash:                  material.Transaction.ClaimOperation.ClaimCoreHash,
		ClaimOperationHash:             material.Transaction.State.ClaimOperationHash,
		AdmissionQCHash:                material.Transaction.ClaimOperation.AdmissionQCHash,
		EnrollmentTransactionStateHash: request.ExpectedTransactionStateHash,
		BootstrapCatalogHash:           material.Invite.Record.BootstrapCatalogHash,
		ProofBundleHash:                material.ProofBundleHash,
		EnrollmentServiceRef:           clonePrivateValue(material.Invite.EnrollmentServiceRef),
		DistributionMirrors:            clonePrivateValue(material.DistributionMirrors),
	}
	if err := wire.ValidateEnrollmentResumeDescriptor(&descriptor, publicKey); err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	encoded, err := wire.MarshalCanonical(descriptor)
	if err != nil || int64(len(encoded)) > material.Invite.Policy.MaximumDescriptorBytes {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[resume] descriptor 超出 certified policy 大小上限")
	}
	descriptorHash, err := wire.EnrollmentResumeDescriptorHash(&descriptor, publicKey)
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	record := resumeFirstResultRecordV1{
		OperationID: request.OperationID, RequestHash: requestHash, Request: request,
		IssuerPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		DescriptorHash:  descriptorHash, Descriptor: cloneResumeDescriptor(descriptor),
	}
	candidate := cloneResumeFirstResultState(issuer.state)
	candidate.Records = append(candidate.Records, resumeFirstResultRecordV1{})
	copy(candidate.Records[index+1:], candidate.Records[index:])
	candidate.Records[index] = record
	if err := issuer.persistLocked(candidate); err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	issuer.state = candidate
	return cloneResumeDescriptor(descriptor), nil
}

func validateResumeIssuanceMaterial(request *ResumeIssueRequestV1,
	material *ResumeIssuanceMaterialV1, now time.Time) (ed25519.PublicKey, wire.BootstrapTunnelCapabilityBodyV1, error) {
	if request == nil || material == nil || now.IsZero() {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] issuance context 不完整")
	}
	record := &material.Transaction
	if err := validateDurableRecord(record); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	if !oneOf(record.State.Status, "reserved", "issued_provisional", "completed") ||
		material.Invite.Status != record.State.Status || record.State.ClusterID != request.ClusterID ||
		record.State.InviteID != request.InviteID || record.State.RequestID != request.RequestID ||
		record.ClaimOperation.ClusterID != request.ClusterID || record.ClaimOperation.InviteID != request.InviteID ||
		record.ClaimOperation.RequestID != request.RequestID ||
		material.Invite.Opening.DeviceEnrollmentIntent.DeviceID != request.DeviceID {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] transaction identity/status 不允许 resume")
	}
	stateHash, err := TransactionHash(record.State)
	if err != nil || stateHash != request.ExpectedTransactionStateHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] expected transaction state 已过期")
	}
	claimHash, err := wire.HashObject(DomainClaimOperation, record.ClaimOperation)
	if err != nil || claimHash != record.State.ClaimOperationHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] claim operation hash 不匹配")
	}
	admissionHash, err := wire.EnrollmentAdmissionQCHash(&record.AdmissionQC)
	if err != nil || admissionHash != record.ClaimOperation.AdmissionQCHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] admission QC hash 不匹配")
	}
	if err := validateCertifiedInviteMaterial(&material.Invite, request.ClusterID, request.InviteID); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	inviteHash, err := wire.CertifiedInviteRecordHash(&material.Invite.Record, &material.Invite.Policy)
	if err != nil || inviteHash != record.ClaimOperation.CertifiedInviteRecordHash ||
		record.Invite.CertifiedInviteRecordHash != inviteHash ||
		record.Invite.TokenCommitment != material.Invite.Record.TokenCommitment ||
		record.Invite.DeviceEnrollmentIntentCommitmentHash != material.Invite.Record.DeviceEnrollmentIntentCommitmentHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] transaction 未绑定 exact certified Invite")
	}
	if err := wire.ValidateBootstrapEndpointCatalogAt(&material.BootstrapCatalog, now,
		material.BootstrapCatalog.RequiredClientProtocol); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	catalogHash, _ := wire.BootstrapEndpointCatalogHash(&material.BootstrapCatalog)
	catalogSetHash, _ := wire.ControlSetHash(&material.CatalogControlSet)
	if catalogHash != material.Invite.Record.BootstrapCatalogHash ||
		material.BootstrapCatalog.ClusterID != request.ClusterID ||
		material.BootstrapCatalog.ParentHeadHash != material.CatalogHead.HeadHash ||
		material.CatalogHead.Body.Payload.ClusterID != request.ClusterID ||
		material.CatalogHead.Body.Payload.ControlSetHash != catalogSetHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] catalog 未绑定 exact certified Head")
	}
	if err := wire.ValidateHeadEntry(&material.CatalogHead, nil); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	if err := wire.VerifyConfigQCAuthority(material.BootstrapCatalog.ParentHeadHash,
		material.BootstrapCatalog.BootstrapIngressSet.ConfigQC, &material.CatalogHead,
		&material.CatalogControlSet, material.CatalogPreviousControlSet); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	proof := &material.IssuerAuthorizationProof
	if err := wire.VerifyBootstrapIssuerAuthorizationProof(proof, now); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	policyHash, _ := wire.InviteIssuancePolicyHash(&material.Invite.Policy)
	if proof.AuthorizationHash != material.Invite.Record.BootstrapIssuerAuthorizationHash ||
		proof.RegistryRoot != material.Invite.Record.BootstrapIssuerRegistryRoot ||
		proof.Authorization.Active == nil || proof.Authorization.Active.InviteIssuancePolicyHash != policyHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] issuer authorization/registry/policy binding 无效")
	}
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(proof.Authorization.Active.IssuerPublicKey)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKeyBytes) != proof.Authorization.Active.IssuerPublicKey {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] issuer public key 无效")
	}
	serviceHash, err := wire.PrivateEnrollmentServiceRefHash(&material.Invite.EnrollmentServiceRef)
	if err != nil || serviceHash != material.Invite.Record.EnrollmentServiceRefHash {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] Enrollment service ref 不匹配")
	}
	if _, err := wire.ParseHash(material.ProofBundleHash); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	if int64(len(material.DistributionMirrors)) < material.Invite.Policy.MinimumDistributionMirrors ||
		int64(len(material.DistributionMirrors)) > material.Invite.Policy.MaximumDistributionMirrors {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] distribution mirror count 超出 certified policy")
	}
	if err := wire.ValidateDistributionMirrorBindings(request.ClusterID, material.DistributionMirrors,
		material.DistributionEndpointSets); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	for _, endpointSet := range material.DistributionEndpointSets {
		from, fromErr := wire.ParseTimeZ(endpointSet.ValidFrom)
		until, untilErr := wire.ParseTimeZ(endpointSet.ValidUntil)
		issuedAt, issuedErr := wire.ParseTimeZ(request.IssuedAt)
		expiresAt, expiresErr := wire.ParseTimeZ(request.ExpiresAt)
		if fromErr != nil || untilErr != nil || issuedErr != nil || expiresErr != nil ||
			now.Before(from) || !now.Before(until) || issuedAt.Before(from) || expiresAt.After(until) {
			return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] distribution EndpointSet 不在有效期")
		}
	}

	issuedAt, _ := wire.ParseTimeZ(request.IssuedAt)
	expiresAt, _ := wire.ParseTimeZ(request.ExpiresAt)
	retryNotAfter, _ := wire.ParseTimeZ(record.ClaimOperation.RetryNotAfter)
	catalogFrom, _ := wire.ParseTimeZ(material.BootstrapCatalog.ValidFrom)
	catalogUntil, _ := wire.ParseTimeZ(material.BootstrapCatalog.ValidUntil)
	authorizationFrom, _ := wire.ParseTimeZ(proof.Authorization.Active.ValidFrom)
	authorizationUntil, _ := wire.ParseTimeZ(proof.Authorization.Active.ValidUntil)
	maximumTTL := minInt64(proof.Authorization.Active.MaximumCapabilityTTLSeconds,
		material.Invite.Policy.MaximumResumeCapabilityTTLSeconds)
	if issuedAt.Before(catalogFrom) || issuedAt.Before(authorizationFrom) ||
		!now.Before(expiresAt) || int64(expiresAt.Sub(issuedAt)/time.Second) > maximumTTL ||
		expiresAt.After(retryNotAfter) || expiresAt.After(catalogUntil) || expiresAt.After(authorizationUntil) {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, errors.New("[resume] capability validity 超出 certified deadline")
	}
	address, err := netip.ParseAddr(material.Invite.EnrollmentServiceRef.OverlayIP)
	if err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	prefix := int64(128)
	if address.Is4() {
		prefix = 32
	}
	active := proof.Authorization.Active
	body := wire.BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: request.ClusterID, InviteID: request.InviteID,
		CommittedInviteRecordHash: inviteHash, InviteIssuancePolicyHash: policyHash,
		BootstrapIssuerAuthorizationHash: proof.AuthorizationHash,
		BootstrapIssuerRegistryRoot:      proof.RegistryRoot, EnrollmentServiceRefHash: serviceHash,
		Mode: "resume_committed_claim", ResumeBinding: &wire.BootstrapCapabilityResumeBindingV1{
			RequestID: request.RequestID, ClaimOperationHash: claimHash, AdmissionQCHash: admissionHash,
			ClaimCoreHash: record.ClaimOperation.ClaimCoreHash, CSRHash: record.ClaimOperation.CSRHash,
			IdentityKeyHash: record.ClaimOperation.IdentityKeyHash, WrappingKeyHash: record.ClaimOperation.WrappingKeyHash,
			EnrollmentTransactionStateHash: stateHash,
		},
		IssuedAt: request.IssuedAt, NotBefore: request.IssuedAt, ExpiresAt: request.ExpiresAt,
		AllowedIngressSetHash:          material.BootstrapCatalog.BootstrapIngressSetHash,
		AllowedServiceID:               material.Invite.EnrollmentServiceRef.ServiceID,
		AllowedDestinationIP:           material.Invite.EnrollmentServiceRef.OverlayIP,
		AllowedDestinationPrefixLength: prefix,
		AllowedDestinationPort:         material.Invite.EnrollmentServiceRef.TCPPort,
		AllowedInsideTransport:         "tcp",
		MaximumConnectionAttempts:      minInt64(active.MaximumConnectionAttempts, material.Invite.Policy.BootstrapConnectionAttempts),
		MaximumConcurrentSessions:      minInt64(active.MaximumConcurrentSessions, material.Invite.Policy.BootstrapMaxConcurrentSessions),
		MaximumSessionSeconds:          minInt64(active.MaximumSessionSeconds, material.Invite.Policy.BootstrapSessionSeconds),
		MaximumTotalBytes:              minInt64(active.MaximumTotalBytes, material.Invite.Policy.BootstrapTotalBytes),
		IssuerEpoch:                    active.IssuerEpoch, IssuerKeyID: active.IssuerKeyID,
	}
	if err := wire.ValidateCapabilityBody(&body); err != nil {
		return nil, wire.BootstrapTunnelCapabilityBodyV1{}, err
	}
	return ed25519.PublicKey(publicKeyBytes), body, nil
}

func resumeIssueRequestHash(request *ResumeIssueRequestV1) (string, error) {
	if request == nil || request.Schema != 1 || request.OperationID == "" || request.ClusterID == "" ||
		request.InviteID == "" || request.RequestID == "" || request.DeviceID == "" {
		return "", errors.New("[resume] issue request identity 无效")
	}
	if _, err := wire.ParseHash(request.ExpectedTransactionStateHash); err != nil {
		return "", err
	}
	issued, err := wire.ParseTimeZ(request.IssuedAt)
	if err != nil {
		return "", err
	}
	expires, err := wire.ParseTimeZ(request.ExpiresAt)
	if err != nil || !issued.Before(expires) {
		return "", errors.New("[resume] issue request validity 无效")
	}
	return wire.HashObject(DomainEnrollmentResumeIssueRequest, request)
}

func validateResumeFirstResultState(state *resumeFirstResultStateV1) error {
	if state == nil || state.Schema != 1 || state.Records == nil {
		return errors.New("[resume] first-result store schema 无效")
	}
	for index := range state.Records {
		if index > 0 && state.Records[index-1].OperationID >= state.Records[index].OperationID {
			return errors.New("[resume] first-results 未按 operation ID 严格排序")
		}
		if err := validateResumeFirstResultRecord(&state.Records[index]); err != nil {
			return err
		}
	}
	return nil
}

func validateResumeFirstResultRecord(record *resumeFirstResultRecordV1) error {
	if record == nil || record.OperationID == "" || record.OperationID != record.Request.OperationID {
		return errors.New("[resume] stored first-result identity 无效")
	}
	requestHash, err := resumeIssueRequestHash(&record.Request)
	if err != nil || requestHash != record.RequestHash {
		return errors.New("[resume] stored request hash 不匹配")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(record.IssuerPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != record.IssuerPublicKey {
		return errors.New("[resume] stored issuer public key 无效")
	}
	if record.Descriptor.ClusterID != record.Request.ClusterID ||
		record.Descriptor.InviteID != record.Request.InviteID ||
		record.Descriptor.RequestID != record.Request.RequestID ||
		record.Descriptor.ExpiresAt != record.Request.ExpiresAt ||
		record.Descriptor.EnrollmentTransactionStateHash != record.Request.ExpectedTransactionStateHash {
		return errors.New("[resume] stored descriptor/request binding 无效")
	}
	descriptorHash, err := wire.EnrollmentResumeDescriptorHash(&record.Descriptor, ed25519.PublicKey(publicKey))
	if err != nil || descriptorHash != record.DescriptorHash {
		return errors.New("[resume] stored descriptor hash/signature 无效")
	}
	return nil
}

func (issuer *DurableResumeIssuer) persistLocked(candidate resumeFirstResultStateV1) error {
	if err := validateResumeFirstResultState(&candidate); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(candidate)
	if err != nil {
		return err
	}
	directory := filepath.Dir(issuer.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(issuer.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := replaceDurableFile(temporary, issuer.path); err != nil {
		return err
	}
	return syncDurableDirectory(directory)
}

func cloneResumeDescriptor(value wire.EnrollmentResumeDescriptorV1) wire.EnrollmentResumeDescriptorV1 {
	return clonePrivateValue(value)
}

func cloneResumeFirstResultState(value resumeFirstResultStateV1) resumeFirstResultStateV1 {
	return clonePrivateValue(value)
}

func cloneCapabilityBody(value wire.BootstrapTunnelCapabilityBodyV1) wire.BootstrapTunnelCapabilityBodyV1 {
	return clonePrivateValue(value)
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
