package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"loom/internal/releasefloor"
)

const (
	domainControlSet                 = "loom-control-set-v1"
	domainHeadEntry                  = "loom-raft-head-entry-v2"
	domainControlHead                = "loom-control-head-v2"
	domainHeadReplicationAttestation = "loom-head-replication-attestation-v1"
	domainControlOperation           = "loom-control-operation-v1"
	domainControlOperationSignature  = "loom-control-operation-signature-v1"
	domainAdminRotation              = "loom-local-admin-rotation-v1"
	domainAdminCertificateDER        = "loom-admin-certificate-der-v1"
)

type ImportInput struct {
	ConfigPath       string
	CertifiedPath    string
	OperationsPath   string
	BrowserTLSPath   string
	ReleaseFloorPath string
	ObservationPath  string
}

type controlMember struct {
	Schema                 int    `json:"schema"`
	ClusterID              string `json:"cluster_id"`
	MemberID               string `json:"member_id"`
	MembershipKeyID        string `json:"membership_key_id"`
	MembershipPublicKey    string `json:"membership_public_key"`
	ConfigKeyID            string `json:"config_key_id"`
	ConfigPublicKey        string `json:"config_public_key"`
	EnrollmentKeyID        string `json:"enrollment_key_id"`
	EnrollmentPublicKey    string `json:"enrollment_public_key"`
	MinimumControlProtocol int64  `json:"minimum_control_protocol"`
}

type controlSet struct {
	Schema    int             `json:"schema"`
	ClusterID string          `json:"cluster_id"`
	Members   []controlMember `json:"members"`
}

type headPayload struct {
	Schema                      int             `json:"schema"`
	HeadKind                    string          `json:"head_kind"`
	ClusterID                   string          `json:"cluster_id"`
	RecoveryEpoch               int64           `json:"recovery_epoch"`
	RecoveryStatementHash       string          `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string          `json:"recovery_policy_hash"`
	ControlEpoch                int64           `json:"control_epoch"`
	ControlSetHash              string          `json:"control_set_hash"`
	ControlPeerDirectoryHash    string          `json:"control_peer_directory_hash"`
	RaftTerm                    int64           `json:"raft_term"`
	RaftIndex                   int64           `json:"raft_index"`
	PreviousLogEntryHash        string          `json:"previous_log_entry_hash"`
	ControlRevision             int64           `json:"control_revision"`
	ParentHeadHash              string          `json:"parent_head_hash"`
	OperationRoot               string          `json:"operation_root"`
	SnapshotHash                string          `json:"snapshot_hash"`
	EffectiveSSOTHash           string          `json:"effective_ssot_hash"`
	DeviceViewsRoot             string          `json:"device_views_root"`
	AdminACLRoot                string          `json:"admin_acl_root"`
	CAProfileRoot               string          `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string          `json:"bootstrap_issuer_registry_root"`
	RenderContractVersion       int64           `json:"render_contract_version"`
	MinReaderVersion            int64           `json:"min_reader_version"`
	CommittedLogicalTime        string          `json:"committed_logical_time"`
	MaxClockSkewSeconds         int64           `json:"max_clock_skew_seconds"`
	TransitionContext           json.RawMessage `json:"transition_context"`
}

type headBody struct {
	Payload             headPayload `json:"payload"`
	TransitionProofHash string      `json:"transition_proof_hash"`
}

type legacyHead struct {
	Body      headBody `json:"body"`
	EntryHash string   `json:"entry_hash"`
	HeadHash  string   `json:"head_hash"`
}

type attestation struct {
	Schema                      int    `json:"schema"`
	AttestationType             string `json:"attestation_type"`
	ClusterID                   string `json:"cluster_id"`
	RecoveryEpoch               int64  `json:"recovery_epoch"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	ControlEpoch                int64  `json:"control_epoch"`
	ControlSetHash              string `json:"control_set_hash"`
	ControlPeerDirectoryHash    string `json:"control_peer_directory_hash"`
	RaftTerm                    int64  `json:"raft_term"`
	RaftIndex                   int64  `json:"raft_index"`
	PreviousLogEntryHash        string `json:"previous_log_entry_hash"`
	ControlRevision             int64  `json:"control_revision"`
	EntryHash                   string `json:"entry_hash"`
	HeadHash                    string `json:"head_hash"`
	ParentHeadHash              string `json:"parent_head_hash"`
	TransitionProofHash         string `json:"transition_proof_hash"`
	OperationRoot               string `json:"operation_root"`
	SnapshotHash                string `json:"snapshot_hash"`
	EffectiveSSOTHash           string `json:"effective_ssot_hash"`
	DeviceViewsRoot             string `json:"device_views_root"`
	AdminACLRoot                string `json:"admin_acl_root"`
	CAProfileRoot               string `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string `json:"bootstrap_issuer_registry_root"`
	RenderContractVersion       int64  `json:"render_contract_version"`
	MinReaderVersion            int64  `json:"min_reader_version"`
	CommittedLogicalTime        string `json:"committed_logical_time"`
	MaxClockSkewSeconds         int64  `json:"max_clock_skew_seconds"`
}

type controlSignature struct {
	Algorithm   string `json:"algorithm"`
	MemberID    string `json:"member_id"`
	ConfigKeyID string `json:"config_key_id"`
	Signature   string `json:"signature"`
}

type signerRef struct {
	MemberID    string `json:"member_id"`
	ConfigKeyID string `json:"config_key_id"`
}

type stableQC struct {
	Schema      int                `json:"schema"`
	QCType      string             `json:"qc_type"`
	Attestation attestation        `json:"attestation"`
	Signatures  []controlSignature `json:"signatures"`
	SignerRefs  []signerRef        `json:"signer_refs"`
}

type certifiedState struct {
	Schema        int             `json:"schema"`
	ControlSet    controlSet      `json:"control_set"`
	Active        json.RawMessage `json:"active,omitempty"`
	CertifiedHead *legacyHead     `json:"certified_head"`
	CertifiedQC   *stableQC       `json:"certified_qc"`
}

type operationBody struct {
	Schema                    int    `json:"schema"`
	ClusterID                 string `json:"cluster_id"`
	OperationID               string `json:"operation_id"`
	AuthorID                  string `json:"author_id"`
	AdminCertDigest           string `json:"admin_cert_digest"`
	CreatedAt                 string `json:"created_at"`
	ExpiresAt                 string `json:"expires_at,omitempty"`
	BaseRecoveryEpoch         int64  `json:"base_recovery_epoch"`
	BaseRecoveryStatementHash string `json:"base_recovery_statement_hash"`
	BaseRecoveryPolicyHash    string `json:"base_recovery_policy_hash"`
	BaseControlEpoch          int64  `json:"base_control_epoch"`
	BaseControlSetHash        string `json:"base_control_set_hash"`
	BaseControlRevision       int64  `json:"base_control_revision"`
	ParentHeadHash            string `json:"parent_head_hash"`
	Kind                      string `json:"kind"`
	PayloadSchema             int64  `json:"payload_schema"`
	PayloadHash               string `json:"payload_hash"`
	Reason                    string `json:"reason"`
}

type adminSignature struct {
	Algorithm  string `json:"algorithm"`
	AdminKeyID string `json:"admin_key_id"`
	Signature  string `json:"signature"`
}

type controlOperation struct {
	Body            operationBody  `json:"body"`
	AuthorSignature adminSignature `json:"author_signature"`
}

type operationLeaf struct {
	Schema      int    `json:"schema"`
	OperationID string `json:"operation_id"`
	ObjectID    string `json:"object_id"`
}

type adminAuthorization struct {
	Schema                 int    `json:"schema"`
	ClusterID              string `json:"cluster_id"`
	AuthorizationID        string `json:"authorization_id"`
	Generation             int64  `json:"generation"`
	AdminID                string `json:"admin_id"`
	AdminCertificateDER    string `json:"admin_certificate_der"`
	AdminCertificateDigest string `json:"admin_certificate_digest"`
	AdminKeyID             string `json:"admin_key_id"`
	Status                 string `json:"status"`
}

type operationJournal struct {
	Schema  int `json:"schema"`
	Records []struct {
		Schema           int              `json:"schema"`
		Operation        controlOperation `json:"operation"`
		Leaf             operationLeaf    `json:"leaf"`
		Candidate        legacyHead       `json:"candidate"`
		AdditionalLeaves []operationLeaf  `json:"additional_leaves,omitempty"`
		Result           *struct {
			Schema   int             `json:"schema"`
			Status   string          `json:"status"`
			Head     legacyHead      `json:"head"`
			ConfigQC json.RawMessage `json:"config_qc"`
		} `json:"result,omitempty"`
		AdminRotation *struct {
			Payload json.RawMessage `json:"payload"`
		} `json:"admin_rotation,omitempty"`
		Activation *struct {
			Application struct {
				Schema         int                  `json:"schema"`
				ClusterID      string               `json:"cluster_id"`
				LegacySSOT     string               `json:"legacy_ssot"`
				Authorizations []adminAuthorization `json:"authorizations"`
			} `json:"application"`
		} `json:"activation,omitempty"`
	} `json:"records"`
}

func Import(input ImportInput) (State, error) {
	state, _, err := importValidated(input)
	return state, err
}

// importValidated returns the exact protected LKG only to the one-time
// NetworkIntent converter.  The daemon never persists or rereads this legacy
// source after the import Material is certified.
func importValidated(input ImportInput) (State, []byte, error) {
	files := map[string]string{"config": input.ConfigPath, "certified": input.CertifiedPath,
		"operations": input.OperationsPath, "browser TLS": input.BrowserTLSPath, "release floor": input.ReleaseFloorPath}
	bodies := map[string][]byte{}
	for name, path := range files {
		body, err := readProtected(path, 64<<20)
		if err != nil {
			return State{}, nil, fmt.Errorf("read %s: %w", name, err)
		}
		bodies[name] = body
	}

	var certified certifiedState
	if err := decodeStrict(bodies["certified"], &certified); err != nil {
		return State{}, nil, fmt.Errorf("verify certified state: %w", err)
	}
	if certified.Schema != 2 || len(certified.Active) != 0 && string(certified.Active) != "null" || certified.CertifiedHead == nil || certified.CertifiedQC == nil {
		return State{}, nil, errors.New("certified state is not a stable completed head")
	}
	if err := verifyCertified(certified.ControlSet, *certified.CertifiedHead, *certified.CertifiedQC); err != nil {
		return State{}, nil, err
	}

	config, err := decodeObject(bodies["config"])
	if err != nil {
		return State{}, nil, fmt.Errorf("verify control identity: %w", err)
	}
	for _, key := range []string{"schema", "cluster_id", "member_id", "device_id", "overlay_ip", "control_port", "raft_port", "control_set", "peer_directory", "control_service", "admin_profiles", "authorizations", "genesis_evidence"} {
		if _, ok := config[key]; !ok {
			return State{}, nil, fmt.Errorf("control identity is missing %s", key)
		}
	}
	if len(config) != 13 {
		return State{}, nil, errors.New("control identity contains an unknown field")
	}
	var schema int
	var clusterID, overlayIP string
	var port int64
	var configuredSet controlSet
	if json.Unmarshal(config["schema"], &schema) != nil || schema != 1 ||
		json.Unmarshal(config["cluster_id"], &clusterID) != nil || clusterID != certified.ControlSet.ClusterID ||
		json.Unmarshal(config["overlay_ip"], &overlayIP) != nil ||
		json.Unmarshal(config["control_port"], &port) != nil || port < 1 || port > 65535 ||
		json.Unmarshal(config["control_set"], &configuredSet) != nil || !canonicalEqual(configuredSet, certified.ControlSet) {
		return State{}, nil, errors.New("control identity does not match certified authority")
	}
	ip := net.ParseIP(overlayIP)
	if ip == nil || !ip.IsPrivate() && !ip.IsLoopback() {
		return State{}, nil, errors.New("control identity listener is not private")
	}

	var tlsEnvelope struct {
		Schema int `json:"schema"`
		BrowserTLS
	}
	if err := decodeStrict(bodies["browser TLS"], &tlsEnvelope); err != nil || tlsEnvelope.Schema != 1 {
		return State{}, nil, errors.New("browser TLS identity is invalid")
	}
	if err := verifyBrowserTLS(tlsEnvelope.BrowserTLS, overlayIP); err != nil {
		return State{}, nil, err
	}
	floor, err := releasefloor.Read(input.ReleaseFloorPath)
	if err != nil || floor == nil {
		return State{}, nil, errors.New("release anti-rollback floor is unavailable or invalid")
	}
	lkg, readCerts, adminCerts, err := recoverJournal(bodies["operations"], clusterID, certified.ControlSet,
		*certified.CertifiedHead, config["authorizations"])
	if err != nil {
		return State{}, nil, err
	}
	head := CertifiedHead{Hash: certified.CertifiedHead.HeadHash, Index: certified.CertifiedHead.Body.Payload.RaftIndex,
		Revision: certified.CertifiedHead.Body.Payload.ControlRevision}
	projection, err := ProjectionFromSSOT(lkg, head)
	if err != nil {
		return State{}, nil, err
	}
	if input.ObservationPath != "" {
		if body, readErr := os.ReadFile(input.ObservationPath); readErr == nil {
			applyObservation(&projection, body)
		}
	}
	state := State{Schema: StateSchema, ClusterID: clusterID, Listen: net.JoinHostPort(overlayIP, strconv.FormatInt(port, 10)), Head: head,
		Recovery: RecoveryEvidence{ConfigSHA256: SHA256(bodies["config"]), CertifiedSHA256: SHA256(bodies["certified"]),
			OperationsSHA256: SHA256(bodies["operations"]), ReleaseFloorSHA256: SHA256(bodies["release floor"]),
			ReleaseFloor: *floor, V2Latch: certified.CertifiedHead.Body.Payload.MinReaderVersion >= 2},
		BrowserTLS: tlsEnvelope.BrowserTLS, ReadCertDER: readCerts, AdminCertDER: adminCerts, Projection: projection}
	if err := state.Validate(); err != nil {
		return State{}, nil, err
	}
	return state, lkg, nil
}

func verifyCertified(set controlSet, head legacyHead, qc stableQC) error {
	if set.Schema != 1 || set.ClusterID == "" || len(set.Members) == 0 {
		return errors.New("certified ControlSet is invalid")
	}
	seen := map[string]bool{}
	for index, member := range set.Members {
		if member.Schema != 1 || member.ClusterID != set.ClusterID || member.MinimumControlProtocol < 1 ||
			index > 0 && set.Members[index-1].MemberID >= member.MemberID || seen[member.MemberID] {
			return errors.New("certified ControlSet members are invalid")
		}
		seen[member.MemberID] = true
		for _, pair := range [][2]string{{member.MembershipKeyID, member.MembershipPublicKey}, {member.ConfigKeyID, member.ConfigPublicKey}, {member.EnrollmentKeyID, member.EnrollmentPublicKey}} {
			key, err := base64.RawURLEncoding.DecodeString(pair[1])
			if err != nil || len(key) != ed25519.PublicKeySize || keyID(key) != pair[0] {
				return errors.New("certified ControlSet key is invalid")
			}
		}
	}
	setHash, err := hashObject(domainControlSet, set)
	payload := head.Body.Payload
	if err != nil || payload.Schema != 2 || payload.ClusterID != set.ClusterID || payload.ControlSetHash != setHash ||
		payload.RaftTerm < 1 || payload.RaftIndex < 1 || payload.ControlRevision != payload.RaftIndex ||
		payload.RenderContractVersion < 1 || payload.MinReaderVersion < 2 || len(payload.TransitionContext) == 0 {
		return errors.New("certified head coordinates are invalid")
	}
	for _, value := range []string{payload.RecoveryStatementHash, payload.RecoveryPolicyHash, payload.ControlSetHash,
		payload.ControlPeerDirectoryHash, payload.PreviousLogEntryHash, payload.ParentHeadHash, payload.OperationRoot,
		payload.SnapshotHash, payload.EffectiveSSOTHash, payload.DeviceViewsRoot, payload.AdminACLRoot, payload.CAProfileRoot,
		payload.BootstrapIssuerRegistryRoot, head.Body.TransitionProofHash, head.EntryHash, head.HeadHash} {
		if !validTypedHash(value) {
			return errors.New("certified head contains a non-canonical hash")
		}
	}
	wantEntry, _ := hashObject(domainHeadEntry, head.Body)
	wantHead, _ := hashObject(domainControlHead, head.Body)
	if head.EntryHash != wantEntry || head.HeadHash != wantHead {
		return errors.New("certified head hash does not match its canonical body")
	}
	wantAttestation := attestationFor(head)
	if qc.Schema != 1 || qc.QCType != "stable_head" || !canonicalEqual(qc.Attestation, wantAttestation) || len(qc.Signatures) != len(qc.SignerRefs) || len(qc.Signatures) < len(set.Members)/2+1 {
		return errors.New("certified quorum proof is invalid")
	}
	members := map[string]controlMember{}
	for _, member := range set.Members {
		members[member.MemberID] = member
	}
	canonical, _ := canonicalJSON(wantAttestation)
	message := frame(domainHeadReplicationAttestation, canonical)
	for index, signature := range qc.Signatures {
		ref := qc.SignerRefs[index]
		member, ok := members[signature.MemberID]
		key, keyErr := base64.RawURLEncoding.DecodeString(member.ConfigPublicKey)
		raw, sigErr := base64.RawURLEncoding.DecodeString(signature.Signature)
		if !ok || signature.Algorithm != "ed25519" || signature.ConfigKeyID != member.ConfigKeyID ||
			ref.MemberID != signature.MemberID || ref.ConfigKeyID != signature.ConfigKeyID || keyErr != nil || sigErr != nil ||
			len(raw) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), message, raw) {
			return errors.New("certified quorum signature is invalid")
		}
		if index > 0 && qc.Signatures[index-1].MemberID >= signature.MemberID {
			return errors.New("certified quorum signers are not canonical")
		}
	}
	return nil
}

func attestationFor(head legacyHead) attestation {
	p := head.Body.Payload
	return attestation{Schema: 1, AttestationType: "head", ClusterID: p.ClusterID, RecoveryEpoch: p.RecoveryEpoch,
		RecoveryStatementHash: p.RecoveryStatementHash, RecoveryPolicyHash: p.RecoveryPolicyHash,
		ControlEpoch: p.ControlEpoch, ControlSetHash: p.ControlSetHash, ControlPeerDirectoryHash: p.ControlPeerDirectoryHash,
		RaftTerm: p.RaftTerm, RaftIndex: p.RaftIndex, PreviousLogEntryHash: p.PreviousLogEntryHash,
		ControlRevision: p.ControlRevision, EntryHash: head.EntryHash, HeadHash: head.HeadHash,
		ParentHeadHash: p.ParentHeadHash, TransitionProofHash: head.Body.TransitionProofHash,
		OperationRoot: p.OperationRoot, SnapshotHash: p.SnapshotHash, EffectiveSSOTHash: p.EffectiveSSOTHash,
		DeviceViewsRoot: p.DeviceViewsRoot, AdminACLRoot: p.AdminACLRoot, CAProfileRoot: p.CAProfileRoot,
		BootstrapIssuerRegistryRoot: p.BootstrapIssuerRegistryRoot, RenderContractVersion: p.RenderContractVersion,
		MinReaderVersion: p.MinReaderVersion, CommittedLogicalTime: p.CommittedLogicalTime, MaxClockSkewSeconds: p.MaxClockSkewSeconds}
}

func recoverJournal(body []byte, clusterID string, set controlSet, certified legacyHead,
	initialAuthorizations json.RawMessage) ([]byte, []string, []string, error) {
	if _, err := canonicalBytes(body); err != nil {
		return nil, nil, nil, fmt.Errorf("operations store is ambiguous: %w", err)
	}
	var journal operationJournal
	if err := json.Unmarshal(body, &journal); err != nil || journal.Schema != 1 {
		return nil, nil, nil, errors.New("operations store cannot be decoded")
	}
	var initial []adminAuthorization
	if err := json.Unmarshal(initialAuthorizations, &initial); err != nil || len(initial) != 1 {
		return nil, nil, nil, errors.New("control identity has no unique administrator authorization")
	}
	current := initial[0]
	if err := validateAuthorization(current, clusterID); err != nil {
		return nil, nil, nil, err
	}
	readers := []string{current.AdminCertificateDER}
	leaves := []operationLeaf{}
	var lkg string
	foundCertified := false
	for index, record := range journal.Records {
		if record.Schema != 1 || record.Result == nil || record.Result.Schema != 1 || record.Result.Status != "certified" ||
			!canonicalEqual(record.Candidate, record.Result.Head) {
			return nil, nil, nil, fmt.Errorf("operations store record %d has no exact certified result", index)
		}
		var qc stableQC
		if err := decodeStrict(record.Result.ConfigQC, &qc); err != nil || verifyCertified(set, record.Candidate, qc) != nil {
			return nil, nil, nil, fmt.Errorf("operations store record %d has an invalid quorum proof", index)
		}
		if record.Candidate.Body.Payload.RaftIndex > certified.Body.Payload.RaftIndex {
			return nil, nil, nil, errors.New("operations store advances beyond the imported certified head")
		}
		if canonicalEqual(record.Candidate, certified) {
			foundCertified = true
		}
		if record.Operation.Body.Schema != 0 {
			if err := verifyOperation(record.Operation, current, record.Candidate.Body.Payload.CommittedLogicalTime); err != nil {
				return nil, nil, nil, fmt.Errorf("operations store record %d: %w", index, err)
			}
		}
		if record.Leaf.Schema != 1 || record.Leaf.OperationID == "" || !validTypedHash(record.Leaf.ObjectID) ||
			record.Operation.Body.Schema != 0 && record.Leaf.OperationID != record.Operation.Body.OperationID {
			return nil, nil, nil, fmt.Errorf("operations store record %d leaf is not bound to its signed operation", index)
		}
		if record.Activation != nil && record.Leaf.ObjectID != record.Operation.Body.PayloadHash {
			return nil, nil, nil, errors.New("activation LKG is not bound to its signed operation")
		}
		leaves = append(leaves, record.Leaf)
		leaves = append(leaves, record.AdditionalLeaves...)
		root, err := operationRoot(leaves)
		if err != nil || root != record.Candidate.Body.Payload.OperationRoot {
			return nil, nil, nil, fmt.Errorf("operations store record %d root does not match its certified head", index)
		}
		if record.Activation != nil {
			application := record.Activation.Application
			if lkg != "" || application.Schema != 2 || application.ClusterID != clusterID || application.LegacySSOT == "" ||
				len(application.Authorizations) != 1 {
				return nil, nil, nil, errors.New("operations store has an invalid activation LKG")
			}
			next := application.Authorizations[0]
			if err := validateAuthorization(next, clusterID); err != nil || next.Generation != current.Generation+1 ||
				next.AuthorizationID != current.AuthorizationID || next.AdminID != current.AdminID ||
				next.AdminCertificateDER != current.AdminCertificateDER || next.AdminCertificateDigest != current.AdminCertificateDigest ||
				next.AdminKeyID != current.AdminKeyID {
				return nil, nil, nil, errors.New("activation administrator identity is not continuous")
			}
			current = next
			readers = appendUnique(readers, current.AdminCertificateDER)
			lkg = application.LegacySSOT
		}
		if record.AdminRotation != nil {
			objectID, _ := hashObject(domainControlOperation, record.Operation)
			if record.Leaf.ObjectID != objectID {
				return nil, nil, nil, errors.New("administrator rotation leaf is not bound to its signed operation")
			}
			var payload struct {
				Schema                int                `json:"schema"`
				PreviousAuthorization adminAuthorization `json:"previous_authorization"`
				NextAuthorization     adminAuthorization `json:"next_authorization"`
			}
			_, canonicalErr := canonicalBytes(record.AdminRotation.Payload)
			if canonicalErr != nil || json.Unmarshal(record.AdminRotation.Payload, &payload) != nil || payload.Schema != 1 {
				return nil, nil, nil, errors.New("operations store has an invalid administrator rotation payload")
			}
			payloadHash, _ := hashRawObject(domainAdminRotation, record.AdminRotation.Payload)
			if payloadHash != record.Operation.Body.PayloadHash || !sameAuthorization(current, payload.PreviousAuthorization) ||
				payload.NextAuthorization.Generation != current.Generation+1 ||
				payload.NextAuthorization.AuthorizationID != current.AuthorizationID ||
				payload.NextAuthorization.AdminID != current.AdminID {
				return nil, nil, nil, errors.New("administrator rotation is not continuous or bound to its signed payload")
			}
			if err := validateAuthorization(payload.NextAuthorization, clusterID); err != nil {
				return nil, nil, nil, err
			}
			current = payload.NextAuthorization
			readers = appendUnique(readers, current.AdminCertificateDER)
		}
	}
	if lkg == "" || !foundCertified {
		return nil, nil, nil, errors.New("operations store does not contain the activation LKG and imported certified head")
	}
	sort.Strings(readers)
	return []byte(lkg), readers, []string{current.AdminCertificateDER}, nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func validateAuthorization(authorization adminAuthorization, clusterID string) error {
	if authorization.Schema != 1 || authorization.ClusterID != clusterID || authorization.AuthorizationID == "" ||
		authorization.AdminID == "" || authorization.Generation < 1 || authorization.Status != "active" {
		return errors.New("administrator authorization identity is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(authorization.AdminCertificateDER)
	certificate, parseErr := x509.ParseCertificate(raw)
	if err != nil || parseErr != nil || !bytes.Equal(certificate.Raw, raw) {
		return errors.New("administrator certificate is invalid")
	}
	digest := hashRaw(domainAdminCertificateDER, raw)
	keyDigest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	if digest != authorization.AdminCertificateDigest || "sha256:"+hex.EncodeToString(keyDigest[:]) != authorization.AdminKeyID {
		return errors.New("administrator certificate is not bound to its authorization")
	}
	return nil
}

func sameAuthorization(left, right adminAuthorization) bool {
	return left.Schema == right.Schema && left.ClusterID == right.ClusterID && left.AuthorizationID == right.AuthorizationID &&
		left.Generation == right.Generation && left.AdminID == right.AdminID &&
		left.AdminCertificateDER == right.AdminCertificateDER && left.AdminCertificateDigest == right.AdminCertificateDigest &&
		left.AdminKeyID == right.AdminKeyID && left.Status == right.Status
}

func verifyOperation(operation controlOperation, authorization adminAuthorization, committed string) error {
	body := operation.Body
	if body.Schema != 1 || body.ClusterID != authorization.ClusterID || body.OperationID == "" || body.AuthorID != authorization.AdminID ||
		body.AdminCertDigest != authorization.AdminCertificateDigest || body.BaseControlRevision < 1 || body.Kind == "" ||
		body.PayloadSchema < 1 || body.Reason == "" {
		return errors.New("signed administrator operation identity is invalid")
	}
	for _, digest := range []string{body.AdminCertDigest, body.BaseRecoveryStatementHash, body.BaseRecoveryPolicyHash,
		body.BaseControlSetHash, body.ParentHeadHash, body.PayloadHash} {
		if !validTypedHash(digest) {
			return errors.New("signed administrator operation hash is invalid")
		}
	}
	trusted, err := time.Parse(time.RFC3339, committed)
	created, createdErr := time.Parse(time.RFC3339, body.CreatedAt)
	if err != nil || createdErr != nil || trusted.Before(created) {
		return errors.New("signed administrator operation time is invalid")
	}
	if body.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil || !created.Before(expires) || !trusted.Before(expires) {
			return errors.New("signed administrator operation expiry is invalid")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(authorization.AdminCertificateDER)
	if err != nil {
		return errors.New("administrator certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return errors.New("administrator certificate is invalid")
	}
	keyDigest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	if operation.AuthorSignature.AdminKeyID != "sha256:"+hex.EncodeToString(keyDigest[:]) {
		return errors.New("administrator operation key ID is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(operation.AuthorSignature.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("administrator operation signature is invalid")
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return err
	}
	message := frame(domainControlOperationSignature, canonical)
	valid := false
	switch key := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		valid = operation.AuthorSignature.Algorithm == "ed25519" && ed25519.Verify(key, message, signature)
	case *ecdsa.PublicKey:
		if operation.AuthorSignature.Algorithm == "ecdsa-p256-sha256" && key.Curve == elliptic.P256() {
			r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
			halfOrder := new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)
			digest := sha256.Sum256(message)
			valid = r.Sign() > 0 && s.Sign() > 0 && s.Cmp(halfOrder) <= 0 && ecdsa.Verify(key, digest[:], r, s)
		}
	}
	if !valid {
		return errors.New("administrator operation signature is invalid")
	}
	return nil
}

func operationRoot(leaves []operationLeaf) (string, error) {
	ordered := append([]operationLeaf(nil), leaves...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].OperationID < ordered[j].OperationID })
	hashes := make([][]byte, len(ordered))
	for index, leaf := range ordered {
		if leaf.Schema != 1 || leaf.OperationID == "" || !validTypedHash(leaf.ObjectID) ||
			index > 0 && ordered[index-1].OperationID == leaf.OperationID {
			return "", errors.New("operation journal leaf is invalid")
		}
		canonical, err := canonicalJSON(leaf)
		if err != nil {
			return "", err
		}
		value := append([]byte{0}, canonical...)
		digest := sha256.Sum256(value)
		hashes[index] = digest[:]
	}
	root := merkleRoot(hashes)
	return "sha256:" + hex.EncodeToString(root), nil
}

func merkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		digest := sha256.Sum256(nil)
		return digest[:]
	}
	if len(hashes) == 1 {
		return append([]byte(nil), hashes[0]...)
	}
	split := 1
	for split<<1 < len(hashes) {
		split <<= 1
	}
	left, right := merkleRoot(hashes[:split]), merkleRoot(hashes[split:])
	value := make([]byte, 1+len(left)+len(right))
	value[0] = 1
	copy(value[1:], left)
	copy(value[1+len(left):], right)
	digest := sha256.Sum256(value)
	return digest[:]
}

func hashRawObject(domain string, raw []byte) (string, error) {
	canonical, err := canonicalBytes(raw)
	if err != nil {
		return "", err
	}
	return hashRaw(domain, canonical), nil
}

func hashRaw(domain string, raw []byte) string {
	digest := sha256.Sum256(frame(domain, raw))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func verifyBrowserTLS(identity BrowserTLS, overlay string) error {
	certificate, err := tls.X509KeyPair([]byte(identity.CertificateChainPEM), []byte(identity.PrivateKeyPKCS8PEM))
	if err != nil || len(certificate.Certificate) != 2 {
		return errors.New("browser TLS identity is not an exact leaf/root chain")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(overlay) != nil || leaf.VerifyHostname("127.0.0.1") != nil {
		return errors.New("browser TLS identity does not cover the private and loopback listeners")
	}
	block, _ := pem.Decode([]byte(identity.RootPrivateKeyPKCS8PEM))
	if block == nil {
		return errors.New("browser TLS recovery key is invalid")
	}
	return nil
}

func applyObservation(projection *WebProjection, body []byte) {
	var snapshot struct {
		View struct {
			Nodes []struct {
				ID     string `json:"ID"`
				Health string `json:"Health"`
			} `json:"Nodes"`
		} `json:"view"`
	}
	if json.Unmarshal(body, &snapshot) != nil {
		return
	}
	observed := map[string]string{}
	for _, node := range snapshot.View.Nodes {
		switch node.Health {
		case "healthy", "available", "ok":
			observed[node.ID] = "available"
		case "unhealthy", "unavailable", "problem":
			observed[node.ID] = "unavailable"
		default:
			observed[node.ID] = "unknown"
		}
	}
	for index := range projection.Devices {
		if state, ok := observed[projection.Devices[index].ID]; ok {
			projection.Devices[index].Availability = state
		}
	}
}

func readProtected(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !controlPrivateRegular(info) || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("protected input must be a non-empty owner-only regular file")
	}
	return os.ReadFile(path)
}

func decodeStrict(body []byte, target any) error {
	if _, err := canonicalBytes(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing content")
	}
	return nil
}

func decodeObject(body []byte) (map[string]json.RawMessage, error) {
	if _, err := canonicalBytes(body); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return nil, errors.New("JSON is not an object")
	}
	return object, nil
}

func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validTypedHash(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(raw) == sha256.Size
}

func frame(domain string, body []byte) []byte {
	result := make([]byte, 4+len(domain)+len(body))
	binary.BigEndian.PutUint32(result[:4], uint32(len(domain)))
	copy(result[4:], domain)
	copy(result[4+len(domain):], body)
	return result
}

func hashObject(domain string, value any) (string, error) {
	canonical, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(frame(domain, canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalEqual(left, right any) bool {
	a, errA := canonicalJSON(left)
	b, errB := canonicalJSON(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func canonicalJSON(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalBytes(body)
}

type member struct {
	key   string
	value any
}

func canonicalBytes(body []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	value, err := decodeCanonical(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON has trailing content")
	}
	var result bytes.Buffer
	appendCanonical(&result, value)
	return result.Bytes(), nil
}

func decodeCanonical(decoder *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]bool{}
			members := []member{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || seen[key] {
					return nil, errors.New("JSON object has an invalid or duplicate key")
				}
				seen[key] = true
				child, err := decodeCanonical(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				members = append(members, member{key, child})
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("JSON object is incomplete")
			}
			sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
			return members, nil
		case '[':
			items := []any{}
			for decoder.More() {
				child, err := decodeCanonical(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				items = append(items, child)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("JSON array is incomplete")
			}
			return items, nil
		}
	case json.Number:
		if strings.ContainsAny(value.String(), ".eE") {
			return nil, errors.New("authority JSON cannot contain floating point numbers")
		}
		integer := new(big.Int)
		if _, ok := integer.SetString(value.String(), 10); !ok || !integer.IsInt64() {
			return nil, errors.New("authority JSON integer is invalid")
		}
		return integer.Int64(), nil
	case string, bool, nil:
		return value, nil
	}
	return nil, errors.New("JSON value is invalid")
}

func appendCanonical(output *bytes.Buffer, value any) {
	switch value := value.(type) {
	case []member:
		output.WriteByte('{')
		for index, item := range value {
			if index > 0 {
				output.WriteByte(',')
			}
			key, _ := json.Marshal(item.key)
			output.Write(key)
			output.WriteByte(':')
			appendCanonical(output, item.value)
		}
		output.WriteByte('}')
	case []any:
		output.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				output.WriteByte(',')
			}
			appendCanonical(output, item)
		}
		output.WriteByte(']')
	case string:
		encoded, _ := json.Marshal(value)
		output.Write(encoded)
	case int64:
		output.WriteString(strconv.FormatInt(value, 10))
	case bool:
		output.WriteString(strconv.FormatBool(value))
	case nil:
		output.WriteString("null")
	}
}

func lessUTF16(left, right string) bool {
	a, b := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] != b[index] {
			return a[index] < b[index]
		}
	}
	return len(a) < len(b)
}
