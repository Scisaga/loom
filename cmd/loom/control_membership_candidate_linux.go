//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/clientv2"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const (
	controlCandidateRequestName = "candidate-request.json"
	controlCandidateSecretsName = "candidate-secrets.json"
)

// controlCandidateRequestV1 是 admin 构造 membership intent 前取得的私有提案
// 输入。它只含公钥、已入网 Device/Head 绑定和 peer 密文证据；
// 三类 control key 只留在 candidate-secrets.json，peer key 只留在本机 sealed store。
type controlCandidateRequestV1 struct {
	Schema                 int                                   `json:"schema"`
	ClusterID              string                                `json:"cluster_id"`
	ObservedHeadHash       string                                `json:"observed_head_hash"`
	ObservedControlEpoch   int64                                 `json:"observed_control_epoch"`
	ObservedControlSetHash string                                `json:"observed_control_set_hash"`
	DeviceID               string                                `json:"device_id"`
	DeviceCertificateHash  string                                `json:"device_certificate_hash"`
	DeviceIdentitySPKIHash string                                `json:"device_identity_spki_hash"`
	DeviceWrappingKeyHash  string                                `json:"device_wrapping_key_hash"`
	DeviceViewHash         string                                `json:"device_view_hash"`
	Member                 wire.ControlMemberV1                  `json:"member"`
	Peer                   wire.ControlPeerDirectoryMemberV1     `json:"peer"`
	PeerIdentityEvidence   enrollmentv2.SealedMaterialEvidenceV1 `json:"peer_identity_evidence"`
	PreparedAt             string                                `json:"prepared_at"`
}

type controlCandidateSecretsV1 struct {
	Schema               int    `json:"schema"`
	ClusterID            string `json:"cluster_id"`
	MemberID             string `json:"member_id"`
	MembershipPrivateKey string `json:"membership_private_key"`
	ConfigPrivateKey     string `json:"config_private_key"`
	EnrollmentPrivateKey string `json:"enrollment_private_key"`
}

func cmdControlPrepareCandidate(args []string) error {
	fs := flag.NewFlagSet("control prepare-control-candidate", flag.ContinueOnError)
	deviceStateDir := fs.String("device-state-dir", "/var/lib/loom/client-v2", "已入网 Linux Device 的 v2 LKG 目录")
	out := fs.String("out", "", "新建的 root-only candidate 材料目录")
	memberID := fs.String("member-id", "", "新 control member ID（默认安全随机生成）")
	overlayIP := fs.String("overlay-ip", "", "candidate 的永久 Loom overlay IP")
	raftPort := fs.Int64("raft-port", 7445, "candidate 私有 peer/Raft TCP port")
	faultDomain := fs.String("fault-domain", "", "operator 定义的故障域")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" || *overlayIP == "" || *faultDomain == "" {
		return errors.New("control prepare-control-candidate 必须指定 -out、-overlay-ip、-fault-domain，且不接受位置参数")
	}
	for _, path := range []string{*deviceStateDir, *out} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("candidate 的 device-state-dir/out 必须是规范绝对路径")
		}
	}
	store, err := clientv2.Open(filepath.Join(*deviceStateDir, "state.json"))
	if err != nil {
		return err
	}
	envelope, installation := store.Envelope(), store.Installation()
	set, _ := store.ControlSets()
	if envelope == nil || envelope.Payload.Active == nil || installation == nil || set == nil ||
		envelope.Payload.DeviceID == "" || installation.DeviceCertificateHash == "" ||
		installation.WrappingKeyHash == "" {
		return errors.New("[control candidate] Device 尚未完成 active v2 Enrollment/LKG")
	}
	identity, err := clientv2.LoadEnrollmentIdentityForResume(filepath.Join(*deviceStateDir, "identity.json"))
	if err != nil {
		return err
	}
	if *memberID == "" {
		*memberID, err = newControlMemberID()
		if err != nil {
			return err
		}
	}
	if _, err := os.Lstat(*out); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("[control candidate] out 已存在，拒绝覆盖 candidate 私钥")
		}
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(*out)
		}
	}()
	artifactStore, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(*out, "sealed-artifacts"))
	if err != nil {
		return err
	}
	request, secrets, err := newControlCandidateMaterial(controlCandidateInput{
		ClusterID: set.ClusterID, ObservedHeadHash: envelope.SignedCurrent.Head.HeadHash,
		ObservedControlEpoch:   envelope.SignedCurrent.Head.Body.Payload.ControlEpoch,
		ObservedControlSetHash: envelope.SignedCurrent.Head.Body.Payload.ControlSetHash,
		DeviceID:               envelope.Payload.DeviceID, DeviceCertificateHash: installation.DeviceCertificateHash,
		DeviceIdentitySPKIHash: envelope.Payload.Active.IdentitySPKIHash,
		DeviceWrappingKeyHash:  installation.WrappingKeyHash,
		DeviceView:             envelope.Payload, MemberID: *memberID, OverlayIP: *overlayIP,
		RaftPort: *raftPort, FaultDomain: *faultDomain, Now: time.Now().UTC(),
		Identity: identity, ArtifactStore: artifactStore,
	})
	if err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(*out, controlCandidateRequestName), request, 0o600); err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(*out, controlCandidateSecretsName), secrets, 0o600); err != nil {
		return err
	}
	committed = true
	fmt.Printf("✓ control candidate 本机材料已生成\n  request: %s\n  secrets: %s\n",
		filepath.Join(*out, controlCandidateRequestName), filepath.Join(*out, controlCandidateSecretsName))
	return nil
}

type controlCandidateInput struct {
	ClusterID              string
	ObservedHeadHash       string
	ObservedControlEpoch   int64
	ObservedControlSetHash string
	DeviceID               string
	DeviceCertificateHash  string
	DeviceIdentitySPKIHash string
	DeviceWrappingKeyHash  string
	DeviceView             wire.DeviceViewPayloadV2
	MemberID               string
	OverlayIP              string
	RaftPort               int64
	FaultDomain            string
	Now                    time.Time
	Identity               *clientv2.EnrollmentIdentityV1
	ArtifactStore          *enrollmentv2.SealedArtifactStore
}

func newControlCandidateMaterial(input controlCandidateInput) (controlCandidateRequestV1,
	controlCandidateSecretsV1, error) {
	var request controlCandidateRequestV1
	var secrets controlCandidateSecretsV1
	address, err := netip.ParseAddr(input.OverlayIP)
	if err != nil || address.String() != input.OverlayIP || !address.IsPrivate() ||
		input.ClusterID == "" || input.DeviceID == "" || !wire.ValidMemberID(input.MemberID) ||
		input.RaftPort < 1 || input.RaftPort > 65535 || input.FaultDomain == "" || input.Now.IsZero() ||
		input.ObservedControlEpoch < 0 || input.DeviceView.ClusterID != input.ClusterID ||
		input.DeviceView.DeviceID != input.DeviceID || input.DeviceView.Active == nil ||
		input.DeviceView.Active.IdentitySPKIHash != input.DeviceIdentitySPKIHash ||
		input.Identity == nil || input.ArtifactStore == nil {
		return request, secrets, errors.New("[control candidate] identity/overlay/port/fault-domain 输入无效")
	}
	for _, hash := range []string{input.ObservedHeadHash, input.ObservedControlSetHash,
		input.DeviceCertificateHash, input.DeviceIdentitySPKIHash, input.DeviceWrappingKeyHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return request, secrets, err
		}
	}
	viewHash, err := wire.DeviceViewHash(&input.DeviceView)
	if err != nil {
		return request, secrets, err
	}
	publicKeys := make([]ed25519.PublicKey, 3)
	privateKeys := make([]ed25519.PrivateKey, 3)
	for index := range publicKeys {
		publicKeys[index], privateKeys[index], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return request, secrets, err
		}
	}
	defer func() {
		for _, private := range privateKeys {
			clear(private)
		}
	}()
	keyIDs := make([]string, len(publicKeys))
	for index := range publicKeys {
		keyIDs[index], _ = wire.ControlKeyID(publicKeys[index])
	}
	member := wire.ControlMemberV1{Schema: 1, ClusterID: input.ClusterID, MemberID: input.MemberID,
		MembershipKeyID: keyIDs[0], MembershipPublicKey: base64.RawURLEncoding.EncodeToString(publicKeys[0]),
		ConfigKeyID: keyIDs[1], ConfigPublicKey: base64.RawURLEncoding.EncodeToString(publicKeys[1]),
		EnrollmentKeyID: keyIDs[2], EnrollmentPublicKey: base64.RawURLEncoding.EncodeToString(publicKeys[2]),
		MinimumControlProtocol: 2}
	_, peerKeyPEM, peerDER, err := makeControlPeerCertificate(input.ClusterID,
		input.MemberID, input.OverlayIP, input.Now.UTC().Truncate(time.Second))
	if err != nil {
		return request, secrets, err
	}
	defer clear(peerKeyPEM)
	peerPrivate, err := parsePrivateKeyPKCS8PEM(peerKeyPEM)
	if err != nil {
		return request, secrets, err
	}
	defer clear(peerPrivate)
	peerPrivatePKCS8, err := x509.MarshalPKCS8PrivateKey(peerPrivate)
	if err != nil {
		return request, secrets, err
	}
	defer clear(peerPrivatePKCS8)
	preparedAt := input.Now.UTC().Truncate(time.Second)
	proposalID := "control-candidate-" + input.MemberID
	secretID := "control-peer-" + input.MemberID
	evidence, err := input.Identity.CreateControlPeerIdentityEvidence(input.ArtifactStore,
		input.ClusterID, input.DeviceID, proposalID, secretID, input.FaultDomain,
		peerPrivatePKCS8, peerPrivate, preparedAt)
	if err != nil {
		return request, secrets, err
	}
	peerArtifactHash, err := wire.SecretArtifactRefHash(&evidence.Ref)
	if err != nil {
		return request, secrets, err
	}
	peerCertificate, err := x509.ParseCertificate(peerDER)
	if err != nil {
		return request, secrets, err
	}
	peerSPKI, _ := wire.HashBytes(wire.DomainControlPeerIdentitySPKI,
		peerCertificate.RawSubjectPublicKeyInfo)
	peerCertHash, _ := wire.HashBytes(wire.DomainControlPeerCertificate, peerDER)
	peer := wire.ControlPeerDirectoryMemberV1{Schema: 1, ClusterID: input.ClusterID,
		MemberID: input.MemberID, DeviceID: input.DeviceID, PeerIdentitySPKIHash: peerSPKI,
		PeerIdentityArtifactHash: peerArtifactHash,
		PeerCertificateDER:       base64.RawURLEncoding.EncodeToString(peerDER),
		PeerCertificateHash:      peerCertHash,
		PeerEndpoints: []wire.ControlPeerEndpointV1{{EndpointID: "raft-" + input.MemberID,
			URL: "https://" + net.JoinHostPort(input.OverlayIP, fmt.Sprint(input.RaftPort))}},
		FaultDomain: input.FaultDomain}
	request = controlCandidateRequestV1{Schema: 1, ClusterID: input.ClusterID,
		ObservedHeadHash: input.ObservedHeadHash, ObservedControlEpoch: input.ObservedControlEpoch,
		ObservedControlSetHash: input.ObservedControlSetHash, DeviceID: input.DeviceID,
		DeviceCertificateHash: input.DeviceCertificateHash, DeviceIdentitySPKIHash: input.DeviceIdentitySPKIHash,
		DeviceWrappingKeyHash: input.DeviceWrappingKeyHash,
		DeviceViewHash:        viewHash, Member: member, Peer: peer, PeerIdentityEvidence: evidence,
		PreparedAt: preparedAt.Format(time.RFC3339)}
	secrets = controlCandidateSecretsV1{Schema: 1, ClusterID: input.ClusterID,
		MemberID:             input.MemberID,
		MembershipPrivateKey: base64.RawURLEncoding.EncodeToString(privateKeys[0]),
		ConfigPrivateKey:     base64.RawURLEncoding.EncodeToString(privateKeys[1]),
		EnrollmentPrivateKey: base64.RawURLEncoding.EncodeToString(privateKeys[2])}
	if err := validateControlCandidateMaterial(&request, &secrets, input.Now); err != nil {
		return controlCandidateRequestV1{}, controlCandidateSecretsV1{}, err
	}
	return request, secrets, nil
}

func validateControlCandidateMaterial(request *controlCandidateRequestV1,
	secrets *controlCandidateSecretsV1, now time.Time) error {
	if request == nil || secrets == nil || request.Schema != 1 || secrets.Schema != 1 ||
		request.ClusterID == "" || request.ClusterID != secrets.ClusterID ||
		request.Member.MemberID != secrets.MemberID || request.Member.MemberID != request.Peer.MemberID ||
		request.DeviceID != request.Peer.DeviceID || request.Member.ClusterID != request.ClusterID ||
		request.Peer.ClusterID != request.ClusterID || !wire.ValidMemberID(request.Member.MemberID) {
		return errors.New("[control candidate] request/secrets header 无效")
	}
	preparedAt, err := wire.ParseTimeZ(request.PreparedAt)
	if err != nil {
		return err
	}
	for _, hash := range []string{request.ObservedHeadHash, request.ObservedControlSetHash,
		request.DeviceCertificateHash, request.DeviceIdentitySPKIHash,
		request.DeviceWrappingKeyHash, request.DeviceViewHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	set := wire.ControlSetV1{Schema: 1, ClusterID: request.ClusterID,
		Members: []wire.ControlMemberV1{request.Member}}
	if err := wire.ValidateControlSet(&set); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	directory := wire.ControlPeerDirectoryV1{Schema: 1, ClusterID: request.ClusterID,
		DirectoryGeneration: 1, HidingNonce: nonce,
		Members: []wire.ControlPeerDirectoryMemberV1{request.Peer}}
	if err := wire.ValidateControlPeerDirectoryAt(&set, &directory, now); err != nil {
		return err
	}
	ref := &request.PeerIdentityEvidence.Ref
	artifactHash, err := wire.SecretArtifactRefHash(ref)
	if err != nil || artifactHash != request.Peer.PeerIdentityArtifactHash ||
		ref.ClusterID != request.ClusterID || ref.ProposalID != "control-candidate-"+request.Member.MemberID ||
		ref.SecretID != "control-peer-"+request.Member.MemberID || ref.Purpose != "control_peer_identity" ||
		ref.Generation != 1 || ref.Owner.Device == nil || ref.Owner.Device.DeviceID != request.DeviceID {
		return errors.New("[control candidate] peer identity artifact/ref/owner 不匹配")
	}
	if err := wire.VerifySecretArtifactEvidence(&request.PeerIdentityEvidence.Ref,
		request.PeerIdentityEvidence.Proof, &request.PeerIdentityEvidence.Policy,
		request.PeerIdentityEvidence.Receipts, now.UTC().Truncate(time.Second), 0, ""); err != nil {
		return err
	}
	if ref.PublicKey == nil {
		return errors.New("[control candidate] peer identity artifact 缺公钥")
	}
	if len(request.PeerIdentityEvidence.Policy.Reporters) != 1 ||
		len(request.PeerIdentityEvidence.Receipts) != 1 || ref.SealedBlob == nil ||
		len(ref.SealedBlob.RecipientKeyVersions) != 1 {
		return errors.New("[control candidate] peer artifact 必须只绑定本机 Device reporter/recipient")
	}
	reporter := &request.PeerIdentityEvidence.Policy.Reporters[0]
	recipient := &ref.SealedBlob.RecipientKeyVersions[0]
	if reporter.ReporterID != request.DeviceID || reporter.FaultDomain != request.Peer.FaultDomain ||
		recipient.RecipientID != request.DeviceID ||
		request.PeerIdentityEvidence.Receipts[0].Body.ObservedAt != preparedAt.Format(time.RFC3339) {
		return errors.New("[control candidate] peer artifact Device/fault-domain/time 绑定不匹配")
	}
	reporterSPKI, err := authorityKeySPKI(&reporter.ReporterKey)
	if err != nil {
		return err
	}
	reporterHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, reporterSPKI)
	recipientSPKI, err := authorityKeySPKI(&recipient.RecipientPublicKey)
	if err != nil {
		return err
	}
	recipientHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, recipientSPKI)
	if reporterHash != request.DeviceIdentitySPKIHash || recipientHash != request.DeviceWrappingKeyHash {
		return errors.New("[control candidate] artifact reporter/recipient 与 Device identity/wrapping key 不匹配")
	}
	artifactPublic, err := wire.ParseAuthorityProofKey(ref.PublicKey)
	if err != nil {
		return err
	}
	peerCertificateDER, err := base64.RawURLEncoding.DecodeString(request.Peer.PeerCertificateDER)
	if err != nil {
		return err
	}
	peerCertificate, err := x509.ParseCertificate(peerCertificateDER)
	artifactSPKI, marshalErr := x509.MarshalPKIXPublicKey(artifactPublic)
	if err != nil || marshalErr != nil || !bytes.Equal(peerCertificate.RawSubjectPublicKeyInfo, artifactSPKI) {
		return errors.New("[control candidate] peer certificate 与 artifact SPKI 不匹配")
	}
	encodedPrivate := []string{secrets.MembershipPrivateKey, secrets.ConfigPrivateKey,
		secrets.EnrollmentPrivateKey}
	encodedPublic := []string{request.Member.MembershipPublicKey, request.Member.ConfigPublicKey,
		request.Member.EnrollmentPublicKey}
	for index := range encodedPrivate {
		private, decodeErr := base64.RawURLEncoding.DecodeString(encodedPrivate[index])
		defer clear(private)
		public, publicErr := base64.RawURLEncoding.DecodeString(encodedPublic[index])
		if decodeErr != nil || publicErr != nil || len(private) != ed25519.PrivateKeySize ||
			len(public) != ed25519.PublicKeySize ||
			!bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
			return errors.New("[control candidate] control private key 与 member 不匹配")
		}
	}
	// 明确要求三个 purpose 的 key bytes 全部不同；ControlSet validator 同时校验 key ID。
	values := append([]string(nil), encodedPublic...)
	sort.Strings(values)
	if values[0] == values[1] || values[1] == values[2] {
		return errors.New("[control candidate] control key purpose 发生复用")
	}
	return nil
}

func authorityKeySPKI(key *wire.AuthorityProofKeyV1) ([]byte, error) {
	public, err := wire.ParseAuthorityProofKey(key)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(public)
}
