package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DomainControlPeerDirectory              = "loom-control-peer-directory-v1"
	DomainControlPeerDirectoryPrivateObject = "loom-control-peer-directory-private-object-v1"
	DomainControlPeerIdentitySPKI           = "loom-control-peer-identity-spki-v1"
	DomainControlPeerCertificate            = "loom-control-peer-certificate-der-v1"
	DomainControlKeyPoP                     = "loom-control-key-possession-proof-v1"
	DomainControlKeyPoPSignature            = "loom-control-key-possession-proof-signature-v1"
)

type ControlPeerEndpointV1 struct {
	EndpointID string `json:"endpoint_id"`
	URL        string `json:"url"`
}

type ControlPeerDirectoryMemberV1 struct {
	Schema                   int                     `json:"schema"`
	ClusterID                string                  `json:"cluster_id"`
	MemberID                 string                  `json:"member_id"`
	DeviceID                 string                  `json:"device_id"`
	PeerIdentitySPKIHash     string                  `json:"peer_identity_spki_hash"`
	PeerIdentityArtifactHash string                  `json:"peer_identity_artifact_hash"`
	PeerCertificateDER       string                  `json:"peer_certificate_der"`
	PeerCertificateHash      string                  `json:"peer_certificate_hash"`
	PeerEndpoints            []ControlPeerEndpointV1 `json:"peer_endpoints"`
	FaultDomain              string                  `json:"fault_domain"`
}

type ControlPeerDirectoryV1 struct {
	Schema              int                            `json:"schema"`
	ClusterID           string                         `json:"cluster_id"`
	DirectoryGeneration int64                          `json:"directory_generation"`
	HidingNonce         string                         `json:"hiding_nonce"`
	Members             []ControlPeerDirectoryMemberV1 `json:"members"`
}

type ControlPeerDirectoryPrivateObjectV1 struct {
	Schema                   int                    `json:"schema"`
	ClusterID                string                 `json:"cluster_id"`
	ControlSetHash           string                 `json:"control_set_hash"`
	ControlPeerDirectoryHash string                 `json:"control_peer_directory_hash"`
	Directory                ControlPeerDirectoryV1 `json:"directory"`
}

type ControlKeyPossessionProofBodyV1 struct {
	Schema         int    `json:"schema"`
	ClusterID      string `json:"cluster_id"`
	ControlSetHash string `json:"control_set_hash"`
	MemberID       string `json:"member_id"`
	KeyPurpose     string `json:"key_purpose"`
	KeyID          string `json:"key_id"`
	PublicKey      string `json:"public_key"`
}

type ControlKeyPossessionSignatureV1 struct {
	Algorithm  string `json:"algorithm"`
	MemberID   string `json:"member_id"`
	KeyPurpose string `json:"key_purpose"`
	KeyID      string `json:"key_id"`
	Signature  string `json:"signature"`
}

type ControlKeyPossessionProofV1 struct {
	Body      ControlKeyPossessionProofBodyV1 `json:"body"`
	Signature ControlKeyPossessionSignatureV1 `json:"signature"`
}

// ValidateControlPeerDirectory 验证不随本机时钟变化的目录事实。参与 Raft 握手前还必须调用
// ValidateControlPeerDirectoryAt，以 §7.5 提供的可信时间检查证书有效期（D124）。
func ValidateControlPeerDirectory(set *ControlSetV1, directory *ControlPeerDirectoryV1) error {
	return validateControlPeerDirectory(set, directory, nil)
}

// ValidateControlPeerDirectoryAt 在注入的可信时间检查完整 control-peer 身份 profile。
// 时间必须由 certified logical time/受信时间源提供，不能在纯验证器中读取本机时钟。
func ValidateControlPeerDirectoryAt(set *ControlSetV1, directory *ControlPeerDirectoryV1, trustedTime time.Time) error {
	if trustedTime.IsZero() {
		return errors.New("[D124 private directory] 可信时间不能为空")
	}
	instant := trustedTime.UTC()
	return validateControlPeerDirectory(set, directory, &instant)
}

func validateControlPeerDirectory(set *ControlSetV1, directory *ControlPeerDirectoryV1, trustedTime *time.Time) error {
	if err := ValidateControlSet(set); err != nil {
		return err
	}
	if directory == nil || directory.Schema != 1 || directory.ClusterID != set.ClusterID ||
		directory.DirectoryGeneration < 1 || len(directory.Members) != len(set.Members) {
		return errors.New("[D124 private directory] schema/cluster/generation/member count 无效")
	}
	if _, err := decodeRawURL(directory.HidingNonce, 32); err != nil {
		return errors.New("[D124 private directory] hiding nonce 无效")
	}
	devices := make(map[string]struct{}, len(directory.Members))
	spkis := make(map[string]struct{}, len(directory.Members))
	endpoints := make(map[string]struct{})
	endpointURLs := make(map[string]struct{})
	for i := range directory.Members {
		member := &directory.Members[i]
		if i > 0 && directory.Members[i-1].MemberID >= member.MemberID {
			return errors.New("[D124 private directory] members 必须按 member_id 严格排序")
		}
		if member.Schema != 1 || member.ClusterID != set.ClusterID || member.MemberID != set.Members[i].MemberID ||
			!validIdentifier(member.DeviceID, 128) || !validIdentifier(member.FaultDomain, 128) || len(member.PeerEndpoints) == 0 {
			return errors.New("[D124 private directory] member 与 ControlSet 不一一对应")
		}
		for _, hash := range []string{member.PeerIdentitySPKIHash, member.PeerIdentityArtifactHash, member.PeerCertificateHash} {
			if _, err := ParseHash(hash); err != nil {
				return err
			}
		}
		certificateDER, err := decodeCanonicalBase64URL(member.PeerCertificateDER)
		if err != nil {
			return errors.New("[D124 private directory] peer certificate DER 编码无效")
		}
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil || !bytes.Equal(certificate.Raw, certificateDER) {
			return errors.New("[D124 private directory] peer certificate 必须是单一 strict DER 证书")
		}
		publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok || len(publicKey) != ed25519.PublicKeySize ||
			!bytes.Equal(certificate.RawSubject, certificate.RawIssuer) ||
			certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil {
			return errors.New("[D124 private directory] peer certificate 必须由所携 Ed25519 key 自签")
		}
		if !certificate.BasicConstraintsValid || certificate.IsCA || certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
			!exactPeerExtKeyUsage(certificate.ExtKeyUsage) || len(certificate.UnknownExtKeyUsage) != 0 {
			return errors.New("[D124 private directory] peer certificate CA/KeyUsage/EKU profile 无效")
		}
		if trustedTime != nil && (trustedTime.Before(certificate.NotBefore) || trustedTime.After(certificate.NotAfter)) {
			return errors.New("[D124 private directory] peer certificate 在可信时间无效")
		}
		spkiHash, err := HashBytes(DomainControlPeerIdentitySPKI, certificate.RawSubjectPublicKeyInfo)
		if err != nil || spkiHash != member.PeerIdentitySPKIHash {
			return errors.New("[D124 private directory] peer SPKI hash 不匹配")
		}
		certificateHash, err := HashBytes(DomainControlPeerCertificate, certificateDER)
		if err != nil || certificateHash != member.PeerCertificateHash {
			return errors.New("[D124 private directory] peer certificate hash 不匹配")
		}
		if _, duplicate := devices[member.DeviceID]; duplicate {
			return errors.New("[D124 private directory] Device ID 重复")
		}
		if _, duplicate := spkis[member.PeerIdentitySPKIHash]; duplicate {
			return errors.New("[D124 private directory] peer SPKI 重复")
		}
		devices[member.DeviceID], spkis[member.PeerIdentitySPKIHash] = struct{}{}, struct{}{}
		for j, endpoint := range member.PeerEndpoints {
			if j > 0 && member.PeerEndpoints[j-1].EndpointID >= endpoint.EndpointID {
				return errors.New("[D124 private directory] peer endpoints 必须按 ID 严格排序")
			}
			parsed, err := url.ParseRequestURI(endpoint.URL)
			var port uint64
			var portErr error
			if err == nil && parsed != nil {
				port, portErr = strconv.ParseUint(parsed.Port(), 10, 16)
			}
			if err != nil || parsed == nil || parsed.String() != endpoint.URL || parsed.Scheme != "https" || parsed.User != nil ||
				parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" ||
				parsed.Hostname() == "" || portErr != nil || port == 0 {
				return errors.New("[D124 private directory] peer endpoint URL 必须是规范 private mTLS HTTPS origin")
			}
			host := parsed.Hostname()
			address, err := netip.ParseAddr(host)
			if err != nil || !address.IsPrivate() || address.String() != strings.Trim(host, "[]") {
				return errors.New("[D124 private directory] peer endpoint 必须使用 private overlay IP")
			}
			if _, duplicate := endpoints[endpoint.EndpointID]; duplicate {
				return errors.New("[D124 private directory] endpoint ID 在目录内重复")
			}
			if _, duplicate := endpointURLs[endpoint.URL]; duplicate {
				return errors.New("[D124 private directory] endpoint URL 在目录内重复")
			}
			endpoints[endpoint.EndpointID] = struct{}{}
			endpointURLs[endpoint.URL] = struct{}{}
		}
	}
	return nil
}

func exactPeerExtKeyUsage(usages []x509.ExtKeyUsage) bool {
	if len(usages) != 2 {
		return false
	}
	foundClient, foundServer := false, false
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageClientAuth:
			if foundClient {
				return false
			}
			foundClient = true
		case x509.ExtKeyUsageServerAuth:
			if foundServer {
				return false
			}
			foundServer = true
		default:
			return false
		}
	}
	return foundClient && foundServer
}

func ControlPeerDirectoryHash(set *ControlSetV1, directory *ControlPeerDirectoryV1) (string, error) {
	if err := ValidateControlPeerDirectory(set, directory); err != nil {
		return "", err
	}
	return HashObject(DomainControlPeerDirectory, directory)
}

// ValidateControlPeerDirectoryPrivateObject 把私有 preimage 与公开 set/directory hash
// 逐字节绑定；调用方负责在同一私有安装事务中提供 set（D124）。
func ValidateControlPeerDirectoryPrivateObject(set *ControlSetV1, object *ControlPeerDirectoryPrivateObjectV1) error {
	if object == nil || object.Schema != 1 || object.ClusterID != set.ClusterID || object.Directory.ClusterID != set.ClusterID {
		return errors.New("[D124 private directory] private object schema/cluster 无效")
	}
	setHash, err := ControlSetHash(set)
	if err != nil || setHash != object.ControlSetHash {
		return errors.New("[D124 private directory] private object ControlSet hash 不匹配")
	}
	directoryHash, err := ControlPeerDirectoryHash(set, &object.Directory)
	if err != nil || directoryHash != object.ControlPeerDirectoryHash {
		return errors.New("[D124 private directory] private object directory hash 不匹配")
	}
	return nil
}

func ControlPeerDirectoryPrivateObjectHash(set *ControlSetV1, object *ControlPeerDirectoryPrivateObjectV1) (string, error) {
	if err := ValidateControlPeerDirectoryPrivateObject(set, object); err != nil {
		return "", err
	}
	return HashObject(DomainControlPeerDirectoryPrivateObject, object)
}

// ControlPeerMemberForCertificate 把一次 TLS 握手的 exact leaf 解析为唯一 member。
// 系统 trust store、DNS 名和仅相同 subject 的证书都不会被接受（D124）。
func ControlPeerMemberForCertificate(set *ControlSetV1, directory *ControlPeerDirectoryV1, rawCertificate []byte, trustedTime time.Time) (string, error) {
	if err := ValidateControlPeerDirectoryAt(set, directory, trustedTime); err != nil {
		return "", err
	}
	certificate, err := x509.ParseCertificate(rawCertificate)
	if err != nil || !bytes.Equal(certificate.Raw, rawCertificate) {
		return "", errors.New("[D124 control mTLS] peer leaf DER 无效")
	}
	certificateHash, _ := HashBytes(DomainControlPeerCertificate, rawCertificate)
	spkiHash, _ := HashBytes(DomainControlPeerIdentitySPKI, certificate.RawSubjectPublicKeyInfo)
	memberID := ""
	for _, member := range directory.Members {
		if member.PeerCertificateHash != certificateHash || member.PeerIdentitySPKIHash != spkiHash {
			continue
		}
		if memberID != "" {
			return "", errors.New("[D124 control mTLS] peer certificate 映射不唯一")
		}
		memberID = member.MemberID
	}
	if memberID == "" {
		return "", errors.New("[D124 control mTLS] peer certificate 不在当前 private directory")
	}
	return memberID, nil
}

func VerifyControlKeyPossessionProofs(set *ControlSetV1, proofs []ControlKeyPossessionProofV1) error {
	if err := ValidateControlSet(set); err != nil {
		return err
	}
	if len(proofs) != len(set.Members)*3 {
		return errors.New("[D116 key PoP] 必须恰好覆盖每个 member 的三类 key")
	}
	setHash, _ := ControlSetHash(set)
	lookup := make(map[string]ControlMemberV1, len(set.Members))
	for _, member := range set.Members {
		lookup[member.MemberID] = member
	}
	for i, proof := range proofs {
		body, signature := proof.Body, proof.Signature
		if i > 0 {
			previous := proofs[i-1].Body
			if previous.MemberID > body.MemberID || previous.MemberID == body.MemberID && purposeOrder(previous.KeyPurpose) >= purposeOrder(body.KeyPurpose) {
				return errors.New("[D116 key PoP] proofs 必须按 member/purpose 严格排序")
			}
		}
		member, ok := lookup[body.MemberID]
		if !ok || body.Schema != 1 || body.ClusterID != set.ClusterID || body.ControlSetHash != setHash ||
			!oneOf(body.KeyPurpose, "membership", "config", "enrollment") || signature.Algorithm != "ed25519" ||
			signature.MemberID != body.MemberID || signature.KeyPurpose != body.KeyPurpose || signature.KeyID != body.KeyID {
			return errors.New("[D116 key PoP] proof body/signature binding 无效")
		}
		var keyID, publicKey string
		switch body.KeyPurpose {
		case "membership":
			keyID, publicKey = member.MembershipKeyID, member.MembershipPublicKey
		case "config":
			keyID, publicKey = member.ConfigKeyID, member.ConfigPublicKey
		case "enrollment":
			keyID, publicKey = member.EnrollmentKeyID, member.EnrollmentPublicKey
		}
		if body.KeyID != keyID || body.PublicKey != publicKey {
			return errors.New("[D116 key PoP] proof 与 ControlSet exact key 不匹配")
		}
		rawKey, _ := decodeRawURL(publicKey, ed25519.PublicKeySize)
		rawSignature, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
		canonical, canonicalErr := MarshalCanonical(body)
		message, frameErr := Frame(DomainControlKeyPoPSignature, canonical)
		if err != nil || canonicalErr != nil || frameErr != nil || !ed25519.Verify(rawKey, message, rawSignature) {
			return errors.New("[D116 key PoP] signature 无效")
		}
	}
	return nil
}

func NewControlKeyPossessionProof(body ControlKeyPossessionProofBodyV1, privateKey ed25519.PrivateKey) (ControlKeyPossessionProofV1, error) {
	public := privateKey.Public().(ed25519.PublicKey)
	keyID, err := ControlKeyID(public)
	if err != nil || keyID != body.KeyID || base64.RawURLEncoding.EncodeToString(public) != body.PublicKey {
		return ControlKeyPossessionProofV1{}, errors.New("[D116 key PoP] private key 与 proof body 不匹配")
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return ControlKeyPossessionProofV1{}, err
	}
	message, _ := Frame(DomainControlKeyPoPSignature, canonical)
	return ControlKeyPossessionProofV1{
		Body: body,
		Signature: ControlKeyPossessionSignatureV1{
			Algorithm: "ed25519", MemberID: body.MemberID, KeyPurpose: body.KeyPurpose, KeyID: body.KeyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
		},
	}, nil
}

func JointQuorum(oldSet, newSet *ControlSetV1, signerMemberIDs []string) error {
	if err := ValidateControlSet(oldSet); err != nil {
		return err
	}
	if err := ValidateControlSet(newSet); err != nil {
		return err
	}
	if oldSet.ClusterID != newSet.ClusterID {
		return errors.New("[D112 joint] old/new ControlSet cluster 不一致")
	}
	signers := append([]string(nil), signerMemberIDs...)
	sort.Strings(signers)
	for i := range signers {
		if i > 0 && signers[i-1] == signers[i] {
			return errors.New("[D112 joint] signer 重复")
		}
	}
	count := func(set *ControlSetV1) int {
		members := make(map[string]struct{}, len(set.Members))
		for _, member := range set.Members {
			members[member.MemberID] = struct{}{}
		}
		found := 0
		for _, signer := range signers {
			if _, ok := members[signer]; ok {
				found++
			}
		}
		return found
	}
	oldQuorum, _ := Quorum(len(oldSet.Members))
	newQuorum, _ := Quorum(len(newSet.Members))
	if count(oldSet) < oldQuorum || count(newSet) < newQuorum {
		return fmt.Errorf("[D112 joint] 未同时达到 old %d/%d 与 new %d/%d 多数", oldQuorum, len(oldSet.Members), newQuorum, len(newSet.Members))
	}
	return nil
}

func purposeOrder(value string) int {
	switch value {
	case "membership":
		return 0
	case "config":
		return 1
	case "enrollment":
		return 2
	default:
		return 99
	}
}
