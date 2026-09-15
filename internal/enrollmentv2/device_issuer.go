package enrollmentv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"loom/internal/wire"
)

// DeviceIssuanceContext 是 sequencer 冻结坐标时读取的公开权威材料。身份 SPKI
// 必须匹配已 admission/reservation 的 hash；不需要再次取得 raw token 或 CSR（D129、D130）。
type DeviceIssuanceContext struct {
	Reservation           DurableRecord
	Head                  wire.HeadEntryV2
	ConfigQC              json.RawMessage
	ControlSet            wire.ControlSetV1
	PreviousControlSet    *wire.ControlSetV1
	ReservationToHead     []wire.HeadEntryV2
	ControlSetTransitions []wire.ControlSetTransitionBundleV1
	CARegistry            CARegistryPreimageV1
	Profile               wire.DeviceCertificateProfileStateV1
	Coordinate            EnrollmentCommitCoordinateV1
	IdentitySPKIDER       []byte
}

// IssueReservedDeviceCertificate 只生成 provisional leaf。调用方必须通过
// DurableProvisionalService 先保存 first-result，再走 issuance/approval/completion QC；
// CA 签名本身不赋予 Device 身份或配置访问权（D102、D130）。
func IssueReservedDeviceCertificate(input DeviceIssuanceContext, issuerKey crypto.Signer, random io.Reader) ([]byte, error) {
	record := &input.Reservation
	if record.State.Status != "reserved" {
		return nil, errors.New("[D130 Device CA] 只允许已认证 reservation 签发首次制品")
	}
	if err := validateDurableRecord(record); err != nil {
		return nil, err
	}
	if err := wire.VerifyConfigQCAuthority(input.Head.HeadHash, input.ConfigQC, &input.Head,
		&input.ControlSet, input.PreviousControlSet); err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(record.ReservationCertification.Head, input.Head) {
		if err := VerifyEnrollmentHeadLineage(&record.ReservationCertification.Head, input.ReservationToHead,
			input.ControlSetTransitions, &input.Head, &input.ControlSet); err != nil {
			return nil, err
		}
	} else if len(input.ReservationToHead) != 0 || len(input.ControlSetTransitions) != 0 {
		return nil, errors.New("[D130 Device CA] 同 Head 不得夹带无关 lineage")
	}
	if err := validateCommitCoordinate(&input.Coordinate, record.State.ClusterID); err != nil {
		return nil, err
	}
	coordinate := input.Coordinate
	if coordinate.ParentHeadHash != input.Head.HeadHash || coordinate.RecoveryEpoch != input.Head.Body.Payload.RecoveryEpoch ||
		coordinate.RaftIndex <= input.Head.Body.Payload.RaftIndex || coordinate.CommittedLogicalTime < input.Head.Body.Payload.CommittedLogicalTime ||
		coordinate.CommittedLogicalTime >= record.ClaimOperation.RetryNotAfter {
		return nil, errors.New("[D130 Device CA] 签发坐标/base/retry deadline 不匹配")
	}
	profile := input.Profile
	if profile.Status != "active" || profile.ClusterID != input.Head.Body.Payload.ClusterID {
		return nil, errors.New("[D102 Device CA] issuer/profile 不是当前 active state")
	}
	if err := verifyCARegistryAtHead(&profile, &input.CARegistry, &input.Head); err != nil {
		return nil, err
	}
	intent := record.ClaimEvidence.Opening.DeviceEnrollmentIntent
	if err := wire.ValidateDeviceCertificateProfileRef(&intent.DeviceCertificateProfileRef, &profile); err != nil {
		return nil, err
	}
	identityHash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, input.IdentitySPKIDER)
	if err != nil || identityHash != record.State.IdentityKeyHash {
		return nil, errors.New("[D129 Device CA] identity key 不匹配已 admission 的 SPKI")
	}
	return issueDeviceCertificate(profile, intent.DeviceID, intent.Platform, intent.Responsibilities.Values,
		input.IdentitySPKIDER, identityHash, coordinate.CommittedLogicalTime,
		wire.IssuanceLogCoordinateV1{RecoveryEpoch: coordinate.RecoveryEpoch, RaftIndex: coordinate.RaftIndex}, issuerKey, random)
}

// issueDeviceCertificate 只负责 exact profile 的证书材料；调用方必须先验证
// reservation 或原设备迁移请求。证书本身不授予 Device view/config authority。
func issueDeviceCertificate(profile wire.DeviceCertificateProfileStateV1, deviceID, platform string,
	responsibilities []string, identitySPKIDER []byte, identityHash, issuedAtText string,
	issuance wire.IssuanceLogCoordinateV1, issuerKey crypto.Signer, random io.Reader) ([]byte, error) {
	if err := wire.ValidateDeviceCertificateProfileState(&profile); err != nil {
		return nil, err
	}
	if profile.Status != "active" {
		return nil, errors.New("[Device CA] 签发仅允许 active profile")
	}
	if _, err := wire.ParseTimeZ(issuedAtText); err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(identitySPKIDER)
	identity, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || identity.Curve != elliptic.P256() {
		return nil, errors.New("[D102 Device CA] identity 必须是 P-256")
	}
	canonicalSPKI, err := x509.MarshalPKIXPublicKey(identity)
	if err != nil || !bytes.Equal(canonicalSPKI, identitySPKIDER) {
		return nil, errors.New("[D102 Device CA] identity SPKI 不是 canonical DER")
	}
	issuerDER, err := base64.RawURLEncoding.DecodeString(profile.ProfileIntent.IssuerCertificateDER)
	if err != nil {
		return nil, err
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil || issuerKey == nil || issuer.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, errors.New("[D102 Device CA] issuer certificate/key 无效")
	}
	issuerSPKI, err := x509.MarshalPKIXPublicKey(issuerKey.Public())
	if err != nil || !bytes.Equal(issuerSPKI, issuer.RawSubjectPublicKeyInfo) {
		return nil, errors.New("[D102 Device CA] signer 不属于当前 profile issuer")
	}
	issuedAt, _ := wire.ParseTimeZ(issuedAtText)
	from, _ := wire.ParseTimeZ(profile.ProfileIntent.IssuanceNotBefore)
	until, _ := wire.ParseTimeZ(profile.ProfileIntent.IssuanceNotAfter)
	if issuedAt.Before(from) || !issuedAt.Before(until) {
		return nil, errors.New("[D102 Device CA] 签发超出 certified issuance window")
	}
	expiresAt := issuedAt.Add(time.Duration(profile.ProfileIntent.ValiditySeconds) * time.Second)
	for _, encoded := range profile.ProfileIntent.IssuerChainDER {
		der, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || issuedAt.Before(certificate.NotBefore) || !issuedAt.Before(certificate.NotAfter) {
			return nil, errors.New("[D102 Device CA] issuer chain 在签发时不可用")
		}
		if expiresAt.After(certificate.NotAfter) {
			expiresAt = certificate.NotAfter
		}
	}
	if random == nil {
		random = rand.Reader
	}
	serial, err := rand.Int(random, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	uri, err := url.Parse(profile.ProfileIntent.SANURIPrefix + url.PathEscape(deviceID))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{},
		NotBefore: issuedAt, NotAfter: expiresAt, BasicConstraintsValid: true,
		SignatureAlgorithm: x509.PureEd25519, URIs: []*url.URL{uri}}
	for _, usage := range profile.ProfileIntent.KeyUsageBits {
		switch usage {
		case "digital_signature":
			template.KeyUsage |= x509.KeyUsageDigitalSignature
		case "key_encipherment":
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		case "key_agreement":
			template.KeyUsage |= x509.KeyUsageKeyAgreement
		default:
			return nil, errors.New("[D102 Device CA] 未实现的 key usage")
		}
	}
	for _, value := range profile.ProfileIntent.RequiredEKUOIDs {
		switch value {
		case "1.3.6.1.5.5.7.3.2":
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case "1.3.6.1.5.5.7.3.1", "2.5.29.37.0":
			return nil, errors.New("[D102 Device CA] Device leaf 不得签发 server/Any EKU")
		default:
			oid, err := issuanceASN1OID(value)
			if err != nil {
				return nil, err
			}
			template.UnknownExtKeyUsage = append(template.UnknownExtKeyUsage, oid)
		}
	}
	for _, value := range profile.ProfileIntent.RequiredPolicyOIDs {
		oid, err := x509.ParseOID(value)
		if err != nil {
			return nil, err
		}
		template.Policies = append(template.Policies, oid)
	}
	der, err := x509.CreateCertificate(random, template, issuer, identity, issuerKey)
	if err != nil {
		return nil, err
	}
	if _, err := wire.VerifyDeviceCertificateAt(der, &profile, deviceID, identityHash, platform,
		responsibilities, issuance, issuedAt, issuedAt); err != nil {
		return nil, err
	}
	return der, nil
}

func issuanceASN1OID(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for index, part := range parts {
		component, err := strconv.Atoi(part)
		if err != nil || component < 0 {
			return nil, errors.New("[D102 Device CA] EKU OID 无效")
		}
		oid[index] = component
	}
	return oid, nil
}
