package control

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

const invitationPrefix = "loom://enroll#"
const maximumInvitationReference = 1536

// InvitationEndpoint is a dialing projection, never a second endpoint authority.
type InvitationEndpoint struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	ServerName        string `json:"server_name"`
	SPKISHA256        string `json:"spki_sha256"`
	CertificateDigest string `json:"certificate_digest"`
}

func (value InvitationEndpoint) Validate() error {
	if !canonicalHost(value.Host) || !canonicalHost(value.ServerName) || value.Port < 1 || value.Port > 65535 || ValidateDigest(value.SPKISHA256) != nil || ValidateDigest(value.CertificateDigest) != nil {
		return errors.New("invalid invitation endpoint")
	}
	return nil
}
func invitationEndpoint(value EndpointGeneration) InvitationEndpoint {
	return InvitationEndpoint{value.Host, value.Port, value.ServerName, value.SPKISHA256, value.CertificateDigest}
}

// InvitationReference conveys only an existing transaction's bearer capability
// and its frozen TLS coordinates. Internal authorization stays with the issuer.
type InvitationReference struct {
	Schema        int                `json:"schema"`
	GenesisDigest string             `json:"genesis_digest"`
	TransactionID string             `json:"transaction_id"`
	Medium        string             `json:"medium"`
	Endpoint      InvitationEndpoint `json:"endpoint"`
	Capability    string             `json:"capability"`
}

func validInvitationCapability(value string) bool {
	body, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(body) == sha256.Size && base64.RawURLEncoding.EncodeToString(body) == value
}
func (value InvitationReference) Validate() error {
	if value.Schema != 3 || ValidateDigest(value.GenesisDigest) != nil || ValidateID(value.TransactionID) != nil || (value.Medium != "qr" && value.Medium != "ssh" && value.Medium != "sh") || !validInvitationCapability(value.Capability) || value.Endpoint.Validate() != nil {
		return errors.New("invalid invitation reference")
	}
	return nil
}
func invitationCapability(material Material) (string, error) {
	id, err := MaterialID(material)
	if err != nil {
		return "", err
	}
	signature, err := base64.RawURLEncoding.DecodeString(material.Signature)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	digest.Write([]byte("loom-invite-capability-v3\x00"))
	digest.Write(signature)
	digest.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil)), nil
}
func ReferenceForInvite(invite BootstrapInvite) (InvitationReference, error) {
	if err := invite.Validate(); err != nil {
		return InvitationReference{}, err
	}
	payload := invite.Material.Payload.(Invite)
	capability, err := invitationCapability(invite.Material)
	if err != nil {
		return InvitationReference{}, err
	}
	value := InvitationReference{3, invite.GenesisDigest, payload.ID, payload.Medium, invitationEndpoint(payload.Endpoint), capability}
	return value, value.Validate()
}

// MatchesInvite checks the private proof after binding without changing the
// original signature, endpoint, key or transaction.
func (value InvitationReference) MatchesInvite(invite BootstrapInvite) error {
	expected, err := ReferenceForInvite(invite)
	if err != nil || value.Validate() != nil || value.Schema != expected.Schema || value.GenesisDigest != expected.GenesisDigest || value.TransactionID != expected.TransactionID || value.Medium != expected.Medium || value.Endpoint != expected.Endpoint || subtle.ConstantTimeCompare([]byte(value.Capability), []byte(expected.Capability)) != 1 {
		return errors.New("enrollment proof differs from invitation reference")
	}
	return nil
}
func EncodeInvitationReference(value InvitationReference) (string, error) {
	body, err := CanonicalEncode(value)
	if err != nil {
		return "", err
	}
	if len(body) > maximumInvitationReference {
		return "", errors.New("invitation reference exceeds delivery limit")
	}
	return invitationPrefix + base64.RawURLEncoding.EncodeToString(body), nil
}
func EncodeInvite(invite BootstrapInvite) (string, error) {
	reference, err := ReferenceForInvite(invite)
	if err != nil {
		return "", err
	}
	return EncodeInvitationReference(reference)
}
func DecodeInvite(raw string) (InvitationReference, error) {
	if !strings.HasPrefix(raw, invitationPrefix) {
		return InvitationReference{}, errors.New("invalid invitation prefix")
	}
	encoded := strings.TrimPrefix(raw, invitationPrefix)
	if len(encoded) == 0 || len(encoded) > base64.RawURLEncoding.EncodedLen(maximumInvitationReference) {
		return InvitationReference{}, errors.New("invitation exceeds delivery limit")
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded {
		return InvitationReference{}, errors.New("invalid invitation encoding")
	}
	var value InvitationReference
	if err := DecodeCanonical(body, &value, ContractDecodeLimits{MaxBytes: maximumInvitationReference, MaxDepth: 8, MaxItems: 32}); err != nil {
		return InvitationReference{}, err
	}
	return value, nil
}

// EnrollmentStart is returned only inside the credential-authenticated TLS
// session. It contains the inputs for signing a claim, never policy or proof data.
type EnrollmentStart struct {
	Schema           int    `json:"schema"`
	NetworkID        string `json:"network_id"`
	GenesisDigest    string `json:"genesis_digest"`
	TransactionID    string `json:"transaction_id"`
	InviteMaterialID string `json:"invite_material_id"`
	Medium           string `json:"medium"`
}

func (value EnrollmentStart) Validate() error {
	if value.Schema != 3 || ValidateID(value.NetworkID) != nil || ValidateDigest(value.GenesisDigest) != nil || ValidateID(value.TransactionID) != nil || ValidateDigest(value.InviteMaterialID) != nil {
		return errors.New("invalid enrollment start")
	}
	if value.Medium != "qr" && value.Medium != "ssh" && value.Medium != "sh" {
		return errors.New("invalid enrollment medium")
	}
	return nil
}
