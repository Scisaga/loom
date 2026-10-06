package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
)

// WebsiteRequest is a public, member-authenticated signing handoff. It grants
// neither CA trust nor an endpoint, and contains no leaf private key.
type WebsiteRequest struct {
	Schema        int          `json:"schema"`
	NetworkID     string       `json:"network_id"`
	GenesisDigest string       `json:"genesis_digest"`
	ControlProof  ControlProof `json:"control_proof"`
	ControlID     string       `json:"control_id"`
	NodeID        string       `json:"node_id"`
	EndpointID    string       `json:"endpoint_id"`
	Generation    U64          `json:"generation"`
	CSRDER        string       `json:"csr_der"`
	Signature     string       `json:"signature"`
}

// WebsiteRequestExpectation is supplied independently by the offline operator,
// never populated from the untrusted handoff being checked.
type WebsiteRequestExpectation struct {
	NetworkID, GenesisDigest, ControlConfigID string
	ControlID, NodeID, EndpointID             string
	Generation                                U64
}

func (request WebsiteRequest) message() ([]byte, error) {
	body, err := CanonicalEncode(map[string]any{
		"schema": request.Schema, "network_id": request.NetworkID, "genesis_digest": request.GenesisDigest,
		"control_proof": request.ControlProof, "control_id": request.ControlID, "node_id": request.NodeID,
		"endpoint_id": request.EndpointID, "generation": request.Generation, "csr_der": request.CSRDER,
	})
	return append([]byte("loom-website-request-v3\x00"), body...), err
}

func (request WebsiteRequest) csr() (*x509.CertificateRequest, error) {
	der, err := base64.RawURLEncoding.DecodeString(request.CSRDER)
	if err != nil || len(der) > 32<<10 || base64.RawURLEncoding.EncodeToString(der) != request.CSRDER {
		return nil, errors.New("website CSR requires canonical bounded DER")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || !bytes.Equal(csr.Raw, der) || csr.CheckSignature() != nil {
		return nil, errors.New("website CSR signature is invalid")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "control.loom" ||
		len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 ||
		len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
		return nil, errors.New("website CSR requires P-256 and only the control.loom SAN")
	}
	return csr, nil
}

func (request WebsiteRequest) Validate() error {
	if request.Schema != 3 || ValidateID(request.NetworkID) != nil || ValidateDigest(request.GenesisDigest) != nil ||
		ValidateID(request.ControlID) != nil || ValidateID(request.NodeID) != nil || ValidateID(request.EndpointID) != nil || request.Generation == 0 {
		return errors.New("website signing handoff identity is invalid")
	}
	if _, err := request.csr(); err != nil {
		return err
	}
	config, err := VerifyControlProof(request.ControlProof, request.NetworkID, request.GenesisDigest)
	if err != nil {
		return err
	}
	member, found := proofMember(config, request.ControlID)
	if !found || member.NodeID != request.NodeID {
		return errors.New("website request is not bound to its control member")
	}
	public, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != request.Signature {
		return errors.New("website handoff signature is not canonical")
	}
	message, err := request.message()
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return errors.New("website handoff member signature is invalid")
	}
	return nil
}

func VerifyWebsiteRequest(request WebsiteRequest, expected WebsiteRequestExpectation) (*x509.CertificateRequest, error) {
	if ValidateID(expected.NetworkID) != nil || ValidateDigest(expected.GenesisDigest) != nil || ValidateDigest(expected.ControlConfigID) != nil ||
		ValidateID(expected.ControlID) != nil || ValidateID(expected.NodeID) != nil || ValidateID(expected.EndpointID) != nil || expected.Generation == 0 {
		return nil, errors.New("independent network anchor, current member configuration and intended endpoint are required")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if request.NetworkID != expected.NetworkID || request.GenesisDigest != expected.GenesisDigest || request.ControlID != expected.ControlID ||
		request.NodeID != expected.NodeID || request.EndpointID != expected.EndpointID || request.Generation != expected.Generation {
		return nil, errors.New("website request differs from the independently selected member or endpoint")
	}
	config, err := VerifyControlProof(request.ControlProof, expected.NetworkID, expected.GenesisDigest)
	if err != nil {
		return nil, err
	}
	id, err := ConfigID(config)
	if err != nil || id != expected.ControlConfigID {
		return nil, errors.New("website request does not use the selected current member configuration")
	}
	return request.csr()
}
