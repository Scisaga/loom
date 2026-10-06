package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func websiteRequestDirectory(root, id string, generation U64) string {
	body, _ := CanonicalEncode(map[string]any{"id": id, "generation": generation})
	return filepath.Join(root, "website-requests", endpointByteDigest(body)[7:])
}

func ownedWebsiteDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !adminEntryOwned(info) {
		return errors.New("website request directory must be owned, private and not a symbolic link")
	}
	return nil
}

func readWebsiteRequest(directory string, expected WebsiteRequestExpectation) (WebsiteRequest, error) {
	var request WebsiteRequest
	if err := ownedWebsiteDirectory(directory); err != nil {
		return request, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 || entries[0].Name() != "key.pem" || entries[1].Name() != "request.json" {
		return request, errors.New("website request directory is incomplete or contains unexpected files")
	}
	for _, name := range []string{"key.pem", "request.json"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !controlPrivateRegular(info) || info.Mode().Perm() != 0o600 || !adminEntryOwned(info) {
			return request, errors.New("website request material must be an owned private regular file")
		}
	}
	body, err := readProtectedControlFile(filepath.Join(directory, "request.json"))
	if err != nil {
		return request, err
	}
	if err := DecodeCanonical(body, &request, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return request, err
	}
	csr, err := VerifyWebsiteRequest(request, expected)
	if err != nil {
		return request, err
	}
	body, err = readProtectedControlFile(filepath.Join(directory, "key.pem"))
	if err != nil {
		return request, err
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return request, errors.New("website leaf key must be one PKCS8 PEM value")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := value.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() || !key.PublicKey.Equal(csr.PublicKey) {
		return request, errors.New("website leaf key does not match its original CSR")
	}
	return request, nil
}

func verifyLocalWebsiteRequest(root string, projection Projection, endpoint EndpointGeneration, inputs EndpointLocalInputs, now time.Time) error {
	node, err := LoadNodeConfig(root)
	if err != nil {
		return err
	}
	if _, err := activeLocalMember(node, projection.Config); err != nil {
		return err
	}
	directory := websiteRequestDirectory(root, endpoint.ID, endpoint.Generation)
	if inputs.KeyFile != filepath.Join(directory, "key.pem") || endpoint.OwnerControlID != node.ControlID {
		return errors.New("website endpoint must use its owning control's original CSR key")
	}
	expected := WebsiteRequestExpectation{node.NetworkID, node.GenesisID, projection.ControlConfigID,
		node.ControlID, node.NodeID, endpoint.ID, endpoint.Generation}
	request, err := readWebsiteRequest(directory, expected)
	if err != nil {
		return err
	}
	certificate, err := loadAuthorizedEndpointCertificate(projection, endpoint, inputs, now)
	if err != nil {
		return err
	}
	csr, err := VerifyWebsiteRequest(request, expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, certificate.Leaf.RawSubjectPublicKeyInfo) {
		return errors.New("website endpoint leaf does not match its original CSR")
	}
	return nil
}

// PrepareWebsiteRequest creates only a leaf key and a public signing request on
// the control. The authority lock freezes the member and endpoint checks while
// the complete directory is durably published. No authority fact is written.
func PrepareWebsiteRequest(root, endpointID string, generation U64) (WebsiteRequest, error) {
	var empty WebsiteRequest
	if ValidateID(endpointID) != nil || generation == 0 {
		return empty, errors.New("website request requires an endpoint and generation")
	}
	authority, err := OpenAuthority(root)
	if err != nil {
		return empty, err
	}
	if err := ownedWebsiteDirectory(root); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lock, err := lockAuthority(ctx, root)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	if err := authority.reloadLocked(); err != nil {
		return empty, err
	}
	node, err := LoadNodeConfig(root)
	if err != nil {
		return empty, err
	}
	if _, err := activeLocalMember(node, authority.projection.Config); err != nil {
		return empty, err
	}
	expected := WebsiteRequestExpectation{node.NetworkID, node.GenesisID, authority.projection.ControlConfigID,
		node.ControlID, node.NodeID, endpointID, generation}
	directory := websiteRequestDirectory(root, endpointID, generation)
	parent := filepath.Dir(directory)
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return empty, err
	}
	if err := ownedWebsiteDirectory(parent); err != nil {
		return empty, err
	}
	if _, err := os.Lstat(directory); err == nil {
		return readWebsiteRequest(directory, expected)
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	var last U64
	for _, endpoint := range authority.projection.EndpointGenerations {
		if endpoint.ID != endpointID {
			continue
		}
		if endpoint.OwnerControlID != node.ControlID {
			return empty, errors.New("website endpoint belongs to another control")
		}
		if endpoint.Generation > last {
			last = endpoint.Generation
		}
	}
	if last == ^U64(0) || generation != last+1 {
		return empty, errors.New("website request must target the first or immediately following endpoint generation")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return empty, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "control.loom"}, DNSNames: []string{"control.loom"},
	}, key)
	if err != nil {
		return empty, err
	}
	request := WebsiteRequest{Schema: 3, NetworkID: node.NetworkID, GenesisDigest: node.GenesisID,
		ControlProof: ControlProof{Genesis: authority.genesis, Successors: []ControlCertificate{}},
		ControlID:    node.ControlID, NodeID: node.NodeID, EndpointID: endpointID, Generation: generation,
		CSRDER: base64.RawURLEncoding.EncodeToString(csr)}
	message, err := request.message()
	if err != nil {
		return empty, err
	}
	signer, err := node.PrivateKey()
	if err != nil {
		return empty, err
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, message))
	if _, err := VerifyWebsiteRequest(request, expected); err != nil {
		return empty, err
	}
	body, err := CanonicalEncode(request)
	if err != nil {
		return empty, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return empty, err
	}
	temporary, err := os.MkdirTemp(parent, ".request-*")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(temporary)
	if err := putControlBytes(filepath.Join(temporary, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return empty, err
	}
	if err := putControlBytes(filepath.Join(temporary, "request.json"), body); err != nil {
		return empty, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, directory, unix.RENAME_NOREPLACE); err != nil {
		return empty, err
	}
	if err := syncControlDirectory(parent); err != nil {
		return empty, err
	}
	if err := syncControlDirectory(root); err != nil {
		return empty, err
	}
	return readWebsiteRequest(directory, expected)
}
