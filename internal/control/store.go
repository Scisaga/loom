package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const NodeSchema = 3

type NodeConfig struct {
	Schema             int              `json:"schema"`
	ClusterID          string           `json:"cluster_id"`
	MemberID           string           `json:"member_id"`
	Node               string           `json:"node"`
	IdentityPrivateKey string           `json:"identity_private_key"`
	Bootstrap          bool             `json:"bootstrap"`
	Recovery           RecoveryEvidence `json:"recovery"`
	BrowserTLS         BrowserTLS       `json:"browser_tls"`
	PeerTLS            TLSIdentity      `json:"peer_tls"`
	ReadCertDER        []string         `json:"read_cert_der"`
	AdminCertDER       []string         `json:"admin_cert_der"`
}

type legacyNodeConfigV2 struct {
	Schema             int              `json:"schema"`
	ClusterID          string           `json:"cluster_id"`
	MemberID           string           `json:"member_id"`
	Node               string           `json:"node"`
	IdentityPrivateKey string           `json:"identity_private_key"`
	Bootstrap          bool             `json:"bootstrap"`
	Recovery           RecoveryEvidence `json:"recovery"`
	BrowserTLS         BrowserTLS       `json:"browser_tls"`
	ReadCertDER        []string         `json:"read_cert_der"`
	AdminCertDER       []string         `json:"admin_cert_der"`
}

func (config NodeConfig) Validate() error {
	key, err := base64.RawURLEncoding.DecodeString(config.IdentityPrivateKey)
	if config.Schema != NodeSchema || config.ClusterID == "" || config.MemberID == "" || config.Node == "" || err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("control node config is incomplete")
	}
	if !config.Recovery.V2Latch || config.BrowserTLS.CertificateChainPEM == "" || config.BrowserTLS.PrivateKeyPKCS8PEM == "" ||
		config.PeerTLS.CertificateChainPEM == "" || config.PeerTLS.PrivateKeyPKCS8PEM == "" ||
		len(config.ReadCertDER) == 0 || len(config.AdminCertDER) == 0 {
		return errors.New("control node recovery boundary is incomplete")
	}
	return nil
}

func (config NodeConfig) PrivateKey() ed25519.PrivateKey {
	key, _ := base64.RawURLEncoding.DecodeString(config.IdentityPrivateKey)
	return ed25519.PrivateKey(key)
}

func (config NodeConfig) Member() Member {
	public := config.PrivateKey().Public().(ed25519.PublicKey)
	return Member{ID: config.MemberID, Node: config.Node, PublicKey: base64.RawURLEncoding.EncodeToString(public)}
}

type Authority struct {
	root       string
	mu         sync.RWMutex
	consensus  ConsensusState
	projection Projection
	certified  CertifiedState
}

func OpenAuthority(root string) (*Authority, error) {
	authority := &Authority{root: root}
	if err := readStrict(filepath.Join(root, "consensus.json"), &authority.consensus); err != nil {
		return nil, err
	}
	if authority.consensus.Schema != 1 || len(authority.consensus.Entries) == 0 {
		return nil, errors.New("consensus store is empty")
	}
	projection, err := authority.rebuildLocked()
	if err != nil {
		return nil, err
	}
	authority.projection = projection
	if err := readStrict(filepath.Join(root, "certified.json"), &authority.certified); err != nil {
		return nil, err
	}
	if authority.certified.Schema != 1 {
		return nil, errors.New("certified store schema is invalid")
	}
	if err := VerifyHead(authority.certified.Head, authority.certified.Projection, authority.consensus.Entries); err != nil {
		return nil, err
	}
	certifiedProjection, err := authority.rebuildPrefixLocked(int(authority.certified.Head.Index))
	if err != nil {
		return nil, err
	}
	want, _ := projectionDigest(certifiedProjection)
	got, _ := projectionDigest(authority.certified.Projection)
	if want != got {
		return nil, fmt.Errorf("certified projection does not match rebuilt projection: rebuilt=%s certified=%s index=%d entries=%d", want, got, authority.certified.Head.Index, len(authority.consensus.Entries))
	}
	authority.projection.Web.UIState = authority.certified.Projection.Web.UIState
	return authority, nil
}

func jsonEqual(left, right []byte) bool { return string(left) == string(right) }

func (authority *Authority) materialPath(id string) (string, error) {
	if !strings.HasPrefix(id, "sha256:") || len(id) != 71 {
		return "", errors.New("material ID is invalid")
	}
	digest := strings.TrimPrefix(id, "sha256:")
	if _, err := hex.DecodeString(digest); err != nil {
		return "", errors.New("material ID is invalid")
	}
	return filepath.Join(authority.root, "materials", digest+".json"), nil
}

func (authority *Authority) PutMaterial(body []byte) (string, error) {
	material, err := DecodeMaterial(body)
	if err != nil {
		return "", err
	}
	canonicalBody, id, err := EncodeMaterial(material)
	if err != nil {
		return "", err
	}
	path, _ := authority.materialPath(id)
	if existing, err := os.ReadFile(path); err == nil {
		if !jsonEqual(existing, canonicalBody) {
			return "", errors.New("material ID collision")
		}
		return id, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := atomicWrite(path, canonicalBody); err != nil {
		return "", err
	}
	return id, nil
}

func (authority *Authority) Material(id string) ([]byte, error) {
	path, err := authority.materialPath(id)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, actual, err := EncodeMaterialFromBytes(body)
	if err != nil || actual != id {
		return nil, errors.New("material bytes do not match ID")
	}
	return body, nil
}

func EncodeMaterialFromBytes(body []byte) (Material, string, error) {
	material, err := DecodeMaterial(body)
	if err != nil {
		return material, "", err
	}
	_, id, err := EncodeMaterial(material)
	return material, id, err
}

func (authority *Authority) MaterialIDs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(authority.root, "materials"))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := "sha256:" + strings.TrimSuffix(entry.Name(), ".json")
		if _, err := authority.Material(id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func (authority *Authority) MaterialForRequest(requestID string) (string, Material, error) {
	consensus, _, _ := authority.Snapshot()
	for _, entry := range consensus.Entries {
		body, err := authority.Material(entry.MaterialID)
		if err != nil {
			return "", Material{}, err
		}
		material, err := DecodeMaterial(body)
		if err != nil {
			return "", Material{}, err
		}
		if material.RequestID == requestID {
			return entry.MaterialID, material, nil
		}
	}
	return "", Material{}, os.ErrNotExist
}

func (authority *Authority) Append(materialID string, term uint64) (Projection, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	body, err := authority.Material(materialID)
	if err != nil {
		return Projection{}, err
	}
	material, err := DecodeMaterial(body)
	if err != nil {
		return Projection{}, err
	}
	if contains(authority.projection.Applied, material.RequestID) {
		return authority.projection, nil
	}
	next, err := Reduce(authority.projection, material, materialID)
	if err != nil {
		return Projection{}, err
	}
	entry := ConsensusEntry{Index: uint64(len(authority.consensus.Entries) + 1), Term: term, MaterialID: materialID}
	previous := ""
	if len(authority.consensus.Entries) != 0 {
		previous = authority.consensus.Entries[len(authority.consensus.Entries)-1].PrefixDigest
	}
	seed, _ := canonical(struct {
		Index                uint64 `json:"index"`
		Term                 uint64 `json:"term"`
		MaterialID, Previous string
	}{entry.Index, entry.Term, entry.MaterialID, previous})
	sum := sha256.Sum256(seed)
	entry.PrefixDigest = "sha256:" + hex.EncodeToString(sum[:])
	authority.consensus.Entries = append(authority.consensus.Entries, entry)
	if err := atomicJSON(filepath.Join(authority.root, "consensus.json"), authority.consensus); err != nil {
		authority.consensus.Entries = authority.consensus.Entries[:len(authority.consensus.Entries)-1]
		return Projection{}, err
	}
	authority.projection = next
	return next, nil
}

func (authority *Authority) rebuildLocked() (Projection, error) {
	return authority.rebuildPrefixLocked(len(authority.consensus.Entries))
}

func (authority *Authority) rebuildPrefixLocked(count int) (Projection, error) {
	var projection Projection
	if count < 0 || count > len(authority.consensus.Entries) {
		return projection, errors.New("consensus prefix is invalid")
	}
	for index, entry := range authority.consensus.Entries[:count] {
		if entry.Index != uint64(index+1) {
			return Projection{}, errors.New("consensus indexes are not contiguous")
		}
		previous := ""
		if index > 0 {
			previous = authority.consensus.Entries[index-1].PrefixDigest
		}
		seed, _ := canonical(struct {
			Index                uint64 `json:"index"`
			Term                 uint64 `json:"term"`
			MaterialID, Previous string
		}{entry.Index, entry.Term, entry.MaterialID, previous})
		sum := sha256.Sum256(seed)
		if entry.PrefixDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			return Projection{}, errors.New("consensus prefix digest is invalid")
		}
		body, err := authority.Material(entry.MaterialID)
		if err != nil {
			return Projection{}, err
		}
		material, err := DecodeMaterial(body)
		if err != nil {
			return Projection{}, err
		}
		projection, err = Reduce(projection, material, entry.MaterialID)
		if err != nil {
			return Projection{}, err
		}
	}
	return projection, nil
}

func (authority *Authority) Snapshot() (ConsensusState, Projection, CertifiedState) {
	authority.mu.RLock()
	defer authority.mu.RUnlock()
	return authority.consensus, authority.projection, authority.certified
}

// HistoricalReportKeys reconstructs every certified DeviceView identity up to
// the current certified head. It lets members authenticate immutable report
// history after a device floor/view has advanced without making old reports
// current again.
func (authority *Authority) HistoricalReportAuthorities() (map[string]reportAuthority, error) {
	authority.mu.RLock()
	entries := append([]ConsensusEntry(nil), authority.consensus.Entries...)
	limit := int(authority.certified.Head.Index)
	certifiedProjection := authority.certified.Projection
	authority.mu.RUnlock()
	// Some package-level protocol tests use an in-memory certified projection
	// without a disk consensus log. A real opened authority can never take this
	// branch because OpenAuthority rejects an empty consensus store.
	if len(entries) == 0 && certifiedProjection.Schema == 1 {
		return currentReportAuthorities(certifiedProjection), nil
	}
	if limit < 1 || limit > len(entries) {
		return nil, errors.New("certified report history boundary is invalid")
	}
	identities := map[string]reportAuthority{}
	var projection Projection
	for _, entry := range entries[:limit] {
		body, err := authority.Material(entry.MaterialID)
		if err != nil {
			return nil, err
		}
		material, err := DecodeMaterial(body)
		if err != nil {
			return nil, err
		}
		projection, err = Reduce(projection, material, entry.MaterialID)
		if err != nil {
			return nil, err
		}
		for _, authorization := range projection.DeviceAuthorizations {
			view, found := projectDeviceView(projection, authorization.DeviceID)
			if !found {
				continue
			}
			digest, digestErr := DeviceViewDigest(view)
			if digestErr != nil {
				return nil, digestErr
			}
			key := authorization.DeviceID + "\x00" + digest
			identity := reportAuthority{PublicKey: authorization.DevicePublicKey, View: view}
			if previous, exists := identities[key]; exists && previous.PublicKey != identity.PublicKey {
				return nil, errors.New("historical device view digest has conflicting keys")
			}
			identities[key] = identity
		}
	}
	return identities, nil
}

func (authority *Authority) CandidateHead() (GovernanceHead, Projection, error) {
	authority.mu.RLock()
	defer authority.mu.RUnlock()
	logHash, err := logDigest(authority.consensus.Entries)
	if err != nil {
		return GovernanceHead{}, Projection{}, err
	}
	projectionHash, err := projectionDigest(authority.projection)
	if err != nil {
		return GovernanceHead{}, Projection{}, err
	}
	viewsHash, err := deviceViewsDigest(authority.projection)
	if err != nil {
		return GovernanceHead{}, Projection{}, err
	}
	head := GovernanceHead{Schema: HeadSchema, Index: uint64(len(authority.consensus.Entries)), LogDigest: logHash,
		ProjectionDigest: projectionHash, DeviceViewsDigest: viewsHash,
		ConfigMaterial: authority.projection.ConfigMaterial, Signatures: []HeadSignature{}}
	return head, authority.projection, nil
}

func (authority *Authority) InstallCertified(head GovernanceHead) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := VerifyHead(head, authority.projection, authority.consensus.Entries); err != nil {
		return err
	}
	if authority.certified.Head.Index > head.Index {
		return errors.New("certified head cannot move backwards")
	}
	projection := authority.projection
	projection.Web.UIState.Head = HeadID(head)
	projection.Web.UIState.Revision = int64(head.Index)
	projection.Web.UIState.Writable = true
	projection.Web.UIState.Warnings = []string{}
	state := CertifiedState{Schema: 1, Head: head, Projection: projection}
	if err := atomicJSON(filepath.Join(authority.root, "certified.json"), state); err != nil {
		return err
	}
	authority.projection = projection
	authority.certified = state
	return nil
}

func (authority *Authority) SignCandidate(config NodeConfig, head GovernanceHead) (HeadSignature, error) {
	_, projection, _ := authority.Snapshot()
	members := projection.Config.Members
	if projection.Config.Mode == "joint" {
		members = append(append([]Member{}, projection.Config.Old...), projection.Config.New...)
	}
	found := false
	for _, member := range members {
		if member.ID == config.MemberID && member.PublicKey == config.Member().PublicKey {
			found = true
		}
	}
	if !found {
		return HeadSignature{}, errors.New("local signer is not in the active control config")
	}
	candidate, _, err := authority.CandidateHead()
	if err != nil {
		return HeadSignature{}, err
	}
	left, _ := headSigningBytes(candidate)
	right, _ := headSigningBytes(head)
	if !jsonEqual(left, right) {
		return HeadSignature{}, errors.New("candidate head does not match local committed state")
	}
	return HeadSignature{MemberID: config.MemberID, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(config.PrivateKey(), right))}, nil
}

func ActivateLegacy(root string, legacy State, memberID, node string, listen []string) (NodeConfig, error) {
	if err := legacy.Validate(); err != nil {
		return NodeConfig{}, err
	}
	if _, err := os.Stat(filepath.Join(root, "node.json")); err == nil {
		return NodeConfig{}, errors.New("control authority is already activated")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return NodeConfig{}, err
	}
	config := NodeConfig{Schema: NodeSchema, ClusterID: legacy.ClusterID, MemberID: memberID, Node: node,
		IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(private), Bootstrap: true,
		Recovery: legacy.Recovery, BrowserTLS: legacy.BrowserTLS, ReadCertDER: legacy.ReadCertDER, AdminCertDER: legacy.AdminCertDER}
	config.PeerTLS, err = issuePeerTLS(config.BrowserTLS, memberID, listen, private)
	if err == nil {
		config.BrowserTLS, err = issueBrowserTLS(config.BrowserTLS, memberID, listen)
	}
	if err != nil {
		return NodeConfig{}, err
	}
	if err := config.Validate(); err != nil {
		return NodeConfig{}, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return NodeConfig{}, err
	}
	genesis := Material{Schema: MaterialSchema, Kind: "genesis", RequestID: "genesis:" + legacy.Head.Hash,
		Genesis: &Genesis{LegacyHead: legacy.Head.Hash, ControlConfig: StableConfig([]Member{config.Member()}), Projection: legacy.Projection}}
	body, id, err := EncodeMaterial(genesis)
	if err != nil {
		return NodeConfig{}, err
	}
	authority := &Authority{root: root, consensus: ConsensusState{Schema: 1, Entries: []ConsensusEntry{}}, projection: Projection{}}
	if _, err := authority.PutMaterial(body); err != nil {
		return NodeConfig{}, err
	}
	if err := atomicJSON(filepath.Join(root, "consensus.json"), authority.consensus); err != nil {
		return NodeConfig{}, err
	}
	if _, err := authority.Append(id, 1); err != nil {
		return NodeConfig{}, err
	}
	head, _, err := authority.CandidateHead()
	if err != nil {
		return NodeConfig{}, err
	}
	signature, err := authority.SignCandidate(config, head)
	if err != nil {
		return NodeConfig{}, err
	}
	head.Signatures = []HeadSignature{signature}
	if err := authority.InstallCertified(head); err != nil {
		return NodeConfig{}, err
	}
	if err := atomicJSON(filepath.Join(root, "node.json"), config); err != nil {
		return NodeConfig{}, err
	}
	return config, nil
}

func LoadNodeConfig(root string) (NodeConfig, error) {
	var config NodeConfig
	if err := readStrict(filepath.Join(root, "node.json"), &config); err != nil {
		return config, err
	}
	return config, config.Validate()
}

// MigrateBrowserTLS separates the browser-compatible P-256 server identity
// from the Ed25519 member identity used by Raft. It preserves the retained
// browser root, certified authority, member key, and exact read/admin leaves.
func MigrateBrowserTLS(root string, listen []string) (bool, error) {
	path := filepath.Join(root, "node.json")
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !controlPrivateRegular(info) {
		return false, errors.New("node.json must be an owner-only regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var header struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(body, &header); err != nil {
		return false, err
	}
	if header.Schema == NodeSchema {
		config, loadErr := LoadNodeConfig(root)
		if loadErr != nil {
			return false, loadErr
		}
		if _, configErr := browserTLSConfig(config); configErr != nil {
			return false, configErr
		}
		if _, configErr := peerTLSConfig(config); configErr != nil {
			return false, configErr
		}
		if err := verifyTLSListeners(config.BrowserTLS.CertificateChainPEM, listen); err != nil {
			return false, err
		}
		if err := verifyTLSListeners(config.PeerTLS.CertificateChainPEM, listen); err != nil {
			return false, err
		}
		return false, nil
	}
	if header.Schema != 2 {
		return false, errors.New("control node schema cannot be migrated")
	}
	var legacy legacyNodeConfigV2
	if err := readStrict(path, &legacy); err != nil {
		return false, err
	}
	key, err := base64.RawURLEncoding.DecodeString(legacy.IdentityPrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize || legacy.ClusterID == "" || legacy.MemberID == "" || legacy.Node == "" ||
		!legacy.Recovery.V2Latch || len(legacy.ReadCertDER) == 0 || len(legacy.AdminCertDER) == 0 {
		return false, errors.New("legacy control node is incomplete")
	}
	config := NodeConfig{Schema: NodeSchema, ClusterID: legacy.ClusterID, MemberID: legacy.MemberID, Node: legacy.Node,
		IdentityPrivateKey: legacy.IdentityPrivateKey, Bootstrap: legacy.Bootstrap, Recovery: legacy.Recovery,
		PeerTLS: TLSIdentity{CertificateChainPEM: legacy.BrowserTLS.CertificateChainPEM,
			PrivateKeyPKCS8PEM: legacy.BrowserTLS.PrivateKeyPKCS8PEM},
		ReadCertDER: append([]string(nil), legacy.ReadCertDER...), AdminCertDER: append([]string(nil), legacy.AdminCertDER...)}
	config.BrowserTLS, err = issueBrowserTLS(legacy.BrowserTLS, legacy.MemberID, listen)
	if err != nil {
		return false, err
	}
	if err := config.Validate(); err != nil {
		return false, err
	}
	if _, err := browserTLSConfig(config); err != nil {
		return false, err
	}
	if _, err := peerTLSConfig(config); err != nil {
		return false, err
	}
	if err := verifyTLSListeners(config.BrowserTLS.CertificateChainPEM, listen); err != nil {
		return false, err
	}
	if err := verifyTLSListeners(config.PeerTLS.CertificateChainPEM, listen); err != nil {
		return false, err
	}
	if err := atomicJSON(path, config); err != nil {
		return false, err
	}
	return true, nil
}

func verifyTLSListeners(chain string, listen []string) error {
	block, _ := pem.Decode([]byte(chain))
	if block == nil {
		return errors.New("control TLS leaf is missing")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	for _, address := range listen {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil || leaf.VerifyHostname(host) != nil {
			return errors.New("control TLS leaf does not cover a private listener")
		}
	}
	return nil
}

func readStrict(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !controlPrivateRegular(info) {
		return fmt.Errorf("%s must be an owner-only regular file", filepath.Base(path))
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s has trailing content", filepath.Base(path))
	}
	want, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	want = append(want, '\n')
	if !jsonEqual(body, want) {
		return fmt.Errorf("%s is not canonical", filepath.Base(path))
	}
	return nil
}

func atomicJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(body, '\n'))
}

func atomicWrite(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".write-*")
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
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := replaceControlFile(temporary, path); err != nil {
		return err
	}
	return syncControlDirectory(dir)
}
