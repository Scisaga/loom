package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const NodeSchema = 3

type TLSFiles struct {
	CertificateFile string `json:"certificate_file"`
	KeyFile         string `json:"key_file"`
	TrustFile       string `json:"trust_file"`
}

func (files TLSFiles) Validate() error {
	for _, path := range []string{files.CertificateFile, files.KeyFile, files.TrustFile} {
		if !absoluteControlPath(path) {
			return errors.New("TLS inputs require canonical absolute file references")
		}
	}
	return nil
}

// NodeConfig contains local execution references and the protected genesis
// anchor, never a second projection, old recovery floor, or CA private key.
type NodeConfig struct {
	Schema         int       `json:"schema"`
	NetworkID      string    `json:"network_id"`
	ControlID      string    `json:"control_id"`
	NodeID         string    `json:"node_id"`
	GenesisID      string    `json:"genesis_id"`
	SigningKeyFile string    `json:"signing_key_file"`
	BrowserTLS     *TLSFiles `json:"browser_tls,omitempty"`
	PeerTLS        *TLSFiles `json:"peer_tls,omitempty"`
}

func absoluteControlPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}
func (config NodeConfig) Validate() error {
	if config.Schema != NodeSchema || ValidateID(config.NetworkID) != nil || ValidateID(config.ControlID) != nil || ValidateID(config.NodeID) != nil || config.NodeID == "direct" || ValidateDigest(config.GenesisID) != nil || !absoluteControlPath(config.SigningKeyFile) {
		return errors.New("control node identity or anchor is invalid")
	}
	for _, files := range []*TLSFiles{config.BrowserTLS, config.PeerTLS} {
		if files != nil {
			if err := files.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (config NodeConfig) PrivateKey() (ed25519.PrivateKey, error) {
	body, err := readProtectedControlFile(config.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load control signing key: %w", err)
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("control signing key must be one PKCS8 PEM value")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("control signing key is not valid PKCS8")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("control signing key must be Ed25519")
	}
	return key, nil
}
func (config NodeConfig) PublicKey() (ed25519.PublicKey, error) {
	key, err := config.PrivateKey()
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}
func (config NodeConfig) Member() (Member, error) {
	key, err := config.PublicKey()
	if err != nil {
		return Member{}, err
	}
	return Member{ControlID: config.ControlID, NodeID: config.NodeID, PublicKey: base64.RawURLEncoding.EncodeToString(key)}, nil
}
func LoadNodeConfig(root string) (NodeConfig, error) {
	var config NodeConfig
	body, err := readProtectedControlFile(filepath.Join(root, "node.json"))
	if err != nil {
		return config, err
	}
	err = DecodeCanonical(body, &config, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 128})
	return config, err
}

type Submission struct {
	MaterialID string
	Projection Projection
}
type Authority struct {
	root       string
	mu         sync.RWMutex
	genesis    Material
	materials  []Material
	projection Projection
}

func OpenAuthority(root string) (*Authority, error) {
	if err := validateControlRoot(root); err != nil {
		return nil, err
	}
	lock, err := lockAuthority(context.Background(), root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	a := &Authority{root: root}
	if err := a.reloadLocked(); err != nil {
		return nil, err
	}
	return a, nil
}

// Initialization is explicit and never overwrites a partial or historical store.
func InitializeAuthority(root string, config NodeConfig, genesis Material) (*Authority, error) {
	if !absoluteControlPath(root) || config.Validate() != nil {
		return nil, errors.New("explicit initialization requires an absolute root and valid identity")
	}
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := validateControlRoot(root); err != nil {
		return nil, err
	}
	lock, err := lockAuthority(context.Background(), root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() != ".authority.lock" {
			return nil, errors.New("control initialization requires an empty authority directory")
		}
	}
	body, id, err := EncodeMaterial(genesis)
	if err != nil || genesis.Operation != "genesis" || id != config.GenesisID || genesis.NetworkID != config.NetworkID {
		return nil, errors.New("genesis does not match the protected network anchor")
	}
	projection, err := Project(genesis, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := activeLocalMember(config, projection.Config); err != nil {
		return nil, err
	}
	a := &Authority{root: root}
	path, _ := a.materialPath(id)
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := putControlBytes(path, body); err != nil {
		return nil, err
	}
	if err := initializeObservationDB(filepath.Join(root, "observations.db")); err != nil {
		return nil, err
	}
	encoded, err := CanonicalEncode(config)
	if err != nil {
		return nil, err
	}
	if err := putControlBytes(filepath.Join(root, "node.json"), encoded); err != nil {
		return nil, err
	}
	if err := syncControlDirectory(root); err != nil {
		return nil, err
	}
	if err := syncControlDirectory(filepath.Dir(root)); err != nil {
		return nil, err
	}
	if err := a.reloadLocked(); err != nil {
		return nil, err
	}
	return a, nil
}
func validateControlRoot(root string) error {
	if !absoluteControlPath(root) {
		return errors.New("control root must be a canonical absolute path")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("control root must be an owner-only directory")
	}
	return nil
}
func lockAuthority(ctx context.Context, root string) (*os.File, error) {
	return lockProtectedControlPath(ctx, filepath.Join(root, ".authority.lock"))
}
func lockProtectedControlPath(ctx context.Context, path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	info, a := file.Stat()
	entry, b := os.Lstat(path)
	if a != nil || b != nil || !controlPrivateRegular(info) || !os.SameFile(info, entry) || entry.Mode()&os.ModeSymlink != 0 {
		file.Close()
		return nil, errors.New("control lock is not a protected regular file")
	}
	if err := lockControlFile(ctx, file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func (a *Authority) reloadLocked() error {
	entries, err := os.ReadDir(a.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "consensus.json", "certified.json", "consensus-raft.db", "state.json", "recovery.json", "floor.json", "latch.json":
			return errors.New("legacy authority and recovery evidence cannot enter the current decoder")
		}
	}
	config, err := LoadNodeConfig(a.root)
	if err != nil {
		return err
	}
	path, err := a.materialPath(config.GenesisID)
	if err != nil {
		return err
	}
	body, err := readProtectedControlFile(path)
	if err != nil {
		return fmt.Errorf("read fixed genesis: %w", err)
	}
	genesis, id, err := EncodeMaterialFromBytes(body)
	if err != nil || id != config.GenesisID || genesis.Operation != "genesis" || genesis.NetworkID != config.NetworkID {
		return errors.New("genesis anchor does not match original signed bytes")
	}
	materials, err := a.readMaterialsLocked(config.GenesisID)
	if err != nil {
		return err
	}
	projection, err := Project(genesis, nil, materials)
	if err != nil {
		return err
	}
	if err := syncControlDirectory(filepath.Join(a.root, "materials")); err != nil {
		return err
	}
	a.genesis, a.materials, a.projection = genesis, materials, projection
	return nil
}
func (a *Authority) materialPath(id string) (string, error) {
	if ValidateDigest(id) != nil {
		return "", errors.New("material ID is invalid")
	}
	return filepath.Join(a.root, "materials", strings.TrimPrefix(id, "sha256:")+".json"), nil
}
func (a *Authority) readMaterialsLocked(genesisID string) ([]Material, error) {
	directory := filepath.Join(a.root, "materials")
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("material directory is missing or not protected")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := []Material{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("unexpected object in material directory")
		}
		id := "sha256:" + strings.TrimSuffix(entry.Name(), ".json")
		path, err := a.materialPath(id)
		if err != nil {
			return nil, err
		}
		body, err := readProtectedControlFile(path)
		if err != nil {
			return nil, err
		}
		material, actual, err := EncodeMaterialFromBytes(body)
		if err != nil || actual != id {
			return nil, errors.New("material filename does not match its signed bytes")
		}
		if id == genesisID {
			continue
		}
		if material.Operation == "genesis" {
			return nil, errors.New("another genesis cannot enter the fixed network")
		}
		result = append(result, material)
	}
	return result, nil
}

func (a *Authority) Material(id string) ([]byte, error) {
	path, err := a.materialPath(id)
	if err != nil {
		return nil, err
	}
	body, err := readProtectedControlFile(path)
	if err != nil {
		return nil, err
	}
	_, actual, err := EncodeMaterialFromBytes(body)
	if err != nil || actual != id {
		return nil, errors.New("material bytes do not match ID")
	}
	return body, nil
}
func (a *Authority) Snapshot() Projection {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return cloneAuthorityProjection(a.projection)
}
func cloneAuthorityProjection(p Projection) Projection {
	body, err := json.Marshal(p)
	var copy Projection
	if err == nil {
		err = json.Unmarshal(body, &copy)
	}
	if err != nil {
		return Projection{}
	}
	return copy
}
func (a *Authority) Genesis() (Material, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	body, _, err := EncodeMaterial(a.genesis)
	if err != nil {
		return Material{}, err
	}
	return DecodeMaterial(body)
}
func (a *Authority) Frontier() []FactFrontier { p := a.Snapshot(); return p.Frontier }
func (a *Authority) MaterialsAfter(keyID string, after U64) ([][]byte, error) {
	if ValidateDigest(keyID) != nil {
		return nil, errors.New("invalid signing key ID")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	values := []Material{}
	limit := frontierFor(a.projection.Frontier, keyID).Sequence
	for _, m := range a.materials {
		if m.IssuerKeyID == keyID && m.Sequence > after && m.Sequence <= limit {
			values = append(values, m)
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Sequence != values[j].Sequence {
			return values[i].Sequence < values[j].Sequence
		}
		a, _ := MaterialID(values[i])
		b, _ := MaterialID(values[j])
		return a < b
	})
	result := [][]byte{}
	for _, m := range values {
		body, _, err := EncodeMaterial(m)
		if err != nil {
			return nil, err
		}
		result = append(result, body)
	}
	return result, nil
}
func (a *Authority) materialAtSequence(keyID string, sequence U64) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	id := ""
	for _, material := range a.materials {
		if material.IssuerKeyID != keyID || material.Sequence != sequence {
			continue
		}
		if id != "" {
			return "", ErrMaterialEquivocation
		}
		id, _ = MaterialID(material)
	}
	if id == "" {
		return "", os.ErrNotExist
	}
	return id, nil
}
func (a *Authority) PendingDependencies() ([]string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	known := map[string]bool{}
	id, err := MaterialID(a.genesis)
	if err != nil {
		return nil, err
	}
	known[id] = true
	for _, m := range a.materials {
		id, err := MaterialID(m)
		if err != nil {
			return nil, err
		}
		known[id] = true
	}
	missing := map[string]bool{}
	for _, m := range a.materials {
		refs := append([]string{}, m.Dependencies...)
		if m.Sequence > 1 {
			refs = append(refs, m.PreviousMaterialID)
		}
		for _, id := range refs {
			if !known[id] {
				missing[id] = true
			}
		}
	}
	result := []string{}
	for id := range missing {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}
func (a *Authority) PutMaterial(body []byte) (string, error) {
	material, id, err := EncodeMaterialFromBytes(body)
	if err != nil {
		return "", err
	}
	lock, err := lockAuthority(context.Background(), a.root)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.reloadLocked(); err != nil {
		return "", err
	}
	path, _ := a.materialPath(id)
	if existing, err := readProtectedControlFile(path); err == nil {
		if !bytes.Equal(existing, body) {
			return "", errors.New("material ID collision")
		}
		if err := syncControlDirectory(filepath.Dir(path)); err != nil {
			return "", err
		}
		if err := ValidateAdmission(material, a.genesis, nil, a.materials); errors.Is(err, ErrMaterialEquivocation) {
			return id, err
		}
		return id, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if material.Operation == "genesis" {
		return "", errors.New("another genesis cannot replace the fixed network")
	}
	admissionErr := ValidateAdmission(material, a.genesis, nil, a.materials)
	if admissionErr != nil && !errors.Is(admissionErr, ErrMissingDependencies) && !errors.Is(admissionErr, ErrMaterialEquivocation) {
		return "", admissionErr
	}
	next := append(append([]Material{}, a.materials...), material)
	projection, err := Project(a.genesis, nil, next)
	if err != nil {
		return "", err
	}
	if err := putControlBytes(path, body); err != nil {
		return "", err
	}
	a.materials, a.projection = next, projection
	if errors.Is(admissionErr, ErrMaterialEquivocation) {
		return id, admissionErr
	}
	return id, nil
}
func activeLocalMember(config NodeConfig, membership ControlConfig) (Member, error) {
	local, err := config.Member()
	if err != nil {
		return Member{}, err
	}
	for _, member := range membership.Members {
		if member.ControlID == local.ControlID && member.NodeID == local.NodeID && member.PublicKey == local.PublicKey {
			return member, nil
		}
	}
	return Member{}, errors.New("local signing identity is not an active control member")
}
func emptyAuthorityChainID() string {
	value := sha256.Sum256([]byte("loom-empty-material-chain-v3\x00"))
	return "sha256:" + hex.EncodeToString(value[:])
}
func (a *Authority) Submit(ctx context.Context, op Operation, local NodeConfig) (Submission, error) {
	if _, err := EncodeOperation(op); err != nil {
		return Submission{}, err
	}
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return Submission{}, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.reloadLocked(); err != nil {
		return Submission{}, err
	}
	return a.submitOperationLocked(ctx, op, local)
}

// The caller owns both the operating-system writer lock and a.mu. Enrollment
// uses this same signer for its two individually durable facts.
func (a *Authority) submitOperationLocked(ctx context.Context, op Operation, local NodeConfig) (Submission, error) {
	requested, err := EncodeOperation(op)
	if err != nil {
		return Submission{}, err
	}
	config, err := LoadNodeConfig(a.root)
	if err != nil {
		return Submission{}, err
	}
	if config.NetworkID != local.NetworkID || config.GenesisID != local.GenesisID || config.ControlID != local.ControlID || config.NodeID != local.NodeID || config.SigningKeyFile != local.SigningKeyFile {
		return Submission{}, errors.New("local signing identity changed; reopen the control runtime")
	}
	member, err := activeLocalMember(config, a.projection.Config)
	if err != nil {
		return Submission{}, err
	}
	keyID, err := KeyID(member.PublicKey)
	if err != nil {
		return Submission{}, err
	}
	for _, m := range a.materials {
		if m.IssuerKeyID != keyID || m.RequestID != op.RequestID {
			continue
		}
		prior, err := m.OperationRequest()
		if err != nil {
			return Submission{}, err
		}
		previous, err := EncodeOperation(prior)
		if err != nil || !bytes.Equal(previous, requested) {
			return Submission{}, errors.New("request ID is already bound to another operation")
		}
		id, _ := MaterialID(m)
		return Submission{MaterialID: id, Projection: cloneAuthorityProjection(a.projection)}, nil
	}
	for _, target := range a.projection.Targets {
		if target.TargetKind != op.TargetKind || target.TargetID != op.TargetID {
			continue
		}
		for _, id := range target.MaterialIDs {
			index := sort.SearchStrings(op.Dependencies, id)
			if index == len(op.Dependencies) || op.Dependencies[index] != id {
				return Submission{}, errors.New("target dependencies are stale")
			}
		}
	}
	sequence, previous := U64(0), emptyAuthorityChainID()
	for _, frontier := range a.projection.Frontier {
		if frontier.KeyID == keyID {
			sequence, previous = frontier.Sequence, frontier.TipMaterialID
		}
	}
	for _, m := range a.materials {
		if m.IssuerKeyID == keyID && m.Sequence > sequence {
			return Submission{}, errors.New("local signing history is unresolved; signing is stopped")
		}
	}
	if sequence == ^U64(0) {
		return Submission{}, errors.New("signing sequence is exhausted")
	}
	if err := ctx.Err(); err != nil {
		return Submission{}, err
	}
	payload := op.Payload
	if op.Operation == "device.put" {
		public := op.Payload.(DevicePut)
		var original *DeviceAuthorization
		excluded := map[string]bool{}
		for _, id := range a.projection.PendingMaterialIDs {
			excluded[id] = true
		}
		for _, rejected := range a.projection.InvalidMaterials {
			excluded[rejected.MaterialID] = true
		}
		for _, fact := range a.materials {
			if fact.Operation != "device.join" || fact.TargetID != op.TargetID {
				continue
			}
			id, _ := MaterialID(fact)
			if excluded[id] {
				continue
			}
			value := fact.Payload.(DeviceAuthorization)
			if original != nil {
				return Submission{}, errors.New("device has no unique original identity binding")
			}
			original = &value
		}
		if original == nil {
			return Submission{}, errors.New("device update has no verified original binding")
		}
		original.Name, original.Responsibilities, original.PolicyIDs, original.DistributionURLs = public.Name,
			append([]string{}, public.Responsibilities...), append([]string{}, public.PolicyIDs...), append([]string{}, public.DistributionURLs...)
		original.DNSServers = append([]string(nil), public.DNSServers...)
		payload = *original
	}
	material := Material{Schema: MaterialSchema, NetworkID: config.NetworkID, IssuerControlID: config.ControlID, IssuerKeyID: keyID, ControlConfigID: a.projection.ControlConfigID, Sequence: sequence + 1, PreviousMaterialID: previous, Dependencies: append([]string{}, op.Dependencies...), RequestID: op.RequestID, TargetKind: op.TargetKind, TargetID: op.TargetID, Operation: op.Operation, Payload: payload}
	private, err := config.PrivateKey()
	if err != nil {
		return Submission{}, err
	}
	material, err = SignMaterial(material, private)
	if err != nil {
		return Submission{}, err
	}
	if err := ValidateAdmission(material, a.genesis, nil, a.materials); err != nil {
		return Submission{}, err
	}
	next := append(append([]Material{}, a.materials...), material)
	projection, err := Project(a.genesis, nil, next)
	if err != nil {
		return Submission{}, err
	}
	body, id, err := EncodeMaterial(material)
	if err != nil {
		return Submission{}, err
	}
	path, _ := a.materialPath(id)
	if err := putControlBytes(path, body); err != nil {
		return Submission{}, err
	}
	a.materials, a.projection = next, projection
	return Submission{MaterialID: id, Projection: cloneAuthorityProjection(projection)}, nil
}

const maxControlInputBytes = 64 << 20

func readProtectedControlFile(path string) ([]byte, error) {
	return readProtectedControlFileMatching(path, nil)
}

// A byte hint is immutable and grants no trust: every byte is read from the
// protected opened file before the hint can be reused.
func readProtectedControlFileMatching(path string, known []byte) ([]byte, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !controlPrivateRegular(entry) || entry.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("control input must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(entry, info) {
		return nil, errors.New("control input changed while opening")
	}
	if info.Size() > maxControlInputBytes {
		return nil, errors.New("control input exceeds the current reader resource bound")
	}
	var body []byte
	if known != nil && int64(len(known)) == info.Size() {
		body = known
		buffer := make([]byte, min(64<<10, len(known)))
		for offset := 0; offset < len(known); {
			end := min(offset+len(buffer), len(known))
			chunk := buffer[:end-offset]
			if _, err := io.ReadFull(file, chunk); err != nil {
				return nil, err
			}
			if !bytes.Equal(chunk, known[offset:end]) {
				body = make([]byte, len(known))
				copy(body, known[:offset])
				copy(body[offset:end], chunk)
				if _, err := io.ReadFull(file, body[end:]); err != nil {
					return nil, err
				}
				break
			}
			offset = end
		}
	} else {
		body = make([]byte, int(info.Size()))
		if _, err := io.ReadFull(file, body); err != nil {
			return nil, err
		}
	}
	var extra [1]byte
	if _, err := io.ReadFull(file, extra[:]); err != io.EOF {
		return nil, errors.New("control input changed while reading")
	}
	return body, nil
}

// Hard-link publication is atomic put-if-absent, including against writers
// that do not cooperate with the advisory process lock.
func putControlBytes(path string, body []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".material-*")
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
	if err := os.Link(temporary, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := readProtectedControlFile(path)
		if readErr != nil || !bytes.Equal(existing, body) {
			return errors.New("immutable control bytes already exist with different content")
		}
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return syncControlDirectory(dir)
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
