package control

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

const internalDomain = "loom-control-internal-v1\n"

type Runtime struct {
	Config    NodeConfig
	Authority *Authority
	Raft      *raft.Raft
	transport *raft.NetworkTransport
	store     io.Closer
	mu        sync.Mutex
	stop      chan struct{}
	done      chan struct{}
}

type authorityFSM struct{ authority *Authority }

func (fsm *authorityFSM) Apply(log *raft.Log) any {
	if log.Type != raft.LogCommand {
		return nil
	}
	_, err := fsm.authority.Append(string(log.Data), log.Term)
	return err
}
func (fsm *authorityFSM) Snapshot() (raft.FSMSnapshot, error) { return &discardFSMSnapshot{}, nil }
func (fsm *authorityFSM) Restore(io.ReadCloser) error {
	return errors.New("control snapshots are disabled; replay the consensus log")
}

type discardFSMSnapshot struct{}

func (*discardFSMSnapshot) Persist(sink raft.SnapshotSink) error { return sink.Cancel() }
func (*discardFSMSnapshot) Release()                             {}

type guardedLogStore struct {
	raft.LogStore
	authority *Authority
}

func (store guardedLogStore) StoreLog(log *raft.Log) error { return store.StoreLogs([]*raft.Log{log}) }
func (store guardedLogStore) StoreLogs(logs []*raft.Log) error {
	for _, log := range logs {
		if log.Type == raft.LogCommand {
			if _, err := store.authority.Material(string(log.Data)); err != nil {
				return fmt.Errorf("raft entry references material not persisted locally: %w", err)
			}
		}
	}
	return store.LogStore.StoreLogs(logs)
}

func OpenRuntime(root string) (*Runtime, error) {
	config, err := LoadNodeConfig(root)
	if err != nil {
		return nil, err
	}
	authority, err := OpenAuthority(root)
	if err != nil {
		return nil, err
	}
	_, projection, _ := authority.Snapshot()
	memberOK := false
	all := projection.Config.Members
	if projection.Config.Mode == "joint" {
		all = append(append([]Member{}, projection.Config.Old...), projection.Config.New...)
	}
	for _, member := range all {
		if member.ID == config.MemberID && member.PublicKey == config.Member().PublicKey {
			memberOK = true
		}
	}
	if !memberOK && config.Bootstrap {
		return nil, errors.New("bootstrap node identity is not present in the certified control config")
	}

	bolt, err := raftboltdb.NewBoltStore(filepath.Join(root, "consensus-raft.db"))
	if err != nil {
		return nil, err
	}
	transport, err := raft.NewTCPTransport(config.RaftAddress, nil, 4, 10*time.Second, io.Discard)
	if err != nil {
		return nil, err
	}
	raftConfig := raft.DefaultConfig()
	raftConfig.LocalID = raft.ServerID(config.MemberID)
	raftConfig.SnapshotThreshold = math.MaxUint64
	raftConfig.SnapshotInterval = 24 * time.Hour
	raftConfig.LogOutput = io.Discard
	logs := guardedLogStore{LogStore: bolt, authority: authority}
	hasState, err := raft.HasExistingState(logs, bolt, raft.NewInmemSnapshotStore())
	if err != nil {
		transport.Close()
		return nil, err
	}
	if !hasState && config.Bootstrap {
		bootstrap := raft.Configuration{Servers: []raft.Server{{ID: raft.ServerID(config.MemberID), Address: raft.ServerAddress(config.RaftAddress), Suffrage: raft.Voter}}}
		if err := raft.BootstrapCluster(raftConfig, logs, bolt, raft.NewInmemSnapshotStore(), transport, bootstrap); err != nil {
			transport.Close()
			return nil, err
		}
	}
	instance, err := raft.NewRaft(raftConfig, &authorityFSM{authority}, logs, bolt, raft.NewInmemSnapshotStore(), transport)
	if err != nil {
		transport.Close()
		return nil, err
	}
	runtime := &Runtime{Config: config, Authority: authority, Raft: instance, transport: transport, store: bolt, stop: make(chan struct{}), done: make(chan struct{})}
	go runtime.reconcileLoop()
	return runtime, nil
}

func (runtime *Runtime) Close() error {
	if runtime.stop != nil {
		select {
		case <-runtime.stop:
		default:
			close(runtime.stop)
		}
		<-runtime.done
	}
	if runtime.Raft != nil {
		_ = runtime.Raft.Shutdown().Error()
	}
	var result error
	if runtime.transport != nil {
		result = runtime.transport.Close()
	}
	if runtime.store != nil {
		if err := runtime.store.Close(); result == nil {
			result = err
		}
	}
	return result
}

func (runtime *Runtime) reconcileLoop() {
	defer close(runtime.done)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-runtime.stop:
			return
		case <-ticker.C:
			if runtime.Raft.State() == raft.Leader {
				runtime.reconcilePeers()
			}
		}
	}
}

func (runtime *Runtime) reconcilePeers() {
	localIDs, err := runtime.Authority.MaterialIDs()
	if err != nil {
		return
	}
	_, projection, certified := runtime.Authority.Snapshot()
	for _, member := range uniqueMembers(projection.Config) {
		if member.ID == runtime.Config.MemberID {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var remoteIDs []string
		if err := runtime.peerJSON(ctx, member, http.MethodGet, "/internal/materials", nil, &remoteIDs); err == nil {
			remote := map[string]bool{}
			for _, id := range remoteIDs {
				remote[id] = true
			}
			for _, id := range localIDs {
				if !remote[id] {
					if body, readErr := runtime.Authority.Material(id); readErr == nil {
						_ = runtime.peerJSON(ctx, member, http.MethodPut, "/internal/materials/"+strings.TrimPrefix(id, "sha256:"), body, nil)
					}
				}
			}
			_ = runtime.peerJSON(ctx, member, http.MethodPut, "/internal/certified", mustJSON(certified.Head), nil)
		}
		cancel()
	}
}

func (runtime *Runtime) LeaderMember() (Member, bool) {
	_, id := runtime.Raft.LeaderWithID()
	_, projection, _ := runtime.Authority.Snapshot()
	all := projection.Config.Members
	if projection.Config.Mode == "joint" {
		all = append(append([]Member{}, projection.Config.Old...), projection.Config.New...)
	}
	for _, member := range all {
		if member.ID == string(id) {
			return member, true
		}
	}
	return Member{}, false
}

func (runtime *Runtime) Submit(ctx context.Context, body []byte) (CertifiedState, error) {
	material, id, err := EncodeMaterialFromBytes(body)
	if err != nil {
		return CertifiedState{}, err
	}
	consensus, projection, certified := runtime.Authority.Snapshot()
	if contains(projection.Applied, material.RequestID) {
		if certified.Head.Index == uint64(len(consensus.Entries)) && len(uniqueMembers(projection.Config)) == 1 {
			return certified, nil
		}
		if runtime.Raft.State() != raft.Leader {
			leader, ok := runtime.LeaderMember()
			if !ok {
				return CertifiedState{}, errors.New("write quorum is unavailable")
			}
			var result CertifiedState
			if err := runtime.peerJSON(ctx, leader, http.MethodPost, "/internal/submit", body, &result); err != nil {
				return CertifiedState{}, err
			}
			return result, nil
		}
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		if material.Kind == "control.config" && material.ControlConfig.Mode == "joint" {
			if err := runtime.applyRaftMembership(material.ControlConfig.New); err != nil {
				return CertifiedState{}, err
			}
		}
		if _, err := runtime.certify(ctx); err != nil {
			return CertifiedState{}, err
		}
		if material.Kind == "control.config" && material.ControlConfig.Mode == "stable" {
			if err := runtime.removeOldRaftMembers(material.ControlConfig.Members); err != nil {
				return CertifiedState{}, err
			}
		}
		_, _, result := runtime.Authority.Snapshot()
		return result, nil
	}
	if material.BaseHead != HeadID(certified.Head) {
		return CertifiedState{}, errors.New("base head is stale")
	}
	if _, err := runtime.Authority.PutMaterial(body); err != nil {
		return CertifiedState{}, err
	}
	if runtime.Raft.State() != raft.Leader {
		leader, ok := runtime.LeaderMember()
		if !ok {
			return CertifiedState{}, errors.New("write quorum is unavailable")
		}
		var result CertifiedState
		if err := runtime.peerJSON(ctx, leader, http.MethodPost, "/internal/submit", body, &result); err != nil {
			return CertifiedState{}, err
		}
		return result, nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.submitLeader(ctx, material, id, body)
}

func (runtime *Runtime) submitLeader(ctx context.Context, material Material, id string, body []byte) (CertifiedState, error) {
	if err := runtime.syncMaterialToVoters(ctx, id, body); err != nil {
		return CertifiedState{}, err
	}
	future := runtime.Raft.Apply([]byte(id), 15*time.Second)
	if err := future.Error(); err != nil {
		return CertifiedState{}, fmt.Errorf("raft commit: %w", err)
	}
	if applyErr, ok := future.Response().(error); ok && applyErr != nil {
		return CertifiedState{}, applyErr
	}
	if material.Kind == "control.config" && material.ControlConfig.Mode == "joint" {
		for _, member := range material.ControlConfig.New {
			if member.ID == runtime.Config.MemberID {
				continue
			}
			if err := runtime.peerJSON(ctx, member, http.MethodPut, "/internal/materials/"+strings.TrimPrefix(id, "sha256:"), body, nil); err != nil {
				return CertifiedState{}, fmt.Errorf("stage material on joining member %s: %w", member.ID, err)
			}
		}
		if err := runtime.applyRaftMembership(material.ControlConfig.New); err != nil {
			return CertifiedState{}, err
		}
	}
	head, err := runtime.certify(ctx)
	if err != nil {
		return CertifiedState{}, err
	}
	if material.Kind == "control.config" && material.ControlConfig.Mode == "stable" {
		if err := runtime.removeOldRaftMembers(material.ControlConfig.Members); err != nil {
			return CertifiedState{}, err
		}
	}
	_, _, certified := runtime.Authority.Snapshot()
	if HeadID(certified.Head) != HeadID(head) {
		return CertifiedState{}, errors.New("certified store did not advance")
	}
	return certified, nil
}

func (runtime *Runtime) ReplaceMembers(ctx context.Context, requestID, baseHead string, members []Member) (CertifiedState, error) {
	_, projection, _ := runtime.Authority.Snapshot()
	if projection.Config.Mode != "stable" {
		return CertifiedState{}, errors.New("member replacement requires a stable current config")
	}
	joint := JointConfig(projection.Config.Members, members)
	jointMaterial := Material{Schema: 1, Kind: "control.config", RequestID: requestID + ":joint", BaseHead: baseHead, ControlConfig: &joint}
	body, _, err := EncodeMaterial(jointMaterial)
	if err != nil {
		return CertifiedState{}, err
	}
	jointResult, err := runtime.Submit(ctx, body)
	if err != nil {
		return CertifiedState{}, err
	}
	stable := StableConfig(members)
	stableMaterial := Material{Schema: 1, Kind: "control.config", RequestID: requestID + ":stable", BaseHead: HeadID(jointResult.Head), ControlConfig: &stable}
	body, _, err = EncodeMaterial(stableMaterial)
	if err != nil {
		return CertifiedState{}, err
	}
	return runtime.Submit(ctx, body)
}

func (runtime *Runtime) syncMaterialToVoters(ctx context.Context, id string, body []byte) error {
	configuration := runtime.Raft.GetConfiguration()
	if err := configuration.Error(); err != nil {
		return err
	}
	_, projection, _ := runtime.Authority.Snapshot()
	byID := memberMap(projection.Config)
	for _, server := range configuration.Configuration().Servers {
		if string(server.ID) == runtime.Config.MemberID {
			continue
		}
		member, ok := byID[string(server.ID)]
		if !ok {
			return errors.New("raft voter is absent from ControlConfig")
		}
		if err := runtime.peerJSON(ctx, member, http.MethodPut, "/internal/materials/"+strings.TrimPrefix(id, "sha256:"), body, nil); err != nil {
			// A missing minority is allowed. The guarded follower log store will
			// refuse to acknowledge this entry until its material arrives.
			continue
		}
	}
	return nil
}

func (runtime *Runtime) applyRaftMembership(members []Member) error {
	current := runtime.Raft.GetConfiguration()
	if err := current.Error(); err != nil {
		return err
	}
	present := map[string]bool{}
	for _, server := range current.Configuration().Servers {
		present[string(server.ID)] = true
	}
	for _, member := range members {
		if present[member.ID] {
			continue
		}
		if err := runtime.Raft.AddVoter(raft.ServerID(member.ID), raft.ServerAddress(member.RaftAddress), 0, 30*time.Second).Error(); err != nil {
			return fmt.Errorf("add raft voter %s: %w", member.ID, err)
		}
	}
	return nil
}

func (runtime *Runtime) removeOldRaftMembers(members []Member) error {
	want := map[string]bool{}
	for _, member := range members {
		want[member.ID] = true
	}
	current := runtime.Raft.GetConfiguration()
	if err := current.Error(); err != nil {
		return err
	}
	for _, server := range current.Configuration().Servers {
		if want[string(server.ID)] {
			continue
		}
		if err := runtime.Raft.RemoveServer(server.ID, 0, 30*time.Second).Error(); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) certify(ctx context.Context) (GovernanceHead, error) {
	head, projection, err := runtime.Authority.CandidateHead()
	if err != nil {
		return head, err
	}
	local, err := runtime.Authority.SignCandidate(runtime.Config, head)
	if err != nil {
		return head, err
	}
	signatures := []HeadSignature{local}
	seen := map[string]bool{local.MemberID: true}
	for _, member := range uniqueMembers(projection.Config) {
		if seen[member.ID] {
			continue
		}
		var signature HeadSignature
		for attempt := 0; attempt < 10; attempt++ {
			if err := runtime.peerJSON(ctx, member, http.MethodPost, "/internal/head/sign", mustJSON(head), &signature); err == nil {
				signatures = append(signatures, signature)
				seen[member.ID] = true
				break
			}
			select {
			case <-ctx.Done():
				return head, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].MemberID < signatures[j].MemberID })
	head.Signatures = signatures
	if err := VerifyHead(head, projection, func() []ConsensusEntry { c, _, _ := runtime.Authority.Snapshot(); return c.Entries }()); err != nil {
		return head, err
	}
	if err := runtime.Authority.InstallCertified(head); err != nil {
		return head, err
	}
	installed := map[string]bool{runtime.Config.MemberID: true}
	for _, member := range uniqueMembers(projection.Config) {
		if member.ID == runtime.Config.MemberID {
			continue
		}
		if err := runtime.peerJSON(ctx, member, http.MethodPut, "/internal/certified", mustJSON(head), nil); err == nil {
			installed[member.ID] = true
		}
	}
	count := func(members []Member) int {
		total := 0
		for _, member := range members {
			if installed[member.ID] {
				total++
			}
		}
		return total
	}
	if projection.Config.Mode == "stable" {
		if count(projection.Config.Members) < projection.Config.Quorum {
			return head, errors.New("certified head was not installed on a quorum")
		}
	} else if count(projection.Config.Old) < projection.Config.OldQuorum || count(projection.Config.New) < projection.Config.NewQuorum {
		return head, errors.New("certified joint head was not installed on both quorums")
	}
	return head, nil
}

func memberMap(config ControlConfig) map[string]Member {
	result := map[string]Member{}
	for _, member := range uniqueMembers(config) {
		result[member.ID] = member
	}
	return result
}
func uniqueMembers(config ControlConfig) []Member {
	all := config.Members
	if config.Mode == "joint" {
		all = append(append([]Member{}, config.Old...), config.New...)
	}
	byID := map[string]Member{}
	for _, member := range all {
		byID[member.ID] = member
	}
	result := make([]Member, 0, len(byID))
	for _, member := range byID {
		result = append(result, member)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func mustJSON(value any) []byte { body, _ := json.Marshal(value); return body }

func (runtime *Runtime) peerJSON(ctx context.Context, member Member, method, path string, body []byte, result any) error {
	certificate, err := tls.X509KeyPair([]byte(runtime.Config.BrowserTLS.CertificateChainPEM), []byte(runtime.Config.BrowserTLS.PrivateKeyPKCS8PEM))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(runtime.Config.BrowserTLS.CertificateChainPEM)) {
		return errors.New("control TLS trust chain is invalid")
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool}}}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+member.APIAddress+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	runtime.signRequest(request, body)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("peer %s: %s: %s", member.ID, response.Status, strings.TrimSpace(string(message)))
	}
	if result != nil {
		decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
		decoder.DisallowUnknownFields()
		return decoder.Decode(result)
	}
	return nil
}

func requestBytes(method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(internalDomain + method + "\n" + path + "\n" + hex.EncodeToString(sum[:]))
}
func (runtime *Runtime) signRequest(request *http.Request, body []byte) {
	request.Header.Set("X-Loom-Member", runtime.Config.MemberID)
	request.Header.Set("X-Loom-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(runtime.Config.PrivateKey(), requestBytes(request.Method, request.URL.Path, body))))
}
func (runtime *Runtime) verifyRequest(request *http.Request, body []byte) bool {
	member, ok := memberMap(func() ControlConfig { _, p, _ := runtime.Authority.Snapshot(); return p.Config }())[request.Header.Get("X-Loom-Member")]
	if !ok {
		return false
	}
	key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Loom-Signature"))
	return err == nil && ed25519.Verify(key, requestBytes(request.Method, request.URL.Path, body), signature)
}

func TLSConfig(config NodeConfig) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair([]byte(config.BrowserTLS.CertificateChainPEM), []byte(config.BrowserTLS.PrivateKeyPKCS8PEM))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(config.BrowserTLS.CertificateChainPEM))
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: pool, ClientAuth: tls.RequireAnyClientCert}, nil
}

func PrepareMember(root, sourceRoot, memberID, listen, raftAddress string) (NodeConfig, error) {
	source, err := LoadNodeConfig(sourceRoot)
	if err != nil {
		return NodeConfig{}, err
	}
	authority, err := OpenAuthority(sourceRoot)
	if err != nil {
		return NodeConfig{}, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return NodeConfig{}, err
	}
	config := source
	config.MemberID = memberID
	config.Listen = listen
	config.RaftAddress = raftAddress
	config.Bootstrap = false
	config.IdentityPrivateKey = base64.RawURLEncoding.EncodeToString(private)
	config.BrowserTLS, err = issueNodeTLS(source.BrowserTLS, memberID, listen)
	if err != nil {
		return NodeConfig{}, err
	}
	if err := os.MkdirAll(filepath.Join(root, "materials"), 0o700); err != nil {
		return NodeConfig{}, err
	}
	ids, err := authority.MaterialIDs()
	if err != nil {
		return NodeConfig{}, err
	}
	for _, id := range ids {
		body, _ := authority.Material(id)
		target := &Authority{root: root}
		if _, err := target.PutMaterial(body); err != nil {
			return NodeConfig{}, err
		}
	}
	for _, name := range []string{"consensus.json", "certified.json"} {
		body, err := os.ReadFile(filepath.Join(sourceRoot, name))
		if err != nil {
			return NodeConfig{}, err
		}
		if err := atomicWrite(filepath.Join(root, name), body); err != nil {
			return NodeConfig{}, err
		}
	}
	if err := config.Validate(); err != nil {
		return NodeConfig{}, err
	}
	if err := atomicJSON(filepath.Join(root, "node.json"), config); err != nil {
		return NodeConfig{}, err
	}
	return config, nil
}

func issueNodeTLS(source BrowserTLS, memberID, listen string) (BrowserTLS, error) {
	block, _ := pem.Decode([]byte(source.RootPrivateKeyPKCS8PEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		return BrowserTLS{}, errors.New("browser root private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return BrowserTLS{}, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return BrowserTLS{}, errors.New("browser root key cannot sign")
	}
	wantPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return BrowserTLS{}, err
	}
	remaining := []byte(source.CertificateChainPEM)
	var authority *x509.Certificate
	caPEM := []byte{}
	for {
		certificateBlock, rest := pem.Decode(remaining)
		if certificateBlock == nil {
			break
		}
		remaining = rest
		certificate, parseErr := x509.ParseCertificate(certificateBlock.Bytes)
		if parseErr != nil {
			return BrowserTLS{}, parseErr
		}
		if certificate.IsCA {
			caPEM = append(caPEM, pem.EncodeToMemory(certificateBlock)...)
			public, marshalErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
			if marshalErr == nil && bytes.Equal(public, wantPublic) {
				authority = certificate
			}
		}
	}
	if authority == nil {
		return BrowserTLS{}, errors.New("browser root certificate does not match retained root key")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return BrowserTLS{}, err
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return BrowserTLS{}, errors.New("browser listen address is invalid")
	}
	serialSeed := sha256.Sum256([]byte("loom-control-browser-leaf-v1\n" + memberID + "\n" + listen))
	serial := new(big.Int).SetBytes(serialSeed[:20])
	serial.SetBit(serial, 159, 0)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: memberID}, NotBefore: authority.NotBefore,
		NotAfter: authority.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, authority, public, signer)
	if err != nil {
		return BrowserTLS{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return BrowserTLS{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), caPEM...)
	return BrowserTLS{CertificateChainPEM: string(chain), PrivateKeyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})), RootPrivateKeyPKCS8PEM: source.RootPrivateKeyPKCS8PEM}, nil
}
