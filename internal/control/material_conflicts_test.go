package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemberDeltaPreservesForksBeyondEqualFrontiers(t *testing.T) {
	parent := t.TempDir()
	ca := testTransportCA(t, parent)
	firstRoot, firstConfig, genesis := authorityFixture(t)
	firstKey, err := firstConfig.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{firstKey, testKey(t)}
	initial := genesis.Payload.(Genesis)
	initial.ControlConfig.Members = append(initial.ControlConfig.Members, Member{ControlID: "demo-control-b", NodeID: "demo-node-b", PublicKey: base64.RawURLEncoding.EncodeToString(keys[1].Public().(ed25519.PublicKey))})
	genesis.Payload, genesis.Signature = initial, ""
	genesis, err = SignMaterial(genesis, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := MaterialID(genesis)
	members := initial.ControlConfig.Members
	roots := []string{firstRoot, filepath.Join(parent, "demo-second-authority")}
	addresses := []string{testLoopbackAddress(t), testLoopbackAddress(t)}
	configs := []NodeConfig{}
	for i, member := range members {
		files, _, _ := testTransportIdentity(t, parent, member.ControlID, int64(i+10), keys[i], ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		browser, _, _ := testTransportIdentity(t, parent, member.ControlID+"-browser", int64(i+20), testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		config := NodeConfig{Schema: 3, NetworkID: firstConfig.NetworkID, ControlID: member.ControlID, NodeID: member.NodeID, GenesisID: genesisID, SigningKeyFile: files.KeyFile, PeerTLS: &files, BrowserTLS: &browser}
		configs = append(configs, config)
		if _, err := InitializeAuthority(roots[i], config, genesis); err != nil {
			t.Fatal(err)
		}
	}
	var capture sync.Mutex
	requests := map[string]int{}
	failID := ""
	var forgedIndex []byte
	start := func(i int) reportTestPeer {
		t.Helper()
		runtime, err := OpenRuntime(roots[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		channel, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: members[i].NodeID, Listen: []string{addresses[i]}, Peers: []PrivatePeer{{Node: members[1-i].NodeID, Addresses: []string{addresses[1-i]}}}}, configs[i])
		if err != nil {
			t.Fatal(err)
		}
		channel.AttachAuthority(runtime.Authority)
		runtime.Channel = channel
		server := &Server{Runtime: runtime, Channel: channel, Config: configs[i]}
		handler := server.Handler()
		httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capture.Lock()
			index := append([]byte{}, forgedIndex...)
			capture.Unlock()
			if len(index) > 0 && r.URL.Path == "/internal/material-conflicts" {
				_, _ = w.Write(index)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/internal/materials/") {
				capture.Lock()
				requests[r.URL.Path]++
				fail := failID != "" && r.URL.Path == "/internal/materials/"+strings.TrimPrefix(failID, "sha256:")
				if fail {
					failID = ""
				}
				capture.Unlock()
				if fail {
					http.Error(w, "demo interrupted transfer", http.StatusServiceUnavailable)
					return
				}
			}
			handler.ServeHTTP(w, r)
		}), ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
		go httpServer.Serve(channel.ControlListener())
		return reportTestPeer{server, channel, httpServer}
	}
	peers := []reportTestPeer{start(0), start(1)}
	t.Cleanup(func() {
		for _, peer := range peers {
			peer.close()
		}
	})
	syncPeer := func(to, from int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := peers[to].server.Runtime.reconcilePeer(ctx, members[from]); err != nil {
			t.Fatal(err)
		}
	}
	accepted := submitAuthority(t, peers[0].server.Runtime, authorityService("demo-original", "demo-normal-write"))
	syncPeer(1, 0)
	original, err := peers[0].server.Runtime.Authority.Material(accepted.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string][]byte{accepted.MaterialID: original}
	remoteForkIDs := []string{}
	for i := range peers {
		for branch := 0; branch < 2; branch++ {
			fork, err := DecodeMaterial(original)
			if err != nil {
				t.Fatal(err)
			}
			service := fork.Payload.(Service)
			service.Name = fmt.Sprintf("Demo fork %d branch %d", i, branch)
			fork.Payload, fork.Signature = service, ""
			fork, err = SignMaterial(fork, firstKey)
			if err != nil {
				t.Fatal(err)
			}
			body, id, err := EncodeMaterial(fork)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := peers[i].server.Runtime.Authority.PutMaterial(body); !errors.Is(err, ErrMaterialEquivocation) {
				t.Fatal("signed fork was not durably rejected from projection", err)
			}
			bodies[id] = body
			if i == 1 {
				remoteForkIDs = append(remoteForkIDs, id)
			}
			if frontierFor(peers[i].server.Runtime.Authority.Frontier(), fork.IssuerKeyID).Sequence != 0 {
				t.Fatal("forked signing key retained an effective prefix")
			}
		}
	}
	// A different valid signing key must still carry ordinary business changes.
	healthy := submitAuthority(t, peers[1].server.Runtime, authorityService("demo-independent", "demo-independent-write"))
	sort.Strings(remoteForkIDs)
	capture.Lock()
	failID = remoteForkIDs[1]
	capture.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = peers[0].server.Runtime.reconcilePeer(ctx, members[1])
	cancel()
	if err == nil {
		t.Fatal("interrupted member transfer appeared complete")
	}
	if stored, err := peers[0].server.Runtime.Authority.Material(remoteForkIDs[0]); err != nil || !bytes.Equal(stored, bodies[remoteForkIDs[0]]) {
		t.Fatal("interruption discarded an already persisted original", err)
	}
	syncPeer(0, 1)
	syncPeer(1, 0)
	for i := range peers {
		peers[i].close()
		peers[i] = start(i)
		for id, body := range bodies {
			stored, err := peers[i].server.Runtime.Authority.Material(id)
			if err != nil || !bytes.Equal(stored, body) {
				t.Fatalf("equal frontiers concealed original fork evidence on peer %d: %v", i, err)
			}
		}
		projection := peers[i].server.Runtime.Authority.Snapshot()
		if len(projection.NetworkIntent.Services) != 1 || projection.NetworkIntent.Services[0].ID != "demo-independent" {
			t.Fatal("fork acquired a winner or blocked an independent signing key")
		}
		if _, err := peers[i].server.Runtime.Authority.Material(healthy.MaterialID); err != nil || peers[i].server.Runtime.Writable() != (i == 1) {
			t.Fatal("restart changed independent facts or forked-key signing restriction", err)
		}
	}
	capture.Lock()
	before := 0
	for _, n := range requests {
		before += n
	}
	capture.Unlock()
	syncPeer(0, 1)
	syncPeer(1, 0)
	capture.Lock()
	after := 0
	for _, n := range requests {
		after += n
	}
	if after != before {
		t.Fatal("restart downloaded already persisted immutable originals")
	}
	if requests["/internal/materials/"+strings.TrimPrefix(remoteForkIDs[0], "sha256:")] != 1 {
		t.Fatal("interrupted retry downloaded an already persisted fork")
	}
	capture.Unlock()
	for _, body := range []string{
		`{"material_ids":[],"more":true}`,
		`{"material_ids":null,"more":false}`,
		`{"material_ids":[]}`,
		`{"material_ids":[],"more":false,"unknown":true}`,
		`{"material_ids":["` + accepted.MaterialID + `","` + accepted.MaterialID + `"],"more":false}`,
	} {
		capture.Lock()
		forgedIndex = []byte(body)
		capture.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := peers[0].server.Runtime.reconcilePeer(ctx, members[1])
		cancel()
		if err == nil {
			t.Fatal("malformed peer conflict index was accepted")
		}
	}
	capture.Lock()
	forgedIndex = nil
	capture.Unlock()
	syncPeer(0, 1)
	t.Run("normal offline copy discovers the full fork", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "demo-offline-authority")
		authority, err := InitializeAuthority(root, configs[0], genesis)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authority.PutMaterial(original); err != nil {
			t.Fatal(err)
		}
		reports, err := OpenObservationStore(root)
		if err != nil {
			t.Fatal(err)
		}
		recovery := &Runtime{Config: configs[0], Authority: authority, Reports: reports, Channel: peers[0].channel}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := recovery.reconcilePeer(ctx, members[1]); err != nil {
			t.Fatal(err)
		}
		if recovery.Writable() {
			t.Fatal("original healthy prefix hid the recovered fork")
		}
		for id, body := range bodies {
			stored, err := authority.Material(id)
			if err != nil || !bytes.Equal(stored, body) {
				t.Fatal("offline copy did not recover every signed original", err)
			}
		}
	})
}

func TestMaterialConflictPaginationAndStrictCursor(t *testing.T) {
	f := newMaterialFixture(t)
	a := &Authority{}
	expected := []string{}
	for i := 0; i <= materialConflictPageSize; i++ {
		id := fmt.Sprintf("demo-service-%d", i)
		material := f.sign(t, 0, 1, nil, id, "service.put", "service", id, Service{ID: id, Name: "Demo", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}})
		a.materials = append(a.materials, material)
		expected = append(expected, materialTestID(t, material))
	}
	sort.Strings(expected)
	first, err := a.materialConflictsAfter("")
	if err != nil || !first.More || !slices.Equal(first.MaterialIDs, expected[:materialConflictPageSize]) {
		t.Fatal("first page did not preserve the exact bounded evidence set", err)
	}
	last, err := a.materialConflictsAfter(first.MaterialIDs[len(first.MaterialIDs)-1])
	if err != nil || last.More || !slices.Equal(last.MaterialIDs, expected[materialConflictPageSize:]) {
		t.Fatal("continuation lost original evidence", err)
	}
	server := &Server{Runtime: &Runtime{Authority: a}}
	for _, query := range []string{"", "?after=invalid", "?after=&after=", "?after=&other=", "?after=%"} {
		response := httptest.NewRecorder()
		server.internalMaterialConflicts(response, httptest.NewRequest(http.MethodGet, "/internal/material-conflicts"+query, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatal("ambiguous conflict cursor accepted", query)
		}
	}
}
