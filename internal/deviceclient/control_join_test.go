package deviceclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func TestMemberAuthorityRetriesCompleteVerifiedCollection(t *testing.T) {
	base, makeView := schema3Fixture(t, "linux", func(invite *control.Invite) {
		invite.DeviceID, invite.Responsibilities, invite.PolicyIDs, invite.Medium = "demo-node-b", []string{"control"}, []string{}, "sh"
	})
	seed := sha256.Sum256([]byte("demo-device-control-b"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	var projection control.Projection
	var facts []control.Material
	byID := map[string]control.Material{}
	badReached := make(chan struct{})
	var badOnce sync.Once
	var goodOriginals atomic.Int32
	handler := func(primary bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/device/control")
			switch {
			case path == "/proof":
				writeDeviceResponse(t, w, base.ControlProof)
			case path == "/frontier":
				writeDeviceResponse(t, w, projection.Frontier)
			case path == "/material-conflicts":
				writeDeviceResponse(t, w, struct {
					MaterialIDs []string `json:"material_ids"`
					More        bool     `json:"more"`
				}{[]string{}, false})
			case strings.HasPrefix(path, "/material/"):
				if primary {
					badOnce.Do(func() { close(badReached) })
					// Valid signed bytes for a different original cannot complete
					// this candidate, even after proof/frontier HTTP succeeded.
					writeDeviceResponse(t, w, facts[0])
					return
				}
				goodOriginals.Add(1)
				material, found := byID["sha256:"+strings.TrimPrefix(path, "/material/")]
				if !found {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeDeviceResponse(t, w, material)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}
	addresses := map[string]string{}
	endpoints := []control.EndpointGeneration{}
	for i, primary := range []bool{true, false} {
		endpoint, address := testDeviceTunnel(t, public, handler(primary))
		endpoint.ID, endpoint.Host, endpoint.Modes = fmt.Sprintf("demo-entry-%d", i), fmt.Sprintf("192.0.2.%d", i+1), []string{"bootstrap", "device"}
		endpoints = append(endpoints, endpoint)
		addresses[net.JoinHostPort(endpoint.Host, "443")] = address
	}
	previous := control.EmptyMaterialChainID()
	sign := func(kind, id, operation string, payload control.MaterialPayload, dependencies []string) string {
		t.Helper()
		material, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: base.NetworkID, IssuerControlID: base.Material.IssuerControlID, IssuerKeyID: base.Material.IssuerKeyID, ControlConfigID: base.Material.ControlConfigID,
			Sequence: control.U64(len(facts) + 1), PreviousMaterialID: previous, Dependencies: dependencies, RequestID: fmt.Sprintf("demo-original-%d", len(facts)+1), TargetKind: kind, TargetID: id, Operation: operation, Payload: payload}, private)
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := control.MaterialID(material)
		previous = actual
		facts = append(facts, material)
		byID[actual] = material
		return actual
	}
	servingIDs := []string{}
	for _, endpoint := range endpoints {
		prepared := endpoint
		prepared.State = "prepared"
		id := sign("endpoint", endpoint.ID, "endpoint.put", prepared, []string{})
		servingIDs = append(servingIDs, sign("endpoint", endpoint.ID, "endpoint.put", endpoint, []string{id}))
	}
	invitation := base.Material.Payload.(control.Invite)
	invitation.Endpoint = endpoints[0]
	sign("invite", invitation.ID, "invite.issue", invitation, []string{servingIDs[0]})
	base.Material = facts[len(facts)-1]
	var err error
	projection, err = control.Project(base.ControlProof.Genesis, base.ControlProof.Successors, facts)
	if err != nil {
		t.Fatal(err)
	}
	view := makeView(public, uint64(len(facts)), func(view *control.DeviceView) { view.Endpoints = endpoints }).View
	envelope, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: base.NetworkID, GenesisDigest: base.GenesisDigest, IssuerControlID: base.Material.IssuerControlID, IssuerKeyID: base.Material.IssuerKeyID,
		ControlProof: base.ControlProof, FactFrontier: projection.Frontier, View: view}, private)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewIdentityState(base, "linux", private, "demo-member-claim")
	if err != nil {
		t.Fatal(err)
	}
	state, err = AcceptLKG(state, envelope)
	if err != nil {
		t.Fatal(err)
	}
	before, err := EncodeIdentityState(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "192.0.2.2:443" {
			select {
			case <-badReached:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, addresses[address])
	})
	proof, originals, err := FetchMemberAuthority(ctx, store)
	if err != nil || len(originals) != len(facts) || goodOriginals.Load() != int32(len(facts)) {
		t.Fatalf("incomplete primary prevented healthy complete collection: %v facts=%d requests=%d", err, len(originals), goodOriginals.Load())
	}
	if _, err := control.Project(proof.Genesis, proof.Successors, originals); err != nil {
		t.Fatal("winning originals were not independently replayable", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("member original fetch modified accepted identity or frontier")
	}
}
