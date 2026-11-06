//go:build linux

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/localconfig"

	"golang.org/x/sys/unix"
)

type recoveryManagementFixture struct {
	nodes   []localconfig.NodeNetwork
	local   string
	check   func(DeviceView) error
	deliver func(DeviceViewEnvelope) error
}

func (f recoveryManagementFixture) Targets() ([]string, error) { return nil, nil }
func (f recoveryManagementFixture) Resolve(context.Context, string) (SSHTargetReadback, error) {
	return SSHTargetReadback{}, errors.New("unused management operation")
}
func (f recoveryManagementFixture) Run(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("unused management operation")
}
func (f recoveryManagementFixture) WGPortMappings() ([]localconfig.NodeNetwork, string, error) {
	return f.nodes, f.local, nil
}
func (f recoveryManagementFixture) WGPortOccupied(context.Context, string, TransportResource) ([]int, error) {
	return nil, nil
}
func (f recoveryManagementFixture) WGPortCheck(_ context.Context, _ string, view DeviceView) error {
	return f.check(view)
}
func (f recoveryManagementFixture) WGPortDeliver(_ context.Context, _ string, envelope DeviceViewEnvelope, _ string) error {
	return f.deliver(envelope)
}

func TestWGPortRecoveryReconcilesAnotherMembersFactAndStopsConcurrentEdit(t *testing.T) {
	for _, concurrentEdit := range []bool{false, true} {
		t.Run(fmt.Sprint("concurrent-edit-", concurrentEdit), func(t *testing.T) {
			server, fixture := remoteWGRecoveryFixture(t)
			before := server.Runtime.Authority.Snapshot()
			resource := wgPortRecoveryResource(before, fixture.link.ResourceID)
			head, err := server.wgPortRecoveryHead(before, resource.ID)
			if err != nil || head.IssuerControlID == server.Config.ControlID {
				t.Fatal("fixture must use another active member's current resource fact", err)
			}
			var checks, deliveries atomic.Int32
			var once sync.Once
			var editErr error
			mapping := localconfig.IngressMapping{Purpose: "demo-ingress", Protocol: "udp", PublicHost: resource.DialHost, PublicPorts: localconfig.PortRange{First: resource.DialPort, Last: resource.DialPort + 1}, HostAddress: resource.DialHost, HostPorts: localconfig.PortRange{First: resource.DialPort, Last: resource.DialPort + 1}}
			server.SSH = recoveryManagementFixture{local: server.Config.NodeID, nodes: []localconfig.NodeNetwork{{ID: resource.OwnerNodeID, Ingress: []localconfig.IngressMapping{mapping}}},
				check: func(DeviceView) error {
					checks.Add(1)
					if concurrentEdit {
						once.Do(func() {
							manual := resource
							manual.DialPort += 2
							target, _ := before.CurrentTarget("resource", resource.ID)
							owner, _ := before.CurrentTarget("device", resource.OwnerNodeID)
							body, err := EncodeOperation(Operation{Schema: 3, RequestID: "demo-concurrent-manual-port", Operation: "resource.put", TargetKind: "resource", TargetID: resource.ID, Dependencies: sortedUniqueDependencies(append(target.MaterialIDs, owner.MaterialIDs...)), Payload: manual})
							if err == nil {
								_, err = server.Runtime.Submit(context.Background(), body)
							}
							editErr = err
						})
					}
					return editErr
				},
				deliver: func(envelope DeviceViewEnvelope) error {
					deliveries.Add(1)
					p := server.Runtime.Authority.Snapshot()
					now := time.Now()
					current := &wgRecoveryFixture{p: p, keys: fixture.keys, now: now}
					links, err := DerivedNetworkLinks(p)
					if err != nil {
						return err
					}
					observations := []Observation{}
					for _, link := range links {
						if link.FromNodeID == envelope.View.DeviceID {
							observations = append(observations, current.sample(t, link, now, "available"))
						}
					}
					sequence := U64(2)
					if envelope.View.DeviceID == fixture.link.FromNodeID {
						sequence = 4
					}
					report := current.report(t, envelope.View.DeviceID, sequence, now, observations)
					identity, _ := identityFor(p, report.DeviceID)
					return server.Runtime.Reports.Put(report, identity.DevicePublicKey)
				}}
			err = server.reconcileWGPorts(context.Background())
			after := server.Runtime.Authority.Snapshot()
			actual := wgPortRecoveryResource(after, resource.ID)
			if checks.Load() != 2 {
				t.Fatal("another member's fact never reached the existing management preflight", checks.Load(), err)
			}
			if concurrentEdit {
				if err == nil || editErr != nil || actual.DialPort != resource.DialPort+2 || deliveries.Load() != 0 {
					t.Fatal("concurrent manual edit did not stop recovery before signing/delivery", err, editErr)
				}
				return
			}
			if err != nil || actual.DialPort != resource.DialPort+1 || deliveries.Load() != 2 {
				t.Fatal("existing executor did not complete another member's ordinary resource change", err)
			}
			next, err := server.wgPortRecoveryHead(after, resource.ID)
			actual.DialPort = resource.DialPort
			if err != nil || next.IssuerControlID != server.Config.ControlID || !reflect.DeepEqual(actual, resource) || !reflect.DeepEqual(before.Config, after.Config) || !reflect.DeepEqual(before.DeviceAuthorizations, after.DeviceAuthorizations) {
				t.Fatal("recovery changed identity, membership, or another resource field", err)
			}
		})
	}
}

func remoteWGRecoveryFixture(t *testing.T) (*Server, *wgRecoveryFixture) {
	t.Helper()
	f := newMaterialFixture(t)
	authorities, configs := materialAuthorities(t, f)
	runtime, err := OpenRuntime(authorities[0].root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	server := &Server{Runtime: runtime, Config: configs[0], Now: time.Now}
	fixture := &wgRecoveryFixture{keys: map[string]ed25519.PrivateKey{}, now: time.Now()}
	var history []Material
	appendFact := func(operation, kind, id string, payload MaterialPayload, dependencies ...string) string {
		t.Helper()
		var previous *Material
		if len(history) > 0 {
			previous = &history[len(history)-1]
		}
		material := f.sign(t, 1, U64(len(history)+1), previous, fmt.Sprintf("demo-remote-%d", len(history)+1), operation, kind, id, payload, dependencies...)
		body, id, err := EncodeMaterial(material)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtime.Authority.PutMaterial(body); err != nil {
			t.Fatal(err)
		}
		history = append(history, material)
		if operation == "resource.put" {
			path, _ := runtime.Authority.materialPath(id)
			if err := unix.Setxattr(path, receptionAttribute, binary.BigEndian.AppendUint64(nil, uint64(fixture.now.Add(-10*time.Minute).UnixNano())), 0); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: f.members[1].ControlID, Host: "demo.example", Port: 443, ServerName: "demo.example", SPKISHA256: configs[0].GenesisID, CertificateDigest: configs[0].GenesisID, Modes: []string{"bootstrap", "device"}, State: "prepared"}
	prepared := appendFact("endpoint.put", "endpoint", endpoint.ID, endpoint)
	endpoint.State = "serving"
	serving := appendFact("endpoint.put", "endpoint", endpoint.ID, endpoint, prepared)
	resources := relayProjectionFixture(t).NetworkIntent.Resources
	for _, id := range []string{"demo-entry", "demo-exit"} {
		invite := Invite{ID: id + "-invite", GenesisDigest: configs[0].GenesisID, IssuerControlID: f.members[1].ControlID, DeviceID: id, Name: id, Responsibilities: []string{"forward"}, PolicyIDs: []string{}, Medium: "ssh", Endpoint: endpoint, ExpiresAt: fixture.now.Add(time.Hour).UnixMilli()}
		issued := appendFact("invite.issue", "invite", invite.ID, invite, serving)
		seed := sha256.Sum256([]byte(id))
		key := ed25519.NewKeyFromSeed(seed[:])
		fixture.keys[id] = key
		public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: issued, ClaimRequestID: id + "-claim", DevicePublicKey: public, Platform: "linux"}
		bound := appendFact("invite.bind", "invite", invite.ID, binding, issued)
		device := DeviceAuthorization{ID: id, Name: id, Platform: "linux", DevicePublicKey: public, Responsibilities: []string{"forward"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: base64.RawURLEncoding.EncodeToString(seed[:]), TransactionID: invite.ID, InviteMaterialID: issued, BindingMaterialID: bound}
		for _, resource := range resources {
			if resource.Kind == "wireguard" && resource.OwnerNodeID == id {
				device.WireGuardPublicKey = *resource.Authentication.PublicKey
			}
		}
		joined := appendFact("device.join", "device", id, device, bound)
		for _, resource := range resources {
			if resource.Kind == "wireguard" && resource.OwnerNodeID == id {
				appendFact("resource.put", "resource", resource.ID, resource, joined)
			}
		}
	}
	fixture.p = runtime.Authority.Snapshot()
	fixture.link = testDerivedLink(t, fixture.p, "demo-entry", "demo-exit")
	for index, before := range []time.Duration{41 * time.Second, 21 * time.Second, time.Second} {
		at := fixture.now.Add(-before)
		report := fixture.report(t, fixture.link.FromNodeID, U64(index+1), at, []Observation{fixture.sample(t, fixture.link, at, "unavailable")})
		if err := runtime.Reports.Put(report, base64.RawURLEncoding.EncodeToString(fixture.keys[report.DeviceID].Public().(ed25519.PublicKey))); err != nil {
			t.Fatal(err)
		}
	}
	report := fixture.report(t, fixture.link.ToNodeID, 1, fixture.now, []Observation{})
	if err := runtime.Reports.Put(report, base64.RawURLEncoding.EncodeToString(fixture.keys[report.DeviceID].Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	return server, fixture
}
