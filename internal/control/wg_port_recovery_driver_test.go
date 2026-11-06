package control

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/localconfig"
)

func TestWGPortRecoveryMappingsAreCyclicSuppliedAndUnoccupied(t *testing.T) {
	resource := TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-node", DialHost: "192.0.2.10", DialPort: 51822}
	mapping := localconfig.IngressMapping{Purpose: "demo-ingress", Protocol: "udp", PublicHost: resource.DialHost, PublicPorts: localconfig.PortRange{First: 51820, Last: 51824}, HostAddress: "192.0.2.10", HostPorts: localconfig.PortRange{First: 51820, Last: 51824}}
	node := localconfig.NodeNetwork{ID: resource.OwnerNodeID, ManagementHost: "192.0.2.10", ManagementPort: 22, HostAddresses: []string{"192.0.2.10"}, Ingress: []localconfig.IngressMapping{mapping}}
	for _, tc := range []struct {
		name      string
		node      localconfig.NodeNetwork
		resources []TransportResource
		avoided   []int
		want      []int
	}{
		{"cyclic", node, nil, nil, []int{51823, 51824, 51820, 51821}},
		{"previously failed and authenticated resources", node, []TransportResource{
			{ID: "demo-other-wg", Kind: "wireguard", OwnerNodeID: resource.OwnerNodeID, DialHost: resource.DialHost, DialPort: 51823},
			{ID: "demo-other-hy2", Kind: "hysteria2", OwnerNodeID: "demo-other", DialHost: resource.DialHost, DialPort: 51824},
		}, []int{51820}, []int{51821}},
		{"unrelated resource does not occupy this host", node, []TransportResource{{ID: "demo-other", Kind: "wireguard", OwnerNodeID: "demo-other", DialHost: "192.0.2.11", DialPort: 51823}}, nil, []int{51823, 51824, 51820, 51821}},
		{"nonidentical translation", func() localconfig.NodeNetwork {
			value := node
			other := mapping
			other.HostPorts = localconfig.PortRange{First: 60000, Last: 60004}
			value.Ingress = []localconfig.IngressMapping{other}
			return value
		}(), nil, nil, []int{51823, 51824, 51820, 51821}},
		{"other host and protocol", func() localconfig.NodeNetwork {
			value := node
			tcp, other := mapping, mapping
			tcp.Protocol, other.PublicHost = "tcp", "192.0.2.11"
			value.Ingress = []localconfig.IngressMapping{tcp, other}
			return value
		}(), nil, nil, []int{}},
		{"all supplied same host ranges", func() localconfig.NodeNetwork {
			value := node
			other := mapping
			other.PublicPorts = localconfig.PortRange{First: 51830, Last: 51831}
			other.HostPorts = other.PublicPorts
			value.Ingress = append([]localconfig.IngressMapping{mapping}, other)
			return value
		}(), nil, nil, []int{51823, 51824, 51830, 51831, 51820, 51821}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Projection{NetworkIntent: NetworkIntent{Resources: append([]TransportResource{resource}, tc.resources...)}}
			got := wgPortRecoveryPorts([]localconfig.NodeNetwork{tc.node}, p, resource, tc.avoided)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatal("candidate ports differ from supplied executable mappings", got, tc.want)
			}
		})
	}
}

func wgRecoveryAuthorityFixture(t *testing.T) (*Server, TransportResource, DeviceReport) {
	t.Helper()
	server, key := localNetworkWriteFixture(t)
	p := server.Runtime.Authority.Snapshot()
	owner, _ := p.CurrentTarget("device", "demo-gateway")
	resource := relayProjectionFixture(t).NetworkIntent.Resources[1]
	resource.ID, resource.ListenerID, resource.OwnerNodeID = "demo-gateway-wg", "demo-gateway-wg", "demo-gateway"
	if resource.Kind != "wireguard" {
		t.Fatal("fixture requires a native WG resource")
	}
	for _, device := range p.DeviceAuthorizations {
		if device.ID == resource.OwnerNodeID {
			public := device.WireGuardPublicKey
			resource.Authentication.PublicKey = &public
		}
	}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-create-wg", Operation: "resource.put", TargetKind: "resource", TargetID: resource.ID, Dependencies: owner.MaterialIDs, Payload: resource})
	view, err := ProjectDeviceView(server.Runtime.Authority.Snapshot(), resource.OwnerNodeID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DeviceViewDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ReportSequence: 8, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "unknown"}, Components: []ComponentReadback{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: view.DeviceID}); response.Code != http.StatusOK {
		t.Fatal("normal signed report failed", response.Code)
	}
	return server, resource, report
}

func TestWGPortRecoveryOrdinaryPutPreservesIdentityAndDurableProgress(t *testing.T) {
	server, resource, report := wgRecoveryAuthorityFixture(t)
	p := server.Runtime.Authority.Snapshot()
	oldTarget, _ := p.CurrentTarget("resource", resource.ID)
	original, err := server.Runtime.Authority.Material(oldTarget.MaterialIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	replacement := resource
	replacement.DialPort++
	saved, err := server.wgPortRecoveryPut(context.Background(), p, replacement, false)
	if err != nil {
		t.Fatal("ordinary automatic resource write failed", err)
	}
	if !reflect.DeepEqual(saved.Projection.DeviceAuthorizations, p.DeviceAuthorizations) || !reflect.DeepEqual(saved.Projection.Config, p.Config) ||
		!reflect.DeepEqual(wgPortRecoveryResource(saved.Projection, resource.ID), replacement) {
		t.Fatal("port recovery altered another identity or resource field")
	}
	for _, floor := range p.Frontier {
		next := frontierFor(saved.Projection.Frontier, floor.KeyID)
		if next.Sequence < floor.Sequence || next.Sequence == floor.Sequence && !reflect.DeepEqual(next, floor) {
			t.Fatal("port recovery rewound an authenticated fact frontier")
		}
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Runtime.Close() })
	if !reflect.DeepEqual(wgPortRecoveryResource(server.Runtime.Authority.Snapshot(), resource.ID), replacement) {
		t.Fatal("restart lost the ordinary resource update")
	}
	after, err := server.Runtime.Authority.Material(oldTarget.MaterialIDs[0])
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("port recovery replaced a previously signed original", err)
	}
	latest, err := server.Runtime.Reports.Latest(context.Background())
	if err != nil || len(latest) != 1 || !reflect.DeepEqual(latest[0], report) {
		t.Fatal("resource recovery changed device report progress or original", err)
	}
	retry, err := server.wgPortRecoveryPut(context.Background(), p, replacement, false)
	if err != nil || retry.MaterialID != saved.MaterialID {
		t.Fatal("deterministic recovery request was not an ordinary idempotent retry", err)
	}
}

func TestWGPortRecoveryOrdinaryPutRejectsConcurrentManualChanges(t *testing.T) {
	for _, kind := range []string{"resource", "owner"} {
		t.Run(kind, func(t *testing.T) {
			server, resource, _ := wgRecoveryAuthorityFixture(t)
			p := server.Runtime.Authority.Snapshot()
			if kind == "resource" {
				manual := resource
				manual.DialPort += 2
				target, _ := p.CurrentTarget("resource", resource.ID)
				owner, _ := p.CurrentTarget("device", resource.OwnerNodeID)
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-manual-port", Operation: "resource.put", TargetKind: "resource", TargetID: resource.ID, Dependencies: sortedUniqueDependencies(append(target.MaterialIDs, owner.MaterialIDs...)), Payload: manual})
			} else {
				owner, _ := p.CurrentTarget("device", resource.OwnerNodeID)
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-manual-owner", Operation: "device.put", TargetKind: "device", TargetID: resource.OwnerNodeID, Dependencies: owner.MaterialIDs,
					Payload: DevicePut{ID: resource.OwnerNodeID, Name: "Demo manually renamed", Responsibilities: []string{"forward"}, PolicyIDs: []string{}, DistributionURLs: []string{}}})
			}
			before := server.Runtime.Authority.Frontier()
			head, err := server.wgPortRecoveryHead(p, resource.ID)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, err = server.wgPortRecoveryWait(ctx, p, resource, head, map[string]bool{}, time.Now().Add(time.Minute))
			cancel()
			if err == nil || !strings.Contains(err.Error(), "superseded") {
				t.Fatal("verification did not stop at a concurrent manual resource/owner edit", err)
			}
			replacement := resource
			replacement.DialPort++
			if _, err := server.wgPortRecoveryPut(context.Background(), p, replacement, false); err == nil {
				t.Fatal("stale recovery review signed over a concurrent manual update")
			}
			if !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
				t.Fatal("rejected recovery changed the authenticated frontier")
			}
		})
	}
}

func TestWGPortRecoveryOrdinaryPutOnlyChangesExistingPort(t *testing.T) {
	server, resource, _ := wgRecoveryAuthorityFixture(t)
	p := server.Runtime.Authority.Snapshot()
	before := server.Runtime.Authority.Frontier()
	replacement := resource
	replacement.DialPort++
	replacement.ListenerID = "demo-other-listener"
	if _, err := server.wgPortRecoveryPut(context.Background(), p, replacement, false); err == nil {
		t.Fatal("port recovery accepted an identity or listener change")
	}
	if !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
		t.Fatal("rejected identity change advanced the signer")
	}
}

func TestWGPortRecoveryCurrentProtectsHealthyDirectionsAndEveryConsumer(t *testing.T) {
	for _, condition := range []string{"all recovered", "old healthy failed", "old consumer view", "receiver old listener"} {
		t.Run(condition, func(t *testing.T) {
			f := newWGRecoveryFixture(t)
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := OpenObservationStore(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			server := &Server{Runtime: &Runtime{Reports: store}, Now: func() time.Time { return f.now }}
			mappedResource := wgPortRecoveryResource(f.p, f.link.ResourceID)
			server.SSH = recoveryManagementFixture{nodes: []localconfig.NodeNetwork{{ID: mappedResource.OwnerNodeID, Ingress: []localconfig.IngressMapping{{Protocol: "udp", PublicHost: mappedResource.DialHost, PublicPorts: localconfig.PortRange{First: mappedResource.DialPort, Last: mappedResource.DialPort}, HostAddress: mappedResource.DialHost, HostPorts: localconfig.PortRange{First: mappedResource.DialPort, Last: mappedResource.DialPort}}}}}}
			healthy := testDerivedLink(t, f.p, "demo-other", "demo-exit")
			for _, device := range f.p.DeviceAuthorizations {
				samples := []Observation{}
				if device.ID == f.link.FromNodeID {
					samples = append(samples, f.sample(t, f.link, f.now.Add(-time.Second), "available"))
				} else if device.ID == healthy.FromNodeID {
					result := "available"
					if condition == "old healthy failed" {
						result = "unavailable"
					}
					samples = append(samples, f.sample(t, healthy, f.now.Add(-time.Second), result))
				}
				report := f.report(t, device.ID, 1, f.now, samples)
				if condition == "old consumer view" && device.ID == "demo-other" {
					report.ViewDigest = ReleaseDigest([]byte("demo-prior-view"))
					report.Runtime.AppliedViewDigest = report.ViewDigest
				} else if condition == "receiver old listener" && device.ID == f.link.ToNodeID {
					for i := range *report.Runtime.Resources {
						if (*report.Runtime.Resources)[i].ResourceID == f.link.ResourceID {
							(*report.Runtime.Resources)[i].Listen = "0.0.0.0:51819"
						}
					}
				}
				report = f.sign(t, report)
				if err := store.Put(report, device.DevicePublicKey); err != nil {
					t.Fatal(err)
				}
			}
			resource := wgPortRecoveryResource(f.p, f.link.ResourceID)
			got, err := server.wgPortRecoveryCurrent(context.Background(), f.p, resource, map[string]bool{f.link.ID: false, healthy.ID: true})
			if err != nil || got != (condition == "all recovered") {
				t.Fatal("recovery completion ignored a shared direction or consumer", err, got)
			}
		})
	}
}

func TestWGPortRecoveryHistoricalCompletionRequiresOneSimultaneousCut(t *testing.T) {
	for _, condition := range []string{"overlapping success", "later full view differs", "nonoverlapping success", "receiver report missing", "ambiguous window"} {
		t.Run(condition, func(t *testing.T) {
			f := newWGRecoveryFixture(t)
			healthy := testDerivedLink(t, f.p, "demo-other", "demo-exit")
			histories := []WGPortRecoveryReports{}
			for _, id := range []string{f.link.FromNodeID, healthy.FromNodeID, f.link.ToNodeID} {
				if condition == "receiver report missing" && id == f.link.ToNodeID {
					continue
				}
				at := f.now
				samples := []Observation{}
				if id == healthy.FromNodeID && condition == "nonoverlapping success" {
					at = f.now.Add(-40 * time.Second)
				}
				if id == f.link.FromNodeID {
					samples = append(samples, f.sample(t, f.link, at, "available"))
				} else if id == healthy.FromNodeID {
					samples = append(samples, f.sample(t, healthy, at, "available"))
				}
				report := f.report(t, id, 1, at, samples)
				if condition == "later full view differs" {
					report.ViewDigest = ReleaseDigest([]byte("demo-historical-view"))
					report.Runtime.AppliedViewDigest = report.ViewDigest
					report = f.sign(t, report)
				}
				histories = append(histories, WGPortRecoveryReports{DeviceID: id, Highest: 9, Reports: []DeviceReport{report}, Forked: condition == "ambiguous window"})
			}
			resource := wgPortRecoveryResource(f.p, f.link.ResourceID)
			got, err := wgPortRecoveryHistoricalComplete(f.p, resource, map[string]bool{f.link.ID: false, healthy.ID: true}, histories, f.now.Add(-time.Minute), f.now.Add(time.Minute))
			want := condition == "overlapping success" || condition == "later full view differs"
			if got != want || err != nil && condition != "ambiguous window" || err == nil && condition == "ambiguous window" {
				t.Fatal("historical completion changed scope or combined separate successes", err, got)
			}
		})
	}
}
