package linuxclient

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
	"loom/protocol"
)

func TestEntryScopeUpdatesAdmissionWithoutReplacingForwardFacilities(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	build := func(scope control.PolicyScope, admitted bool) string {
		t.Helper()
		p.NetworkIntent.Policies[0].EntryScope = scope
		view, err := control.ProjectDeviceView(p, "demo-entry")
		if err != nil {
			t.Fatal(err)
		}
		executions, err := prepareResourceExecutions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		config, err := nodeRuntimeConfig(view, "demo-secret", nil, "mixed", executions)
		if err != nil {
			t.Fatal(err)
		}
		wg, _, err := projectWireGuard(view, executions)
		if err != nil {
			t.Fatal(err)
		}
		config, err = appendNativeWireGuard(config, view, wg, nil, keys[view.DeviceID])
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal([]byte(config), &document); err != nil {
			t.Fatal(err)
		}
		checked := 0
		for _, section := range []string{"endpoints", "inbounds"} {
			entries, _ := document[section].([]any)
			for _, raw := range entries {
				entry := raw.(map[string]any)
				if entry["execution"] == nil {
					continue
				}
				body, _ := json.Marshal(entry["execution"])
				var receiver struct {
					Policies []struct {
						Policy protocol.HopPolicy `json:"policy"`
					} `json:"policies"`
				}
				if err := json.Unmarshal(body, &receiver); err != nil {
					t.Fatal(err)
				}
				for _, value := range receiver.Policies {
					if value.Policy.PolicyID != p.NetworkIntent.Policies[0].ID {
						continue
					}
					if value.Policy.EntryScope.Mode != scope.Mode || !reflect.DeepEqual(value.Policy.EntryScope.NodeIDs, scope.NodeIDs) {
						t.Fatal("receiver changed the actual entry permission")
					}
					_, err := value.Policy.Admit(protocol.PathContext{OriginID: "demo-access", FinalExitID: "demo-exit", Visited: []string{}},
						protocol.HopPermission{SenderID: "demo-access", ReceiverID: "demo-entry", Purpose: "access", Forward: true})
					if (err == nil) != admitted {
						t.Fatal("receiver did not enforce the current first-hop permission")
					}
					checked++
				}
			}
		}
		if checked != 2 {
			t.Fatal("both WG and Hy2 receiving projections must enforce entry scope")
		}
		return config
	}
	anyConfig := build(control.PolicyScope{Mode: "any", NodeIDs: []string{}}, true)
	only := build(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}, true)
	withdrawn := build(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}, false)
	for _, pair := range [][2]string{{anyConfig, only}, {only, anyConfig}, {anyConfig, withdrawn}} {
		changes, hot, err := clientadapter.ReceiverChanges(pair[0], pair[1])
		if err != nil || !hot {
			t.Fatal("entry permission change replaced unchanged forward facilities", hot, err)
		}
		updated, err := clientadapter.WithReceiverChanges(pair[0], changes)
		if err != nil {
			t.Fatal(err)
		}
		var actual, want any
		if json.Unmarshal([]byte(updated), &actual) != nil || json.Unmarshal([]byte(pair[1]), &want) != nil || !reflect.DeepEqual(actual, want) {
			t.Fatal("entry permission update did not reproduce the complete current projection")
		}
	}
}

func TestLocalAccessRevocationRetainsSharedForwardFacilities(t *testing.T) {
	hy2, input, at := resourceExecutionFixture(t, time.Now())
	_, _, makeView := linuxAcceptanceFixture(t, func(sequence uint64, view *control.DeviceView) {
		view.Responsibilities = []string{"access", "forward", "internet_egress"}
		resource := hy2.Resources[0]
		resource.OwnerNodeID = view.DeviceID
		view.Resources = []control.TransportResource{resource}
		service, policy := view.Services[0], view.Policies[0]
		service.ID, service.Name = "demo-spare", "Demo spare"
		policy.ID, policy.Name, policy.ServiceID = "demo-spare-policy", "Demo spare policy", service.ID
		view.Services = append(view.Services, service)
		view.Policies = append(view.Policies, policy)
		if sequence < 8 {
			view.PolicyIDs = append(view.PolicyIDs, policy.ID)
		}
		if sequence >= 9 {
			view.PolicyIDs = []string{}
		}
	})
	views := []control.DeviceView{makeView(7, true).View, makeView(8, true).View, makeView(9, true).View}
	configs := make([]string, len(views))
	for index, view := range views {
		config, err := clientadapter.RuntimeSource(view, "demo-secret", true)
		if err != nil {
			t.Fatal(err)
		}
		assertOfficialAccessPolicies(t, []byte(config), view.PolicyIDs)
		executions, err := prepareResourceExecutions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nodeRuntimeConfig(view, "demo-secret", nil, "mixed", executions); err != nil {
			t.Fatal("retained forwarding facilities lost their receiving business entry", err)
		}
		configs[index] = config
	}
	for _, pair := range [][2]int{{0, 1}, {1, 0}, {1, 2}} {
		before, after := configs[pair[0]], configs[pair[1]]
		changes, hot, err := clientadapter.ReceiverChanges(before, after)
		if err != nil || !hot {
			t.Fatal("changing only local access grants replaced retained shared facilities", err)
		}
		updated, err := clientadapter.WithReceiverChanges(before, changes)
		if err != nil {
			t.Fatal(err)
		}
		var actual, want any
		if json.Unmarshal([]byte(updated), &actual) != nil || json.Unmarshal([]byte(after), &want) != nil || !reflect.DeepEqual(actual, want) {
			t.Fatal("access update did not derive the exact current permission and component references")
		}
	}
	for _, change := range []func(map[string]any){
		func(outbound map[string]any) { outbound["hop"].(map[string]any)["node_id"] = "demo-other" },
		func(outbound map[string]any) { outbound["hop"].(map[string]any)["runtime_fallback"] = true },
	} {
		var document map[string]any
		if err := json.Unmarshal([]byte(configs[1]), &document); err != nil {
			t.Fatal(err)
		}
		for _, raw := range document["outbounds"].([]any) {
			outbound := raw.(map[string]any)
			if outbound["tag"] == control.ForwardSelectorTag("demo-spare-policy") {
				change(outbound)
			}
		}
		body, _ := json.Marshal(document)
		if _, err := deriveLinuxMixedRuntime(string(body)); err == nil {
			t.Fatal("an unknown or differently owned hop selector manufactured a business entry")
		}
	}
}

func TestMultiExitEntryScopeKeepsFacilitiesAndValidFinalConnections(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" || p.DeviceAuthorizations[i].ID == "demo-exit" {
			p.DeviceAuthorizations[i].Responsibilities = []string{"forward", "internet_egress"}
			if p.DeviceAuthorizations[i].ID == "demo-entry" {
				p.DeviceAuthorizations[i].Responsibilities = []string{"access", "forward", "internet_egress"}
				p.DeviceAuthorizations[i].PolicyIDs = []string{"demo-policy"}
			}
		}
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-exit-wg" {
			p.NetworkIntent.Resources[i].AccessEnabled = true
		}
	}
	policy := &p.NetworkIntent.Policies[0]
	policy.RelayScope = control.PolicyScope{Mode: "none", NodeIDs: []string{}}
	policy.ExitScope = new(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry", "demo-exit"}})
	policy.MaxHops = 2
	policy.EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry", "demo-exit"}}
	build := func() (control.DeviceExecution, map[string]any) {
		view, err := control.ProjectDeviceView(p, "demo-entry")
		if err != nil {
			t.Fatal(err)
		}
		execution, err := control.ProjectDeviceExecution(view, nil)
		if err != nil {
			t.Fatal(err)
		}
		executions, err := prepareResourceExecutions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		config, err := nodeRuntimeConfig(view, "demo-secret", nil, "mixed", executions)
		if err != nil {
			t.Fatal(err)
		}
		wg, _, err := projectWireGuard(view, executions)
		if err != nil {
			t.Fatal(err)
		}
		config, err = appendNativeWireGuard(config, view, wg, nil, keys[view.DeviceID])
		if err != nil {
			t.Fatal(err)
		}
		execution.RuntimeProfile.Config = config
		var document map[string]any
		if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &document); err != nil {
			t.Fatal(err)
		}
		return execution, document
	}
	first, before := build()
	policy.EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
	next, after := build()
	old := protocol.PathContext{OriginID: "demo-access", FinalExitID: "demo-entry", Visited: []string{"demo-exit", "demo-entry"}}
	permission := protocol.HopPermission{SenderID: "demo-exit", ReceiverID: "demo-entry", Purpose: "forward", Forward: true, InternetEgress: true}
	for _, execution := range []control.DeviceExecution{first, next} {
		hop, err := control.HopPolicyProjection(execution, execution.Policies[0])
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := hop.Compile()
		if err != nil {
			t.Fatal(err)
		}
		if err := compiled.VerifyCurrent(old, permission); err != nil {
			t.Fatal("old final-egress flow is not currently allowed", err)
		}
	}
	source, err := control.ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := control.ProjectDeviceCandidates(source, []string{policy.ID})
	if err != nil {
		t.Fatal(err)
	}
	entryStillEligible := false
	for _, candidate := range candidates.Routes {
		entryStillEligible = entryStillEligible || candidate.EntryNodeID == "demo-exit" && candidate.FinalExit == "demo-entry" && candidate.FirstResourceID == "demo-exit-wg"
	}
	if !entryStillEligible {
		t.Fatal("there is no legitimate source entry for the purported preserved flow")
	}
	changes, hot, err := clientadapter.ReceiverChanges(first.RuntimeProfile.Config, next.RuntimeProfile.Config)
	if err != nil {
		t.Fatal(err)
	}

	if !hot {
		t.Fatal("entry qualification changed a retained forward facility")
	}
	updated, err := clientadapter.WithReceiverChanges(first.RuntimeProfile.Config, changes)
	if err != nil {
		t.Fatal(err)
	}
	var updatedDocument map[string]any
	if json.Unmarshal([]byte(updated), &updatedDocument) != nil || !reflect.DeepEqual(updatedDocument, after) {
		t.Fatal("permission delta did not reproduce the complete current projection")
	}
	ownCandidates, err := control.ProjectDeviceCandidates(next.DeviceView, []string{policy.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range ownCandidates.Routes {
		if candidate.EntryNodeID == next.DeviceID {
			t.Fatal("composed access role bypassed the actual entry scope")
		}
	}
	oldSpecs, err := control.LinkSpecifications(first.DeviceView)
	if err != nil {
		t.Fatal(err)
	}
	newSpecs, err := control.LinkSpecifications(next.DeviceView)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldSpecs, newSpecs) || !reflect.DeepEqual(first.Links, next.Links) {
		t.Fatal("retaining facilities expanded the shared link measurement universe")
	}
	oldProbes, err := control.FirstHopProbes(first)
	if err != nil {
		t.Fatal(err)
	}
	newProbes, err := control.FirstHopProbes(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(newProbes) > len(oldProbes) {
		t.Fatal("entry narrowing added access measurement jobs")
	}
	_ = before
}
