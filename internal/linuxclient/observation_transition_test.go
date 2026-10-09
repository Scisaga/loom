package linuxclient

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func TestAcceptedViewPreservesOnlyUnchangedBusinessEvidence(t *testing.T) {
	for _, test := range []struct {
		name         string
		change       func(*control.DeviceView)
		cache        func(*LocalState)
		lostPrior    bool
		newNetwork   bool
		wantA, wantB bool
	}{
		{name: "display name", change: func(v *control.DeviceView) { v.Name = "Demo renamed device" }, wantA: true, wantB: true},
		{name: "candidate specification", change: func(v *control.DeviceView) { v.Policies[0].Name = "Demo revised policy" }, wantB: true},
		{name: "business target", change: func(v *control.DeviceView) { v.BusinessProbeTargets[0].Targets[0] = "https://demo-a.example/other" }, wantB: true},
		{name: "resolver", change: func(v *control.DeviceView) { v.DNSServers = []string{"192.0.2.54"} }},
		{name: "withdrawn service", change: func(v *control.DeviceView) {
			v.Policies[0].Action = "deny"
			v.BusinessProbeTargets = v.BusinessProbeTargets[1:]
		}, wantB: true},
		{name: "multiple targets", change: func(v *control.DeviceView) {
			v.BusinessProbeTargets[0].Targets = append(v.BusinessProbeTargets[0].Targets, "https://demo-a.example/other")
		}, wantA: true, wantB: true},
		{name: "restart without prior view", lostPrior: true},
		{name: "old targetless cache", cache: func(s *LocalState) {
			for i := range s.Observations {
				s.Observations[i].Target = ""
			}
		}},
		{name: "cache from a different view", cache: func(s *LocalState) { s.ObservationViewDigest = "sha256:" + strings.Repeat("f", 64) }},
		{name: "underlay changed", newNetwork: true},
		{name: "unproven diagnostic action", cache: func(s *LocalState) {
			for i := range s.Observations {
				if s.Observations[i].Scope == "service:demo-a" {
					s.Observations[i].Action = "demo-diagnostic"
				}
			}
		}, wantB: true},
		{name: "TUN endpoint exclusion", change: func(v *control.DeviceView) {
			v.Endpoints[0].Generation++
			v.Endpoints[0].Host = "192.0.2.2"
		}, cache: func(s *LocalState) {
			for i := range s.Observations {
				s.Observations[i].Action = "tcp_udp_dns"
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, identityPath, makeView := linuxAcceptanceFixture(t, func(sequence uint64, v *control.DeviceView) {
				scope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
				v.PolicyIDs = []string{"demo-a", "demo-b"}
				v.Services, v.Policies = []control.Service{}, []control.NetworkPolicy{}
				for _, id := range v.PolicyIDs {
					v.Services = append(v.Services, control.Service{ID: id, Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: id + ".example"}}})
					v.Policies = append(v.Policies, control.NetworkPolicy{ID: id, Name: "Demo policy", ServiceID: id, Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: new(scope), AllowDirect: new(true), LocalEgressDevices: new([]string{})})
				}
				v.DNSServers = []string{"192.0.2.53"}
				v.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-a", Targets: []string{"https://demo-a.example/"}}, {ServiceID: "demo-b", Targets: []string{"https://demo-b.example/"}}}
				if sequence == 8 && test.change != nil {
					test.change(v)
				} else if sequence == 8 {
					v.Name = "Demo next view"
				}
			})
			previous, next := makeView(7, true), makeView(8, true)
			if previous.ViewDigest == next.ViewDigest {
				t.Fatal("fixture did not change the authenticated View")
			}
			if err := store.SaveLKG(previous); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "runtime.json")
			state, err := loadLocalStateForView(path, "demo-network", store.LKG(), nil)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			for _, route := range previous.View.Routes {
				outcome := "available"
				if route.ServiceID == "demo-b" {
					outcome = "unavailable"
				}
				state.Observations = append(state.Observations, clientmodel.Observation{CandidateID: route.ID, Target: "https://" + route.ServiceID + ".example/", NetworkGeneration: state.NetworkGeneration, Scope: route.Scope, Action: "https_request", Result: outcome, ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339), MetricMillis: 17})
			}
			if test.cache != nil {
				test.cache(&state)
			}
			if err := SaveLocalState(path, state); err != nil {
				t.Fatal(err)
			}
			// A CLI write after the runtime took its old snapshot must survive
			// the cache transition under the same existing file lock.
			preference := clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeDirect}
			if err := SetPreference(path, state.NetworkGeneration, preference); err != nil {
				t.Fatal(err)
			}
			if changed, err := acceptCertifiedView(store, next); err != nil || !changed {
				t.Fatal("next signed View was not durably accepted", err)
			}
			prior := &previous
			if test.lostPrior {
				prior = nil
			}
			generation := state.NetworkGeneration
			if test.newNetwork {
				generation = "demo-next-network"
			}
			actual, err := loadLocalStateForView(path, generation, store.LKG(), prior)
			if err != nil {
				t.Fatal(err)
			}
			wanted := []clientmodel.Observation{}
			for _, observation := range state.Observations {
				if observation.Scope == "service:demo-a" && test.wantA || observation.Scope == "service:demo-b" && test.wantB {
					wanted = append(wanted, observation)
				}
			}
			if !reflect.DeepEqual(actual.Observations, wanted) || actual.Preference != preference || actual.ObservationViewDigest != next.ViewDigest || actual.NetworkGeneration != generation {
				t.Fatal("transition lost valid evidence/preference or retained changed evidence")
			}
			restarted, err := deviceclient.Load(identityPath)
			if err != nil || !reflect.DeepEqual(restarted.LKG(), &next) {
				t.Fatal("cache transition changed the sole persistent authenticated View", err)
			}
			readback, err := loadLocalState(path, generation, next.ViewDigest)
			if err != nil || !reflect.DeepEqual(readback, actual) {
				t.Fatal("transition was not persisted canonically", err)
			}
			if _, err := SaveObservations(path, state); err == nil {
				t.Fatal("stale writer restored observations from the previous binding")
			}
		})
	}
}

func TestObservationExecutionIncludesNativeSenderIdentity(t *testing.T) {
	before := observationOutbounds(&control.RuntimeProfile{Kind: "sing_box", Config: `{"outbounds":[{"detour":"demo-hop","inet6_bind_address":"fdab::2","tag":"demo-route","type":"direct"}],"endpoints":[{"private_key":"demo-hop-secret","tag":"demo-hop","type":"wireguard"}]}`})
	if !sameObservationOutbound(before, before, "demo-route") {
		t.Fatal("unchanged private execution was discarded")
	}
	for _, tag := range []string{"demo-route", "demo-hop"} {
		after := map[string]json.RawMessage{}
		for key, value := range before {
			after[key] = value
		}
		after[tag] = json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(string(after[tag]), "-secret", "-changed"), "fdab::2", "fdab::3"))
		if sameObservationOutbound(before, after, "demo-route") {
			t.Fatal("a changed outbound credential reused an old business result")
		}
	}
	cycle := map[string]json.RawMessage{"demo-route": json.RawMessage(`{"detour":"demo-route","tag":"demo-route"}`)}
	if sameObservationOutbound(cycle, cycle, "demo-route") || sameObservationOutbound(nil, nil, "demo-missing") {
		t.Fatal("missing or cyclic execution established observation equivalence")
	}
}
