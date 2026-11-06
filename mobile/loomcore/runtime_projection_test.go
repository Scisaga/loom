package loomcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

// Synthetic selection vectors enter the same typed pure calculation. The
// exported host bridge accepts only the authenticated current identity.
func evaluateTestRoutes(routesBody, observationsBody, preferenceBody, currentBody []byte,
	generation string, nowMS int64, targetsBody, resourcesBody, linksBody, scopesBody, memoryBody []byte, monotonicMS int64, graphsBody []byte) ([]byte, error) {
	var routes []clientmodel.RouteCandidate
	if err := decodeStrictJSON(routesBody, 1<<20, &routes); err != nil {
		return nil, fmt.Errorf("Android route projection: %w", err)
	}
	state, current, err := decodeAndroidRoutingSamples(observationsBody, currentBody, resourcesBody, linksBody, memoryBody, generation)
	if err != nil {
		return nil, err
	}
	if len(preferenceBody) == 0 {
		preferenceBody, _ = control.CanonicalEncode(clientmodel.EmptyPreference())
	}
	if err := control.DecodeCanonical(preferenceBody, &state.Preference, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 1024}); err != nil {
		return nil, err
	}
	var scopes []string
	if len(scopesBody) > 0 {
		if err := decodeStrictJSON(scopesBody, 1<<20, &scopes); err != nil {
			return nil, err
		}
	}
	if len(graphsBody) > 0 {
		if err := decodeStrictJSON(graphsBody, 8<<20, &state.Graphs); err != nil {
			return nil, err
		}
	}
	var groups []control.ServiceProbeTargets
	if len(targetsBody) > 0 {
		if err := decodeStrictJSON(targetsBody, 1<<20, &groups); err != nil {
			return nil, err
		}
	}
	targets := map[string][]string{}
	for _, group := range groups {
		if control.ValidateID(group.ServiceID) != nil {
			return nil, errors.New("invalid Service probe group")
		}
		if _, found := targets["service:"+group.ServiceID]; found {
			return nil, errors.New("duplicate Service probe group")
		}
		for _, target := range group.Targets {
			if control.ValidateHTTPSURL(target) != nil {
				return nil, errors.New("invalid Service probe target")
			}
		}
		targets["service:"+group.ServiceID], targets["local_network:"+group.ServiceID] = group.Targets, group.Targets
	}
	return evaluateAndroidRouting(routes, state, current, scopes, targets, nowMS, monotonicMS)
}

func TestAndroidEvaluationUsesCurrentPolicyAndIndependentLAN(t *testing.T) {
	var baseline []byte
	for _, additional := range []int{0, 40} {
		t.Run(fmt.Sprint(additional), func(t *testing.T) {
			identity, body := androidFixture(t, 7, false, func(p *control.Projection) {
				p.DeviceAuthorizations[0].Responsibilities = []string{"access", "forward"}
				second := p.NetworkIntent.Policies[0]
				second.ID, second.ServiceID = "demo-policy-b", "demo-service-b"
				p.NetworkIntent.Services = append(p.NetworkIntent.Services, control.Service{ID: second.ServiceID, Name: "Demo second service", Kind: "internet", RestrictToProbeTargets: new(false)})
				p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, second)
				p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, second.ID)
				prefix, err := control.AllocateLocalNetworkPrefix(p.NetworkID, "demo-lan", 0, "192.0.2.0/24", nil)
				if err != nil {
					t.Fatal(err)
				}
				p.NetworkIntent.Services = append(p.NetworkIntent.Services, control.Service{ID: "demo-lan", Name: "Demo LAN", Kind: "local_network", RestrictToProbeTargets: new(false), LocalNetwork: &control.LocalNetwork{GatewayNodeID: "demo-access", LocalPrefix: "192.0.2.0/24", VirtualPrefix: prefix.String(), Enabled: true}})
				lan := p.NetworkIntent.Policies[0]
				lan.ID, lan.ServiceID, lan.ExitScope, lan.AllowDirect, lan.LocalEgressDevices = "demo-policy-lan", "demo-lan", nil, nil, nil
				p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, lan)
				p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, lan.ID)
				for i := range additional {
					unused := second
					unused.ID = fmt.Sprintf("demo-unused-%02d", i)
					p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, unused)
					p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, unused.ID)
				}
			})
			chosen, err := ChooseAndroidPolicy(body, "demo-policy")
			if err != nil {
				t.Fatal(err)
			}
			profile, err := AndroidDeviceProfile(chosen)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			var projected androidProfile
			if json.Unmarshal(profile, &fields) != nil || json.Unmarshal(profile, &projected) != nil || fields["graphs"] != nil || len(projected.Routes) != 2 {
				t.Fatal("profile serialized per-Policy graphs or unselected candidates")
			}
			now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli()
			first, err := EvaluateAndroidRoutes(chosen, nil, nil, "demo-network", now, nil, nil, nil, 1000, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if additional == 0 {
				baseline = first
			} else if !bytes.Equal(baseline, first) {
				t.Fatal("unselected Policies expanded the evaluation bridge output")
			}
			var application runtimeApplication
			if json.Unmarshal(first, &application) != nil || application.PolicyID != "demo-policy" || application.ServiceID != "demo-service" || len(application.Selections) != 2 || application.LANPolicyIDs["demo-lan"] != "demo-policy-lan" {
				t.Fatal("current Internet/LAN choice was not applied", string(first))
			}
			current := map[string]clientmodel.Selection{}
			for _, item := range application.Selections {
				current[item.Selector] = clientmodel.Selection{Scope: item.Selector, PolicyID: item.PolicyID, Choices: item.Choices, CandidateID: item.Candidate, Targets: item.Targets}
			}
			currentBody, _ := json.Marshal(current)
			switched, err := ChooseAndroidPolicy(chosen, "demo-policy-b")
			if err != nil {
				t.Fatal(err)
			}
			// Reuse the running selectors without creating a second profile.
			next, err := EvaluateAndroidRoutes(switched, nil, currentBody, "demo-network", now+1, nil, nil, nil, 1001, nil, nil)
			if err != nil || json.Unmarshal(next, &application) != nil || application.PolicyID != "demo-policy-b" || application.ServiceID != "demo-service-b" || len(application.Selections) != 2 {
				t.Fatal("a live Policy change retained the initial graph/selection", string(next), err)
			}
			for _, item := range application.Selections {
				if item.Selector == control.AccessSelectorScope && (item.PolicyID != "demo-policy-b" || item.ExpectedPolicyID != "demo-policy") || item.Selector == "local_network:demo-lan" && (item.PolicyID != "demo-policy-lan" || item.Candidate != current[item.Selector].CandidateID) {
					t.Fatal("Internet hot-switch altered the independent LAN or used the old Policy", item)
				}
			}
			accepted, err := decodeState(switched)
			if err != nil || accepted.LKG.Signature != identity.LKG.Signature || accepted.PrivateKey != identity.PrivateKey || accepted.ReportSequence != identity.ReportSequence {
				t.Fatal("local optimization changed authenticated identity or progress", err)
			}
		})
	}
}

func TestAndroidEvaluationRejectsUnauthenticatedState(t *testing.T) {
	if _, err := EvaluateAndroidRoutes([]byte(`{"schema":3}`), nil, nil, "demo-network", 1, nil, nil, nil, 1, nil, nil); err == nil {
		t.Fatal("raw projections bypassed the protected identity boundary")
	}
}
