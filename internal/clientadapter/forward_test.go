package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

type forwardTestTransport func(*http.Request) (*http.Response, error)

func (f forwardTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestForwardOptimizationAppliesIndependentResourceMeasurements(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint("wg-faster=", reverse), func(t *testing.T) {
			view, _, at := resourceProbeFixture(t)
			wg, _, _ := resourceProbeFixture(t, "wireguard")
			view.Responsibilities = []string{"access", "forward"}
			view.Resources[0] = wg.Resources[0]
			for i := range view.Nodes {
				if view.Nodes[i].ID == "demo-exit" {
					view.Nodes[i].WireGuardPublicKey = *wg.Resources[0].Authentication.PublicKey
				}
			}
			view.TransportCredentials = slices.DeleteFunc(view.TransportCredentials, func(c control.TransportCredential) bool { return c.ResourceID == wg.Resources[0].ID })
			graphs, err := PolicyGraphs(view, []string{"demo-a"})
			if err != nil {
				t.Fatal(err)
			}
			local := []control.Observation{}
			wantResource := view.Resources[1].ID
			for _, link := range graphs[0].Links {
				rtt := int64(100)
				if link.Ref.ResourceID == view.Resources[1].ID {
					rtt = 25
				}
				if reverse {
					if link.Ref.ResourceID == view.Resources[0].ID {
						rtt = 20
					} else {
						rtt = 120
					}
					wantResource = view.Resources[0].ID
				}
				ref := link.Ref
				local = append(local, control.Observation{Level: "link", LinkID: ref.LinkID, ResourceID: ref.ResourceID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action,
					NetworkGeneration: "demo-network", Result: "available", RoundTripMS: new(rtt), DurationMS: new(rtt + 1), ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli()})
			}
			want, err := control.ForwardSegmentTag(wantResource)
			if err != nil {
				t.Fatal(err)
			}
			states := map[string]forwardReadback{}
			requests := []string{}
			var putErr error
			wantCount := 2
			transport := forwardTestTransport(func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				scope := strings.TrimPrefix(r.URL.Path, "/proxies/")
				state, ok := states[scope]
				if !ok {
					state = forwardReadback{Revision: "demo-initial", Choices: map[string][]string{"demo-exit": {}}}
				}
				if r.Method == http.MethodPut {
					if putErr != nil {
						return nil, putErr
					}
					var update struct {
						Choices  map[string][]string `json:"exit_choices"`
						Expected map[string][]string `json:"expected_exit_choices"`
						Revision string              `json:"expected_revision"`
					}
					if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
						return nil, err
					}
					if !reflect.DeepEqual(update.Expected, state.Choices) || update.Revision != state.Revision || len(update.Choices) != 1 || len(update.Choices["demo-exit"]) != wantCount || update.Choices["demo-exit"][0] != want {
						return nil, fmt.Errorf("wrong resource choice or incomplete CAS: %+v", update)
					}
					state = forwardReadback{Revision: state.Revision + "-applied", Choices: update.Choices}
					states[scope] = state
				}
				body, err := json.Marshal(state)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, err
			})
			selector := &HTTPSelector{secret: "demo-secret", client: &http.Client{Transport: transport}, started: time.Now()}
			lines := []string{}
			diagnostic := WithForwardDiagnosticLog(context.Background(), func(line string) error {
				lines = append(lines, line)
				if len(lines) == 1 {
					panic("demo-private diagnostic panic")
				}
				return errors.New("demo-private diagnostic error")
			})
			memory, err := selector.OptimizeForwarding(diagnostic, view, local, nil, "demo-network", at, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(memory) != len(view.Policies) || len(requests) != 3*len(view.Policies) {
				t.Fatal("each Policy must complete GET, CAS, and own readback", requests, memory)
			}
			for _, policy := range view.Policies {
				key := control.ForwardSelectorTag(policy.ID) + "\x00demo-exit"
				if memory[key].Decisions[""].Current != want {
					t.Fatal("confirmed memory does not match applied resource", key, memory[key])
				}
			}
			if len(lines) < 2*len(view.Policies) || !strings.Contains(strings.Join(lines, "\n"), "outcome=cas-success") {
				t.Fatal("forward lifecycle diagnostics omitted the plan or CAS result")
			}
			for _, forbidden := range []string{"demo-secret", "demo-private", "demo-network", view.DeviceID, "192.0.2.", view.Policies[0].ID, view.Resources[0].ID} {
				if strings.Contains(strings.Join(lines, "\n"), forbidden) {
					t.Fatal("forward diagnostics exposed identifiers, targets or error text")
				}
			}
			// A genuinely new, better original must expose pending proof memory
			// while the existing stability rule keeps the actual current choice.
			otherResource := view.Resources[0].ID
			if otherResource == wantResource {
				otherResource = view.Resources[1].ID
			}
			other, err := control.ForwardSegmentTag(otherResource)
			if err != nil {
				t.Fatal(err)
			}
			improved := slices.Clone(local)
			for index := range improved {
				rtt := int64(120)
				if improved[index].ResourceID == otherResource {
					rtt = 10
				}
				improved[index].ObservedAt = at.Add(time.Second).UnixMilli()
				improved[index].RoundTripMS, improved[index].DurationMS = new(rtt), new(rtt+1)
			}
			memory, err = selector.OptimizeForwarding(diagnostic, view, improved, nil, "demo-network", at.Add(time.Second), memory)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range memory {
				decision := value.Decisions[""]
				if decision.Current != want || decision.Pending != other || decision.Confirmations != 1 || decision.Through == 0 || value.Version == 0 || len(value.Samples) == 0 {
					t.Fatal("diagnostic delivery changed the actual stability decision", value)
				}
			}
			pendingLog := lines[len(lines)-1]
			if !strings.Contains(pendingLog, "confirmations=1") || strings.Contains(pendingLog, "sample_versions=-") || strings.Contains(pendingLog, otherResource) {
				t.Fatal("pending original proof was lost or emitted with raw resource identity")
			}
			putErr = errors.New("demo-private.example target-bearing CAS failure")
			for scope, value := range states {
				value.Choices = map[string][]string{"demo-exit": {}}
				states[scope] = value
			}
			unchanged, failed := selector.OptimizeForwarding(diagnostic, view, local, nil, "demo-network", at, memory)
			if !errors.Is(failed, putErr) || !reflect.DeepEqual(unchanged, memory) || !strings.Contains(strings.Join(lines, "\n"), "outcome=cas-failed") || strings.Contains(strings.Join(lines, "\n"), "demo-private.example") {
				t.Fatal("diagnostics changed failed CAS memory/cause or exposed its error text", failed)
			}
			putErr = nil
			// Current topology is reprojected: measurements cannot restore the
			// removed resource, even when it had the best RTT and confirmed memory.
			view.Resources = slices.DeleteFunc(view.Resources, func(r control.TransportResource) bool { return r.ID == wantResource })
			view.TransportCredentials = slices.DeleteFunc(view.TransportCredentials, func(c control.TransportCredential) bool { return c.ResourceID == wantResource })
			projections, err := forwardProjections(view)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range projections {
				if _, exists := p.Nodes[want]; exists {
					t.Fatal("withdrawn transport remained a forwarding candidate")
				}
			}
			wantCount = 1
			want, err = control.ForwardSegmentTag(view.Resources[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			memory, err = selector.OptimizeForwarding(context.Background(), view, local, nil, "demo-network", at, memory)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range memory {
				if value.Decisions[""].Current != want {
					t.Fatal("better stale measurement restored a withdrawn resource", key, value)
				}
			}
		})
	}
}
