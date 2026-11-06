package clientadapter

import (
	"context"
	"encoding/json"
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
			wantCount := 2
			transport := forwardTestTransport(func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				scope := strings.TrimPrefix(r.URL.Path, "/proxies/")
				state, ok := states[scope]
				if !ok {
					state = forwardReadback{Revision: "demo-initial", Choices: map[string][]string{"demo-exit": {}}}
				}
				if r.Method == http.MethodPut {
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
			memory, err := selector.OptimizeForwarding(context.Background(), view, local, nil, "demo-network", at, nil)
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
