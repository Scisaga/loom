package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type continuitySelector struct {
	*fakeSelector
	connections map[string]net.Conn
	fail        string
}

var errContinuityPreparation = errors.New("demo preparation unavailable")

func (s *continuitySelector) Set(ctx context.Context, scope, candidate string) error {
	if candidate == s.fail {
		return errContinuityPreparation
	}
	return s.fakeSelector.Set(ctx, scope, candidate)
}

func (s *continuitySelector) CloseConnections(_ context.Context, scopes []string) error {
	s.closed++
	for _, scope := range scopes {
		if conn := s.connections[scope]; conn != nil {
			_ = conn.Close()
		}
	}
	return nil
}

func continuityStream(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		<-done
	})
	return client
}

func continuityExchange(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("legal old connection was closed", err)
	}
	if _, err := conn.Write([]byte("demo")); err != nil {
		t.Fatal("legal old connection stopped carrying data", err)
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(conn, body); err != nil || string(body) != "demo" {
		t.Fatal("legal old connection lost its response", string(body), err)
	}
}

func TestSelectorRejectionAndFailedSelectionKeepExistingConnections(t *testing.T) {
	for _, scenario := range []string{"explicit rejection", "blocked proposal", "failed proposal"} {
		t.Run(scenario, func(t *testing.T) {
			s := &continuitySelector{
				fakeSelector: &fakeSelector{current: map[string]string{"access": "demo-a", "local_network:demo-lan": "demo-lan-path"}},
				connections:  map[string]net.Conn{"access": continuityStream(t), "local_network:demo-lan": continuityStream(t)},
			}
			var actual map[string]string
			var err error
			switch scenario {
			case "explicit rejection":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				actual, err = RejectSelections(ctx, s, []string{"access"})
			case "blocked proposal":
				actual, err = ApplySelections(context.Background(), s, map[string]string{"access": BlockedSelection})
			case "failed proposal":
				s.fail = "demo-b"
				actual, err = ApplySelections(context.Background(), s, map[string]string{"access": "demo-b"})
				if !errors.Is(err, errContinuityPreparation) {
					t.Fatal("failed proposal lost its original error", err)
				}
			}
			if scenario != "failed proposal" && err != nil || actual["access"] != BlockedSelection {
				t.Fatal("new-connection rejection was not confirmed", actual, err)
			}
			if s.closed != 0 || s.current["local_network:demo-lan"] != "demo-lan-path" {
				t.Fatal("ordinary rejection closed flows or changed another scope", s.closed, s.current)
			}
			continuityExchange(t, s.connections["access"])
			continuityExchange(t, s.connections["local_network:demo-lan"])
			// A separate explicit rebuild still closes only the requested scope.
			if err := s.CloseConnections(context.Background(), []string{"access"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.connections["access"].Write([]byte("demo")); err == nil {
				t.Fatal("explicit rebuild did not close the requested connection")
			}
			continuityExchange(t, s.connections["local_network:demo-lan"])
		})
	}
}

func TestSameServicePreferenceRetainsBothPoliciesInSourcePermissions(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	view.Policies[1].ServiceID = view.Policies[0].ServiceID
	first, firstConfig, err := AccessRuntimeProjection(view, []string{view.Policies[0].ID}, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	second, secondConfig, err := AccessRuntimeProjection(view, []string{view.Policies[1].ID}, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	if firstConfig != secondConfig || len(first) == 0 || len(second) == 0 {
		t.Fatal("preference changed complete permissions or lost executable candidates")
	}
	for _, candidate := range first {
		if candidate.PolicyID != view.Policies[0].ID {
			t.Fatal("first preference generated another Policy")
		}
	}
	for _, candidate := range second {
		if candidate.PolicyID != view.Policies[1].ID {
			t.Fatal("second preference generated another Policy")
		}
	}
	var document struct {
		Outbounds []struct {
			Tag    string `json:"tag"`
			Access struct {
				Policies []struct {
					Policy struct {
						ID string `json:"policy_id"`
					} `json:"policy"`
				} `json:"policies"`
			} `json:"access"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(secondConfig), &document); err != nil {
		t.Fatal(err)
	}
	policies := map[string]bool{}
	for _, outbound := range document.Outbounds {
		if outbound.Tag == "access" {
			for _, policy := range outbound.Access.Policies {
				policies[policy.Policy.ID] = true
			}
		}
	}
	if !policies[view.Policies[0].ID] || !policies[view.Policies[1].ID] {
		t.Fatal("source permissions discarded a still-authorized Policy", policies)
	}
}
