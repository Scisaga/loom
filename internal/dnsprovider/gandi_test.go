package dnsprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGandiReplaceUsesBearerAndReadback(t *testing.T) {
	t.Helper()
	desired := RRSet{Zone: "example.test", Name: "edge", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/domains/example.test/records/edge/A" || r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Fatalf("unexpected request: %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodPut {
			var body gandiRRSet
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RRSetTTL != 300 || len(body.RRSetValues) != 1 {
				t.Fatalf("unexpected PUT body: %#v err=%v", body, err)
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		_ = json.NewEncoder(w).Encode(gandiRRSet{RRSetTTL: 300, RRSetValues: []string{"203.0.113.8"}})
	}))
	defer server.Close()

	provider, err := newGandi(server.URL, "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Replace(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || !Equal(got.RRSet, desired) {
		t.Fatalf("replace/readback mismatch: requests=%d got=%#v", requests, got.RRSet)
	}
}

func TestGandiRejectsScopeEscapeBeforeNetwork(t *testing.T) {
	provider, err := newGandi("http://127.0.0.1:1", "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []RRSet{
		{Zone: "other.test", Name: "edge", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}},
		{Zone: "example.test", Name: "control", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}},
	} {
		if _, err := provider.Replace(context.Background(), input); err == nil {
			t.Fatalf("scope escape accepted: %#v", input)
		}
	}
}

func TestNormalizeIsDeterministic(t *testing.T) {
	got, err := Normalize(RRSet{Zone: "EXAMPLE.TEST.", Name: "Edge.", Type: "a", TTL: 300, Values: []string{"203.0.113.9", "203.0.113.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone != "example.test" || got.Name != "edge" || got.Type != "A" || got.Values[0] != "203.0.113.8" {
		t.Fatalf("not canonical: %#v", got)
	}
}

func TestGandiRejectsRedirectWithoutForwardingCredential(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		redirected++
		if request.Header.Get("Authorization") != "" {
			t.Fatal("Gandi credential 被带到 redirect target")
		}
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	provider, err := newGandi(origin.URL, "secret-token", GandiScope{Zone: "example.test", AllowedNamePrefixes: []string{"edge"}}, origin.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Replace(context.Background(), RRSet{Zone: "example.test", Name: "edge", Type: "A", TTL: 300, Values: []string{"203.0.113.8"}})
	if err == nil || redirected != 0 {
		t.Fatalf("redirect 未失败关闭: err=%v redirected=%d", err, redirected)
	}
}
