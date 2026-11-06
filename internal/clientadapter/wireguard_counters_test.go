package clientadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"loom/internal/control"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWireGuardCounterReadRequiresActualAuthorizedPeerSample(t *testing.T) {
	raw := []byte(strings.Repeat("a", 32))
	public := base64.RawURLEncoding.EncodeToString(raw)
	expected := []control.WireGuardPeerCounter{{PublicKey: public, Links: []control.WireGuardCounterLink{}}}
	valid := `{"endpoints":[{"interface":"wg-shared","epoch":"` + strings.Repeat("a", 32) + `","peers":[{"public_key":"` + public + `","rx_bytes":"0","tx_bytes":"18446744073709551615"}]}]}`
	body := valid
	status := http.StatusOK
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/loom/wireguard-counters" || r.Header.Get("Authorization") != "Bearer demo-secret" {
			t.Error("wrong running entry")
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer server.Close()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:61800" {
			t.Error("counter read escaped local owner")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	ctx, err := NativeDiagnosticContext(context.Background(), "demo-secret", dial)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.UnixMilli(123) }
	got, err := observeWireGuardCounters(ctx, "wg-shared", expected, now)
	if err != nil || got == nil || got.ObservedAt != 123 || got.Peers[0].RXBytes != 0 || got.Peers[0].TXBytes != 18446744073709551615 {
		t.Fatal("actual zero or full unsigned precision lost", err)
	}
	if expected[0].TXBytes != 0 {
		t.Fatal("reading runtime counters mutated the View binding")
	}
	for _, bad := range []string{strings.Replace(valid, `,"rx_bytes":"0"`, "", 1), strings.Replace(valid, `"rx_bytes":"0"`, `"rx_bytes":null`, 1), strings.Replace(valid, public, "demo-wrong", 1), strings.Replace(valid, `"wg-shared"`, `"resource:demo-other"`, 1), strings.Replace(valid, `"0"`, `0`, 1), valid + `{}`, `{"endpoints":[]}`, strings.Replace(valid, `"interface"`, `"unknown"`, 1)} {
		if !json.Valid([]byte(bad)) && bad != valid+`{}` {
			t.Fatal("bad fixture")
		}
		body = bad
		if got, err := observeWireGuardCounters(ctx, "wg-shared", expected, now); err == nil || got != nil {
			t.Fatal("incomplete or foreign sample invented a measurement")
		}
	}
	other := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	retired := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("d", 32)))
	link := control.WireGuardCounterLink{LinkID: "demo-link", SpecDigest: "sha256:" + strings.Repeat("1", 64)}
	allowed := []control.WireGuardPeerCounter{{PublicKey: public, Links: []control.WireGuardCounterLink{link}}, {PublicKey: other, Links: []control.WireGuardCounterLink{}}}
	frame := func(peers ...map[string]any) string {
		t.Helper()
		if peers == nil {
			peers = []map[string]any{}
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i]["public_key"].(string) < peers[j]["public_key"].(string) })
		body, err := json.Marshal(map[string]any{"endpoints": []any{map[string]any{"interface": "wg-shared", "epoch": strings.Repeat("a", 32), "peers": peers}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	observed := map[string]any{"public_key": public, "rx_bytes": "7", "tx_bytes": "11"}
	oldSlot := map[string]any{"public_key": retired, "rx_bytes": "19", "tx_bytes": "23"}
	for _, tc := range []struct {
		name string
		body string
		want []control.WireGuardPeerCounter
	}{
		{"allowed subset", frame(observed), []control.WireGuardPeerCounter{{PublicKey: public, RXBytes: 7, TXBytes: 11, Links: []control.WireGuardCounterLink{link}}}},
		{"retired slot filtered", frame(observed, oldSlot), []control.WireGuardPeerCounter{{PublicKey: public, RXBytes: 7, TXBytes: 11, Links: []control.WireGuardCounterLink{link}}}},
		{"no allowed observation", frame(oldSlot), []control.WireGuardPeerCounter{}},
		{"no observed slots", frame(), []control.WireGuardPeerCounter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body = tc.body
			got, err := observeWireGuardCounters(ctx, "wg-shared", allowed, now)
			if err != nil || got == nil || !reflect.DeepEqual(got.Peers, tc.want) {
				t.Fatal("unobserved peer was filled with zero or retired slot escaped current authorization", got, err)
			}
		})
	}
	for _, invalid := range []string{
		frame(observed, observed),
		frame(observed, map[string]any{"public_key": retired, "rx_bytes": "19"}),
		frame(observed, map[string]any{"public_key": retired + "=", "rx_bytes": "19", "tx_bytes": "23"}),
	} {
		body = invalid
		if got, err := observeWireGuardCounters(ctx, "wg-shared", allowed, now); err == nil || got != nil {
			t.Fatal("invalid native slot was hidden by authorization filtering")
		}
	}
	body = valid
	status = http.StatusServiceUnavailable
	if got, err := observeWireGuardCounters(ctx, "wg-shared", expected, now); err == nil || got != nil {
		t.Fatal("unavailable owner became zero")
	}
	before := calls
	if got, err := ObserveWireGuardCounters(ctx, control.DeviceView{}, now); err != nil || got != nil || calls != before {
		t.Fatal("non-WG View queried an unrelated process")
	}
	if got, err := observeWireGuardCounters(context.Background(), "wg-shared", expected, now); err == nil || got != nil {
		t.Fatal("read without execution identity")
	}
}
