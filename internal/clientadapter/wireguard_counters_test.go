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
	"strings"
	"testing"
	"time"
)

func TestWireGuardCounterReadRequiresActualCompletePeerSample(t *testing.T) {
	raw := []byte(strings.Repeat("a", 32))
	public := base64.RawURLEncoding.EncodeToString(raw)
	view := control.DeviceView{RuntimeProfile: &control.RuntimeProfile{Config: `{"endpoints":[{"type":"wireguard","tag":"wg-shared","peers":[{"public_key":"` + base64.StdEncoding.EncodeToString(raw) + `"}]}]}`}}
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
	got, err := ObserveWireGuardCounters(ctx, view, now)
	if err != nil || got == nil || got.ObservedAt != 123 || got.Peers[0].RXBytes != 0 || got.Peers[0].TXBytes != 18446744073709551615 {
		t.Fatal("actual zero or full unsigned precision lost", err)
	}
	for _, bad := range []string{strings.Replace(valid, `,"rx_bytes":"0"`, "", 1), strings.Replace(valid, `"rx_bytes":"0"`, `"rx_bytes":null`, 1), strings.Replace(valid, public, "demo-wrong", 1), strings.Replace(valid, `"wg-shared"`, `"resource:demo-other"`, 1), strings.Replace(valid, `"0"`, `0`, 1), valid + `{}`, `{"endpoints":[]}`, strings.Replace(valid, `"interface"`, `"unknown"`, 1)} {
		if !json.Valid([]byte(bad)) && bad != valid+`{}` {
			t.Fatal("bad fixture")
		}
		body = bad
		if got, err := ObserveWireGuardCounters(ctx, view, now); err == nil || got != nil {
			t.Fatal("incomplete or foreign sample invented a measurement")
		}
	}
	body = valid
	status = http.StatusServiceUnavailable
	if got, err := ObserveWireGuardCounters(ctx, view, now); err == nil || got != nil {
		t.Fatal("unavailable owner became zero")
	}
	before := calls
	if got, err := ObserveWireGuardCounters(ctx, control.DeviceView{}, now); err != nil || got != nil || calls != before {
		t.Fatal("non-WG View queried an unrelated process")
	}
	if got, err := ObserveWireGuardCounters(context.Background(), view, now); err == nil || got != nil {
		t.Fatal("read without execution identity")
	}
}
