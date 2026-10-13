package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"loom/internal/control"
)

// This uses actual owned UDP sockets and QUIC/TLS in a dedicated namespace.
// The WG socket checks execution ownership only; real WG business is exercised
// by the separate native projected-segment acceptance tests.
func TestIsolatedResourceTimeoutRecoversSameViewWithoutLosingWGOwnership(t *testing.T) {
	if os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE") == "" {
		t.Skip("run in the isolated Linux runtime acceptance namespace")
	}
	if err := requireDifferentNetworkNamespace("/proc/self/ns/net", "/proc/1/ns/net"); err != nil {
		t.Fatal(err)
	}
	view, path, now := resourceExecutionFixture(t, time.Now())
	hy2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hy2.Close()
	wg, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	var inputs ResourceInputs
	if err := readStrict(path, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	inputs.Listeners[0].Listen = hy2.LocalAddr().String()
	if err := atomicJSON(path, inputs); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(hy2.LocalAddr().String())
	view.Resources[0].DialPort, _ = strconv.Atoi(port)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	view.Resources = append(view.Resources, control.TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: view.DeviceID, ListenerID: "demo-wg-listener",
		DialHost: "192.0.2.11", DialPort: wg.LocalAddr().(*net.UDPAddr).Port, Authentication: control.ResourceAuthentication{PublicKey: &public}})
	executions, err := prepareHY2Executions(view, path, now)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(inputs.Listeners[0].CertificateFile, inputs.Listeners[0].KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	var paused atomic.Bool
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if paused.Load() {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(hy2) }()
	defer func() { _ = server.Close(); <-done }()
	lkg := &control.DeviceViewEnvelope{View: view, ViewDigest: "sha256:" + strings.Repeat("1", 64)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	initial, err := resourceRuntimeReadback(ctx, lkg, executions, os.Getpid(), now, false, nil)
	if err != nil || initial.State != "running" || initial.Resources == nil || len(*initial.Resources) != 2 {
		t.Fatal("real startup identity/listener readback failed", err)
	}
	paused.Store(true)
	if _, err := resourceRuntimeReadback(ctx, lkg, executions, os.Getpid(), now, false, nil); !errors.Is(err, errResourceReadbackTimeout) {
		t.Fatal("initial application accepted an incomplete readback", err)
	}
	unknown, err := resourceRuntimeReadback(ctx, lkg, executions, os.Getpid(), now, true, nil)
	if err != nil || unknown.State != "unknown" || unknown.AppliedViewDigest != "" || unknown.Resources != nil || !processOwnsUDP(os.Getpid(), wg.LocalAddr().String()) {
		t.Fatal("periodic timeout lost WG ownership or manufactured current application", err)
	}
	paused.Store(false)
	recovered, err := resourceRuntimeReadback(ctx, lkg, executions, os.Getpid(), now, true, nil)
	if err != nil || recovered.State != "running" || recovered.AppliedViewDigest != lkg.ViewDigest {
		t.Fatal("unchanged View did not recover on the next actual readback", err)
	}
	wrong := append([]hy2Execution{}, executions...)
	wrong[0].acl = "sha256:" + strings.Repeat("2", 64)
	if _, err := resourceRuntimeReadback(ctx, lkg, wrong, os.Getpid(), now, true, nil); err == nil || errors.Is(err, errResourceReadbackTimeout) {
		t.Fatal("an ACL mismatch was treated as missing observation")
	}
	if err := wg.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := resourceRuntimeReadback(ctx, lkg, executions, os.Getpid(), now, true, nil); !errors.Is(err, ErrWireGuardOwnership) {
		t.Fatal("a Hy2 timeout or recovery hid a missing WG listener", err)
	}
}
