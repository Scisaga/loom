//go:build linux

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"loom/internal/netx"
)

// Exercise the official CLI against the real bootstrap/device TLS listener and
// the real native Mixed process. This does not replace physical Android timing
// or the independent WG/Hy2 receiver admission tests.
func TestInvitationCLIConfigurationFollowAndBusinessContinuity(t *testing.T) {
	binary, native := os.Getenv("LOOM_MEMBER_CLI"), os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if binary == "" || native == "" {
		t.Skip("requires freshly built CLI/native executables in an isolated namespace")
	}
	for _, kind := range []string{"user", "net"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			t.Fatal("CLI business acceptance requires separate user and network namespaces")
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("CLI business acceptance requires only isolated loopback")
	}
	for _, family := range []string{"-4", "-6"} {
		body, err := exec.Command("ip", "-json", family, "route", "show", "table", "all").Output()
		var routes []struct{ Dst, Dev string }
		if err != nil || json.Unmarshal(body, &routes) != nil {
			t.Fatal("could not verify isolated routes")
		}
		for _, route := range routes {
			if route.Dev != "" && route.Dev != "lo" || route.Dst == "default" || route.Dst == "0.0.0.0/0" || route.Dst == "::/0" {
				t.Fatal("CLI fixture cannot have an external or default route")
			}
		}
	}
	// Explicitly approved synthetic public destination, generated only after
	// isolation checks. It cannot leave this namespace or relax the runtime ACL.
	var business netip.Addr
	for range 256 {
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		if candidate := netip.AddrFrom4(raw); netx.IsPublicInternetAddress(candidate) {
			business = candidate
			break
		}
	}
	if !business.IsValid() {
		t.Fatal("could not generate isolated business destination")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", netip.PrefixFrom(business, 32).String(), "dev", "lo"}} {
		if err := exec.Command("ip", args...).Run(); err != nil {
			t.Fatal(err)
		}
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "demo-ordinary-application")
	}))
	target.Listener.Close()
	target.Listener, err = net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	target.Start()
	defer target.Close()
	echo, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	fixture := newEndpointFixture(t)
	server := fixture.server
	service := submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-follow-service", Operation: "service.put", TargetKind: "service", TargetID: "demo-service", Dependencies: []string{}, Payload: Service{ID: "demo-service", Name: "Demo internet", Kind: "internet", RestrictToProbeTargets: new(false)}})
	scope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	policy := submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-follow-policy", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-policy", Dependencies: []string{service.MaterialID}, Payload: NetworkPolicy{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: new(scope), AllowDirect: new(true), LocalEgressDevices: new([]string{})}})
	entry, _ := server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", fixture.endpoint.ID)
	invite := Invite{ID: "demo-follow-invite", GenesisDigest: server.Config.GenesisID, IssuerControlID: server.Config.ControlID, DeviceID: "demo-follow-access", Name: "Demo access", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Medium: "qr", Endpoint: fixture.endpoint, ExpiresAt: fixture.clock.Load() + 60000}
	_, extra, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-follow-issue", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(entry.MaterialIDs, service.MaterialID, policy.MaterialID)), Payload: invite})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	state, status := filepath.Join(root, "identity.json"), filepath.Join(root, "status.json")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	start := time.Now()
	enroll := exec.CommandContext(ctx, binary, "client", "enroll", "-stdin", "-state", state)
	enroll.Stdin = bytes.NewBufferString(extra.Invite + "\n")
	if _, err := enroll.CombinedOutput(); err != nil {
		t.Fatal("official CLI join failed", err)
	}
	joinedAt := time.Now()
	accepted, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(root, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	run := exec.CommandContext(ctx, binary, "client", "run", "-state", state, "-capture", "mixed", "-sing-box", native, "-runtime-config", filepath.Join(root, "runtime.json"), "-runtime-state", filepath.Join(root, "observations.json"), "-status", status)
	run.Stdout, run.Stderr = log, log
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Wait() }()
	defer func() {
		_ = run.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				t.Error("normal client stop failed", err)
			}
		case <-time.After(3 * time.Second):
			cancel()
			<-done
			t.Error("client did not stop normally")
		}
	}()
	wait := func(digest string, frontier []FactFrontier) {
		t.Helper()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		for {
			body, _ := os.ReadFile(status)
			var current struct {
				ViewDigest   string         `json:"view_digest"`
				Runtime      string         `json:"runtime"`
				FactFrontier []FactFrontier `json:"fact_frontier"`
			}
			if json.Unmarshal(body, &current) == nil && current.Runtime == "running" && current.ViewDigest == digest && reflect.DeepEqual(current.FactFrontier, frontier) {
				return
			}
			select {
			case <-deadline.C:
				t.Fatal("official runtime did not consume the new certified configuration")
			case <-ctx.Done():
				t.Fatal("official runtime timed out")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait(accepted.ViewDigest, accepted.FactFrontier)
	proxy := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1080"}), DisableKeepAlives: true}
	defer proxy.CloseIdleConnections()
	request := func() {
		t.Helper()
		r, err := (&http.Client{Transport: proxy, Timeout: time.Second}).Get(target.URL + "/unlisted-dependency")
		if err != nil {
			t.Fatal("ordinary unlisted business failed", err)
		}
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || string(body) != "demo-ordinary-application" {
			t.Fatal("ordinary request returned another result")
		}
	}
	request()
	businessAt := time.Now()
	stream, err := net.DialTimeout("tcp", "127.0.0.1:1080", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	reader := bufio.NewReader(stream)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("persistent connection was not established", err)
	}
	exchange := func() {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		_, err := stream.Write([]byte("demo"))
		var reply [4]byte
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(reader, reply[:]); err != nil || string(reply[:]) != "demo" {
			t.Fatal("configuration follow interrupted the existing connection", err)
		}
	}
	exchange()
	changeAt := time.Now()
	fixture.join(t, "another-access")
	next, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	wait(next.ViewDigest, next.FactFrontier)
	exchange()
	request()
	updatedAt := time.Now()
	targetState, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	put := DevicePut{ID: invite.DeviceID, Name: "Demo renamed access", Responsibilities: invite.Responsibilities, PolicyIDs: invite.PolicyIDs, DistributionURLs: []string{}}
	if _, _, err := server.HandleOperation(ctx, Operation{Schema: 3, RequestID: "demo-follow-rename", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: sortedUniqueDependencies(append(targetState.MaterialIDs, service.MaterialID, policy.MaterialID)), Payload: put}); err != nil {
		t.Fatal(err)
	}
	next, err = server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	wait(next.ViewDigest, next.FactFrontier)
	exchange()
	request()
	t.Logf("isolated CLI join_ms=%d startup_to_business_ms=%d another_join_to_existing_runtime_ms=%d rename_to_business_ms=%d", joinedAt.Sub(start).Milliseconds(), businessAt.Sub(joinedAt).Milliseconds(), updatedAt.Sub(changeAt).Milliseconds(), time.Since(updatedAt).Milliseconds())
}
