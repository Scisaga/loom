//go:build windows

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

// TestWindowsInstalledPrivateRuntimeAcceptance is an opt-in native fixture for
// the installed client's normal UI flow. The test process owns only a private
// loopback control plane; an external desktop driver imports the emitted invite
// through the real Misaka window and starts the SCM-hosted runtime.
func TestWindowsInstalledPrivateRuntimeAcceptance(t *testing.T) {
	runRoot := os.Getenv("LOOM_WINDOWS_ACCEPTANCE_RUN")
	if runRoot == "" {
		t.Skip("set LOOM_WINDOWS_ACCEPTANCE_RUN for native installed acceptance")
	}
	if !filepath.IsAbs(runRoot) || filepath.Clean(runRoot) != runRoot {
		t.Fatal("acceptance run root must be absolute and clean")
	}
	evidenceRoot := filepath.Join(runRoot, "evidence")
	if err := os.MkdirAll(evidenceRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	privateAddress := freeAddress(t, "127.0.0.1")
	state := testState()
	state.BrowserTLS = testTLS(t)
	config, err := ActivateLegacy(root, state, "demo-control", "demo-control-node", []string{privateAddress})
	if err != nil {
		t.Fatal(err)
	}
	channel, err := OpenPrivateChannel(PrivateChannelConfig{Node: config.Node, Listen: []string{privateAddress}, Peers: map[string][]string{}}, config)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, channel)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reportRoot := filepath.Join(root, "reports")
	reports, err := OpenObservationStore(reportRoot)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: runtime, Channel: channel, Config: config, ReleaseRoot: t.TempDir(),
		ReleaseKey: filepath.Join(t.TempDir(), "missing"), AdminSocket: filepath.Join(root, "admin.sock"), Reports: reports}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, http.NotFoundHandler()) }()
	defer func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("control fixture did not stop")
		}
		_ = runtime.Close()
	}()
	waitLeader(t, []*Runtime{runtime})
	deadline := time.Now().Add(10 * time.Second)
	for server.endpointRuntime() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if server.endpointRuntime() == nil {
		t.Fatal("endpoint runtime did not start")
	}
	endpointRuntime := server.endpointRuntime()

	certificatePath := filepath.Join(root, "endpoint.crt")
	keyPath := filepath.Join(root, "endpoint.key")
	if err := os.WriteFile(certificatePath, []byte(config.BrowserTLS.CertificateChainPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(config.BrowserTLS.PrivateKeyPKCS8PEM), 0o600); err != nil {
		t.Fatal(err)
	}
	spki, err := certificateSPKI(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicAddress := freeAddress(t, "127.0.0.1")
	generation := EndpointGeneration{Schema: 1, EndpointID: "demo-windows-entry", Generation: 1, Node: config.Node,
		Transport: "tls_tunnel", Listen: publicAddress, Address: publicAddress, ServerName: "127.0.0.1",
		TLSCertificateFile: certificatePath, TLSPrivateKeyFile: keyPath, SPKISHA256: spki, State: "prepared"}
	if _, err := server.putEndpoint(ctx, "demo-endpoint-prepare", currentHead(runtime), generation); err != nil {
		t.Fatal(err)
	}
	waitEndpointReady(t, endpointRuntime, generation)
	generation.State = "serving"
	if _, err := server.putEndpoint(ctx, "demo-endpoint-serve", currentHead(runtime), generation); err != nil {
		t.Fatal(err)
	}

	routes := []RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"},
	}
	source := []byte(`{
  "log":{"level":"warn"},
  "dns":{"servers":[{"tag":"dns0","address":"1.1.1.1","detour":"internet"}]},
  "inbounds":[
    {"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"stack":"system"},
    {"type":"mixed","tag":"in-1080","listen":"127.0.0.1","listen_port":1080}
  ],
  "outbounds":[
    {"type":"direct","tag":"one-hop","bind_interface":"demo-missing-interface"},
    {"type":"direct","tag":"relay"},
    {"type":"selector","tag":"internet","outbounds":["one-hop","relay"],"default":"one-hop"},
    {"type":"block","tag":"block"}
  ],
  "route":{"rules":[{"inbound":["tun-in","in-1080"],"outbound":"internet"}],"final":"block"},
  "experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-selector-secret"}}
}`)
	canonicalConfig, err := clientmodel.CanonicalizeRuntimeConfig(source)
	if err != nil {
		t.Fatal(err)
	}
	profile := &RuntimeProfile{Kind: "sing_box", Config: canonicalConfig}
	if err := profile.Validate(routes); err != nil {
		t.Fatal(err)
	}
	_, inviteText, err := server.createEnrollment(ctx, "demo-windows-create", currentHead(runtime), enrollmentCreatePayload{
		TransactionID: "demo-windows-transaction", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		DeviceID: "demo-windows-device", Name: "Demo Windows", Platform: "windows", Roles: []string{"access"},
		Routes: routes, Runtime: profile})
	if err != nil {
		t.Fatal(err)
	}
	invitePath := filepath.Join(runRoot, "bootstrap.loom-invite")
	if err := os.WriteFile(invitePath, []byte(inviteText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(invitePath) })

	approved := false
	deadline = time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		_, projection, _ := runtime.Authority.Snapshot()
		_, transaction := findEnrollment(&projection, "demo-windows-transaction")
		if transaction != nil && transaction.State == "bound" {
			if _, err := server.approveEnrollment(ctx, "demo-windows-approve", currentHead(runtime), transaction.ID); err != nil {
				// Claim and the next private resume can advance the certified
				// head between the snapshot and optimistic approval. Retry only
				// that explicit concurrency result with the newly read head.
				if err.Error() == "base head is stale" {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				t.Fatal(err)
			}
			approved = true
		}
		if transaction != nil && transaction.State == "completed" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !approved {
		t.Fatal("normal Windows UI never bound the bootstrap capability")
	}

	deadline = time.Now().Add(3 * time.Minute)
	for len(reports.All()) == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	all := reports.All()
	if len(all) != 1 {
		t.Fatalf("private signed report count = %d", len(all))
	}
	report := all[0]
	if report.DeviceID != "demo-windows-device" || report.Selection != "relay" || len(report.Observations) != 2 {
		t.Fatalf("unexpected Windows report projection: device=%q selection=%q observations=%d", report.DeviceID, report.Selection, len(report.Observations))
	}
	results := map[string]string{}
	for _, observation := range report.Observations {
		if observation.Action != "tcp_udp_dns" || observation.NetworkGeneration == "" {
			t.Fatalf("observation is not a real business result: %+v", observation)
		}
		results[observation.CandidateID] = observation.Result
	}
	if results["one-hop"] != "unavailable" || results["relay"] != "available" {
		t.Fatalf("same-exit fallback evidence is incomplete: %+v", results)
	}

	readback := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(readback, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
	if readback.Code != http.StatusOK || !bytes.Contains(readback.Body.Bytes(), []byte(`"enrollment":"completed"`)) ||
		!bytes.Contains(readback.Body.Bytes(), []byte(`"selection":"relay"`)) || !bytes.Contains(readback.Body.Bytes(), []byte(`"selected":true`)) {
		t.Fatalf("control/UI readback did not project the signed report: status=%d", readback.Code)
	}
	reopenedReports, err := OpenObservationStore(reportRoot)
	if err != nil || len(reopenedReports.All()) != 1 || reopenedReports.All()[0].Selection != "relay" {
		t.Fatalf("persisted report restart readback failed: %v", err)
	}
	result := struct {
		Schema             int               `json:"schema"`
		Device             string            `json:"device"`
		Enrollment         string            `json:"enrollment"`
		Selection          string            `json:"selection"`
		Observations       map[string]string `json:"observations"`
		PrivateReport      bool              `json:"private_report"`
		ControlUIReadback  bool              `json:"control_ui_readback"`
		PersistentReadback bool              `json:"persistent_readback"`
	}{1, report.DeviceID, "completed", report.Selection, results, true, true, true}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidenceRoot, "control-readback.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}
