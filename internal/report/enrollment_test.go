package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"loom/internal/enrollssh"
	"loom/internal/model"
	"loom/internal/validate"
	"loom/internal/webui"
)

func TestLoadControlDefaultsEnrollmentPaths(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(ssotPath, []byte("nodes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "control.json")
	config, err := json.Marshal(Control{SSOTPath: ssotPath, GeoIPDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	control, _, err := LoadControl(configPath)
	// Missing operator credentials disables writes, but configuration defaults
	// must already be visible to diagnostics and remediation.
	if err == nil || control == nil {
		t.Fatalf("LoadControl = %#v, %v; want control plus credential error", control, err)
	}
	if control.BootstrapSSHKey != "/etc/loom/control-bootstrap" ||
		control.KnownHostsPath != "/etc/loom/control-known_hosts" || !control.GeoIPDisabled {
		t.Fatalf("enrollment path defaults = %#v", control)
	}
}

func TestControlDepsAdvertisesEnrollmentOnlyWithIsolatedAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	bootstrap := filepath.Join(dir, "bootstrap")
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte("nodes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := controlDeps(&Control{SSOTPath: path, BootstrapSSHKey: bootstrap}).Enrollment; got != nil {
		t.Fatal("Enrollment was advertised without a known_hosts path")
	}
	if got := controlDeps(&Control{
		SSOTPath: path, BootstrapSSHKey: "relative-bootstrap", KnownHostsPath: knownHosts,
	}).Enrollment; got != nil {
		t.Fatal("Enrollment was advertised with a relative bootstrap identity path")
	}
	if got := controlDeps(&Control{
		SSOTPath: path, BootstrapSSHKey: bootstrap, KnownHostsPath: bootstrap,
	}).Enrollment; got != nil {
		t.Fatal("Enrollment was advertised when known_hosts would replace the private key")
	}
	if got := controlDeps(&Control{
		SSOTPath: path, BootstrapSSHKey: bootstrap, KnownHostsPath: knownHosts,
	}).Enrollment; got == nil {
		t.Fatal("Enrollment was not advertised with both isolated absolute paths")
	}
}

func TestDeterminePublicEndpointUsesOnlyControlEvidence(t *testing.T) {
	t.Run("literal public address", func(t *testing.T) {
		called := false
		endpoint, evidence, resolution, err := determinePublicEndpoint(context.Background(), "8.8.8.8", "10.0.0.9",
			func(context.Context, string) ([]net.IPAddr, error) {
				called = true
				return nil, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint != "8.8.8.8" || resolution != "8.8.8.8" || called {
			t.Fatalf("endpoint=%q lookupCalled=%v", endpoint, called)
		}
		if !strings.Contains(evidence, "10.0.0.9") || !strings.Contains(evidence, "not used") {
			t.Fatalf("evidence does not explain the SSH_CONNECTION boundary: %q", evidence)
		}
	})

	t.Run("private literal is never replaced by SSH_CONNECTION", func(t *testing.T) {
		_, _, _, err := determinePublicEndpoint(context.Background(), "10.24.0.18", "8.8.4.4", nil)
		if err == nil || !strings.Contains(err.Error(), "not a public global-unicast") {
			t.Fatalf("private endpoint error = %v", err)
		}
	})

	t.Run("DNS requires at least one public answer", func(t *testing.T) {
		lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host != "Edge.Example.NET" {
				t.Fatalf("lookup host = %q", host)
			}
			return []net.IPAddr{{IP: net.ParseIP("192.168.1.2")}, {IP: net.ParseIP("1.1.1.1")}}, nil
		}
		endpoint, evidence, resolution, err := determinePublicEndpoint(context.Background(), "Edge.Example.NET", "192.168.1.2", lookup)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint != "edge.example.net" || resolution != "1.1.1.1" || !strings.Contains(evidence, "1.1.1.1") {
			t.Fatalf("endpoint=%q resolution=%q evidence=%q", endpoint, resolution, evidence)
		}

		privateOnly := func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("172.16.1.1")}}, nil
		}
		if _, _, _, err := determinePublicEndpoint(context.Background(), "edge.example.net", "8.8.8.8", privateOnly); err == nil {
			t.Fatal("DNS name with only local/private answers was accepted")
		}
	})
}

func TestResolveEnrollmentDirectionIsConservative(t *testing.T) {
	direction, evidence, err := resolveEnrollmentDirection("automatic")
	if err != nil {
		t.Fatal(err)
	}
	if direction != model.ReverseOnly || !strings.Contains(evidence, "no authenticated UDP") {
		t.Fatalf("automatic = %q, %q", direction, evidence)
	}
	for _, explicit := range []model.Direction{model.Bidirectional, model.ReverseOnly, model.DirectOnly} {
		got, evidence, err := resolveEnrollmentDirection(string(explicit))
		if err != nil || got != explicit || !strings.Contains(evidence, "explicitly requested") {
			t.Errorf("explicit %q = %q, %q, %v", explicit, got, evidence, err)
		}
	}
	if _, _, err := resolveEnrollmentDirection("mesh"); err == nil {
		t.Fatal("unknown direction was accepted")
	}
}

func TestEnrollmentNodeIDNormalizesRemoteHostname(t *testing.T) {
	for input, want := range map[string]string{
		"VM-0-3":       "vm-0-3",
		"EDGE__Berlin": "edge-berlin",
		"_SG---02_":    "sg-02",
		"hk01":         "hk01",
	} {
		got, err := enrollmentNodeID(input)
		if err != nil || got != want {
			t.Errorf("enrollmentNodeID(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	long, err := enrollmentNodeID("VM-0-3-ubuntu")
	if err != nil || !strings.HasPrefix(long, "vm-0-3-") || len(long) > model.LinuxIfnameMax-len("wg-") || !model.ValidNodeID(long) {
		t.Fatalf("long normalized Node ID = %q, %v", long, err)
	}
	for _, input := range []string{"---", "___", "node.example"} {
		if got, err := enrollmentNodeID(input); err == nil {
			t.Errorf("enrollmentNodeID(%q) accepted as %q", input, got)
		}
	}
}

func TestEnrollmentScanValidatesCoordinatesAndReturnsOnlyPublicHostKey(t *testing.T) {
	called := 0
	backend := enrollmentBackend{
		scan: func(_ context.Context, connection enrollssh.Connection) (enrollssh.HostKey, error) {
			called++
			if connection.Host != "edge.example.net" || connection.User != "bootstrap" || connection.Port != 2222 {
				t.Fatalf("scan connection = %#v", connection)
			}
			return enrollssh.HostKey{Algorithm: "ssh-ed25519", PublicKey: "public-blob", Fingerprint: "SHA256:fingerprint"}, nil
		},
	}
	key, err := backend.dependencies().Scan(context.Background(), webui.EnrollmentConnection{
		Host: "edge.example.net", User: "bootstrap", Port: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 || key.Algorithm != "ssh-ed25519" || key.PublicKey != "public-blob" || key.Fingerprint != "SHA256:fingerprint" {
		t.Fatalf("scan result = %#v, calls=%d", key, called)
	}
	if _, err := backend.dependencies().Scan(context.Background(), webui.EnrollmentConnection{
		Host: "-oProxyCommand=bad", User: "bootstrap", Port: 22,
	}); err == nil {
		t.Fatal("unsafe SSH coordinate reached the scanner")
	}
	if called != 1 {
		t.Fatalf("scanner was called for invalid input; calls=%d", called)
	}
}

func TestEnrollmentReviewAndCommitAreOneRevisionGuardedPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	initial, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatal(err)
	}

	backend, counters := fakeEnrollmentBackend(t, path)
	deps := backend.dependencies()
	input := enrollmentReviewInput()
	input.Country = "HK"
	input.City = "Hong Kong"
	review, err := deps.Review(context.Background(), input)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if review.NodeID != "hk01" || review.PublicEndpoint != "edge.example.net" || review.Country != "HK" || review.City != "Hong Kong" ||
		review.RequestedDirection != "automatic" || review.ResolvedDirection != string(model.ReverseOnly) ||
		!review.EgressEnabled || !hasEnrollmentPolicy(review.FixedPolicies, "hk01-fixed", "固定Hong Kong出口") ||
		len(review.Tunnels) != 4 {
		t.Fatalf("unexpected review: %#v", review)
	}
	initialSum := sha256.Sum256(initial)
	if review.Revision != fmt.Sprintf("%x", initialSum[:]) {
		t.Fatalf("review revision = %q, want digest of exact reviewed bytes", review.Revision)
	}
	if afterReview, err := os.ReadFile(path); err != nil || !bytes.Equal(afterReview, initial) {
		t.Fatalf("Review changed SSOT: err=%v", err)
	}
	for _, tunnel := range review.Tunnels {
		if tunnel.From != "hk01" || tunnel.Initiator != "hk01" || tunnel.Acceptor == "hk01" ||
			tunnel.FromAddress == "" || tunnel.ToAddress == "" || tunnel.ListenPort == 0 {
			t.Errorf("incorrect tunnel mapping: %#v", tunnel)
		}
	}
	if counters.confirm != 1 || counters.preflight != 1 || counters.prepare != 0 {
		t.Fatalf("review call counts = %#v", counters)
	}

	added, err := deps.Commit(context.Background(), webui.EnrollmentCommitInput{
		EnrollmentReviewInput: input,
		ExpectedNodeID:        review.NodeID, ExpectedEndpoint: review.PublicEndpoint,
		ExpectedEndpointResolution: review.EndpointResolution, ExpectedRevision: review.Revision,
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if added != "hk01" || counters.confirm != 2 || counters.preflight != 2 || counters.prepare != 1 {
		t.Fatalf("commit result=%q calls=%#v", added, counters)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(content)
	if err != nil {
		t.Fatal(err)
	}
	if findings := validate.Validate(ssot); len(findings) > 0 {
		t.Fatalf("committed SSOT is invalid: %s", validate.Format(findings))
	}
	node := ssot.NodeByID()["hk01"]
	if node == nil || node.Server == nil || node.Server.Direction != model.ReverseOnly ||
		!node.Server.EgressCapable || node.Server.WGPublicKey != testWGPublicKey ||
		node.PublicEndpoint != "edge.example.net" || node.SSHPort != 22 || node.Country != "HK" || node.City != "Hong Kong" {
		t.Fatalf("committed node = %#v", node)
	}
	fixed := ssot.DeclarationByID()["hk01-fixed"]
	if fixed == nil || fixed.PinnedEgress() != "hk01" || fixed.Objective != model.Latency {
		t.Fatalf("committed fixed policy = %#v", fixed)
	}
}

func hasEnrollmentPolicy(policies []webui.EnrollmentPolicy, id, name string) bool {
	for _, policy := range policies {
		if policy.ID == id && policy.Name == name {
			return true
		}
	}
	return false
}

func TestEnrollmentGeoIPSuggestionIsAdvisoryAndNonBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	initial, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatal(err)
	}
	backend, _ := fakeEnrollmentBackend(t, path)
	lookups := 0
	backend.lookupGeoIP = func(_ context.Context, ip string) (geoIPLocation, error) {
		lookups++
		if ip != "8.8.8.8" {
			t.Fatalf("GeoIP address = %q", ip)
		}
		return geoIPLocation{Country: "HK", City: "Hong Kong", Evidence: "advisory GeoIP result"}, nil
	}
	input := enrollmentReviewInput()
	review, err := backend.review(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if review.Country != "HK" || review.City != "Hong Kong" || !review.GeoIPSuggested ||
		review.GeoIPEvidence != "advisory GeoIP result" || lookups != 1 {
		t.Fatalf("suggested review = %#v; lookups=%d", review, lookups)
	}

	input.Country, input.City = "DE", "Berlin"
	review, err = backend.review(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if review.Country != "DE" || review.City != "Berlin" || review.GeoIPSuggested || lookups != 1 ||
		!strings.Contains(review.GeoIPEvidence, "operator") {
		t.Fatalf("operator review = %#v; lookups=%d", review, lookups)
	}

	input.Country, input.City, input.DisableGeoIP = "", "", true
	review, err = backend.review(context.Background(), input)
	if err != nil || review.Country != "" || review.City != "" || lookups != 1 ||
		!strings.Contains(review.GeoIPEvidence, "disabled") {
		t.Fatalf("disabled review = %#v, %v; lookups=%d", review, err, lookups)
	}

	input.DisableGeoIP = false
	backend.lookupGeoIP = func(context.Context, string) (geoIPLocation, error) {
		return geoIPLocation{}, fmt.Errorf("temporary quota failure")
	}
	review, err = backend.review(context.Background(), input)
	if err != nil || review.Country != "" || review.City != "" ||
		!strings.Contains(review.GeoIPEvidence, "unavailable") || !strings.Contains(review.GeoIPEvidence, "quota") {
		t.Fatalf("failed lookup review = %#v, %v", review, err)
	}
}

func TestEnrollmentAutomaticallyInstallsToolsAndUsesNormalizedNodeID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	initial, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatal(err)
	}

	backend, counters := fakeEnrollmentBackend(t, path)
	toolsAvailable := false
	backend.preflight = func(context.Context, enrollssh.Connection) (enrollssh.PreflightResult, error) {
		counters.preflight++
		return enrollssh.PreflightResult{
			Hostname: "VM-0-3-ubuntu", Uname: "Linux 6.8.0 x86_64 GNU/Linux",
			KernelWireGuard: true, WGCommand: toolsAvailable, Privilege: enrollssh.PrivilegeRoot,
			ObservedSSHServerAddress: "10.24.0.18",
		}, nil
	}
	backend.installWGTools = func(context.Context, enrollssh.Connection) (bool, error) {
		counters.install++
		toolsAvailable = true
		return true, nil
	}
	backend.prepareWG = func(context.Context, enrollssh.Connection) (enrollssh.PrepareWGResult, error) {
		counters.prepare++
		return enrollssh.PrepareWGResult{
			Hostname: "VM-0-3-ubuntu", ObservedSSHServerAddress: "10.24.0.18", PublicKey: testWGPublicKey,
		}, nil
	}

	deps := backend.dependencies()
	input := enrollmentReviewInput()
	review, err := deps.Review(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(review.NodeID, "vm-0-3-") || review.ObservedHostname != "VM-0-3-ubuntu" || !review.WireGuardToolsInstalled || !review.WGCommand {
		t.Fatalf("automatic bootstrap review = %#v", review)
	}
	if counters.install != 1 || counters.preflight != 2 {
		t.Fatalf("review calls = %#v", counters)
	}

	added, err := deps.Commit(context.Background(), webui.EnrollmentCommitInput{
		EnrollmentReviewInput: input,
		ExpectedNodeID:        review.NodeID, ExpectedEndpoint: review.PublicEndpoint,
		ExpectedEndpointResolution: review.EndpointResolution, ExpectedRevision: review.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != review.NodeID || counters.install != 1 || counters.preflight != 3 || counters.prepare != 1 {
		t.Fatalf("commit result=%q calls=%#v", added, counters)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(content)
	if err != nil {
		t.Fatal(err)
	}
	if node := ssot.NodeByID()[review.NodeID]; node == nil || node.Server == nil || node.Server.WGPublicKey != testWGPublicKey {
		t.Fatalf("normalized node was not committed: %#v", node)
	}
}

func TestEnrollmentCommitRejectsDriftAndStaleRevisionWithoutChangingSSOT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	initial, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatal(err)
	}
	backend, counters := fakeEnrollmentBackend(t, path)
	deps := backend.dependencies()
	input := enrollmentReviewInput()
	review, err := deps.Review(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := deps.Commit(context.Background(), webui.EnrollmentCommitInput{
		EnrollmentReviewInput: input,
		ExpectedNodeID:        "some-other-node", ExpectedEndpoint: review.PublicEndpoint,
		ExpectedEndpointResolution: review.EndpointResolution, ExpectedRevision: review.Revision,
	}); err == nil || !strings.Contains(err.Error(), "identity drifted") {
		t.Fatalf("identity drift error = %v", err)
	}
	if counters.prepare != 0 {
		t.Fatal("WireGuard identity was prepared before identity drift was rejected")
	}

	external := append(append([]byte(nil), initial...), []byte("\n# external edit\n")...)
	if err := os.WriteFile(path, external, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := deps.Commit(context.Background(), webui.EnrollmentCommitInput{
		EnrollmentReviewInput: input,
		ExpectedNodeID:        review.NodeID, ExpectedEndpoint: review.PublicEndpoint,
		ExpectedEndpointResolution: review.EndpointResolution, ExpectedRevision: review.Revision,
	}); err == nil || !strings.Contains(err.Error(), "SSOT") {
		t.Fatalf("stale revision error = %v", err)
	}
	if counters.prepare != 1 {
		t.Fatalf("PrepareWG calls = %d, want the documented idempotent remote preparation", counters.prepare)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, external) {
		t.Fatal("stale enrollment changed SSOT")
	}
}

func TestEnrollmentCommitBindsDNSAnswersAndPreparedHostSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*enrollmentBackend, *string)
		want   string
	}{
		{
			name:   "DNS answer set drift",
			mutate: func(_ *enrollmentBackend, ip *string) { *ip = "9.9.9.9" },
			want:   "DNS/address evidence drifted",
		},
		{
			name: "WG preparation reached another host",
			mutate: func(backend *enrollmentBackend, _ *string) {
				backend.prepareWG = func(context.Context, enrollssh.Connection) (enrollssh.PrepareWGResult, error) {
					return enrollssh.PrepareWGResult{
						Hostname: "hk02", ObservedSSHServerAddress: "10.24.0.18", PublicKey: testWGPublicKey,
					}, nil
				}
			},
			want: "identity changed between trusted SSH sessions",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ssot.yaml")
			initial, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, initial, 0o644); err != nil {
				t.Fatal(err)
			}
			backend, _ := fakeEnrollmentBackend(t, path)
			resolvedIP := "8.8.8.8"
			backend.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(resolvedIP)}}, nil
			}
			input := enrollmentReviewInput()
			review, err := backend.review(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&backend, &resolvedIP)
			_, err = backend.commit(context.Background(), webui.EnrollmentCommitInput{
				EnrollmentReviewInput: input,
				ExpectedNodeID:        review.NodeID, ExpectedEndpoint: review.PublicEndpoint,
				ExpectedEndpointResolution: review.EndpointResolution, ExpectedRevision: review.Revision,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("commit drift error = %v, want %q", err, tc.want)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(got, initial) {
				t.Fatalf("drifted commit changed SSOT: err=%v", readErr)
			}
		})
	}
}

type enrollmentCallCounters struct {
	confirm, preflight, install, prepare int
}

const testWGPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func fakeEnrollmentBackend(t *testing.T, path string) (enrollmentBackend, *enrollmentCallCounters) {
	t.Helper()
	counters := &enrollmentCallCounters{}
	mu := &sync.Mutex{}
	revision := func(content []byte) string {
		sum := sha256.Sum256(content)
		return fmt.Sprintf("%x", sum[:])
	}
	backend := enrollmentBackend{
		confirm: func(_ context.Context, _ enrollssh.Connection, key enrollssh.HostKey) (enrollssh.HostKey, error) {
			counters.confirm++
			return key, nil
		},
		preflight: func(context.Context, enrollssh.Connection) (enrollssh.PreflightResult, error) {
			counters.preflight++
			return enrollssh.PreflightResult{
				Hostname: "hk01", Uname: "Linux 6.8.0 x86_64 GNU/Linux",
				KernelWireGuard: true, WGCommand: true, Privilege: enrollssh.PrivilegeSudo,
				ObservedSSHServerAddress: "10.24.0.18",
			}, nil
		},
		installWGTools: func(context.Context, enrollssh.Connection) (bool, error) {
			counters.install++
			return true, nil
		},
		prepareWG: func(context.Context, enrollssh.Connection) (enrollssh.PrepareWGResult, error) {
			counters.prepare++
			return enrollssh.PrepareWGResult{
				Hostname: "hk01", ObservedSSHServerAddress: "10.24.0.18", PublicKey: testWGPublicKey,
			}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		read:     func() ([]byte, error) { return os.ReadFile(path) },
		revision: revision,
		guardRevision: func(current []byte, expected string) error {
			if expected == "" || revision(current) != expected {
				return fmt.Errorf("SSOT revision conflict")
			}
			return nil
		},
		saveMu:   mu,
		ssotPath: path,
	}
	return backend, counters
}

func enrollmentReviewInput() webui.EnrollmentReviewInput {
	return webui.EnrollmentReviewInput{
		Connection: webui.EnrollmentConnection{Host: "edge.example.net", User: "loom-bootstrap", Port: 22},
		HostKey: webui.EnrollmentHostKey{
			Algorithm: "ssh-ed25519", PublicKey: "test-public-key", Fingerprint: "SHA256:test",
		},
		RequestedDirection: "automatic",
	}
}
