package report

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/secret"
	"loom/internal/ssotedit"
)

func TestClientProvisionPrepositionsSecretsBeforeSSOTCommitAndReplaysReady(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	client := clientregistry.Client{
		ID: "client-build01", Name: "Build server", Platform: string(model.LinuxServer),
		Status: "provisioning",
	}
	pinAccessTestIntent(t, &client)
	csrPEM, csr := clientProvisionCSR(t)
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.health = filepath.Join(t.TempDir(), "publisher.json")
	fixedNow := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return fixedNow }

	var installMu sync.Mutex
	installed := map[string][]byte{}
	p.install = func(_ context.Context, nodeID string, body []byte) error {
		current, err := os.ReadFile(control.SSOTPath)
		if err != nil {
			return err
		}
		if strings.Contains(string(current), "id: "+client.ID) {
			return errors.New("SSOT was committed before node secret pre-positioning")
		}
		master, err := secret.Load(paths.masterSecrets)
		if err != nil || master["api/"+client.ID] == "" || master["probe/"+client.ID] == "" {
			return errors.New("new secret values were not durable before node pre-positioning")
		}
		installMu.Lock()
		installed[nodeID] = append([]byte(nil), body...)
		installMu.Unlock()
		return nil
	}

	first, err := p.provision(client, csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if first.Ready {
		t.Fatal("newly committed client was reported ready before publisher confirmation")
	}
	ssotBody, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(ssotBody)
	if err != nil {
		t.Fatal(err)
	}
	node := ssot.NodeByID()[client.ID]
	if node == nil || !node.IsAccess() || node.IsServer() {
		t.Fatalf("provisioned node = %#v", node)
	}
	if len(installed) != 6 {
		t.Fatalf("pre-positioned nodes = %v, want all six existing nodes", mapKeys(installed))
	}
	if !strings.Contains(string(installed["cn-gz"]), "cred/"+client.ID+"/") ||
		!strings.Contains(string(installed["cn-bj"]), "ui/cn-bj=") {
		t.Fatalf("pre-positioned secret layers omitted new server credential or preserved local bootstrap ref")
	}

	prepareClientReadyFiles(t, paths, p.health, ssotBody, fixedNow)
	p.install = func(context.Context, string, []byte) error {
		return errors.New("replay unexpectedly attempted to redistribute existing-node secrets")
	}
	ready, err := p.provision(client, csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Ready || ready.Bootstrap.NodeID != client.ID || len(ready.Bootstrap.DistributionURLs) == 0 {
		t.Fatalf("ready result = %+v", ready)
	}
	if !strings.Contains(ready.Bootstrap.SecretsEnv, "api/"+client.ID+"=") ||
		!strings.Contains(ready.Bootstrap.SecretsEnv, "cred/"+client.ID+"/") {
		t.Fatal("client bootstrap omitted its local control or declaration credentials")
	}
	block, _ := pem.Decode([]byte(ready.Bootstrap.NodeCertPEM))
	if block == nil {
		t.Fatal("ready bootstrap has no PEM node certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(csr.PublicKey) || cert.Subject.CommonName != client.ID+".node.internal" {
		t.Fatalf("issued certificate identity = CN %q key match %v", cert.Subject.CommonName, cert.PublicKey.(*ecdsa.PublicKey).Equal(csr.PublicKey))
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("issued certificate EKU = %v, want only ClientAuth", cert.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ready.Bootstrap.CACertPEM))
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: client.ID + ".node.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued node certificate does not verify: %v", err)
	}
}

func TestWindowsClientProvisionUsesAccessOnlyPlatformShape(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	client := clientregistry.Client{
		ID: "win-laptop01", Name: "Windows laptop", Platform: string(model.WindowsDesktop),
		Status: "provisioning",
	}
	pinAccessTestIntent(t, &client)
	csrPEM, _ := clientProvisionCSR(t)
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.health = filepath.Join(t.TempDir(), "publisher.json")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	installed := map[string]bool{}
	var installedMu sync.Mutex
	p.install = func(_ context.Context, nodeID string, _ []byte) error {
		installedMu.Lock()
		installed[nodeID] = true
		installedMu.Unlock()
		return nil
	}
	first, err := p.provision(client, csrPEM)
	if err != nil || first.Ready {
		t.Fatalf("first Windows provision=%+v err=%v", first, err)
	}
	body, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	node := ssot.NodeByID()[client.ID]
	if node == nil || node.Server != nil || node.Access == nil || node.Access.Platform != model.WindowsDesktop ||
		len(node.Access.MixedPorts) != 1 || node.Access.MixedPorts[0].Port != 1080 || !node.Access.MixedPorts[0].Services {
		t.Fatalf("provisioned Windows node=%+v", node)
	}
	if len(installed) != 6 {
		t.Fatalf("Windows enrollment pre-positioned existing nodes=%v", mapKeysBool(installed))
	}
	if err := validateProvisionedClient(ssot, node, client); err != nil {
		t.Fatalf("generated Windows shape rejected: %v", err)
	}
	prepareClientReadyFiles(t, paths, p.health, body, now)
	ready, err := p.provision(client, csrPEM)
	if err != nil || !ready.Ready || ready.Bootstrap.NodeID != client.ID ||
		!strings.Contains(ready.Bootstrap.SecretsEnv, "cred/"+client.ID+"/") {
		t.Fatalf("Windows ready replay=%+v err=%v", ready, err)
	}
}

func TestAndroidClientProvisionUsesTUNOnlyPlatformShape(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	client := clientregistry.Client{
		ID: "android01", Name: "Android phone", Platform: string(model.Android),
		Status: "provisioning",
	}
	pinAccessTestIntent(t, &client)
	csrPEM, _ := clientProvisionCSR(t)
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.health = filepath.Join(t.TempDir(), "publisher.json")
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	installed := map[string]bool{}
	var installedMu sync.Mutex
	p.install = func(_ context.Context, nodeID string, _ []byte) error {
		installedMu.Lock()
		installed[nodeID] = true
		installedMu.Unlock()
		return nil
	}
	first, err := p.provision(client, csrPEM)
	if err != nil || first.Ready {
		t.Fatalf("first Android provision=%+v err=%v", first, err)
	}
	body, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	node := ssot.NodeByID()[client.ID]
	if node == nil || node.Server != nil || node.Access == nil || node.Access.Platform != model.Android ||
		len(node.Access.MixedPorts) != 0 || node.Access.DefaultDeclaration != "best-egress" {
		t.Fatalf("provisioned Android node=%+v", node)
	}
	if len(installed) != 6 {
		t.Fatalf("Android enrollment pre-positioned existing nodes=%v", mapKeysBool(installed))
	}
	if err := validateProvisionedClient(ssot, node, client); err != nil {
		t.Fatalf("generated Android shape rejected: %v", err)
	}
	// A long-lived master file may contain dormant owner-local entries. They
	// must not cross the Android bootstrap boundary because the Android vault
	// rejects every entry absent from the signed sing-box config.
	all, err := secret.Load(paths.masterSecrets)
	if err != nil {
		t.Fatal(err)
	}
	all["telemetry/"+client.ID] = "unused-telemetry"
	all["unused/"+client.ID] = "unused-owner-local-secret"
	if err := os.WriteFile(paths.masterSecrets, secret.Encode(all, masterSecretsHeader()), 0o600); err != nil {
		t.Fatal(err)
	}
	prepareClientReadyFiles(t, paths, p.health, body, now)
	ready, err := p.provision(client, csrPEM)
	if err != nil || !ready.Ready || ready.Bootstrap.NodeID != client.ID ||
		!strings.Contains(ready.Bootstrap.SecretsEnv, "cred/"+client.ID+"/") {
		t.Fatalf("Android ready replay=%+v err=%v", ready, err)
	}
	secretPath := filepath.Join(t.TempDir(), "android-bootstrap.env")
	if err := os.WriteFile(secretPath, []byte(ready.Bootstrap.SecretsEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	delivered, err := secret.Load(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	var deliveredRefs []string
	for ref := range delivered {
		deliveredRefs = append(deliveredRefs, ref)
	}
	sort.Strings(deliveredRefs)
	wantRefs := []string{
		"api/" + client.ID,
		"cred/" + client.ID + "/best-egress",
		"probe/" + client.ID,
	}
	if !slices.Equal(deliveredRefs, wantRefs) {
		t.Fatalf("Android bootstrap secret refs=%v, want exact bundle refs %v", deliveredRefs, wantRefs)
	}
}

func TestExistingWindowsSecretsAreSkippedOnlyWhenCandidateIsUnchanged(t *testing.T) {
	current := &model.SSOT{
		Nodes: []model.Node{{
			ID: "win-existing", Access: &model.AccessRole{
				Platform: model.WindowsDesktop, Credentials: []string{"cred-win-existing"},
			},
		}},
		Credentials: []model.Credential{{
			ID: "cred-win-existing", Owner: "win-existing", Declaration: "best-egress",
			SecretRef: "cred/win-existing/best-egress",
		}},
	}
	all := map[string]string{
		"api/win-existing": "api", "probe/win-existing": "probe",
		"cred/win-existing/best-egress": "credential",
	}
	body, err := encodedNodeSecrets(current, "win-existing", all)
	if err != nil {
		t.Fatal(err)
	}
	installCalls := 0
	p := &clientProvisioner{install: func(context.Context, string, []byte) error {
		installCalls++
		return nil
	}}
	if err := p.installExistingNodeSecrets(current, all, map[string][]byte{"win-existing": body}); err != nil {
		t.Fatalf("unchanged existing Windows secret layer: %v", err)
	}
	if installCalls != 0 {
		t.Fatalf("existing Windows node was sent through Linux SSH installer %d times", installCalls)
	}
	changed := append(append([]byte(nil), body...), []byte("extra/ref=value\n")...)
	if err := p.installExistingNodeSecrets(current, all, map[string][]byte{"win-existing": changed}); err == nil ||
		!strings.Contains(err.Error(), "steady update channel") {
		t.Fatalf("changed existing Windows secret layer error=%v", err)
	}
}

func TestServerDeviceProvisionUsesTheSameAtomicEnrollmentTransaction(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	client := clientregistry.Client{
		ID: "d-edge01", Name: "Enrolled edge", Platform: string(model.LinuxServer), Status: "provisioning",
		Server: &clientregistry.ServerEnrollment{
			PublicEndpoint: "edge-enrolled.example.net", InboundPort: 5443, Direction: "bidirectional",
			WGPublicKey: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
			Country:     "CN", City: "Beijing", Provider: "example",
		},
	}
	pinServerTestIntent(t, &client)
	csrPEM, _ := clientProvisionCSR(t)
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.health = filepath.Join(t.TempDir(), "publisher.json")
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	installed := map[string]bool{}
	var installedMu sync.Mutex
	p.install = func(_ context.Context, nodeID string, _ []byte) error {
		current, err := os.ReadFile(control.SSOTPath)
		if err != nil {
			return err
		}
		if strings.Contains(string(current), "id: "+client.ID) {
			return errors.New("server SSOT was committed before existing-node secrets")
		}
		installedMu.Lock()
		installed[nodeID] = true
		installedMu.Unlock()
		return nil
	}
	first, err := p.provision(client, csrPEM)
	if err != nil || first.Ready {
		t.Fatalf("first provision=%+v err=%v", first, err)
	}
	if len(installed) != 6 {
		t.Fatalf("pre-positioned existing Devices=%v", mapKeysBool(installed))
	}
	body, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	node := ssot.NodeByID()[client.ID]
	if node == nil || node.Server == nil || node.Access != nil || node.Server.InboundPort != 5443 ||
		!node.Server.EgressCapable || node.Server.SecretGeneration != 1 || node.PublicEndpoint != client.Server.PublicEndpoint {
		t.Fatalf("server Device=%+v", node)
	}
	tunnelCount := 0
	for _, tunnel := range ssot.Tunnels {
		if tunnel.From == client.ID || tunnel.To == client.ID {
			tunnelCount++
		}
	}
	if tunnelCount == 0 {
		t.Fatal("server Device was added without direction-derived WireGuard tunnels")
	}
	fixed := ssot.DeclarationByID()[client.ID+"-fixed"]
	if fixed == nil || fixed.PinnedEgress() != client.ID || !slices.Contains(fixed.AllowedServers, client.ID) {
		t.Fatalf("generated fixed policy=%+v", fixed)
	}
	if !slices.Contains(ssot.DeclarationByID()["best-egress"].AllowedServers, client.ID) {
		t.Fatal("full automatic egress pool was not expanded for the new egress Device")
	}
	if err := validateProvisionedClient(ssot, node, client); err != nil {
		t.Fatalf("generated server shape rejected: %v", err)
	}
	node.Server.InboundPort++
	if err := validateProvisionedClient(ssot, node, client); err == nil || !strings.Contains(err.Error(), "pinned claim") {
		t.Fatalf("mutated server replay error=%v", err)
	}
	node.Server.InboundPort--

	prepareClientReadyFiles(t, paths, p.health, body, now)
	p.install = func(context.Context, string, []byte) error {
		return errors.New("server replay attempted to redistribute existing-node secrets")
	}
	ready, err := p.provision(client, csrPEM)
	if err != nil || !ready.Ready || ready.Bootstrap.NodeID != client.ID {
		t.Fatalf("ready replay=%+v err=%v", ready, err)
	}
}

func TestSignClientCSRRejectsIssuerWithoutCurrentSigningAuthority(t *testing.T) {
	now := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	csrPEM, _ := clientProvisionCSR(t)
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		keyUsage  x509.KeyUsage
		want      string
	}{
		{
			name: "expired", notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour),
			keyUsage: x509.KeyUsageCertSign, want: "not currently valid",
		},
		{
			name: "missing cert sign", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
			keyUsage: x509.KeyUsageCRLSign, want: "not authorized to sign certificates",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			certPath, keyPath := filepath.Join(root, "ca.crt"), filepath.Join(root, "ca.key")
			writeClientTestCA(t, certPath, keyPath, &x509.Certificate{
				SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "Invalid Loom CA"},
				NotBefore: tc.notBefore, NotAfter: tc.notAfter,
				IsCA: true, BasicConstraintsValid: true, KeyUsage: tc.keyUsage,
			})
			if _, _, err := signClientCSR(certPath, keyPath, "client-test01", csrPEM, now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("signClientCSR error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPublisherHasSSOTRequiresCurrentHealthyPublisher(t *testing.T) {
	now := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	body := []byte("same SSOT bytes")
	sum := sha256.Sum256(body)
	state := PublisherState{
		PID: os.Getpid(), UpdatedAt: now.Format(time.RFC3339Nano), IntervalSeconds: 30,
		LastSuccess: now.Format(time.RFC3339Nano), LastSnapshot: "abcdef123456",
		LastSSOT: hex.EncodeToString(sum[:]),
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	write := func() {
		encoded, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if !publisherHasSSOT(path, body, now) {
		t.Fatal("healthy publisher with exact SSOT was not accepted")
	}
	state.LastError = "distribution failed"
	state.LastErrorAt = now.Add(time.Second).Format(time.RFC3339Nano)
	write()
	if publisherHasSSOT(path, body, now.Add(2*time.Second)) {
		t.Fatal("publisher failure newer than LastSuccess was accepted")
	}
	state.LastError, state.LastErrorAt = "", ""
	state.UpdatedAt = now.Add(-10 * time.Minute).Format(time.RFC3339Nano)
	write()
	if publisherHasSSOT(path, body, now) {
		t.Fatal("stale publisher heartbeat was accepted")
	}
}

func TestEnrollmentDistributionUsesOnlyExactSafeDefaultEvidence(t *testing.T) {
	now := time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC)
	body := []byte("exact SSOT")
	sum := sha256.Sum256(body)
	ssotSum := hex.EncodeToString(sum[:])
	s := &model.SSOT{Defaults: &model.SSOTDefaults{DistributionURLs: []string{
		"https://public.example/loom/",
		"http://10.99.0.1/loom/",
		"https://unverified.example/loom/",
		"https://public.example/loom/",
	}}}
	health := &PublisherState{
		PID: os.Getpid(), UpdatedAt: now.Format(time.RFC3339Nano), IntervalSeconds: 30,
		LastError: "a different mirror failed", LastErrorAt: now.Format(time.RFC3339Nano),
		DistributionChecks: []PublisherDistributionCheck{
			{URL: "https://public.example/loom", Snapshot: "snapshot-exact", SSOT: ssotSum, CheckedAt: now.Format(time.RFC3339Nano), Success: true},
			{URL: "http://10.99.0.1/loom/", Snapshot: "snapshot-exact", SSOT: ssotSum, CheckedAt: now.Format(time.RFC3339Nano), Success: true},
			{URL: "https://unverified.example/loom/", Snapshot: "snapshot-old", SSOT: strings.Repeat("0", 64), CheckedAt: now.Format(time.RFC3339Nano), Success: true},
		},
	}
	urls, snapshot, err := verifiedEnrollmentDistributionURLs(s, health, body, now)
	if err != nil || snapshot != "snapshot-exact" || !reflect.DeepEqual(urls, []string{"https://public.example/loom/"}) {
		t.Fatalf("verified enrollment URLs=%v snapshot=%q err=%v", urls, snapshot, err)
	}
	health.DistributionChecks[0].Success = false
	if _, _, err := verifiedEnrollmentDistributionURLs(s, health, body, now); !errors.Is(err, errDistributionNotReady) {
		t.Fatalf("no exact public URL error=%v", err)
	}
}

func TestNodeSecretRefsUseAccessCredentialBindingNotOwnerLabel(t *testing.T) {
	control, _ := clientProvisionFixture(t)
	body, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	credential := ssot.CredentialByID()["cred-control-best"]
	if credential == nil || ssot.AccessNodeForCredential(credential.ID) == nil {
		t.Fatal("fixture is missing the synthetic control access credential binding")
	}
	credential.Owner = "北京工作站"

	refs := nodeSecretRefs(ssot, "cn-gz", nil)
	found := false
	for _, ref := range refs {
		found = found || ref == credential.Ref()
	}
	if !found {
		t.Fatalf("cn-gz secret refs %v omitted access-bound credential %q whose owner is only a label", refs, credential.ID)
	}
}

func TestReadyBootstrapRechecksExactSSOTAfterPublisherMoves(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	client := clientregistry.Client{
		ID: "client-race01", Name: "Race check", Platform: string(model.LinuxServer),
		Status: "provisioning",
	}
	pinAccessTestIntent(t, &client)
	csrPEM, _ := clientProvisionCSR(t)
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.health = filepath.Join(t.TempDir(), "publisher.json")
	now := time.Date(2026, 8, 31, 22, 30, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	p.install = func(context.Context, string, []byte) error { return nil }
	first, err := p.provision(client, csrPEM)
	if err != nil || first.Ready {
		t.Fatalf("initial provision = %+v, err = %v", first, err)
	}
	ssotBody, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(ssotBody)
	if err != nil {
		t.Fatal(err)
	}
	prepareClientReadyFiles(t, paths, p.health, ssotBody, now)
	if !publisherHasSSOT(p.health, ssotBody, now) {
		t.Fatal("fixture did not initially confirm the provisioned SSOT")
	}
	health, err := readPublisherState(p.health)
	if err != nil || health == nil {
		t.Fatalf("read publisher state: %+v, %v", health, err)
	}
	newerSum := sha256.Sum256([]byte("a different concurrently published SSOT"))
	health.LastSSOT = hex.EncodeToString(newerSum[:])
	for i := range health.DistributionChecks {
		health.DistributionChecks[i].SSOT = health.LastSSOT
	}
	healthBody, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.health, healthBody, 0o600); err != nil {
		t.Fatal(err)
	}
	all, err := secret.Load(paths.masterSecrets)
	if err != nil {
		t.Fatal(err)
	}
	clientSecrets, err := encodedNodeSecrets(ssot, client.ID, all)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.readyBootstrap(paths, ssot, ssot.NodeByID()[client.ID], clientSecrets, csrPEM, ssotBody)
	if err == nil || !errors.Is(err, errDistributionNotReady) {
		t.Fatalf("readyBootstrap accepted a different published SSOT: %v", err)
	}
}

func TestValidateProvisionedClientRequiresExactGeneratedShape(t *testing.T) {
	for _, withServices := range []bool{false, true} {
		name := "without services"
		if withServices {
			name = "with services"
		}
		t.Run(name, func(t *testing.T) {
			s, node, client := generatedProvisionedClient(t, withServices)
			if err := validateProvisionedClient(s, node, client); err != nil {
				t.Fatalf("generated shape rejected: %v", err)
			}
		})
	}

	tests := []struct {
		name         string
		withServices bool
		mutate       func(*model.SSOT, *model.Node, clientregistry.Client)
		want         string
	}{
		{
			name: "missing declaration credential",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.Credentials = node.Access.Credentials[:len(node.Access.Credentials)-1]
			}, want: "want exactly",
		},
		{
			name: "extra listed credential",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.Credentials = append(node.Access.Credentials, "cred-ws-sg")
			}, want: "want exactly",
		},
		{
			name: "wrong credential owner",
			mutate: func(s *model.SSOT, node *model.Node, _ clientregistry.Client) {
				s.CredentialByID()[node.Access.Credentials[0]].Owner = "other-client"
			}, want: "owner/declaration/ref",
		},
		{
			name: "wrong credential declaration",
			mutate: func(s *model.SSOT, node *model.Node, _ clientregistry.Client) {
				s.CredentialByID()[node.Access.Credentials[0]].Declaration = "llm-ttft"
			}, want: "owner/declaration/ref",
		},
		{
			name: "wrong credential ref",
			mutate: func(s *model.SSOT, node *model.Node, _ clientregistry.Client) {
				s.CredentialByID()[node.Access.Credentials[0]].SecretRef = "cred/wrong/ref"
			}, want: "owner/declaration/ref",
		},
		{
			name: "extra unlisted owned credential",
			mutate: func(s *model.SSOT, _ *model.Node, client clientregistry.Client) {
				s.Credentials = append(s.Credentials, model.Credential{
					ID: "extra-client-credential", Owner: client.ID,
					Declaration: "best-egress", SecretRef: "cred/extra/client",
				})
			}, want: "extra credential",
		},
		{
			name: "no-services wrong port",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts[0].Port++
			}, want: "mixed port",
		},
		{
			name: "no-services wrong declaration",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts[0].Declaration = "llm-ttft"
			}, want: "mixed port",
		},
		{
			name: "services unmanaged 1080", withServices: true,
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts[0].Services = false
				node.Access.MixedPorts[0].Declaration = "best-egress"
			}, want: "mixed port",
		},
		{
			name: "services extra port", withServices: true,
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts = append(node.Access.MixedPorts, model.MixedPort{Port: 1081, Services: true})
			}, want: "want exactly 1",
		},
		{
			name: "services wrong default", withServices: true,
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.DefaultDeclaration = "sg-fixed"
			}, want: "default_declaration",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, node, client := generatedProvisionedClient(t, tc.withServices)
			tc.mutate(s, node, client)
			if err := validateProvisionedClient(s, node, client); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateProvisionedClient error = %v, want %q", err, tc.want)
			}
		})
	}
}

func generatedProvisionedClient(t *testing.T, withServices bool) (*model.SSOT, *model.Node, clientregistry.Client) {
	t.Helper()
	body, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if withServices {
		body = []byte(strings.Replace(string(body), "declarations:\n", `services:
  - id: web
    declaration: best-egress
    addresses: [api.example.com, .example.com]
declarations:
`, 1))
	}
	base, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	var grants []string
	for _, declaration := range base.Declarations {
		if declaration.AddressFromRequest() {
			grants = append(grants, declaration.ID)
		}
	}
	client := clientregistry.Client{
		ID: "client-shape01", Name: "Shape client", Platform: string(model.LinuxServer),
	}
	pinTestIntent(t, &client, clientregistry.EnrollmentIntent{
		Platform: client.Platform, Responsibilities: []string{"use_loom"}, DestinationGrants: grants,
	})
	plan, err := ssotedit.AddAccessClient(body, ssotedit.ClientInput{
		ID: client.ID, Name: client.Name, Platform: model.LinuxServer, DestinationGrants: grants,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := model.Load(plan.Content)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.NodeByID()[client.ID], client
}

func TestClientProvisionFailureLeavesSSOTUnchangedAndRetryReusesSecrets(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	before, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	client := clientregistry.Client{ID: "client-retry01", Name: "Retry server", Platform: string(model.LinuxServer)}
	pinAccessTestIntent(t, &client)
	csrPEM, _ := clientProvisionCSR(t)
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.install = func(_ context.Context, nodeID string, _ []byte) error {
		if nodeID == "sg-vps" {
			return errors.New("simulated SSH failure")
		}
		return nil
	}
	if _, err := p.provision(client, csrPEM); err == nil || !strings.Contains(err.Error(), "SSOT was not changed") {
		t.Fatalf("failed pre-position error = %v", err)
	}
	after, _ := os.ReadFile(control.SSOTPath)
	if string(after) != string(before) {
		t.Fatal("failed secret pre-position changed SSOT")
	}
	masterBeforeRetry, err := secret.Load(paths.masterSecrets)
	if err != nil {
		t.Fatal(err)
	}
	value := masterBeforeRetry["api/"+client.ID]
	if value == "" {
		t.Fatal("safe orphan secret was not retained for retry")
	}
	p.install = func(context.Context, string, []byte) error { return nil }
	if result, err := p.provision(client, csrPEM); err != nil || result.Ready {
		t.Fatalf("retry result = %+v, %v", result, err)
	}
	masterAfterRetry, _ := secret.Load(paths.masterSecrets)
	if masterAfterRetry["api/"+client.ID] != value {
		t.Fatal("retry rotated an already pre-positioned secret")
	}
}

func TestClientProvisionSSHUsesPinnedTrustAndSuppressesRemoteOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("client provisioning SSH inputs must be root-owned")
	}
	control, paths := clientProvisionFixture(t)
	control.BootstrapSSHKey = filepath.Join(t.TempDir(), "control-bootstrap")
	control.KnownHostsPath = filepath.Join(t.TempDir(), "control-known_hosts")
	if err := os.WriteFile(control.BootstrapSSHKey, []byte("test private key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(control.KnownHostsPath, []byte("cn-gz ssh-ed25519 test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fakeDir := t.TempDir()
	argsPath := filepath.Join(fakeDir, "args")
	stdinPath := filepath.Join(fakeDir, "stdin")
	secret := "do-not-print-client-secret"
	fakeSSH := filepath.Join(fakeDir, "ssh")
	if err := os.WriteFile(fakeSSH, []byte(`#!/bin/sh
printf '%s\n' "$@" >"$LOOM_TEST_SSH_ARGS"
cat >"$LOOM_TEST_SSH_STDIN"
printf '%s\n' "$LOOM_TEST_SSH_SECRET" >&2
exit 23
`), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LOOM_TEST_SSH_ARGS", argsPath)
	t.Setenv("LOOM_TEST_SSH_STDIN", stdinPath)
	t.Setenv("LOOM_TEST_SSH_SECRET", secret)

	p := newClientProvisioner(control, new(sync.Mutex))
	err := p.installNodeSecrets(context.Background(), "cn-gz", []byte("api/client="+secret+"\n"))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("SSH error = %q, want failure without remote output", err)
	}
	gotArgsBody, readErr := os.ReadFile(argsPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	gotArgs := strings.Split(strings.TrimSuffix(string(gotArgsBody), "\n"), "\n")
	wantArgs := []string{
		"-F", paths.sshConfig,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + control.KnownHostsPath,
		"-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=10",
		"-i", control.BootstrapSSHKey,
		"--", "cn-gz", "/bin/sh", "-s", "--",
	}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("ssh args = %#v, want %#v", gotArgs, wantArgs)
	}
	stdin, readErr := os.ReadFile(stdinPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	script := string(stdin)
	fileSync := strings.Index(script, `sync_path "$temporary"`)
	rename := strings.Index(script, `mv -f "$temporary" "$target"`)
	directorySync := strings.Index(script, `sync_path "$directory"`)
	if fileSync < 0 || rename <= fileSync || directorySync <= rename {
		t.Fatalf("remote install durability order is wrong: file sync=%d rename=%d directory sync=%d", fileSync, rename, directorySync)
	}
}

func TestClientProvisionSSHFileSecurityBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("client provisioning SSH inputs must be root-owned")
	}
	t.Run("accepted metadata", func(t *testing.T) {
		dir := t.TempDir()
		config := filepath.Join(dir, "ssh_config")
		key := filepath.Join(dir, "key")
		if err := os.WriteFile(config, []byte("Host node\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, []byte("key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateClientProvisionSSHFile(config, "config", false); err != nil {
			t.Fatalf("safe config rejected: %v", err)
		}
		if err := validateClientProvisionSSHFile(key, "key", true); err != nil {
			t.Fatalf("safe private key rejected: %v", err)
		}
	})

	for _, tc := range []struct {
		name string
		make func(*testing.T, string) string
		key  bool
		want string
	}{
		{
			name: "symlink",
			make: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "input")
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "regular file",
		},
		{
			name: "hard link",
			make: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "input")
				if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, filepath.Join(dir, "other")); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "exactly one hard link",
		},
		{
			name: "writable by group",
			make: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "input")
				if err := os.WriteFile(path, []byte("x"), 0o620); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o620); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "group/world writable",
		},
		{
			name: "private key mode",
			make: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "input")
				if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
					t.Fatal(err)
				}
				return path
			},
			key:  true,
			want: "exactly 0600",
		},
		{
			name: "non-root owner",
			make: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "input")
				if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, 65534, -1); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "require root",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.make(t, t.TempDir())
			err := validateClientProvisionSSHFile(path, "test input", tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error = %v, want %q", err, tc.want)
			}
		})
	}
}

func clientProvisionFixture(t *testing.T) (*Control, clientProvisionPaths) {
	t.Helper()
	root := t.TempDir()
	deployDir := filepath.Join(root, "deploy")
	for _, dir := range []string{
		deployDir, filepath.Join(deployDir, "pki"), filepath.Join(deployDir, "keys"),
		filepath.Join(deployDir, "ssot-history"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	servers := ssot.Nodes[:0]
	for _, node := range ssot.Nodes {
		if node.IsServer() {
			servers = append(servers, node)
		}
	}
	ssot.Nodes = servers
	controlNode := ssot.NodeByID()["cn-bj"]
	controlNode.Access = &model.AccessRole{
		Platform: model.LinuxServer, Credentials: []string{"cred-control-best"},
		DefaultDeclaration: "best-egress",
		MixedPorts:         []model.MixedPort{{Port: 1080, Services: true}},
	}
	ssot.Credentials = append(ssot.Credentials, model.Credential{
		ID: "cred-control-best", Owner: "Synthetic control", Declaration: "best-egress",
		SecretRef: "cred/control-best",
	})
	ssot.Services = append(ssot.Services, model.Service{
		ID: "example-web", Addresses: []string{"api.example.com"}, Declaration: "best-egress",
	})
	best := ssot.DeclarationByID()["best-egress"]
	best.AllowedServers = best.AllowedServers[:0]
	for i := range ssot.Nodes {
		if ssot.Nodes[i].Server.EgressCapable {
			best.AllowedServers = append(best.AllowedServers, ssot.Nodes[i].ID)
		}
	}
	sort.Strings(best.AllowedServers)
	body, err = yaml.Marshal(ssot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deployDir, "ssot.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	all := map[string]string{"ui/cn-bj": "test-ui-secret"}
	for i := range ssot.Nodes {
		for _, ref := range nodeSecretRefs(ssot, ssot.Nodes[i].ID, nil) {
			all[ref] = "test-secret"
		}
	}
	if err := os.WriteFile(filepath.Join(deployDir, "secrets.env"),
		secret.Encode(all, masterSecretsHeader()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ssh_config"), []byte("Host *\n  BatchMode yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	control := &Control{SSOTPath: filepath.Join(deployDir, "ssot.yaml"), OperatorRef: "ui/cn-bj"}
	paths, err := clientPaths(control)
	if err != nil {
		t.Fatal(err)
	}
	return control, paths
}

func pinAccessTestIntent(t *testing.T, client *clientregistry.Client) {
	t.Helper()
	pinTestIntent(t, client, clientregistry.EnrollmentIntent{
		Platform: client.Platform, Responsibilities: []string{"use_loom"}, DestinationGrants: []string{"best-egress"},
	})
}

func pinServerTestIntent(t *testing.T, client *clientregistry.Client) {
	t.Helper()
	direction := ""
	if client.Server != nil {
		direction = client.Server.Direction
	}
	pinTestIntent(t, client, clientregistry.EnrollmentIntent{
		Platform: client.Platform, Responsibilities: []string{"forward", "internet_egress"}, Direction: direction,
	})
}

func pinTestIntent(t *testing.T, client *clientregistry.Client, input clientregistry.EnrollmentIntent) {
	t.Helper()
	intent, err := clientregistry.NormalizeEnrollmentIntent(input)
	if err != nil {
		t.Fatal(err)
	}
	client.Platform = intent.Platform
	client.Responsibilities = append([]string(nil), intent.Responsibilities...)
	client.DestinationGrants = append([]string(nil), intent.DestinationGrants...)
	client.Direction = intent.Direction
}

func mapKeysBool(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func copyTestFile(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, body, mode); err != nil {
		t.Fatal(err)
	}
}

func clientProvisionCSR(t *testing.T) (string, *x509.CertificateRequest) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "local-install"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), csr
}

func TestParseECDSAPrivateKeyAcceptsOpenSSLParametersPrefix(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatal(err)
	}
	body := append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: parameters}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	parsed, err := parseECDSAPrivateKey(body)
	if err != nil || !parsed.Equal(key) {
		t.Fatalf("parse OpenSSL EC key = %v, err=%v", parsed, err)
	}
	wrongParameters, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	wrong := append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: wrongParameters}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if _, err := parseECDSAPrivateKey(wrong); err == nil {
		t.Fatal("mismatched EC PARAMETERS were accepted")
	}
	trailing := append(append([]byte(nil), body...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if _, err := parseECDSAPrivateKey(trailing); err == nil {
		t.Fatal("multiple private keys were accepted")
	}
}

func prepareClientReadyFiles(t *testing.T, paths clientProvisionPaths, healthPath string, ssotBody []byte, now time.Time) {
	t.Helper()
	caTemplate := &x509.Certificate{
		SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "Test Loom CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte("test-ca-subject-key"),
	}
	writeClientTestCA(t, paths.caCert, paths.caKey, caTemplate)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.platformPublic, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority := clientReleaseAuthority{
		Schema: 1, Generation: 7, Snapshot: "abcdef123456", PublishedAt: now.Format(time.RFC3339Nano),
	}
	payload, _ := json.Marshal(clientReleasePayload{
		Schema: authority.Schema, Generation: authority.Generation, Snapshot: authority.Snapshot,
		PublishedAt: authority.PublishedAt,
	})
	authority.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey,
		append([]byte("loom-current-v1\x00"), payload...)))
	authorityBody, _ := json.MarshalIndent(authority, "", "  ")
	authorityBody = append(authorityBody, '\n')
	if err := os.WriteFile(filepath.Join(paths.releaseArchive, "release-authority.json"), authorityBody, 0o600); err != nil {
		t.Fatal(err)
	}
	ssotSum := sha256.Sum256(ssotBody)
	ssot, err := model.Load(ssotBody)
	if err != nil {
		t.Fatal(err)
	}
	distributionURL := ""
	if urls := ssot.DistributionURLs(); len(urls) > 0 {
		distributionURL = urls[0]
	}
	healthBody, _ := json.Marshal(PublisherState{
		PID: os.Getpid(), UpdatedAt: now.Format(time.RFC3339Nano), IntervalSeconds: 30,
		LastSuccess: now.Format(time.RFC3339Nano), LastSnapshot: authority.Snapshot,
		LastSSOT: hex.EncodeToString(ssotSum[:]),
		DistributionChecks: []PublisherDistributionCheck{{
			URL: distributionURL, Snapshot: authority.Snapshot, SSOT: hex.EncodeToString(ssotSum[:]),
			CheckedAt: now.Format(time.RFC3339Nano), Success: true,
		}},
	})
	if err := os.WriteFile(healthPath, healthBody, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeClientTestCA(t *testing.T, certPath, keyPath string, template *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bigOne() *big.Int { return big.NewInt(1) }

func mapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
