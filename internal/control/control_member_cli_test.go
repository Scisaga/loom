package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This opt-in acceptance runs the built CLI, two independent daemons and the
// actual Linux client. All listeners and generated trust are local to this test;
// the pure-control client has no TUN, resources, routes or business proxy.
func TestControlMemberCLIJoinsRunsAndRestarts(t *testing.T) {
	binary := os.Getenv("LOOM_MEMBER_CLI")
	if binary == "" {
		t.Skip("set LOOM_MEMBER_CLI to the exact freshly built executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) string {
		t.Helper()
		body, err := CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, name)
		if err = os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cli := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, args...)
		body, err := command.Output()
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				t.Fatalf("CLI %s: %s", args[0], exit.Stderr)
			}
			t.Fatal(err)
		}
		return body
	}
	start := func(name string, args ...string) func() {
		t.Helper()
		log, err := os.OpenFile(filepath.Join(parent, name+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, binary, args...)
		command.Stdout, command.Stderr = log, log
		if err = command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait(); log.Close() }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
			if t.Failed() {
				body, _ := os.ReadFile(filepath.Join(parent, name+".log"))
				t.Logf("%s process diagnostics: %s", name, body)
			}
		}
		t.Cleanup(stop)
		return stop
	}
	wait := func(message string, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			if check() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal(message)
	}
	snapshot := func(socket string) (WebSnapshot, bool) {
		transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		response, err := client.Get("http://loom.local/api/control/ui/snapshot")
		if err != nil {
			return WebSnapshot{}, false
		}
		defer response.Body.Close()
		var value WebSnapshot
		err = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&value)
		return value, err == nil && response.StatusCode == http.StatusOK
	}

	fixture := newEndpointFixture(t)
	a := fixture.server.Runtime
	rootA, configA := a.Authority.root, a.Config
	target, _ := a.Authority.Snapshot().CurrentTarget("endpoint", fixture.endpoint.ID)
	_ = fixture.runtime.Close()
	_ = a.Close()
	keyA, err := configA.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerA, _, _ := testTransportIdentity(t, parent, configA.ControlID, 101, keyA, fixture.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	browser, _, _ := testTransportIdentity(t, parent, "demo-browser", 102, testKey(t), fixture.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	configA.PeerTLS, configA.BrowserTLS = &peerA, &browser
	body, _ := CanonicalEncode(configA)
	if err = atomicWrite(filepath.Join(rootA, "node.json"), body); err != nil {
		t.Fatal(err)
	}
	addresses := []string{testLoopbackAddress(t), testLoopbackAddress(t)}
	newNode := "demo-cli-member"
	privateA := write("a-private.json", PrivateChannelConfig{Schema: 3, Node: configA.NodeID, Listen: []string{addresses[0]}, Peers: []PrivatePeer{{Node: newNode, Addresses: []string{addresses[1]}}}})
	socketA := filepath.Join(parent, "a.sock")
	stopA := start("a", "control", "serve", "-state-dir", rootA, "-private-inputs", privateA, "-admin-socket", socketA)
	wait("first daemon did not expose formal admin readback", func() bool { _, ok := snapshot(socketA); return ok })
	invite := Invite{ID: "demo-cli-enrollment", GenesisDigest: configA.GenesisID, IssuerControlID: configA.ControlID, DeviceID: newNode, Name: "Demo CLI member", Responsibilities: []string{"control"}, PolicyIDs: []string{}, Medium: "sh", Endpoint: fixture.endpoint, ExpiresAt: time.Now().Add(5 * time.Minute).UnixMilli()}
	operation := Operation{Schema: 3, RequestID: "demo-cli-issue", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: target.MaterialIDs, Payload: invite}
	var issued struct {
		Invite string `json:"invite"`
	}
	if err = json.Unmarshal(cli("control", "write", "-socket", socketA, "-request", write("invite.json", operation)), &issued); err != nil || issued.Invite == "" {
		t.Fatal("formal invite issuance failed", err)
	}
	invitePath := filepath.Join(parent, "invite.txt")
	if err = os.WriteFile(invitePath, []byte(issued.Invite), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "device.json")
	cli("client", "enroll", "-invite-file", invitePath, "-state", state)
	var identity DeviceIdentityReadback
	if err = json.Unmarshal(cli("client", "inspect", "-state", state, "-identity"), &identity); err != nil || !identity.Joined {
		t.Fatal("CLI did not persist the certified claim", err)
	}
	public, err := base64.RawURLEncoding.DecodeString(identity.DevicePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(103), Subject: pkix.Name{CommonName: newNode}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, fixture.ca.certificate, ed25519.PublicKey(public), fixture.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(parent, "member.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	peerB := TLSFiles{CertificateFile: certPath, KeyFile: filepath.Join(parent, "member-key.pem"), TrustFile: fixture.ca.file}
	configB := NodeConfig{Schema: 3, NetworkID: configA.NetworkID, GenesisID: configA.GenesisID, ControlID: newNode, NodeID: newNode, SigningKeyFile: peerB.KeyFile, PeerTLS: &peerB, BrowserTLS: &browser}
	rootB := filepath.Join(parent, "member-authority")
	cli("control", "join", "-state-dir", rootB, "-node-config", write("member-node.json", configB), "-device-state", state)
	privateB := write("b-private.json", PrivateChannelConfig{Schema: 3, Node: newNode, Listen: []string{addresses[1]}, Peers: []PrivatePeer{{Node: configA.NodeID, Addresses: []string{addresses[0]}}}})
	socketB := filepath.Join(parent, "b.sock")
	startB := func(name string) func() {
		return start(name, "control", "serve", "-state-dir", rootB, "-private-inputs", privateB, "-admin-socket", socketB)
	}
	stopB := startB("b")
	wait("joined daemon did not expose formal readback", func() bool { value, ok := snapshot(socketB); return ok && len(value.Members) == 2 })
	cli("control", "write", "-socket", socketB, "-request", write("service.json", authorityService("demo-cli-service", "demo-cli-service-write")))
	wait("new member's original signed fact did not synchronize", func() bool {
		value, ok := snapshot(socketA)
		if !ok {
			return false
		}
		for _, service := range value.Services {
			if service.ID == "demo-cli-service" {
				return true
			}
		}
		return false
	})
	clientStop := start("client", "client", "run", "-state", state, "-runtime-state", filepath.Join(parent, "runtime-state.json"), "-status", filepath.Join(parent, "status.json"), "-runtime-config", filepath.Join(parent, "runtime.json"), "-capture", "mixed")
	wait("pure-control agent did not consume its view and report the absent data plane", func() bool {
		value, ok := snapshot(socketA)
		if !ok {
			return false
		}
		for _, device := range value.Devices {
			if device.ID == newNode && device.Evidence != nil && device.Evidence.Runtime != nil && device.Evidence.Runtime.State == "stopped" && device.Evidence.Runtime.ErrorCode == "" && device.ViewDigest != "" {
				return true
			}
		}
		return false
	})
	clientStop()
	stopB()
	startB("b-restarted")
	wait("restarted member lost fact or original report", func() bool {
		value, ok := snapshot(socketB)
		if !ok {
			return false
		}
		found := false
		for _, service := range value.Services {
			found = found || service.ID == "demo-cli-service"
		}
		for _, device := range value.Devices {
			if device.ID == newNode && found && device.LastReportAt != "" {
				return true
			}
		}
		return false
	})
	var after DeviceIdentityReadback
	if err = json.Unmarshal(cli("client", "inspect", "-state", state, "-identity"), &after); err != nil || after != identity {
		t.Fatal("restart changed the admitted device identity", err)
	}
	stopA()
	t.Log("formal CLI invite, client claim, original-fact join, two daemons, signed sync, pure-control runtime report and restart passed")
}
