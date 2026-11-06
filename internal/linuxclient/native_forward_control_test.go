package linuxclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// Only this acceptance's exact CLI owns the temporary control and its report
// database. The test reads online results through the existing admin socket;
// original bytes are inspected read-only after that owner has exited.
type nativeForwardControl struct {
	root, socket, binary, evidence string
	ctx                            context.Context
	process                        *exec.Cmd
	done                           chan error
	starts, requests               int
}

func startNativeForwardControl(t *testing.T, ctx context.Context, binary, evidence string, intent control.NetworkIntent, sourceWGPublic, exitWGPublic string) (*nativeForwardControl, *deviceclient.Store, string) {
	t.Helper()
	if len(intent.Services) != 1 || len(intent.Policies) != 1 || len(intent.Resources) != 2 || len(intent.Links) != 0 || len(intent.BusinessProbeTargets) != 0 || len(intent.PublicTrust) != 0 || len(intent.ExpectedComponents) != 0 {
		t.Fatal("forward acceptance requires its one Service/Policy and two native resources")
	}
	parent := filepath.Join(evidence, "control")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	// TMPDIR is the isolated runner's short, protected scratch. A short socket
	// path avoids depending on the length of the persistent evidence directory.
	sockets, err := os.MkdirTemp("", "loom-forward-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	f := &nativeForwardControl{root: filepath.Join(parent, "authority"), socket: filepath.Join(sockets, "admin.sock"), binary: binary, evidence: parent, ctx: ctx}
	t.Cleanup(func() { f.stop(t) })
	write := func(name string, value any) string {
		t.Helper()
		body, err := control.CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
		return f.file(t, name, body)
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := f.file(t, "control-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	encodedPublic := base64.RawURLEncoding.EncodeToString(public)
	keyID, err := control.KeyID(encodedPublic)
	if err != nil {
		t.Fatal(err)
	}
	member := control.Member{ControlID: "demo-control", NodeID: "demo-control", PublicKey: encodedPublic}
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: member.ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: []control.Member{member}, SealedKeys: []control.ControlSealedKey{}}, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{}}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := control.MaterialID(genesis)
	if err != nil {
		t.Fatal(err)
	}
	node := control.NodeConfig{Schema: 3, NetworkID: "demo-network", ControlID: member.ControlID, NodeID: member.NodeID, GenesisID: genesisID, SigningKeyFile: keyPath}
	f.cli(t, "control", "init", "-state-dir", f.root, "-node-config", write("node-input.json", node), "-genesis", write("genesis-input.json", genesis))

	// The production endpoint authenticates its exact signed leaf and SPKI.
	// This private leaf is generated for this test, never installed as host trust.
	tlsPublic, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo forward control"}, DNSNames: []string{"demo-control.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(6 * time.Hour)}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, tlsPublic, tlsPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	tlsDER, err := x509.MarshalPKCS8PrivateKey(tlsPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := f.file(t, "endpoint-certificate.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}))
	tlsKeyPath := f.file(t, "endpoint-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsDER}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := control.EndpointGeneration{ID: "demo-forward-control", Generation: 1, OwnerControlID: member.ControlID, Host: host, Port: portNumber, ServerName: "demo-control.example", SPKISHA256: control.ReleaseDigest(leaf.RawSubjectPublicKeyInfo), CertificateDigest: control.ReleaseDigest(leaf.Raw), Modes: []string{"bootstrap", "device"}, State: "prepared"}
	inputs := control.EndpointLocalInputs{Listen: address, CertificateFile: certificatePath, KeyFile: tlsKeyPath}
	f.cli(t, "control", "endpoint-inputs", "-state-dir", f.root, "-endpoint", write("endpoint.json", endpoint), "-inputs", write("endpoint-inputs.json", inputs))
	f.start(t)
	prepared := f.operation(t, "endpoint.put", "endpoint", endpoint.ID, endpoint)
	probe, cancelProbe := context.WithTimeout(ctx, 5*time.Second)
	defer cancelProbe()
	for control.ProbeEndpoint(probe, endpoint) != nil {
		select {
		case <-probe.Done():
			t.Fatal("prepared control endpoint did not complete its actual TLS probe")
		case <-time.After(20 * time.Millisecond):
		}
	}
	endpoint.State = "serving"
	f.operation(t, "endpoint.put", "endpoint", endpoint.ID, endpoint, prepared.MaterialID)
	service := f.operation(t, "service.put", "service", intent.Services[0].ID, intent.Services[0])
	// The first source LKG already has its sole Policy, so the normal identity
	// transition initializes that choice. No test writes a preference directly.
	policy := intent.Policies[0]
	anyScope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	policy.EntryScope, policy.RelayScope, policy.ExitScope = anyScope, anyScope, new(anyScope)
	f.operation(t, "policy.put", "policy", policy.ID, policy, service.MaterialID)
	states := map[string]string{}
	for _, device := range []struct {
		id, name string
		roles    []string
		policies []string
		wg       string
	}{
		{"demo-device", "Demo forward source", []string{"access", "forward"}, []string{policy.ID}, sourceWGPublic},
		{"demo-exit", "Demo internet exit", []string{"internet_egress"}, []string{}, exitWGPublic},
	} {
		invite := control.Invite{ID: device.id + "-enrollment", GenesisDigest: genesisID, IssuerControlID: member.ControlID, DeviceID: device.id, Name: device.name, Responsibilities: device.roles, PolicyIDs: device.policies, DNSServers: []string{"127.0.0.1"}, Medium: "sh", Endpoint: endpoint, ExpiresAt: time.Now().Add(30 * time.Minute).UnixMilli()}
		issued := f.operation(t, "invite.issue", "invite", invite.ID, invite, f.dependencies(t, "endpoint", endpoint.ID, "service", intent.Services[0].ID, "policy", policy.ID)...)
		if issued.Invite == "" {
			t.Fatal("formal control did not return its invitation")
		}
		invitePath := f.file(t, device.id+"-invite.txt", []byte(issued.Invite))
		states[device.id] = filepath.Join(parent, device.id+"-identity.json")
		f.cli(t, "client", "enroll", "-invite-file", invitePath, "-state", states[device.id])
		put := control.DevicePut{ID: device.id, Name: device.name, Responsibilities: device.roles, PolicyIDs: device.policies, DistributionURLs: []string{}, DNSServers: invite.DNSServers, WireGuardPublicKey: device.wg}
		f.operation(t, "device.put", "device", device.id, put, f.dependencies(t, "device", device.id, "policy", policy.ID, "service", intent.Services[0].ID)...)
	}
	for _, resource := range intent.Resources {
		if resource.OwnerNodeID != "demo-exit" {
			t.Fatal("forward acceptance resource belongs to another receiver")
		}
		f.operation(t, "resource.put", "resource", resource.ID, resource, f.dependencies(t, "device", resource.OwnerNodeID)...)
	}
	f.operation(t, "policy.put", "policy", policy.ID, intent.Policies[0], f.dependencies(t, "policy", policy.ID, "service", intent.Services[0].ID, "device", "demo-device", "device", "demo-exit")...)
	for _, record := range intent.DNSRecords {
		f.operation(t, "dns_record.put", "dns_record", record.ID, record)
	}
	for _, id := range []string{"demo-device", "demo-exit"} {
		f.cli(t, "client", "sync", "-state", states[id])
	}
	store, err := deviceclient.Load(states["demo-device"])
	if err != nil || store.LKG() == nil {
		t.Fatal("formal source did not persist its certified LKG", err)
	}
	return f, store, states["demo-device"]
}

func (f *nativeForwardControl) file(t *testing.T, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(f.evidence, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(body)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *nativeForwardControl) cli(t *testing.T, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancel()
	result, err := exec.CommandContext(ctx, f.binary, args...).CombinedOutput()
	if err != nil {
		f.file(t, fmt.Sprintf("cli-failure-%03d.log", f.requests), result)
		// Invitations and identity material must not appear in test output.
		t.Fatalf("official forward-control CLI %s %s failed at setup request %d: %v", args[0], args[1], f.requests, err)
	}
	return result
}

func (f *nativeForwardControl) operation(t *testing.T, operation, kind, id string, payload control.MaterialPayload, dependencies ...string) struct{ MaterialID, Invite string } {
	t.Helper()
	sort.Strings(dependencies)
	unique := []string{}
	for _, dependency := range dependencies {
		if dependency != "" && (len(unique) == 0 || unique[len(unique)-1] != dependency) {
			unique = append(unique, dependency)
		}
	}
	f.requests++
	request := control.Operation{Schema: 3, RequestID: fmt.Sprintf("demo-forward-setup-%d", f.requests), Operation: operation, TargetKind: kind, TargetID: id, Dependencies: unique, Payload: payload}
	body, err := control.EncodeOperation(request)
	if err != nil {
		t.Fatal(err)
	}
	path := f.file(t, fmt.Sprintf("operation-%03d.json", f.requests), body)
	response := f.cli(t, "control", "write", "-socket", f.socket, "-request", path)
	var result struct {
		MaterialID string `json:"material_id"`
		Invite     string `json:"invite"`
	}
	if json.Unmarshal(response, &result) != nil || control.ValidateDigest(result.MaterialID) != nil {
		t.Fatal("official operation did not return a signed fact")
	}
	return struct{ MaterialID, Invite string }{result.MaterialID, result.Invite}
}

func (f *nativeForwardControl) dependencies(t *testing.T, targets ...string) []string {
	t.Helper()
	snapshot, err := f.snapshot(f.ctx)
	if err != nil {
		t.Fatal("current control targets unavailable", err)
	}
	dependencies := []string{}
	for i := 0; i < len(targets); i += 2 {
		found := false
		for _, target := range snapshot.Targets {
			if target.TargetKind == targets[i] && target.TargetID == targets[i+1] && !target.Conflicted && !target.Deleted {
				dependencies = append(dependencies, target.MaterialIDs...)
				found = true
			}
		}
		if !found {
			t.Fatal("required live target is unavailable")
		}
	}
	return dependencies
}

func (f *nativeForwardControl) get(ctx context.Context, path string, value any) error {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", f.socket)
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://loom.local"+path, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("formal control readback returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(body) > 8<<20 {
		return errors.New("formal control readback exceeded its boundary")
	}
	return json.Unmarshal(body, value)
}

func (f *nativeForwardControl) snapshot(ctx context.Context) (control.WebSnapshot, error) {
	var value control.WebSnapshot
	err := f.get(ctx, "/api/control/ui/snapshot", &value)
	return value, err
}

func (f *nativeForwardControl) start(t *testing.T) {
	t.Helper()
	if f.process != nil {
		t.Fatal("forward control already has an online owner")
	}
	f.starts++
	log, err := os.OpenFile(filepath.Join(f.evidence, fmt.Sprintf("daemon-%d.log", f.starts)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(f.ctx, f.binary, "control", "serve", "-state-dir", f.root, "-admin-socket", f.socket)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal("formal control daemon did not start", err)
	}
	f.process, f.done = command, make(chan error, 1)
	done := f.done
	go func() { err := command.Wait(); _ = log.Close(); done <- err }()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		value, err := f.snapshot(f.ctx)
		if err == nil && value.Schema == 3 && value.NetworkID == "demo-network" {
			return
		}
		select {
		case err := <-done:
			f.process = nil
			t.Fatal("formal control daemon exited before readback", err)
		case <-deadline.C:
			t.Fatal("formal control daemon did not expose its snapshot")
		case <-f.ctx.Done():
			t.Fatal("forward control startup was cancelled")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (f *nativeForwardControl) stop(t *testing.T) {
	t.Helper()
	if f.process == nil {
		return
	}
	command, done := f.process, f.done
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		f.process = nil
		if err != nil && f.ctx.Err() == nil {
			t.Fatal("formal control did not stop normally", err)
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		<-done
		f.process = nil
		t.Fatal("formal control did not release its owned process normally")
	}
}

func (f *nativeForwardControl) offlineReports(t *testing.T, name string) []control.DeviceReport {
	t.Helper()
	if f.process != nil || filepath.Base(name) != name || name == "." || name == ".." || name == "" {
		t.Fatal("original inspection requires a stopped owner and one evidence directory name")
	}
	authority, err := control.OpenAuthority(f.root)
	if err != nil {
		t.Fatal(err)
	}
	projection := authority.Snapshot()
	keys := map[string]string{}
	for _, device := range projection.DeviceAuthorizations {
		keys[device.ID] = device.DevicePublicKey
	}
	path := filepath.Join(f.root, "observations.db")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() == 0 {
		t.Fatal("original database is not a protected regular file")
	}
	options := &bolt.Options{ReadOnly: true, Timeout: 250 * time.Millisecond}
	options.OpenFile = func(path string, flags int, mode os.FileMode) (*os.File, error) {
		file, err := os.OpenFile(path, flags&^os.O_CREATE, mode)
		if err != nil {
			return nil, err
		}
		opened, a := file.Stat()
		current, b := os.Lstat(path)
		if a != nil || b != nil || !os.SameFile(before, opened) || !os.SameFile(opened, current) || !current.Mode().IsRegular() || current.Mode().Perm()&0077 != 0 {
			file.Close()
			return nil, errors.New("original database changed while opening")
		}
		return file, nil
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		t.Fatal("stopped original database could not be opened read-only", err)
	}
	defer db.Close()
	directory := filepath.Join(f.evidence, name)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	reports := []control.DeviceReport{}
	highest := map[string]control.U64{}
	ids := []string{}
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("reports"))
		if bucket == nil || bucket.Sequence() != 0 {
			return errors.New("original report bucket is unavailable or independently sequenced")
		}
		return bucket.ForEach(func(key, raw []byte) error {
			if err := f.ctx.Err(); err != nil {
				return err
			}
			if raw == nil {
				return errors.New("original report bucket contains a nested store")
			}
			var report control.DeviceReport
			if err := control.DecodeCanonical(raw, &report, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
				return err
			}
			canonical, err := control.CanonicalEncode(report)
			if err != nil || !bytes.Equal(canonical, raw) || report.NetworkID != projection.NetworkID || report.Verify(keys[report.DeviceID]) != nil {
				return errors.New("stored report lost its canonical bytes, authority identity or signature")
			}
			digest := sha256.Sum256(raw)
			expected := binary.BigEndian.AppendUint64([]byte(report.NetworkID+"\x00"+report.DeviceID+"\x00"), uint64(report.ReportSequence))
			expected = append(expected, digest[:]...)
			if !bytes.Equal(key, expected) {
				return errors.New("original report key differs from its signed owner, sequence or bytes")
			}
			id := hex.EncodeToString(digest[:])
			file, err := os.OpenFile(filepath.Join(directory, id+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, writeErr := file.Write(raw)
			if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
				return err
			}
			if report.ReportSequence > highest[report.DeviceID] {
				highest[report.DeviceID] = report.ReportSequence
			}
			ids = append(ids, "sha256:"+id)
			reports = append(reports, report)
			return nil
		})
	})
	if err != nil {
		t.Fatal("original report inspection failed", err)
	}
	if len(reports) == 0 {
		t.Fatal("formal control persisted no original reports")
	}
	index, err := json.MarshalIndent(struct {
		OriginalIDs     []string               `json:"original_ids"`
		HighestSequence map[string]control.U64 `json:"highest_sequence"`
		ReadOnly        bool                   `json:"read_only"`
	}{ids, highest, true}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "index.json"), append(index, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("read-only original inspection changed the database")
	}
	return reports
}
