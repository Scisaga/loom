package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestEndpointReadinessChecksEachTLSProtocolOnce(t *testing.T) {
	root := t.TempDir()
	ca := testTransportCA(t, root)
	files, _, leaf := testTransportIdentity(t, root, "demo-probe-tls", 52, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	certificate, err := tls.LoadX509KeyPair(files.CertificateFile, files.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		modes     []string
		protocols []string
		want      []string
		fails     bool
	}{
		{"shared tunnel", []string{"bootstrap", "device"}, []string{tunnelALPN}, []string{tunnelALPN}, false},
		{"separate web", []string{"bootstrap", "device", "web"}, []string{tunnelALPN, "http/1.1"}, []string{tunnelALPN, "http/1.1"}, false},
		{"web unavailable", []string{"bootstrap", "device", "web"}, []string{tunnelALPN}, []string{tunnelALPN, "http/1.1"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := make(chan string, 4)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: test.protocols,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					for _, protocol := range hello.SupportedProtos {
						attempts <- protocol
					}
					return nil, nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					connection.SetDeadline(time.Now().Add(3 * time.Second))
					_ = connection.(*tls.Conn).Handshake()
					connection.Close()
				}
			}()
			defer func() { listener.Close(); <-done }()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			endpoint := EndpointGeneration{ID: "demo-probe-entry", Generation: 1, OwnerControlID: "demo-control", Host: host, Port: number, ServerName: "demo.example", SPKISHA256: endpointByteDigest(leaf.RawSubjectPublicKeyInfo), CertificateDigest: endpointByteDigest(leaf.Raw), Modes: test.modes, State: "prepared"}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := ProbeEndpoint(ctx, endpoint); (err != nil) != test.fails {
				t.Fatal("readiness did not verify the advertised protocols", err)
			}
			var got []string
			for len(attempts) > 0 {
				got = append(got, <-attempts)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("TLS attempts %v, want %v", got, test.want)
			}
		})
	}
}

func endpointHTTPClient(connection net.Conn) *http.Client {
	used := false
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, net.ErrClosed
		}
		used = true
		return connection, nil
	}}}
}
func endpointPost(t *testing.T, connection net.Conn, path string, value any) (int, []byte) {
	t.Helper()
	body, err := CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	response, err := endpointHTTPClient(connection).Post("http://control.loom"+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}
func TestEndpointTLSClaimConfigurationReportAndRevocation(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ca := testTransportCA(t, filepath.Dir(root))
	files, _, leaf := testTransportIdentity(t, filepath.Dir(root), "demo-endpoint-tls", 51, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	address := testLoopbackAddress(t)
	host, port, _ := net.SplitHostPort(address)
	number, _ := strconv.Atoi(port)
	endpoint := EndpointGeneration{ID: "demo-live-entry", Generation: 1, OwnerControlID: config.ControlID, Host: host, Port: number, ServerName: "demo.example", SPKISHA256: endpointByteDigest(leaf.RawSubjectPublicKeyInfo), CertificateDigest: endpointByteDigest(leaf.Raw), Modes: []string{"bootstrap", "device"}, State: "prepared"}
	if err := InstallEndpointInputs(root, endpoint, EndpointLocalInputs{Listen: address, CertificateFile: files.CertificateFile, KeyFile: files.KeyFile}); err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: runtime, Config: config}
	prepared, _, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-endpoint-prepared", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{}, Payload: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := NewEndpointRuntime(runtime.Authority, config.ControlID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoints.Close()
	server.Endpoints = endpoints
	deviceServer := &http.Server{Handler: server.DeviceHandler(), ConnContext: endpointConnContext, ReadHeaderTimeout: time.Second}
	defer deviceServer.Close()
	go deviceServer.Serve(endpoints)
	if !endpoints.Ready(endpoint) {
		t.Fatal("prepared endpoint failed actual advertised TLS probe")
	}
	endpoint.State = "serving"
	serving, _, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-endpoint-serving", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{prepared.MaterialID}, Payload: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	service := submitAuthority(t, runtime, authorityService("demo-service", "demo-live-service"))
	scope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	policy := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-live-policy", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-policy", Dependencies: []string{service.MaterialID}, Payload: NetworkPolicy{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: new(scope), AllowDirect: new(true), LocalEgressDevices: new([]string{})}})
	invite := Invite{ID: "demo-live-transaction", GenesisDigest: config.GenesisID, IssuerControlID: config.ControlID, DeviceID: "demo-live-access", Name: "Demo live access", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Medium: "qr", Endpoint: endpoint, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
	issued, extra, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-live-invite", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies([]string{serving.MaterialID, service.MaterialID, policy.MaterialID}), Payload: invite})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := DecodeInvite(extra.Invite)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: config.NetworkID, GenesisDigest: config.GenesisID, TransactionID: invite.ID, InviteMaterialID: issued.MaterialID, RequestID: "demo-live-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := DialEndpoint(ctx, endpoint, TunnelHello{Schema: 3, Mode: "bootstrap", EndpointID: endpoint.ID, Generation: endpoint.Generation, Invite: &bootstrap}, nil)
	if err != nil {
		t.Fatal(err)
	}
	status, body := endpointPost(t, connection, "/enrollment/claim", claim)
	if status != http.StatusOK {
		t.Fatalf("authenticated claim failed: %d %s", status, body)
	}
	var joined EnrollmentResponse
	if err := DecodeCanonical(body, &joined, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if joined.DeviceView == nil || VerifyDeviceViewEnvelope(*joined.DeviceView, bootstrap) != nil {
		t.Fatal("claim did not return a verified current envelope")
	}
	deviceHello := TunnelHello{Schema: 3, Mode: "device", EndpointID: endpoint.ID, Generation: endpoint.Generation, DeviceID: invite.DeviceID}
	// A resolved transport address must not replace the certified TLS name or
	// pin. Exercise the actual private handshake through the injected dialer.
	resolved := WithEndpointDialer(ctx, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	named := endpoint
	named.Host = "demo-entry.example"
	resolvedConnection, err := DialEndpoint(resolved, named, deviceHello, key)
	if err != nil {
		t.Fatal("resolved endpoint lost its certified identity", err)
	}
	resolvedConnection.Close()
	named.ServerName = "demo-wrong.example"
	if bad, err := DialEndpoint(resolved, named, deviceHello, key); err == nil {
		bad.Close()
		t.Fatal("DNS address replaced certified TLS identity")
	}
	connection, err = DialEndpoint(ctx, endpoint, deviceHello, key)
	if err != nil {
		t.Fatal(err)
	}
	status, body = endpointPost(t, connection, "/device/config", struct{}{})
	if status != http.StatusOK {
		t.Fatalf("device configuration rejected: %d %s", status, body)
	}
	var view DeviceViewEnvelope
	if err := DecodeCanonical(body, &view, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if len(view.View.Routes) != 1 {
		t.Fatal("authorized Direct candidate is unavailable")
	}

	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	server.Runtime.Reports = store
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: config.NetworkID, DeviceID: invite.DeviceID, ReportSequence: 1, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-loopback", ReportedAt: time.Now().UnixMilli(), Selections: []ReportSelection{{ServiceID: "demo-service", CandidateID: view.View.Routes[0].ID}}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, err = DialEndpoint(ctx, endpoint, deviceHello, key)
	if err != nil {
		t.Fatal(err)
	}
	status, body = endpointPost(t, connection, "/device/report", report)
	if status != http.StatusOK {
		t.Fatalf("signed report rejected: %d %s", status, body)
	}
	var receipt DeviceReportResponse
	if err := DecodeCanonical(body, &receipt, ContractDecodeLimits{MaxBytes: 1024, MaxDepth: 8, MaxItems: 32}); err != nil || receipt.ReportSequence != 1 {
		t.Fatal("report did not return the canonical accepted sequence")
	}
	if len(store.Verified(runtime.Authority.Snapshot())) != 1 {
		t.Fatal("accepted signed report was not read back")
	}

	current, _ := runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	removed := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-live-remove-policy", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: current.MaterialIDs, Payload: DevicePut{ID: invite.DeviceID, Name: invite.Name, Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{}}})
	connection, err = DialEndpoint(ctx, endpoint, deviceHello, key)
	if err != nil {
		t.Fatal(err)
	}
	status, body = endpointPost(t, connection, "/device/config", struct{}{})
	if status != http.StatusOK {
		t.Fatal("empty-policy configuration unavailable")
	}
	if err := DecodeCanonical(body, &view, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || len(view.View.Routes) != 0 {
		t.Fatal("removed policy survived in authenticated runtime view")
	}
	if len(store.Verified(runtime.Authority.Snapshot())) != 0 {
		t.Fatal("old View report was shown as current after withdrawal")
	}
	submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-live-revoke", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: []string{removed.MaterialID}, Payload: DeleteTarget{ID: invite.DeviceID}})
	if connection, err := DialEndpoint(ctx, endpoint, deviceHello, key); err == nil {
		connection.Close()
		t.Fatal("revoked identity established a new authenticated device tunnel")
	}
}
