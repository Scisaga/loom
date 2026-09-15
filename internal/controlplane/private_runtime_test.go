package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/clientv2"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// 这里经真实 TCP/TLS 进入生产服务组合，不给 request 伪造 TLS 状态（D131）。
func TestPrivateRuntimeDeviceConfigAndReportOverMTLSSurviveRestart(t *testing.T) {
	options, device, reports := privateRuntimeFixture(t)
	// 回执传送原对象，不在传输层制造签名或健康结论；客户端观测 verifier 单独验签。
	observation := json.RawMessage(`{"node":"demo-server","ts":"2026-09-11T12:00:00Z"}`)
	reads := 0
	options.Observations = func(ctx context.Context, report VerifiedDeviceReportV2) ([]json.RawMessage, error) {
		store, err := OpenDeviceReportStore(reports, options.ReportSchemas)
		if err != nil || len(store.Snapshot().Reports) != 1 {
			t.Fatal("报告尚未耐久接受就读取观测", err)
		}
		reads++
		return []json.RawMessage{observation}, nil
	}
	addresses := map[string]string{}
	options.Listen = privateRuntimeLoopbackListen(addresses)
	runtime, err := NewPrivateRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := runtime.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); <-done })
	client := privateRuntimeClient(t, options, addresses, &tls.Certificate{
		Certificate: privateRuntimeDeviceChain(t, device), PrivateKey: device.identityKey,
	})
	response, err := client.Get("https://10.50.0.2:7445" + PrivateDeviceConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	want, _ := wire.MarshalCanonical(device.envelope)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, want) {
		t.Fatalf("实际私有 config 交付失败: status=%d err=%v", response.StatusCode, err)
	}
	set := device.identitiesSet(t)
	floors, err := wire.VerifyDeviceViewEnvelope(&device.envelope, &set)
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"healthy":true,"version":"demo-build"}`)
	payloadHash, _ := wire.DeviceReportPayloadHash(payload)
	report, err := wire.SignDeviceReport(wire.DeviceReportBodyV2{
		Schema: 2, ClusterID: device.record.ProfileState.ClusterID, DeviceID: device.record.DeviceID,
		ReportID: "demo-report", ReportSequence: 1, GeneratedAt: options.Now().Format(time.RFC3339),
		AcceptedFloors: floors, Kind: "health", PayloadSchema: 1, PayloadHash: payloadHash,
	}, payload, device.identityKey, options.ReportSchemas)
	if err != nil {
		t.Fatal(err)
	}
	// 使用生产客户端构造器及完整 Device 链，防止仅 leaf 的 fixture 掩盖宿主不互通。
	roots := x509.NewCertPool()
	for _, certificate := range options.Certificates {
		leaf, _ := x509.ParseCertificate(certificate.Certificate[0])
		roots.AddCert(leaf)
	}
	var reportService wire.PrivateControlServiceV1
	for _, service := range options.Services {
		if service.Role == "device_report" {
			reportService = service
		}
	}
	poster, err := clientv2.NewPrivateDeviceHTTPClient(reportService, "device_report", device.record.ProfileRef.ProfileID,
		privateRuntimeDeviceChain(t, device), device.identityKey, roots,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			local, found := addresses[address]
			if !found {
				return nil, errors.New("demo-unknown-tuple")
			}
			return (&net.Dialer{}).DialContext(ctx, network, local)
		}, options.Now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer poster.CloseIdleConnections()
	observations, err := poster.PostDeviceReportWithObservations(ctx, &report)
	if err != nil {
		t.Fatal("实际完整链签名 report 被拒绝", err)
	}
	if reads != 1 || len(observations) != 1 || !bytes.Equal(observations[0], observation) {
		t.Fatal("一次报告未返回原观测，或重复触发 reader")
	}
	reopened, err := OpenDeviceReportStore(reports, options.ReportSchemas)
	if err != nil {
		t.Fatal(err)
	}
	state := reopened.Snapshot()
	if len(state.Reports) != 1 || state.Reports[0].Body.ReportSequence != 1 ||
		!bytes.Equal(state.Reports[0].Payload, payload) {
		t.Fatal("报告没有持久化 exact 已验签内容")
	}
	anonymous := privateRuntimeClient(t, options, addresses, nil)
	response, err = anonymous.Get("https://10.50.0.2:7445" + PrivateDeviceConfigPath)
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("无 Device mTLS 连接通过 TLS listener")
	}
}

func privateRuntimeDeviceChain(t *testing.T, device deviceConfigFixture) [][]byte {
	chain := [][]byte{device.leaf.Raw}
	for _, encoded := range device.record.ProfileState.ProfileIntent.IssuerChainDER {
		der, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, der)
	}
	return chain
}

func TestPrivateRuntimePartialBindRollbackAndCancellation(t *testing.T) {
	options, _, _ := privateRuntimeFixture(t)
	addresses := map[string]string{}
	listen := privateRuntimeLoopbackListen(addresses)
	var first net.Listener
	binds := 0
	options.Listen = func(ctx context.Context, network, address string) (net.Listener, error) {
		binds++
		if binds == 2 {
			return nil, errors.New("demo-bind-failure")
		}
		listener, err := listen(ctx, network, address)
		first = listener
		return listener, err
	}
	runtime, err := NewPrivateRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Start(context.Background()); err == nil {
		t.Fatal("部分 bind 被当成已启动")
	}
	if conn, err := first.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("失败后残留 listener")
	}
	runtime.listen = listen
	ctx, cancel := context.WithCancel(context.Background())
	done, err := runtime.Start(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := runtime.Start(ctx); err == nil {
		cancel()
		t.Fatal("允许重复 Start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("取消后私有服务没有退出")
	}
}

func TestPrivateRuntimeRejectsRoleTupleAndKeyReuseRegardlessOfOrder(t *testing.T) {
	for _, duplicateKey := range []bool{false, true} {
		options, _, _ := privateRuntimeFixture(t)
		control := options.Services[1]
		control.Role, control.ServiceID = "control_api", "demo-control"
		if duplicateKey {
			control.Port = 7447
		} else {
			control.SPKIPins = []string{wire.EmptyHashV1}
		}
		options.Services = append(options.Services, control)
		if _, err := NewPrivateRuntime(options); err == nil {
			t.Fatal("control_api 放在末尾绕过 role/tuple/key 隔离")
		}
	}
}

func privateRuntimeFixture(t *testing.T) (PrivateRuntimeOptions, deviceConfigFixture, string) {
	t.Helper()
	device := newDeviceConfigFixture(t)
	authority, err := device.identities(context.Background(), device.record.CertificateHash)
	if err != nil {
		t.Fatal(err)
	}
	identities := func(_ context.Context, certificateHash string) (DeviceIdentityAuthorityV1, error) {
		if certificateHash != device.record.CertificateHash {
			return DeviceIdentityAuthorityV1{}, errors.New("demo-unknown-identity")
		}
		return authority, nil
	}
	now := time.Date(2026, 9, 11, 12, 1, 10, 0, time.UTC)
	root := t.TempDir()
	replay, err := enrollmentv2.OpenChallengeReplayStore(filepath.Join(root, "challenges.json"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := enrollmentv2.NewPrivateService("demo-cluster", "demo-enroll", func() time.Time { return now },
		nil, time.Minute, replay,
		func(context.Context, string, string) (enrollmentv2.InviteMaterialV2, error) {
			return enrollmentv2.InviteMaterialV2{}, errors.New("demo-no-invite")
		},
		func(context.Context, wire.CertifiedInviteRecordV2) (string, error) {
			return "", errors.New("demo-no-invite")
		},
		func(context.Context, enrollmentv2.VerifiedClaimAttemptV2) (wire.EnrollmentClaimResultV2, error) {
			return wire.EnrollmentClaimResultV2{}, errors.New("demo-no-claim")
		})
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "reports.json")
	schemas := wire.DeviceReportSchemaRegistry{"health": 1}
	sink, err := OpenDeviceReportStore(reportPath, schemas)
	if err != nil {
		t.Fatal(err)
	}
	options := PrivateRuntimeOptions{
		Certificates: map[string]tls.Certificate{}, Enrollment: enrollment,
		AuthorizeRelay: func(context.Context, []byte, string) (wire.VerifiedBootstrapCapabilityV1, error) {
			return wire.VerifiedBootstrapCapabilityV1{}, errors.New("demo-no-session")
		},
		Identities: identities, ReportSchemas: schemas, Now: func() time.Time { return now }, CommitReport: sink.Commit,
		VerifyReport: func(kind string, schema int64, raw []byte) error {
			_, err := wire.DecodeDeviceHealthPayload(kind, schema, raw)
			return err
		},
	}
	for index, role := range []string{"enroll", "device_config", "device_report"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 1)),
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("10.50.0.2")},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		service := wire.PrivateControlServiceV1{ServiceID: "demo-" + role, Role: role, OverlayIP: "10.50.0.2", Port: int64(7444 + index),
			CertificateProfileRef: "demo-server-" + role, SPKIPins: []string{serviceSPKIPin(leaf)}, AuthorizedSubjectProfiles: []string{device.record.ProfileRef.ProfileID}}
		options.Services = append(options.Services, service)
		options.Certificates[service.ServiceID] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	return options, device, reportPath
}

type privateRuntimeTestListener struct {
	net.Listener
	address string
}
type privateRuntimeTestConn struct {
	net.Conn
	address string
}

func (listener *privateRuntimeTestListener) Addr() net.Addr { return stringAddress(listener.address) }
func (connection *privateRuntimeTestConn) LocalAddr() net.Addr {
	return stringAddress(connection.address)
}
func (listener *privateRuntimeTestListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &privateRuntimeTestConn{Conn: connection, address: listener.address}, nil
}
func privateRuntimeLoopbackListen(addresses map[string]string) func(context.Context, string, string) (net.Listener, error) {
	return func(ctx context.Context, network, address string) (net.Listener, error) {
		listener, err := (&net.ListenConfig{}).Listen(ctx, network, "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		addresses[address] = listener.Addr().String()
		return &privateRuntimeTestListener{Listener: listener, address: address}, nil
	}
}
func privateRuntimeClient(t *testing.T, options PrivateRuntimeOptions, addresses map[string]string, identity *tls.Certificate) *http.Client {
	t.Helper()
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		roots := x509.NewCertPool()
		for _, cert := range options.Certificates {
			leaf, _ := x509.ParseCertificate(cert.Certificate[0])
			roots.AddCert(leaf)
		}
		config := &tls.Config{RootCAs: roots, ServerName: "10.50.0.2", MinVersion: tls.VersionTLS13, Time: options.Now}
		if identity != nil {
			config.Certificates = []tls.Certificate{*identity}
		}
		local, found := addresses[address]
		if !found {
			return nil, fmt.Errorf("demo-unknown-tuple")
		}
		return (&tls.Dialer{Config: config}).DialContext(ctx, network, local)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
