package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/clientv2"
	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/observation"
	"loom/internal/wire"
)

// 同一 daemon 的实际迁移日志、CA、封装密钥和 report store 经真实 TLS 贯通。
// 测试只把绑定地址映射至随机 loopback 端口，不伪造 request.TLS 或身份 reader。
func TestControlDeviceRuntimeUsesCertifiedIdentityAndDurableReport(t *testing.T) {
	for _, server := range []bool{false, true} {
		name := "client"
		if server {
			name = "server-observation"
		}
		t.Run(name, func(t *testing.T) { testControlDeviceRuntimeReports(t, server) })
	}
}

func testControlDeviceRuntimeReports(t *testing.T, server bool) {
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(identity.Public())
	wrap, _ := x509.MarshalPKIXPublicKey(wrapping.Public())
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
	platformHash := wire.HashRaw("demo-platform", []byte("original"))
	var chain [][]byte
	var observationCertificate []byte
	roles, platform := []string{"use_loom"}, "android"
	wrappingProfile := "p256-keystore-ecdh-v1"
	if server {
		roles, platform = []string{"use_loom", "forward"}, "linux-server"
		wrappingProfile = "p256-root-only-pkcs8-ecdh-v1"
	}
	runtime, _, migration, _ := controlMigratedDeviceRuntime(t, func(application *controlApplicationV1, runtime *controlRuntime) {
		now := runtime.now().UTC().Truncate(time.Second)
		material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, true)
		if err != nil {
			t.Fatal(err)
		}
		defer material.Close()
		profile, err := material.prepareDeviceCA(application.ClusterID, "demo-migration", now)
		if err != nil {
			t.Fatal(err)
		}
		application.CARegistry.DeviceProfiles = []wire.DeviceCertificateProfileStateV1{profile}
		issuer, err := runtime.loadDeviceIssuer(profile)
		if err != nil {
			t.Fatal(err)
		}
		defer clearControlSigner(issuer)
		migration := &application.DeviceMigrations[0]
		migration.Platform = platform
		application.Devices[0].View.Active.Responsibilities = wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: roles}
		application.Devices[0].View.Active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", application.Devices[0].View.Active.Responsibilities)
		request, err := wire.SignRuntimeDeviceMigrationRequest(wire.RuntimeDeviceMigrationRequestBodyV1{
			Schema: 1, DeviceID: migration.DeviceID, Platform: platform, PlatformKeyHash: platformHash,
			IdentitySPKIDER: base64.RawURLEncoding.EncodeToString(spki), WrappingSPKIDER: base64.RawURLEncoding.EncodeToString(wrap),
			WrappingKeyProfile: wrappingProfile, LegacyFloor: json.RawMessage(`{"schema":1}`),
		}, identity)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := enrollmentv2.PrepareMigratedDeviceCertificate(request, identityHash, platformHash,
			profile, roles, migration.Issuance, now, issuer, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		chain = [][]byte{certificate}
		for _, encoded := range profile.ProfileIntent.IssuerChainDER {
			der, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			chain = append(chain, der)
		}
		migration.IdentitySPKIHash = identityHash
		migration.WrappingKeyHash, _ = wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrap)
		migration.DeviceCertificateHash, _ = wire.DeviceCertificateHash(certificate)
		migration.DeviceCertificateProfileHash, _ = wire.DeviceCertificateProfileStateHash(&profile)
		application.Devices[0].View.Active.IdentitySPKIHash = identityHash
		if server {
			rootPEM, root, key, err := makeCertificateAuthority("Demo original observation CA", now.Add(-time.Hour), now.Add(365*24*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			application.ObservationCAPEM = string(rootPEM)
			name := migration.DeviceID + ".node.internal"
			template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, root, identity.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			observationCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		ports := map[string]int64{"enroll": runtime.config.ControlPort + 20, "device_config": runtime.config.ControlPort + 21, "device_report": runtime.config.ControlPort + 22}
		prepared, err := runtime.preparePrivateServiceMaterials("demo-migration", profile.ProfileID, ports, now)
		if err != nil {
			t.Fatal(err)
		}
		application.Services = []wire.PrivateControlServiceV1{runtime.config.ControlService}
		for _, entry := range prepared.Services {
			application.Services = append(application.Services, entry.Service)
			if entry.Service.Role == "enroll" {
				application.EnrollmentService = wire.PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: entry.Service.ServiceID,
					OverlayIP: entry.Service.OverlayIP, TCPPort: entry.Service.Port, InternalCAProfileRef: entry.Service.CertificateProfileRef,
					ServerIdentitySPKIPins: entry.Service.SPKIPins, ServiceGeneration: 1}
				for i := range application.BootstrapIssuers {
					application.BootstrapIssuers[i].Active.PermittedServiceIDs = []string{entry.Service.ServiceID}
				}
			}
		}
	})
	certificateHash, err := wire.DeviceCertificateHash(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			runtime, err = openControlRuntime(runtime.dir, runtime.now)
			if err != nil {
				t.Fatal(err)
			}
		}
		options, closeKeys, err := runtime.deviceRuntimeOptions()
		if err != nil || options == nil {
			t.Fatal("daemon 无法加载实际 Device 服务", err)
		}
		addresses := map[string]string{}
		options.Listen = func(ctx context.Context, network, address string) (net.Listener, error) {
			listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			addresses[address] = listener.Addr().String()
			exact, err := net.ResolveTCPAddr("tcp", address)
			if err != nil {
				listener.Close()
				return nil, err
			}
			return controlPrivateTestListener{Listener: listener, address: exact}, nil
		}
		deviceRuntime, err := controlplane.NewPrivateDeviceRuntime(*options)
		if err != nil {
			closeKeys()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done, err := deviceRuntime.Start(ctx)
		if err != nil {
			cancel()
			closeKeys()
			t.Fatal(err)
		}
		func() {
			defer func() { cancel(); <-done; closeKeys() }()
			roots := x509.NewCertPool()
			root, err := x509.ParseCertificate(runtime.controlTLS.Certificate[1])
			if err != nil {
				t.Fatal(err)
			}
			roots.AddCert(root)
			clients := map[string]*clientv2.PrivateDeviceHTTPClient{}
			for _, service := range options.Services {
				if service.Role != "device_config" && service.Role != "device_report" {
					continue
				}
				client, err := clientv2.NewPrivateDeviceHTTPClient(service, service.Role, "device-identity", chain, identity, roots,
					func(ctx context.Context, network, address string) (net.Conn, error) {
						mapped, ok := addresses[address]
						if !ok {
							return nil, errors.New("未授权的测试 tuple")
						}
						return (&net.Dialer{}).DialContext(ctx, network, mapped)
					}, runtime.now, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				clients[service.Role] = client
			}
			delivery, err := clients["device_config"].FetchDeviceConfigDelivery(ctx)
			if err != nil {
				t.Fatal("daemon 配置读取失败", err)
			}
			authority, err := runtime.readDeviceIdentity(ctx, certificateHash)
			if err != nil {
				t.Fatal(err)
			}
			if len(delivery.Updates) == 0 || !wire.EqualCanonical(delivery.Updates[len(delivery.Updates)-1].Envelope, authority.CurrentDeviceView) {
				t.Fatal("返回的配置不属于 daemon 当前日志")
			}
			floors, err := wire.VerifyDeviceViewEnvelope(&authority.CurrentDeviceView, &authority.ControlSet)
			if err != nil {
				t.Fatal(err)
			}
			payload := json.RawMessage(`{"healthy":true,"version":"demo-current-build"}`)
			kind := "health"
			if server {
				kind = "node-health"
				own := observation.Observation{Node: migration.DeviceID, TS: runtime.now().UTC().Format(time.RFC3339), Applied: wire.HashRaw("demo-runtime", []byte("applied")), Edges: []observation.Edge{{To: "demo-peer", RTTMs: 25, Samples: 1}}}
				keyPEM, err := privateKeyPKCS8PEM(identity)
				if err != nil {
					t.Fatal(err)
				}
				own.Attest, err = attest.Sign(attest.Claim{CanonicalVersion: 5, Node: own.Node, TS: own.TS, Applied: own.Applied, MeasurementsSHA256: observation.MeasurementDigest(&own)}, keyPEM, observationCertificate)
				if err != nil {
					t.Fatal(err)
				}
				payload, err = wire.MarshalCanonical(wire.DeviceNodeHealthPayloadV1{Healthy: true, Version: "demo-current-build", Observation: own})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := runtime.verifyNodeReportObservation(payload, authority, runtime.now()); err != nil {
					t.Fatal(err)
				}
				for _, mutate := range []func(*controlplane.DeviceIdentityAuthorityV1){
					func(a *controlplane.DeviceIdentityAuthorityV1) {
						a.CurrentDeviceView.Payload.Active.IdentitySPKIHash = wire.EmptyHashV1
					},
					func(a *controlplane.DeviceIdentityAuthorityV1) { a.Record.IdentityStatus = "revocation_pending" },
					func(a *controlplane.DeviceIdentityAuthorityV1) {
						a.CurrentDeviceView.Payload.Active.Responsibilities.Values = []string{"use_loom"}
					},
				} {
					changed := controlClone(authority)
					mutate(&changed)
					if _, err := runtime.verifyNodeReportObservation(payload, changed, runtime.now()); err == nil {
						t.Fatal("节点观测绕过当前身份或职责")
					}
				}
				if _, err := runtime.verifyNodeReportObservation(payload, authority, runtime.now().Add(11*time.Minute)); err == nil {
					t.Fatal("已过期观测仍被用于回执")
				}
			}
			hash, _ := wire.DeviceReportPayloadHash(payload)
			report, err := wire.SignDeviceReport(wire.DeviceReportBodyV2{Schema: 2, ClusterID: runtime.config.ClusterID, DeviceID: migration.DeviceID,
				ReportID: []string{"demo-report-one", "demo-report-two"}[attempt], ReportSequence: int64(attempt + 1), GeneratedAt: runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339),
				AcceptedFloors: floors, Kind: kind, PayloadSchema: 1, PayloadHash: hash}, payload, identity, controlDeviceReportSchemas)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clients["device_report"].PostDeviceReportWithObservations(ctx, &report); err != nil {
				t.Fatal("daemon 未接受有效签名报告", err)
			}
			stored, err := controlplane.OpenDeviceReportStore(filepath.Join(runtime.dir, "device-reports.json"), controlDeviceReportSchemas)
			if err != nil {
				t.Fatal(err)
			}
			state := stored.Snapshot()
			if len(state.Reports) != 1 || state.Reports[0].Body.ReportSequence != int64(attempt+1) || !bytes.Equal(state.Reports[0].Payload, payload) {
				t.Fatal("有效报告未持久更新")
			}
		}()
	}
	if err := os.Remove(filepath.Join(runtime.dir, "private-services.json")); err != nil {
		t.Fatal(err)
	}
	if _, closeKeys, err := runtime.newDeviceRuntime(); err == nil {
		closeKeys()
		t.Fatal("认证迁移后缺少专用材料仍允许 daemon 启动")
	}
}

type controlPrivateTestListener struct {
	net.Listener
	address net.Addr
}

func (listener controlPrivateTestListener) Addr() net.Addr { return listener.address }

func (listener controlPrivateTestListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return controlPrivateTestConnection{Conn: connection, address: listener.address}, nil
}

type controlPrivateTestConnection struct {
	net.Conn
	address net.Addr
}

func (connection controlPrivateTestConnection) LocalAddr() net.Addr { return connection.address }
