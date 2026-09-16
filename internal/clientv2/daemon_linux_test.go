//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"loom/internal/deploy"
	"loom/internal/wire"
)

func TestLinuxDaemonRestoresLKGSyncsAndRetriesExactPrivateReport(t *testing.T) {
	now := time.Date(2026, 9, 12, 9, 30, 0, 0, time.UTC)
	statePath, _, _, _, _ := linuxRuntimeDeploymentFixture(t)
	dir := filepath.Dir(statePath)
	store, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	set, configKey := clientControlSet(t)
	identity, err := LoadEnrollmentIdentityForResume(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, pin := privateEnrollmentCertificate(t, now, "10.50.0.8")
	current := store.Envelope()
	setHash, _ := wire.ControlSetHash(&set)
	directory := wire.ControlServiceDirectoryV1{Schema: 1, ClusterID: set.ClusterID, Generation: 1, ControlSetHash: setHash,
		ParentHeadHash: current.SignedCurrent.Head.HeadHash, ConfigQC: current.SignedCurrent.QuorumCertificate,
		Services: []wire.PrivateControlServiceV1{
			{ServiceID: "demo-config", Role: "device_config", OverlayIP: "10.50.0.8", Port: 7445, CertificateProfileRef: "internal-device-config-server", SPKIPins: []string{pin}, AuthorizedSubjectProfiles: []string{"device-profile"}},
			{ServiceID: "demo-report", Role: "device_report", OverlayIP: "10.50.0.8", Port: 7446, CertificateProfileRef: "internal-device-report-server", SPKIPins: []string{pin}, AuthorizedSubjectProfiles: []string{"device-profile"}}}}
	hash, _ := wire.ControlServiceDirectoryHash(&directory)
	private := wire.DevicePrivateControlCredentialV1{Schema: 1, ClusterID: set.ClusterID, DeviceID: current.Payload.DeviceID, ParentHead: current.SignedCurrent.Head,
		ControlSet: set, ControlServiceDirectory: directory, ControlServiceDirectoryHash: hash, InternalCARootsDER: []string{base64.RawURLEncoding.EncodeToString(certificate.Certificate[1])}}
	privateRaw, _ := wire.MarshalCanonical(private)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[1]})
	refs := append([]wire.SecretArtifactRefV2(nil), (*store.state.Enrollment.CurrentSecretArtifactRefs)...)
	credentials := append([]InstalledSecretV1(nil), store.state.Enrollment.Credentials...)
	_, wrapping, _ := identity.keys()
	for _, input := range []struct {
		id   string
		body []byte
	}{{wire.DevicePrivateControlCredentialSecretIDV1, privateRaw}, {wire.DeviceObservationCASecretIDV1, ca}} {
		ref, sealed, _ := linuxSealedSecretFixture(t, identity, set.ClusterID, current.Payload.DeviceID, 1, input.id, "device_credential", input.body)
		installed, err := installLinuxSecrets([]wire.SecretArtifactRefV2{ref}, []wire.SealedSecretEnvelopeV1{sealed}, current.Payload.DeviceID, identity.WrappingPublicKeySPKI, wrapping)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
		credentials = append(credentials, installed[0])
	}
	// fixture 的签发者生成一致的初始认证状态；被测宿主随后只能走正式 API。
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Purpose != refs[j].Purpose {
			return refs[i].Purpose < refs[j].Purpose
		}
		return refs[i].SecretID < refs[j].SecretID
	})
	// wire 的 purpose 枚举次序优先于字符串次序。
	ordered := []wire.SecretArtifactRefV2{}
	for _, purpose := range []string{"device_credential", "data_plane_credential"} {
		for _, ref := range refs {
			if ref.Purpose == purpose {
				ordered = append(ordered, ref)
			}
		}
	}
	refs = ordered
	orderedCredentials := []InstalledSecretV1{}
	for _, ref := range refs {
		for _, credential := range credentials {
			if credential.SecretID == ref.SecretID {
				orderedCredentials = append(orderedCredentials, credential)
			}
		}
	}
	store.state.Enrollment.CurrentSecretArtifactRefs = &refs
	store.state.Enrollment.Credentials = orderedCredentials
	linkRaw, err := LinuxInstalledConfigArtifact(store.state.Enrollment, wire.LinuxLinkIntentArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRaw, err := LinuxInstalledConfigArtifact(store.state.Enrollment, wire.LinuxRuntimeArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	var links wire.LinuxLinkIntentArtifactV1
	var runtime wire.LinuxRuntimeArtifactV1
	if err := json.Unmarshal(linkRaw, &links); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(runtimeRaw, &runtime); err != nil {
		t.Fatal(err)
	}
	links.DeviceGeneration++
	links.Generation++
	linkRaw, _ = wire.MarshalCanonical(links)
	linkHash, _ := wire.DeviceConfigArtifactContentHash(linkRaw)
	runtime.DeviceGeneration++
	runtime.Generation++
	runtime.LinkIntentGeneration = links.Generation
	runtime.LinkIntentContentHash = linkHash
	runtimeRaw, _ = wire.MarshalCanonical(runtime)
	configRefs := append([]wire.DeviceConfigArtifactRefV1(nil), current.Payload.Active.ConfigArtifactRefs...)
	configs := []InstalledConfigV1{}
	for i := range configRefs {
		ref := &configRefs[i]
		body := linkRaw
		if ref.ArtifactID == wire.LinuxRuntimeArtifactID {
			body = runtimeRaw
		}
		ref.Generation++
		ref.SizeBytes = int64(len(body))
		ref.ContentHash, _ = wire.DeviceConfigArtifactContentHash(body)
		configs = append(configs, InstalledConfigV1{ArtifactID: ref.ArtifactID, Generation: ref.Generation, Platform: ref.Platform, MediaType: ref.MediaType, RenderContractID: ref.RenderContractID,
			SizeBytes: ref.SizeBytes, ContentHash: ref.ContentHash, Config: body})
	}
	next := advanceClientEnvelopeWithArtifacts(t, *current, &set, configKey, configRefs, refs)
	current = &next
	store.state.Enrollment.Configs = configs
	store.state.Envelope = *current
	store.state.Floors = mustDeviceFloors(t, current, &set)
	if err := persistProtectedCanonical(statePath, store.state); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(statePath); err != nil {
		t.Fatal(err)
	}
	applyCalls, configCalls, reportCalls := 0, 0, 0
	var bodies [][]byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if applyCalls == 0 || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("未先恢复本机配置或未使用 Device mTLS")
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/private/v2/device/config":
			configCalls++
			body, _ := wire.MarshalCanonical(wire.DeviceConfigDeliveryV1{Schema: 1, ClusterID: set.ClusterID, DeviceID: current.Payload.DeviceID,
				Updates: []wire.DeviceConfigUpdateV1{{Schema: 1, Envelope: *current, ControlSet: set}}})
			w.Header().Set("Content-Type", wire.DeviceConfigDeliveryMediaTypeV1)
			_, _ = w.Write(body)
		case "/private/v2/device/report":
			reportCalls++
			body, _ := io.ReadAll(r.Body)
			bodies = append(bodies, body)
			var report wire.DeviceReportEnvelopeV2
			if _, err := wire.DecodeStrict(body, 4<<20, &report); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			public := r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if err := wire.VerifyDeviceReport(&report, public, current.Payload.DeviceID, current.Payload.Active.IdentitySPKIHash, now, time.Hour, time.Minute, wire.DeviceReportSchemaRegistry{"health": 1}); err != nil {
				t.Error(err)
				w.WriteHeader(403)
				return
			}
			health, err := wire.DecodeDeviceHealthPayload(report.Body.Kind, report.Body.PayloadSchema, report.Payload)
			if err != nil || health.Healthy {
				t.Error("不健康的真实服务被报为健康", err)
			}
			if reportCalls == 1 {
				w.WriteHeader(503)
				return
			}
			hash, _ := wire.DeviceReportEnvelopeHash(&report)
			receipt, _ := wire.NewDeviceReportReceipt(report.Body, hash, []json.RawMessage{json.RawMessage(`{"schema":1}`)})
			body, _ = wire.MarshalCanonical(receipt)
			w.Header().Set("Content-Type", wire.DeviceReportReceiptMediaTypeV1)
			_, _ = w.Write(body)
		default:
			t.Error("访问了旧业务入口", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	options := LinuxDeviceDaemonOptions{StateDirectory: dir, Interval: time.Minute, Timeout: 5 * time.Second, Version: "demo-v2", Once: true, Now: func() time.Time { return now },
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "10.50.0.8:7445" && address != "10.50.0.8:7446" {
				t.Fatal("拨号超出认证服务目录")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		Apply: func(_ context.Context, plan *deploy.Plan) error {
			applyCalls++
			if len(plan.Files) == 0 || len(plan.PreCheck) == 0 {
				t.Fatal("缺真实部署计划")
			}
			return nil
		},
		Healthy: func(_ context.Context, units []string) bool {
			if len(units) == 0 {
				t.Fatal("没有检查实际运行服务")
			}
			return false
		}}
	if err := RunLinuxDeviceDaemon(context.Background(), options); err == nil {
		t.Fatal("报告失败未返回")
	}
	journal, err := readLinuxDeviceReportJournal(filepath.Join(dir, "device-report-journal.json"))
	if err != nil || journal.Pending == nil {
		t.Fatal("没有持久保存原 pending 报告", err)
	}
	if err := RunLinuxDeviceDaemon(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if configCalls != 2 || reportCalls != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("重启后未复用 exact 报告或增加额外请求")
	}
	journal, err = readLinuxDeviceReportJournal(filepath.Join(dir, "device-report-journal.json"))
	if err != nil || journal.Pending != nil || journal.LastAcceptedSequence != 1 {
		t.Fatal("已接受报告未持久推进", err)
	}
	observed, roots, err := LinuxAgentObservationInput(statePath, current.Payload.DeviceID)
	if err != nil || len(observed) != 1 || !bytes.Equal(roots, ca) {
		t.Fatal("报告观测未从同一 installation 交给 Agent", err)
	}
	if _, _, err := LinuxAgentObservationInput(statePath, "demo-other"); err == nil {
		t.Fatal("跨设备消费本机观测")
	}
	if err := os.Chmod(filepath.Join(dir, LinuxAgentObservationFile), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LinuxAgentObservationInput(statePath, current.Payload.DeviceID); err == nil {
		t.Fatal("读取了宽权限观测")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunLinuxDeviceDaemon(ctx, options); !errors.Is(err, context.Canceled) {
		t.Fatal("取消未退出", err)
	}
}
