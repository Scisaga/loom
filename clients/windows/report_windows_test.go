//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"loom/internal/attest"
	"loom/internal/clientenroll"
	"loom/internal/clientreport"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsDPAPIReportAfterInviteCleanup(t *testing.T) {
	ca, caKey, caPEM := portableTestCA(t)
	reports := make(chan clientreport.Observation, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/loom-client/report" {
			t.Error("unexpected report endpoint")
			w.WriteHeader(400)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, clientreport.MaxBody+1))
		if bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte(`"token"`)) || bytes.Contains(body, []byte(`"observation"`)) {
			t.Error("report disclosed secrets or used an envelope")
		}
		var o clientreport.Observation
		if err := json.Unmarshal(body, &o); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := verifyNativeReport(&o, caPEM); err != nil {
			t.Error(err)
			w.WriteHeader(403)
			return
		}
		reports <- o
		w.WriteHeader(204)
	}))
	defer server.Close()
	root := t.TempDir()
	protector := clientsecret.UserProtector{}
	invite := clientenroll.Invite{Endpoint: server.URL + "/loom-client/enroll", Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	identity, err := loadOrCreateWindowsIdentity(root, invite, protector, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := portableTestNodeCertificate(ca, caKey, string(identity.CSRPEM), "demo-client")
	clearPreparedIdentity(&identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := clearWindowsPendingInvite(root, protector); err != nil {
		t.Fatal(err)
	}
	recovered, err := readWindowsJoinIdentity(root, protector)
	if err != nil || recovered.Endpoint != invite.Endpoint {
		t.Fatal("consumed invite lost reporting Endpoint")
	}
	clearPreparedIdentity(&recovered)
	if err := os.MkdirAll(filepath.Join(root, "tls"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"node.crt": cert, "ca.crt": caPEM} {
		if err := os.WriteFile(filepath.Join(root, "tls", name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := clientupdate.Config{Schema: 1, NodeID: "demo-client", DistributionURLs: []string{"https://dist.example/loom"}}
	reporter, err := startWindowsReporter(root, protector, config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.stop()
	next := func() clientreport.Observation {
		select {
		case o := <-reports:
			return o
		case <-time.After(5 * time.Second):
			t.Fatal("report not delivered")
		}
		return clientreport.Observation{}
	}
	noReport := func() {
		t.Helper()
		reporter.worker.Trigger()
		select {
		case <-reports:
			t.Fatal("inactive workload sent a report")
		case <-time.After(100 * time.Millisecond):
		}
	}
	noReport()
	reporter.update(clientRuntimeState{Applied: "222222222222"})
	noReport() // 已下载的 candidate 还未激活。
	exited := make(chan struct{})
	state := clientRuntimeState{Applied: "0123456789ab", Ready: true, Exited: exited}
	reporter.update(state)
	connected := next()
	if connected.SelfCheck.Healthy || len(connected.SelfCheck.Problems) == 0 || connected.Applied != state.Applied {
		t.Fatal("active report lost applied or claimed health without end-to-end evidence")
	}
	close(exited)
	noReport()
	state.Exited = make(chan struct{})
	reporter.update(state)
	restored := next()
	connectedAt, _ := time.Parse(time.RFC3339Nano, connected.TS)
	restoredAt, _ := time.Parse(time.RFC3339Nano, restored.TS)
	if !restoredAt.After(connectedAt) || restored.Applied != state.Applied {
		t.Fatal("recovery lost restored snapshot or increasing timestamp")
	}
	reporter.update(clientRuntimeState{})
	noReport()
	reporter.stop()
	noReport()
	if _, err := readWindowsPendingInvite(root, protector); !os.IsNotExist(err) {
		t.Fatal("reporter restored consumed join token")
	}
}

func verifyNativeReport(o *clientreport.Observation, ca []byte) error {
	if o.Attest == nil || o.SelfCheck == nil || o.Attest.CanonicalVersion != 5 ||
		o.Node != o.Attest.Node || o.Node != o.SelfCheck.Node || o.TS != o.Attest.TS ||
		o.TS != o.SelfCheck.TS || o.Applied != o.Attest.Applied || o.Attest.Cert != o.SelfCheck.Cert ||
		o.Attest.MeasurementsSHA256 != clientreport.EmptyMeasurementsDigest() {
		return errors.New("minimal report signature binding mismatch")
	}
	if _, err := attest.VerifyFresh(o.Attest, ca, time.Now(), time.Minute); err != nil {
		return err
	}
	_, err := attest.VerifySelfCheckFresh(o.SelfCheck, ca, time.Now(), time.Minute)
	return err
}
