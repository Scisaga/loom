package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEncodedReportUploadPreservesOriginalAndRejectsInvalidBodies(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	p := server.Runtime.Authority.Snapshot()
	view, _ := server.deviceEnvelope(invite.DeviceID)
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: invite.DeviceID, ReportSequence: 1, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := CanonicalEncode(report)
	compress := func(body []byte) []byte {
		var encoded bytes.Buffer
		writer := gzip.NewWriter(&encoded)
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return encoded.Bytes()
	}
	post := func(encoding string, body []byte) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/device/report", bytes.NewReader(body))
		request.Header.Set("Content-Encoding", encoding)
		request = request.WithContext(context.WithValue(request.Context(), tunnelIdentityKey{}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}))
		response := httptest.NewRecorder()
		server.DeviceHandler().ServeHTTP(response, request)
		return response
	}
	for _, encoding := range []string{"", "gzip"} {
		body := original
		if encoding == "gzip" {
			body = compress(body)
		}
		if response := post(encoding, body); response.Code != http.StatusOK {
			t.Fatal("valid report representation rejected", encoding, response.Code, response.Body.String())
		}
	}
	stored := server.Runtime.Reports.History()
	if len(stored) != 1 {
		t.Fatal("representations became separate stored reports")
	}
	actual, _ := CanonicalEncode(stored[0])
	if !bytes.Equal(actual, original) || stored[0].Verify(claim.DevicePublicKey) != nil {
		t.Fatal("HTTP request encoding changed the canonical signed original")
	}
	before := testObservationBytes(t, server.Runtime.Reports)
	corruptSignature := bytes.Replace(original, []byte(report.Signature), []byte(strings.Repeat("A", len(report.Signature))), 1)
	encoded := compress(original)
	for _, test := range []struct {
		name, encoding string
		body           []byte
	}{
		{"truncated", "gzip", encoded[:len(encoded)-8]},
		{"unknown-encoding", "br", original},
		{"invalid-stream", "gzip", original},
		{"signature", "gzip", compress(corruptSignature)},
		{"noncanonical", "gzip", compress(append(append([]byte{}, original...), '\n'))},
		{"decoded-limit", "gzip", compress(bytes.Repeat([]byte{' '}, controlHTTPBodyLimit+1))},
		{"encoded-limit", "gzip", bytes.Repeat([]byte{0}, controlHTTPBodyLimit+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if response := post(test.encoding, test.body); response.Code < 400 {
				t.Fatal("invalid encoded request was accepted", response.Code)
			}
			if !bytes.Equal(before, testObservationBytes(t, server.Runtime.Reports)) {
				t.Fatal("rejected encoded upload changed durable history or progress")
			}
		})
	}
}
