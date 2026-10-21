package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSnapshotGzipPreservesJSONAndNegotiation(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t, func(invite *Invite) {
		invite.Name = "Demo <snapshot> \"quoted\" 名称"
	})
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("fixture join failed")
	}
	handler := server.AdminHandler()
	read := func(encoding, byteRange string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil)
		request.Header.Set("Accept-Encoding", encoding)
		request.Header.Set("Range", byteRange)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	plain := read("identity", "")
	if plain.Code != http.StatusOK || !bytes.Contains(plain.Body.Bytes(), []byte(`\u003csnapshot\u003e`)) {
		t.Fatal("fixture did not reach the ordinary JSON encoder", plain.Code)
	}
	for _, tc := range []struct {
		name, encoding, byteRange string
		compressed                bool
	}{
		{"gzip", "gzip", "", true},
		{"weighted", "br, gzip;q=0.7", "", true},
		{"absent", "", "", false},
		{"identity", "identity", "", false},
		{"zero", "gzip;q=0", "", false},
		{"invalid weight", "gzip;q=NaN", "", false},
		{"range", "gzip", "bytes=0-7", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := read(tc.encoding, tc.byteRange)
			if response.Code != http.StatusOK || (response.Header().Get("Content-Encoding") == "gzip") != tc.compressed {
				t.Fatal("snapshot negotiation changed its response", response.Code, response.Header())
			}
			body := response.Body.Bytes()
			if tc.compressed {
				reader, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(reader)
				if err != nil || reader.Close() != nil {
					t.Fatal("snapshot did not complete a valid gzip stream", err)
				}
			}
			if !bytes.Equal(body, plain.Body.Bytes()) {
				t.Fatal("decoded snapshot differs from the ordinary JSON response")
			}
			for _, header := range []string{"Content-Type", "Cache-Control", "X-Content-Type-Options", "Referrer-Policy"} {
				if response.Header().Get(header) != plain.Header().Get(header) {
					t.Fatal("snapshot changed its existing header", header)
				}
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Vary") != "Accept-Encoding" {
				t.Fatal("snapshot encoding changed the private response cache boundary")
			}
		})
	}
	// HTTP compression must preserve the complete canonical signed device value.
	deviceRead := func(encoding string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/device/config", nil)
		request.Header.Set("Accept-Encoding", encoding)
		request = request.WithContext(context.WithValue(request.Context(), tunnelIdentityKey{}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}))
		response := httptest.NewRecorder()
		server.DeviceHandler().ServeHTTP(response, request)
		return response
	}
	devicePlain, deviceGzip := deviceRead("identity"), deviceRead("gzip")
	if devicePlain.Code != http.StatusOK || deviceGzip.Code != http.StatusOK || deviceGzip.Header().Get("Content-Encoding") != "gzip" || deviceGzip.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatal("device configuration did not negotiate compression")
	}
	reader, err := gzip.NewReader(deviceGzip.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || reader.Close() != nil || !bytes.Equal(body, devicePlain.Body.Bytes()) {
		t.Fatal("HTTP compression changed the canonical signed device response", err)
	}
	var envelope DeviceViewEnvelope
	trusted, err := server.bootstrapInvite(invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeCanonical(body, &envelope, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || VerifyDeviceViewEnvelope(envelope, trusted) != nil {
		t.Fatal("device response lost its original canonical and signature checks", err)
	}
}

func TestSnapshotGzipDoesNotCompressAuthenticationOrReadFailures(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("fixture join failed")
	}
	server.Channel = &PrivateChannel{config: PrivateChannelConfig{Listen: []string{"demo.example:443"}}}
	read := func(handler http.Handler, encoding string, authenticatedTLS bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "https://demo.example:443/api/control/ui/snapshot", nil)
		request.Header.Set("Accept-Encoding", encoding)
		if authenticatedTLS {
			request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	assertError := func(plain, advertised *httptest.ResponseRecorder, status int) {
		t.Helper()
		if plain.Code != status || advertised.Code != status || !bytes.Equal(plain.Body.Bytes(), advertised.Body.Bytes()) || advertised.Header().Get("Content-Encoding") != "" || advertised.Header().Get("Vary") != "" || advertised.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("gzip changed the existing error or authentication boundary", plain.Code, advertised.Code)
		}
	}
	assertError(read(server.Handler(), "identity", true), read(server.Handler(), "gzip", true), http.StatusForbidden)
	if err := server.Runtime.Reports.Close(); err != nil {
		t.Fatal(err)
	}
	assertError(read(server.AdminHandler(), "identity", false), read(server.AdminHandler(), "gzip", false), http.StatusServiceUnavailable)
}
