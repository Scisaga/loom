package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"

	"github.com/skip2/go-qrcode"
)

func TestInviteQRCapacityPreservesCompleteDelivery(t *testing.T) {
	fixture := newEndpointFixture(t)
	server := fixture.server
	handler := server.AdminHandler()
	for _, test := range []struct {
		name      string
		addresses int
		level     qrcode.RecoveryLevel
		available bool
	}{
		{"normal", 0, qrcode.Medium, true}, {"large", 384, qrcode.Low, true}, {"overflow", 762, qrcode.Low, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := "demo-qr-" + test.name
			target, _ := server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", fixture.endpoint.ID)
			invite := Invite{ID: id, GenesisDigest: server.Config.GenesisID, IssuerControlID: server.Config.ControlID, DeviceID: id,
				Name: "Demo QR capacity", Responsibilities: []string{"access"}, PolicyIDs: []string{}, Medium: "qr", Endpoint: fixture.endpoint, ExpiresAt: fixture.clock.Load() + 60000}
			for i := 0; i < test.addresses; i++ {
				prefix := []string{"192.0.2", "198.51.100", "203.0.113"}[i/254]
				invite.DNSServers = append(invite.DNSServers, fmt.Sprintf("%s.%d", prefix, i%254+1))
			}
			sort.Strings(invite.DNSServers)
			_, extra, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: id, Operation: "invite.issue", TargetKind: "invite", TargetID: id, Dependencies: target.MaterialIDs, Payload: invite})
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/control/ui/invites/" + id
			request := func(path string) *httptest.ResponseRecorder {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
				return response
			}
			response := request(path)
			var readback struct {
				Invite    string `json:"invite"`
				Available bool   `json:"qr_available"`
				Error     string `json:"delivery_error"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &readback) != nil || readback.Invite != extra.Invite || readback.Available != test.available {
				t.Fatalf("capacity projection mismatch for %d-byte delivery: status=%d available=%v", len(extra.Invite), response.Code, readback.Available)
			}
			image := request(path + "/qr.png")
			if test.available {
				code, err := inviteQRCode(extra.Invite)
				if err != nil || code.Level != test.level || code.Content != extra.Invite {
					t.Fatalf("full invitation did not fit expected correction level: bytes=%d error=%v", len(extra.Invite), err)
				}
				size, err := png.DecodeConfig(bytes.NewReader(image.Body.Bytes()))
				if image.Code != http.StatusOK || err != nil || size.Width != size.Height || size.Width != len(code.Bitmap())*5 {
					t.Fatal("QR response lost its full modules or quiet zone", err)
				}
			} else {
				if image.Code != http.StatusUnprocessableEntity || readback.Error == "" {
					t.Fatal("oversized invitation lacks explicit capacity failure")
				}
				if os.Getenv("LOOM_WEB_CHROME_TEST") == "1" {
					endpoint := httptest.NewServer(handler)
					defer endpoint.Close()
					debug := openCommandChrome(t, endpoint.URL+"/devices/invites/"+id)
					waitChromeEvaluation(t, debug, `document.querySelector('#device-enrollment')?.textContent.includes('too large for one QR code')&&!document.querySelector('#device-enrollment img.qr')&&!!document.querySelector('#invite-uri')`)
				}
			}
			file := request(path + "/download")
			if file.Code != http.StatusOK || file.Body.String() != extra.Invite+"\n" {
				t.Fatal("capacity handling changed or removed the original file delivery")
			}
			if _, err := DecodeInvite(readback.Invite); err != nil {
				t.Fatal("capacity handling damaged the signed invitation", err)
			}
		})
	}
}
