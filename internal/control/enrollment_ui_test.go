package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	zxingqr "github.com/makiuchi-d/gozxing/qrcode"
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
			if test.name == "large" && os.Getenv("LOOM_WEB_CHROME_TEST") == "1" {
				endpoint := httptest.NewServer(handler)
				defer endpoint.Close()
				debug := openCommandChrome(t, endpoint.URL+"/devices/invites/"+id)
				waitChromeEvaluation(t, debug, `document.querySelector('img.qr')?.naturalWidth>0`)
				for _, width := range []int{780, 1280} {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 1200, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
						t.Fatal(err)
					}
					// Wait for layout/ResizeObserver without assuming a particular
					// pixel size. Actual screen pixels must decode independently.
					chromeDo(t, debug, `new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))`)
					rect := chromeDo(t, debug, `(()=>{const r=document.querySelector('img.qr').getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height,scale:1}})()`)
					var shot struct {
						Data string `json:"data"`
					}
					if err := debug.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true, "clip": rect}, &shot); err != nil {
						t.Fatal(err)
					}
					cancel()
					body, err := base64.StdEncoding.DecodeString(shot.Data)
					if err != nil {
						t.Fatal(err)
					}
					image, err := png.Decode(bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					bitmap, err := gozxing.NewBinaryBitmapFromImage(image)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := zxingqr.NewQRCodeReader().Decode(bitmap, map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true})
					if err != nil {
						// The native image importer also uses a direct module read
						// when dense data resembles an extra finder pattern.
						decoded, err = zxingqr.NewQRCodeReader().Decode(bitmap, map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_PURE_BARCODE: true})
					}
					if err != nil {
						t.Fatalf("rendered invitation cannot be scanned at viewport %d, image=%v, rect=%v: %v", width, image.Bounds(), rect, err)
					}
					if decoded.GetText() != extra.Invite {
						t.Fatal("rendered QR changed signed invitation bytes")
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 320, "height": 900, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
					t.Fatal(err)
				}
				waitChromeEvaluation(t, debug, `getComputedStyle(document.querySelector('img.qr')).display==='none'&&!document.querySelector('.qr-size-note').hidden&&!!document.querySelector('.qr-frame a[target=_blank]')&&!!document.querySelector('#invite-uri')`)
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

// A synthetic counterpart to a production invitation whose dense data made
// both the Go and Android default readers choose a false finder pattern.
func TestInviteQRCodeSelectsReadableStandardSize(t *testing.T) {
	content := "demo-qr:"
	for i := 0; len(content) < 2425; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("demo-qr-5-%d", i)))
		content += base64.RawURLEncoding.EncodeToString(sum[:])
	}
	content = content[:2425]
	decode := func(code *qrcode.QRCode) (string, error) {
		bitmap, err := gozxing.NewBinaryBitmapFromImage(code.Image(-5))
		if err != nil {
			return "", err
		}
		decoded, err := zxingqr.NewQRCodeReader().Decode(bitmap, map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true})
		if err != nil {
			return "", err
		}
		return decoded.GetText(), nil
	}
	smallest, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decode(smallest); err == nil {
		t.Fatal("dense synthetic example no longer reproduces the client finder failure")
	}
	readable, err := inviteQRCode(content)
	if err != nil {
		t.Fatal(err)
	}
	if readable.VersionNumber <= smallest.VersionNumber {
		t.Fatal("selected the known unreadable standard size")
	}
	actual, err := decode(readable)
	if err != nil || actual != content {
		t.Fatal("readable rendering changed the complete invitation", err)
	}
	again, err := inviteQRCode(content)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := readable.PNG(-5)
	second, _ := again.PNG(-5)
	if !bytes.Equal(first, second) {
		t.Fatal("image selection depends on external state")
	}
}
