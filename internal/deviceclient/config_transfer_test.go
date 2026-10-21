package deviceclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"os"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestConfigurationDigestBindsProgressAcrossSigningMembers(t *testing.T) {
	fixture := newDeviceRequestFixture(t)
	first := fixture.view(8)
	want, err := control.DeviceConfigurationDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	next := fixture.view(9)
	other, err := control.DeviceConfigurationDigest(next)
	if err != nil || first.ViewDigest != next.ViewDigest || want == other {
		t.Fatal("unchanged View hid an advanced authentication frontier", err)
	}
	member := first.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig.Members[0]
	seed := sha256.Sum256([]byte("demo-device-control-a"))
	first.IssuerControlID = member.ControlID
	first.IssuerKeyID, _ = control.KeyID(member.PublicKey)
	first, err = control.SignDeviceViewEnvelope(first, ed25519.NewKeyFromSeed(seed[:]))
	if err != nil || control.VerifyDeviceViewEnvelope(first, fixture.store.Invite()) != nil {
		t.Fatal("alternative current member signature was invalid", err)
	}
	other, err = control.DeviceConfigurationDigest(first)
	if err != nil || other != want {
		t.Fatal("equivalent authenticated configuration depended on its signing member", err)
	}
}

func TestFetchCompressedOrConfirmedConfigurationPreservesAuthentication(t *testing.T) {
	for _, scenario := range []string{"gzip", "truncated", "bad-signature", "confirmed", "wrong-confirmation", "missing-confirmation"} {
		t.Run(scenario, func(t *testing.T) {
			var body []byte
			fixture := newDeviceRequestFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(control.DeviceConfigDigestHeader) == "" || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
					t.Error("configuration request omitted its accepted-state digest or gzip offer")
				}
				if strings.Contains(scenario, "confirm") {
					digest := r.Header.Get(control.DeviceConfigDigestHeader)
					if scenario == "wrong-confirmation" {
						digest = control.ReleaseDigest([]byte("demo-other"))
					}
					if scenario != "missing-confirmation" {
						w.Header().Set(control.DeviceConfigDigestHeader, digest)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(body)
			})
			value := fixture.view(8)
			raw, err := control.CanonicalEncode(value)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "bad-signature" {
				raw = bytes.Replace(raw, []byte(value.Signature), []byte(strings.Repeat("A", 86)), 1)
			}
			var zipped bytes.Buffer
			writer := gzip.NewWriter(&zipped)
			_, _ = writer.Write(raw)
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			body = zipped.Bytes()
			if scenario == "truncated" {
				body = body[:len(body)-8]
			}
			before, _ := os.ReadFile(fixture.store.path)
			got, err := Fetch(fixture.context(context.Background()), fixture.store)
			if scenario == "gzip" || scenario == "confirmed" {
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "confirmed" {
					value = *fixture.store.LKG()
				}
				want, _ := control.CanonicalEncode(value)
				actual, _ := control.CanonicalEncode(got)
				if !bytes.Equal(want, actual) {
					t.Fatal("HTTP transfer altered the exact verified signed envelope")
				}
			} else if err == nil {
				t.Fatal("invalid compressed or unchanged response was accepted")
			}
			after, _ := os.ReadFile(fixture.store.path)
			if !bytes.Equal(before, after) {
				t.Fatal("fetch changed identity, LKG or authentication progress")
			}
		})
	}
}
