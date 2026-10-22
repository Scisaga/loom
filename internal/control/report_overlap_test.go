package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentReportPullsShareCommittedOriginalsThroughMemberTLS(t *testing.T) {
	for _, mode := range []string{"identical", "partial", "failed", "slow", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaterialFixture(t)
			key := testKey(t)
			f.keys = append(f.keys, key)
			f.members = append(f.members, Member{ControlID: "demo-control-c", NodeID: "demo-node-c", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
			genesis := f.genesis.Payload.(Genesis)
			genesis.ControlConfig.Members = f.members
			f.configID, _ = ConfigID(genesis.ControlConfig)
			f.genesis.Payload, f.genesis.Signature = genesis, ""
			var err error
			f.genesis, err = SignMaterial(f.genesis, f.keys[0])
			if err != nil {
				t.Fatal(err)
			}
			var active atomic.Bool
			var mu sync.Mutex
			sent := map[string]int{}
			indexes, started := make(chan int, 8), make(chan int, 8)
			releaseIndexes, releasePrimary := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(releasePrimary) })
			peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(index int, next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !active.Load() || index == 2 || (r.URL.Path != "/internal/report-ids" && r.URL.Path != "/internal/reports") {
						next.ServeHTTP(w, r)
						return
					}
					if r.URL.Path == "/internal/report-ids" {
						if mode == "identical" || mode == "partial" {
							indexes <- index
							select {
							case <-releaseIndexes:
							case <-r.Context().Done():
								return
							}
						}
						next.ServeHTTP(w, r)
						if mode == "cancel" && index == 1 {
							indexes <- index
						}
						return
					}
					started <- index
					if (mode == "slow" || mode == "cancel") && index == 0 {
						select {
						case <-releasePrimary:
						case <-r.Context().Done():
							return
						}
					} else {
						select {
						case <-time.After(50 * time.Millisecond):
						case <-r.Context().Done():
							return
						}
					}
					if mode == "failed" && index == 0 {
						w.Header().Set("Content-Encoding", "gzip")
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte{0x1f, 0x8b})
						return
					}
					recorder := httptest.NewRecorder()
					next.ServeHTTP(recorder, r)
					if recorder.Code == http.StatusOK {
						var batch reportBatch
						if err := DecodeCanonical(capturedReportBody(t, recorder), &batch, ContractDecodeLimits{MaxBytes: reportBatchBytes, MaxDepth: 128, MaxItems: 1 << 16}); err != nil {
							t.Error(err)
						} else {
							mu.Lock()
							for _, report := range batch.Reports {
								body, _ := CanonicalEncode(report)
								sent[ReleaseDigest(body)]++
							}
							mu.Unlock()
						}
					}
					for name, values := range recorder.Header() {
						w.Header()[name] = values
					}
					w.WriteHeader(recorder.Code)
					_, _ = w.Write(recorder.Body.Bytes())
				})
			})
			joining, invite, _, claim, deviceKey, _ := enrollmentFixtureWithRuntime(t, peers[0].server.Runtime)
			if response := enrollmentHTTP(t, joining, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
				t.Fatal("normal claim rejected", response.Code)
			}
			for _, peer := range peers[1:] {
				if err := peer.server.Runtime.reconcilePeerAttempt(context.Background(), f.members[0]); err != nil {
					t.Fatal("authorization did not reach the receiving member", err)
				}
			}
			view, err := joining.deviceEnvelope(invite.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			makeReport := func(sequence U64, state string) DeviceReport {
				t.Helper()
				report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: f.genesis.NetworkID, DeviceID: invite.DeviceID, ReportSequence: sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: joining.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: state}, Components: []ComponentReadback{}}, ed25519.PrivateKey(deviceKey))
				if err != nil {
					t.Fatal(err)
				}
				return report
			}
			common := makeReport(1, "stopped")
			for index := 0; index < 2; index++ {
				if response := enrollmentHTTP(t, peers[index].server, "/device/report", common, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
					t.Fatal("normal report rejected", response.Code)
				}
				if mode == "partial" {
					state := "stopped"
					if index == 1 {
						state = "error"
					}
					report := makeReport(2, state)
					if response := enrollmentHTTP(t, peers[index].server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
						t.Fatal("fork source report rejected", response.Code)
					}
				}
			}
			active.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			pull := func(ctx context.Context, index int) <-chan error {
				result := make(chan error, 1)
				go func() { result <- peers[2].server.Runtime.reconcilePeerAttempt(ctx, f.members[index]) }()
				return result
			}
			wait := func(done <-chan error) error {
				t.Helper()
				select {
				case err := <-done:
					return err
				case <-ctx.Done():
					t.Fatal("member pull failed to finish independently")
					return ctx.Err()
				}
			}
			first := pull(ctx, 0)
			if mode == "identical" || mode == "partial" {
				second := pull(ctx, 1)
				for range 2 {
					select {
					case <-indexes:
					case <-ctx.Done():
						t.Fatal("both sources did not expose their missing leaf")
					}
				}
				close(releaseIndexes)
				if err := wait(first); err != nil {
					t.Fatal(err)
				}
				if err := wait(second); err != nil {
					t.Fatal(err)
				}
			} else {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("first body request never started")
				}
				secondCtx, stopSecond := context.WithCancel(ctx)
				defer stopSecond()
				began := time.Now()
				second := pull(secondCtx, 1)
				if mode == "cancel" {
					select {
					case <-indexes:
					case <-ctx.Done():
						t.Fatal("second source never supplied its leaf")
					}
					stopSecond()
					if err := wait(second); !errors.Is(err, context.Canceled) {
						t.Fatal("cancelled member pull did not return cancellation", err)
					}
				} else if err := wait(second); err != nil {
					t.Fatal("available source was blocked by an overlapping source", err)
				}
				if time.Since(began) > 1500*time.Millisecond {
					t.Fatal("independent member waited beyond the short overlap allowance")
				}
				releaseOnce.Do(func() { close(releasePrimary) })
				err := wait(first)
				if (mode == "failed") != (err != nil) {
					t.Fatal("unexpected first-source result", err)
				}
			}
			want := 1
			if mode == "partial" {
				want = 3
			}
			if got := len(peers[2].server.Runtime.Reports.History()); got != want {
				t.Fatal("missing or forked originals were lost", got, want)
			}
			mu.Lock()
			defer mu.Unlock()
			if mode != "slow" {
				for id, count := range sent {
					if count != 1 {
						t.Errorf("overlapping sources retransmitted one original: %s, %d copies", id, count)
					}
				}
			}
		})
	}
}
