package deviceclient

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientsecret"
	"loom/internal/control"
)

// Pause a writer after its replacement is visible but before its durable
// commit. Every formal reader must wait; a filesystem read alone is too early.
// This tests ordering, not a claim about surviving a simulated power failure.
func TestAuthorityReadersWaitForDurableReplacement(t *testing.T) {
	for _, protected := range []bool{false, true} {
		name := "plain"
		if protected {
			name = "protected"
		}
		t.Run(name, func(t *testing.T) {
			invite, makeEnvelope := windowsProtectedFixture(t)
			path := filepath.Join(t.TempDir(), "state")
			readers := map[string]func() (*control.DeviceViewEnvelope, error){}
			var next control.DeviceViewEnvelope
			var stage func(string) error
			if protected {
				protector := &testProtector{}
				store, err := OpenProtected(path, invite, protector)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SaveLKG(makeEnvelope(store.PublicKey(), 7)); err != nil {
					t.Fatal(err)
				}
				next = makeEnvelope(store.PublicKey(), 8)
				state := store.state
				state.HighWater, state.LKG = append([]control.FactFrontier{}, next.FactFrontier...), &next
				stage = func(target string) error {
					body, err := control.CanonicalEncode(state)
					if err != nil {
						return err
					}
					return clientsecret.WriteProtected(target, protectedStatePurpose, body, protector)
				}
				readers["load"] = func() (*control.DeviceViewEnvelope, error) {
					loaded, err := LoadProtected(path, protector)
					if err != nil {
						return nil, err
					}
					return loaded.LKG(), nil
				}
				readers["open"] = func() (*control.DeviceViewEnvelope, error) {
					loaded, err := OpenProtected(path, invite, protector)
					if err != nil {
						return nil, err
					}
					return loaded.LKG(), nil
				}
				readers["reload"] = func() (*control.DeviceViewEnvelope, error) {
					changed, err := store.Reload()
					if err != nil || !changed {
						return nil, errors.Join(err, errors.New("reload did not observe replacement"))
					}
					return store.LKG(), nil
				}
			} else {
				store, err := OpenForPlatform(path, invite, "windows")
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SaveLKG(makeEnvelope(store.PublicKey(), 7)); err != nil {
					t.Fatal(err)
				}
				next = makeEnvelope(store.PublicKey(), 8)
				state := store.state
				state.HighWater, state.LKG = append([]control.FactFrontier{}, next.FactFrontier...), &next
				stage = func(target string) error {
					body, err := control.CanonicalEncode(state)
					if err != nil {
						return err
					}
					return os.WriteFile(target, body, 0o600)
				}
				readers["load"] = func() (*control.DeviceViewEnvelope, error) {
					loaded, err := Load(path)
					if err != nil {
						return nil, err
					}
					return loaded.LKG(), nil
				}
				readers["open"] = func() (*control.DeviceViewEnvelope, error) {
					loaded, err := OpenForPlatform(path, invite, "windows")
					if err != nil {
						return nil, err
					}
					return loaded.LKG(), nil
				}
				readers["reload"] = func() (*control.DeviceViewEnvelope, error) {
					changed, err := store.Reload()
					if err != nil || !changed {
						return nil, errors.Join(err, errors.New("reload did not observe replacement"))
					}
					return store.LKG(), nil
				}
			}
			lock, err := lockStateFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			pending := filepath.Join(filepath.Dir(path), "pending")
			if err := stage(pending); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(pending, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			syncErr, closeErr := file.Sync(), file.Close()
			if err := errors.Join(syncErr, closeErr); err != nil {
				t.Fatal(err)
			}
			if err := replaceProtectedFile(pending, path); err != nil {
				t.Fatal(err)
			}
			type result struct {
				reader string
				view   *control.DeviceViewEnvelope
				err    error
			}
			started := make(chan struct{}, len(readers))
			done := make(chan result, len(readers))
			for name, read := range readers {
				go func() {
					started <- struct{}{}
					view, err := read()
					done <- result{name, view, err}
				}()
			}
			for range readers {
				<-started
			}
			select {
			case result := <-done:
				t.Fatalf("%s read crossed an incomplete durable commit: %v", result.reader, result.err)
			case <-time.After(100 * time.Millisecond):
			}
			// Deliberately omit the writer's directory sync. The next reader must
			// finish that durability step before accepting the replacement.
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			for range readers {
				select {
				case result := <-done:
					if result.err != nil || !reflect.DeepEqual(result.view, &next) {
						t.Fatalf("%s did not accept the replacement after writer release: %v", result.reader, result.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("authority read deadlocked after writer released its lock")
				}
			}
		})
	}
}
