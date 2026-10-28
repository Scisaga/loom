package loomcore

import (
	"bytes"
	"reflect"
	"sync"
	"testing"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

func TestAndroidStateReadsReuseOnlyValidatedBytesAndReturnOwnedValues(t *testing.T) {
	original, body := androidFixture(t, 10, false)
	var cache androidStateReadCache
	checks := 0
	validate := func(body []byte) (deviceclient.State, error) {
		checks++
		return decodeAndroidIdentity(body)
	}
	first, err := cache.decode(body, validate)
	if err != nil {
		t.Fatal(err)
	}
	first.HighWater[0].Sequence++
	first.LKG.View.Name = "Demo changed caller"
	for range 3 {
		next, err := cache.decode(body, validate)
		if err != nil || !reflect.DeepEqual(next, original) {
			t.Fatal("cached read returned a shared or different identity", err)
		}
	}
	if checks != 1 {
		t.Fatal("unchanged authenticated input was revalidated", checks)
	}
	for _, invalid := range [][]byte{append(bytes.Clone(body), ' '), bytes.Replace(body, []byte("Demo Android"), []byte("Demo forged"), 1), nil} {
		for range 2 {
			if _, err := cache.decode(invalid, validate); err == nil {
				t.Fatal("changed or missing input bypassed canonical authentication")
			}
		}
	}
	if checks != 7 {
		t.Fatal("failed input was cached", checks)
	}
	for sequence := 1; sequence <= 4; sequence++ {
		next := original
		next.ReportSequence = control.U64(sequence)
		encoded, err := deviceclient.EncodeIdentityState(next)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := cache.decode(encoded, validate)
		if err != nil || decoded.ReportSequence != next.ReportSequence {
			t.Fatal("changed report sequence reused stale state", err)
		}
	}
	if _, err := cache.decode(body, validate); err != nil || checks != 12 {
		t.Fatal("evicted validation did not return to the canonical decoder", checks, err)
	}
}

func TestAndroidStateReadCacheCannotAuthorizeRollback(t *testing.T) {
	_, older := androidFixture(t, 10, false)
	_, newer := androidFixture(t, 11, true)
	for _, body := range [][]byte{older, newer, older} {
		if err := ValidateAndroidDeviceState(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckAndroidDeviceStateAdvance(older, newer); err == nil {
		t.Fatal("a cached historical input authorized rollback")
	}
}

func TestAndroidStateReadsKeepConcurrentCallersIndependent(t *testing.T) {
	_, body := androidFixture(t, 10, false)
	var cache androidStateReadCache
	var callers sync.WaitGroup
	for range 8 {
		callers.Go(func() {
			for range 3 {
				state, err := cache.decode(body, decodeAndroidIdentity)
				if err != nil || state.HighWater[0].Sequence != 10 {
					t.Error("concurrent read changed authenticated state", err)
					return
				}
				state.HighWater[0].Sequence++
			}
		})
	}
	callers.Wait()
}
