package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestHistoryOriginalKeepsExactVerificationKeyAcrossCacheStates(t *testing.T) {
	store, reports, public := admissionReports(t)
	other := testKey(t)
	wrong := base64.RawURLEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	raw, err := CanonicalEncode(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"cold", "warm", "cleared"} {
		t.Run(state, func(t *testing.T) {
			if state != "warm" {
				store.cache.clear()
			}
			seen := 0
			err := store.walkDeviceHistorySnapshot(context.Background(), "demo-network", "demo-device", func(highest U64, ref reportReference, original *reportHistoryOriginal) error {
				seen++
				if original == nil || highest != 1 || ref.ReportSequence != 1 || original.id != ReleaseDigest(raw) || !reflect.DeepEqual(original.report, reports[0]) {
					t.Fatal("the callback did not receive the actual canonical original")
				}
				for _, key := range []string{wrong, ""} {
					if _, err := store.verifiedHistoryOriginal(original, key); err == nil {
						t.Fatal("canonical or cached signature proof supplied a different verification key")
					}
				}
				got, err := store.verifiedHistoryOriginal(original, public)
				if err != nil || !reflect.DeepEqual(got, reports[0]) {
					t.Fatal("the current key did not verify the unchanged original", err)
				}
				if _, err := store.verifiedHistoryOriginal(original, wrong); err == nil {
					t.Fatal("successful verification widened the accepted key")
				}
				return nil
			})
			if err != nil || seen != 1 {
				t.Fatal("history read failed or changed its sample set", seen, err)
			}
		})
	}
}

func TestHistoryOriginalRejectsChangedInputAfterAcceptedSameType(t *testing.T) {
	for _, change := range []string{"invalid runtime", "noncanonical", "signature", "signed field", "position"} {
		t.Run(change, func(t *testing.T) {
			store, reports, public := admissionReports(t)
			if err := store.Put(reports[1], public); err != nil {
				t.Fatal(err)
			}
			read := func() (int, error) {
				accepted := 0
				err := store.walkDeviceHistorySnapshot(context.Background(), "demo-network", "demo-device", func(_ U64, _ reportReference, original *reportHistoryOriginal) error {
					if _, err := store.verifiedHistoryOriginal(original, public); err != nil {
						return err
					}
					accepted++
					return nil
				})
				return accepted, err
			}
			if count, err := read(); err != nil || count != 2 {
				t.Fatal("valid originals could not warm the proof cache", count, err)
			}
			old, err := CanonicalEncode(reports[0])
			if err != nil {
				t.Fatal(err)
			}
			raw := bytes.Clone(old)
			switch change {
			case "invalid runtime":
				raw = bytes.Replace(raw, []byte(`"state":"stopped"`), []byte(`"state":"invalid"`), 1)
			case "noncanonical":
				raw = append(raw, '\n')
			case "signature", "signed field":
				report := reports[0]
				if change == "signature" {
					report.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				} else {
					report.ReportedAt++
				}
				raw, err = CanonicalEncode(report)
			case "position":
				raw, err = CanonicalEncode(reports[1])
			}
			if err != nil {
				t.Fatal(err)
			}
			err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
				bucket := tx.Bucket(observationBucket)
				key := referenceOf(reports[0]).key(ReleaseDigest(old))
				if change != "position" {
					if err := bucket.Delete(key); err != nil {
						return err
					}
					key = referenceOf(reports[0]).key(ReleaseDigest(raw))
				}
				return bucket.Put(key, raw)
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, clear := range []bool{false, true} {
				if clear {
					store.cache.clear()
				}
				if count, err := read(); err == nil || count != 1 {
					t.Fatal("an accepted earlier value hid a changed later input", count, err)
				}
			}
		})
	}
}
