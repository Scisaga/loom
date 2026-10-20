package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func counterIndexEncodingFixture() reportCounterIndexValue {
	return reportCounterIndexValue{
		NetworkGeneration: "demo-网络", ReportedAt: 128,
		VerifiedPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 32)),
		Counters: &WireGuardCounters{Interface: "resource:demo-wg", Epoch: strings.Repeat("ab", 16), ObservedAt: 129,
			Peers: []WireGuardPeerCounter{{PublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'b'}, 32)), RXBytes: U64(math.MaxUint64), TXBytes: 128,
				Links: []WireGuardCounterLink{{LinkID: "demo-link-节点", SpecDigest: "sha256:" + strings.Repeat("c", 64)},
					{LinkID: "sha256:" + strings.Repeat("d", 64), SpecDigest: "sha256:" + strings.Repeat("e", 64)}}}}},
	}
}

func TestCounterIndexEncodingPreservesFieldsAndUniqueBytes(t *testing.T) {
	complete := counterIndexEncodingFixture()
	empty := complete
	empty.NetworkGeneration = "sha256:" + strings.Repeat("f", 64)
	empty.Counters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("0", 32), ObservedAt: 1, Peers: []WireGuardPeerCounter{}}
	absent := complete
	absent.Counters = nil
	for _, value := range []reportCounterIndexValue{complete, empty, absent} {
		row, layout, err := encodeReportCounterIndex(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded reportCounterIndexValue
		if err := decodeReportCounterIndex(row, layout, &decoded); err != nil || !reflect.DeepEqual(value, decoded) {
			t.Fatal("projection fields, integer precision, or optional collection changed", err)
		}
		again, static, err := encodeReportCounterIndex(decoded)
		if err != nil || !bytes.Equal(row, again) || !bytes.Equal(layout, static) {
			t.Fatal("accepted index pieces do not round trip", err)
		}
		wire, err := CanonicalEncode(value)
		if err != nil || decodeReportCounterIndex(wire, layout, &decoded) == nil {
			t.Fatal("JSON projection remained a running format", err)
		}
		for end := 0; end < len(row); end++ {
			decoded = complete
			if err := decodeReportCounterIndex(row[:end], layout, &decoded); err == nil || !reflect.DeepEqual(decoded, complete) {
				t.Fatal("truncated sample was accepted or changed its output", end)
			}
		}
		for end := 0; end < len(layout); end++ {
			decoded = complete
			if err := decodeReportCounterIndex(row, layout[:end], &decoded); err == nil || !reflect.DeepEqual(decoded, complete) {
				t.Fatal("truncated layout was accepted or changed its output", end)
			}
		}
	}
	// Only time and counters change; they must not change the shared layout.
	row, layout, _ := encodeReportCounterIndex(complete)
	next := complete
	next.ReportedAt++
	next.Counters = &WireGuardCounters{Interface: complete.Counters.Interface, Epoch: complete.Counters.Epoch, ObservedAt: 130, Peers: append([]WireGuardPeerCounter{}, complete.Counters.Peers...)}
	next.Counters.Peers[0].RXBytes--
	nextRow, nextLayout, err := encodeReportCounterIndex(next)
	if err != nil || !bytes.Equal(layout, nextLayout) || bytes.Equal(row, nextRow) {
		t.Fatal("sample data changed its immutable layout", err)
	}
	static, err := decodeReportCounterLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	var first, second reportCounterIndexValue
	if err := decodeReportCounterSample(row, static, &first); err != nil {
		t.Fatal(err)
	}
	first.Counters.Peers[0].Links[0].SpecDigest = "sha256:" + strings.Repeat("0", 64)
	first.Counters.Peers[0].RXBytes = 0
	if err := decodeReportCounterSample(row, static, &second); err != nil || !reflect.DeepEqual(second, complete) {
		t.Fatal("one consumer modified the reusable immutable batch layout", err)
	}
}

func TestCounterIndexEncodingRejectsAmbiguityAndAllocationAmplification(t *testing.T) {
	value := counterIndexEncodingFixture()
	row, layout, err := encodeReportCounterIndex(value)
	if err != nil {
		t.Fatal(err)
	}
	replace := func(body []byte, at, size int, next []byte) []byte {
		return append(append(bytes.Clone(body[:at]), next...), body[at+size:]...)
	}
	reportedEnd := sha256.Size + len(binary.AppendUvarint(nil, uint64(value.ReportedAt)))
	rows := map[string][]byte{
		"trailing":            append(bytes.Clone(row), 0),
		"nonminimal integer":  replace(row, sha256.Size, reportedEnd-sha256.Size, []byte{0x80, 0x81, 0}),
		"integer overflow":    replace(row, sha256.Size, reportedEnd-sha256.Size, bytes.Repeat([]byte{0xff}, 10)),
		"time overflow":       replace(row, sha256.Size, reportedEnd-sha256.Size, binary.AppendUvarint(nil, math.MaxUint64)),
		"reported time range": replace(row, sha256.Size, reportedEnd-sha256.Size, binary.AppendUvarint(nil, 253402300800000)),
	}
	observedEnd := reportedEnd + len(binary.AppendUvarint(nil, uint64(value.Counters.ObservedAt)))
	rows["observed time range"] = replace(row, reportedEnd, observedEnd-reportedEnd, binary.AppendUvarint(nil, 253402300800000))
	rows["layout hash"] = bytes.Clone(row)
	rows["layout hash"][0] ^= 1
	for name, malformed := range rows {
		t.Run("sample/"+name, func(t *testing.T) {
			out := value
			if err := decodeReportCounterIndex(malformed, layout, &out); err == nil || !reflect.DeepEqual(out, value) {
				t.Fatal("invalid sample was accepted or changed output")
			}
		})
	}
	idEnd := 1 + len(value.NetworkGeneration)
	presence := idEnd + 32
	peerCount := presence + 1 + len(binary.AppendUvarint(nil, uint64(len(value.Counters.Interface)))) + len(value.Counters.Interface) + 16
	linkCount := peerCount + 1 + 32
	layouts := map[string][]byte{
		"trailing":       append(bytes.Clone(layout), 0),
		"ID tag":         replace(layout, 0, 1, []byte{129}),
		"UTF8":           replace(layout, 1, 1, []byte{0xff}),
		"presence":       replace(layout, presence, 1, []byte{2}),
		"peer count":     replace(layout, peerCount, 1, binary.AppendUvarint(nil, math.MaxUint64)),
		"Link count":     replace(layout, linkCount, 1, binary.AppendUvarint(nil, math.MaxUint64)),
		"invalid WG key": replace(layout, peerCount+1, 32, make([]byte, 32)),
	}
	peer := layout[peerCount+1:]
	layouts["duplicate peer"] = append(append(append(bytes.Clone(layout[:peerCount]), 2), peer...), peer...)
	links := layout[linkCount+1:]
	layouts["duplicate Link"] = append(append(append(bytes.Clone(layout[:linkCount]), 4), links...), links...)
	firstLink := 1 + len(value.Counters.Peers[0].Links[0].LinkID) + 32
	layouts["unsorted Links"] = append(append(bytes.Clone(layout[:linkCount+1]), links[firstLink:]...), links[:firstLink]...)
	digest := "sha256:" + strings.Repeat("f", 64)
	layouts["uncompressed digest ID"] = replace(layout, 0, idEnd, append([]byte{byte(len(digest))}, digest...))
	for name, malformed := range layouts {
		t.Run("layout/"+name, func(t *testing.T) {
			out := value
			bound := bytes.Clone(row)
			digest := sha256.Sum256(malformed)
			copy(bound, digest[:])
			if err := decodeReportCounterIndex(bound, malformed, &out); err == nil || !reflect.DeepEqual(out, value) {
				t.Fatal("invalid referenced layout was accepted or changed output")
			}
		})
	}
	for _, width := range []int{33, 34} {
		reader := counterIndexReader{body: append([]byte{2}, make([]byte, 2*width-1)...)}
		if count := reader.count(width); count != 0 || reader.err == nil {
			t.Fatal("allocation permitted before minimum widths fit")
		}
	}
	invalid := []reportCounterIndexValue{value, value, value, value}
	invalid[0].NetworkGeneration = "\xff"
	invalid[1].Counters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("0", 32), ObservedAt: 1, Peers: nil}
	invalid[2].Counters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("0", 32), ObservedAt: 1, Peers: []WireGuardPeerCounter{value.Counters.Peers[0], value.Counters.Peers[0]}}
	invalid[3].ReportedAt = -1
	for _, value := range invalid {
		if _, _, err := encodeReportCounterIndex(value); err == nil {
			t.Fatal("encoding bypassed projection domain validation")
		}
	}
}

func TestCounterIndexOldRepresentationRequiresVerifiedRebuild(t *testing.T) {
	for _, format := range []string{"JSON", "duplicated static fields"} {
		t.Run(format, func(t *testing.T) {
			root, socket, reports, public := reportIndexFixture(t)
			originals := reportBucketSnapshot(t, root, observationBucket)
			receptions := reportBucketSnapshot(t, root, reportReceptionBucket)
			path := filepath.Join(root, "observations.db")
			if err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
				parent := tx.Bucket(reportIndexBucket)
				if err := parent.DeleteBucket(reportCountersBucket); err != nil {
					return err
				}
				index, err := parent.CreateBucket(reportCountersBucket)
				if err != nil {
					return err
				}
				for _, report := range reports {
					raw, err := CanonicalEncode(report)
					if err != nil {
						return err
					}
					value := counterIndexValue(report, public)
					old, err := CanonicalEncode(value)
					if err != nil {
						return err
					}
					if format == "duplicated static fields" {
						old = appendCounterIndexID(nil, value.NetworkGeneration)
						old = binary.AppendUvarint(old, uint64(value.ReportedAt))
						old = appendCounterIndexKey(old, value.VerifiedPublicKey)
						if value.Counters == nil {
							old = append(old, 0)
						} else {
							// This maintenance fixture has an explicit empty peer set.
							if len(value.Counters.Peers) != 0 {
								t.Fatal("old-format fixture unexpectedly acquired peers")
							}
							old = append(old, 1)
							old = binary.AppendUvarint(old, uint64(len(value.Counters.Interface)))
							old = append(old, value.Counters.Interface...)
							epoch, _ := hex.DecodeString(value.Counters.Epoch)
							old = append(old, epoch...)
							old = binary.AppendUvarint(old, uint64(value.Counters.ObservedAt))
							old = append(old, 0)
						}
					}
					if err := index.Put(referenceOf(report).key(ReleaseDigest(raw)), old); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			store, err := OpenObservationStore(root)
			if store != nil {
				store.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "--rebuild") {
				t.Fatal("startup did not explicitly refuse the old physical representation", err)
			}
			if err := PrepareReportIndex(context.Background(), root, socket); err == nil || !strings.Contains(err.Error(), "--rebuild") {
				t.Fatal("preparation implicitly converted an old physical representation", err)
			}
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err == nil {
				t.Fatal("verification accepted the replaced index representation")
			}
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Rebuild: true}); err != nil {
				t.Fatal(err)
			}
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(originals, reportBucketSnapshot(t, root, observationBucket)) || !reflect.DeepEqual(receptions, reportBucketSnapshot(t, root, reportReceptionBucket)) {
				t.Fatal("projection replacement changed signed originals or reception annotations")
			}
		})
	}
}
