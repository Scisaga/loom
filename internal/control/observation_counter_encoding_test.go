package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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
		body, err := encodeReportCounterIndex(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded reportCounterIndexValue
		if err := decodeReportCounterIndex(body, &decoded); err != nil || !reflect.DeepEqual(value, decoded) {
			t.Fatal("projection fields, integer precision, or optional collection changed", err)
		}
		again, err := encodeReportCounterIndex(decoded)
		if err != nil || !bytes.Equal(body, again) {
			t.Fatal("accepted index bytes do not round trip", err)
		}
		wire, err := CanonicalEncode(value)
		if err != nil || decodeReportCounterIndex(wire, &decoded) == nil {
			t.Fatal("JSON projection remained a running format", err)
		}
		for end := 0; end < len(body); end++ {
			decoded = complete
			if err := decodeReportCounterIndex(body[:end], &decoded); err == nil || !reflect.DeepEqual(decoded, complete) {
				t.Fatal("truncated row was accepted or changed its output", end)
			}
		}
	}
}

func TestCounterIndexEncodingRejectsAmbiguityAndAllocationAmplification(t *testing.T) {
	value := counterIndexEncodingFixture()
	body, err := encodeReportCounterIndex(value)
	if err != nil {
		t.Fatal(err)
	}
	idEnd := 1 + len(value.NetworkGeneration)
	reportedEnd := idEnd + len(binary.AppendUvarint(nil, uint64(value.ReportedAt)))
	presence := reportedEnd + 32
	peerCount := presence + 1 + len(binary.AppendUvarint(nil, uint64(len(value.Counters.Interface)))) + len(value.Counters.Interface) + 16 + len(binary.AppendUvarint(nil, uint64(value.Counters.ObservedAt)))
	linkCount := peerCount + 1 + 32 + len(binary.AppendUvarint(nil, math.MaxUint64)) + len(binary.AppendUvarint(nil, 128))
	replace := func(at, size int, next []byte) []byte {
		return append(append(bytes.Clone(body[:at]), next...), body[at+size:]...)
	}
	cases := map[string][]byte{
		"trailing":           append(bytes.Clone(body), 0),
		"ID tag":             replace(0, 1, []byte{129}),
		"UTF8":               replace(1, 1, []byte{0xff}),
		"presence":           replace(presence, 1, []byte{2}),
		"nonminimal integer": replace(idEnd, reportedEnd-idEnd, []byte{0x80, 0x81, 0}),
		"integer overflow":   replace(idEnd, reportedEnd-idEnd, bytes.Repeat([]byte{0xff}, 10)),
		"time overflow":      replace(idEnd, reportedEnd-idEnd, binary.AppendUvarint(nil, math.MaxUint64)),
		"peer count":         replace(peerCount, 1, binary.AppendUvarint(nil, math.MaxUint64)),
		"Link count":         replace(linkCount, 1, binary.AppendUvarint(nil, math.MaxUint64)),
		"invalid WG key":     replace(peerCount+1, 32, make([]byte, 32)),
	}
	peer := body[peerCount+1:]
	cases["duplicate peer"] = append(append(append(bytes.Clone(body[:peerCount]), 2), peer...), peer...)
	links := body[linkCount+1:]
	cases["duplicate Link"] = append(append(append(bytes.Clone(body[:linkCount]), 4), links...), links...)
	firstLink := 1 + len(value.Counters.Peers[0].Links[0].LinkID) + 32
	cases["unsorted Links"] = append(append(bytes.Clone(body[:linkCount+1]), links[firstLink:]...), links[:firstLink]...)
	digest := "sha256:" + strings.Repeat("f", 64)
	cases["uncompressed digest ID"] = replace(0, idEnd, append([]byte{byte(len(digest))}, digest...))
	for name, malformed := range cases {
		t.Run(name, func(t *testing.T) {
			out := value
			if err := decodeReportCounterIndex(malformed, &out); err == nil || !reflect.DeepEqual(out, value) {
				t.Fatal("invalid bytes were accepted or changed the output")
			}
		})
	}
	for _, width := range []int{35, 34} {
		// There are enough bytes for the count itself, but not for two values.
		reader := counterIndexReader{body: append([]byte{2}, make([]byte, 2*width-1)...)}
		if count := reader.count(width); count != 0 || reader.err == nil {
			t.Fatal("collection allocation was permitted before its minimum widths fit")
		}
	}
	invalid := []reportCounterIndexValue{value, value, value}
	invalid[0].NetworkGeneration = "\xff"
	invalid[1].Counters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("0", 32), ObservedAt: 1, Peers: nil}
	invalid[2].Counters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("0", 32), ObservedAt: 1, Peers: []WireGuardPeerCounter{value.Counters.Peers[0], value.Counters.Peers[0]}}
	for _, row := range invalid {
		if _, err := encodeReportCounterIndex(row); err == nil {
			t.Fatal("encoding bypassed the projection's domain validation")
		}
	}
}

func TestCounterIndexOldRepresentationRequiresVerifiedRebuild(t *testing.T) {
	root, socket, reports, public := reportIndexFixture(t)
	originals := reportBucketSnapshot(t, root, observationBucket)
	receptions := reportBucketSnapshot(t, root, reportReceptionBucket)
	path := filepath.Join(root, "observations.db")
	if err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
		for _, report := range reports {
			raw, err := CanonicalEncode(report)
			if err != nil {
				return err
			}
			old, err := CanonicalEncode(counterIndexValue(report, public))
			if err != nil {
				return err
			}
			if err := index.Put(referenceOf(report).key(ReleaseDigest(raw)), old); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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
}
