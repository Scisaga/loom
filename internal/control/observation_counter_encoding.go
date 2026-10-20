package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
)

// These private values describe only immutable physical layout bytes. They have
// no sample time or counters and never stand in for a complete report projection.
type reportCounterLayout struct {
	networkGeneration, verifiedPublicKey string
	counters                             *reportCounterLayoutCounters
	digest                               [sha256.Size]byte
	encodedBytes                         int
}

type reportCounterLayoutCounters struct {
	interfaceName, epoch string
	peers                []reportCounterLayoutPeer
}

type reportCounterLayoutPeer struct {
	publicKey string
	links     []WireGuardCounterLink
}

// Both pieces are disposable physical encodings of one complete projection.
// The row is still keyed by its full original key; its first 32 bytes refer to
// the exact layout bytes stored under NUL followed by that content digest.
func encodeReportCounterIndex(value reportCounterIndexValue) (row, layout []byte, err error) {
	if err := value.Validate(); err != nil {
		return nil, nil, err
	}
	layout = appendCounterIndexID(make([]byte, 0, 1024), value.NetworkGeneration)
	layout = appendCounterIndexKey(layout, value.VerifiedPublicKey)
	if value.Counters == nil {
		layout = append(layout, 0)
	} else {
		layout = append(layout, 1)
		counters := value.Counters
		layout = binary.AppendUvarint(layout, uint64(len(counters.Interface)))
		layout = append(layout, counters.Interface...)
		epoch, _ := hex.DecodeString(counters.Epoch)
		layout = append(layout, epoch...)
		layout = binary.AppendUvarint(layout, uint64(len(counters.Peers)))
		for _, peer := range counters.Peers {
			layout = appendCounterIndexKey(layout, peer.PublicKey)
			layout = binary.AppendUvarint(layout, uint64(len(peer.Links)))
			for _, link := range peer.Links {
				layout = appendCounterIndexID(layout, link.LinkID)
				digest, _ := hex.DecodeString(link.SpecDigest[len("sha256:"):])
				layout = append(layout, digest...)
			}
		}
	}
	digest := sha256.Sum256(layout)
	row = append(make([]byte, 0, 128), digest[:]...)
	row = binary.AppendUvarint(row, uint64(value.ReportedAt))
	if value.Counters != nil {
		row = binary.AppendUvarint(row, uint64(value.Counters.ObservedAt))
		for _, peer := range value.Counters.Peers {
			row = binary.AppendUvarint(row, uint64(peer.RXBytes))
			row = binary.AppendUvarint(row, uint64(peer.TXBytes))
		}
	}
	if len(row)+len(layout)-sha256.Size > controlHTTPBodyLimit {
		return nil, nil, errors.New("counter projection exceeds its input boundary")
	}
	return row, layout, nil
}

func reportCounterLayoutKey(row []byte) ([]byte, error) {
	if len(row) <= sha256.Size || len(row) > controlHTTPBodyLimit {
		return nil, errors.New("invalid counter sample input boundary")
	}
	return append([]byte{0}, row[:sha256.Size]...), nil
}

func isReportCounterLayoutKey(key []byte) bool {
	return len(key) == 1+sha256.Size && key[0] == 0
}

func decodeReportCounterLayout(body []byte) (*reportCounterLayout, error) {
	if len(body) == 0 || len(body) > controlHTTPBodyLimit {
		return nil, errors.New("invalid counter layout input boundary")
	}
	reader := counterIndexReader{body: body}
	value := &reportCounterLayout{networkGeneration: reader.id(), verifiedPublicKey: reader.key(), encodedBytes: len(body)}
	present := reader.take(1)
	if reader.err != nil {
		return nil, reader.err
	}
	switch present[0] {
	case 0:
	case 1:
		counters := &reportCounterLayoutCounters{}
		value.counters = counters
		counters.interfaceName = string(reader.take(reader.count(1)))
		counters.epoch = hex.EncodeToString(reader.take(16))
		// Static peers need their 32-byte key and one Link-count byte.
		counters.peers = make([]reportCounterLayoutPeer, reader.count(33))
		for i := range counters.peers {
			peer := &counters.peers[i]
			peer.publicKey = reader.key()
			// The shortest ID is a length byte plus one byte of text; the
			// specification digest always occupies another 32 bytes.
			peer.links = make([]WireGuardCounterLink, reader.count(34))
			for j := range peer.links {
				peer.links[j] = WireGuardCounterLink{reader.id(), "sha256:" + hex.EncodeToString(reader.take(32))}
			}
		}
	default:
		return nil, errors.New("invalid counter layout presence")
	}
	if reader.err != nil {
		return nil, reader.err
	}
	if len(reader.body) != 0 {
		return nil, errors.New("trailing counter layout bytes")
	}
	if ValidateID(value.networkGeneration) != nil || ValidatePublicKey(value.verifiedPublicKey) != nil {
		return nil, errors.New("invalid counter layout binding")
	}
	if counters := value.counters; counters != nil {
		if counters.interfaceName != wireGuardSharedCredential && (!strings.HasPrefix(counters.interfaceName, "resource:") || ValidateID(strings.TrimPrefix(counters.interfaceName, "resource:")) != nil) {
			return nil, errors.New("invalid counter layout interface")
		}
		links := map[string]bool{}
		for i, peer := range counters.peers {
			if validateWireGuardPublicKey(peer.publicKey) != nil || i > 0 && counters.peers[i-1].publicKey >= peer.publicKey {
				return nil, errors.New("invalid or unsorted counter layout peers")
			}
			for j, link := range peer.links {
				if ValidateID(link.LinkID) != nil || ValidateDigest(link.SpecDigest) != nil || links[link.LinkID] || j > 0 && peer.links[j-1].LinkID >= link.LinkID {
					return nil, errors.New("invalid or duplicated counter layout Link")
				}
				links[link.LinkID] = true
			}
		}
	}
	value.digest = sha256.Sum256(body)
	return value, nil
}

func decodeReportCounterSample(row []byte, layout *reportCounterLayout, out *reportCounterIndexValue) error {
	if out == nil || layout == nil || len(row) <= sha256.Size || len(row)+layout.encodedBytes-sha256.Size > controlHTTPBodyLimit || !bytes.Equal(row[:sha256.Size], layout.digest[:]) {
		return errors.New("invalid counter sample boundary or layout digest")
	}
	reader := counterIndexReader{body: row[sha256.Size:]}
	value := reportCounterIndexValue{NetworkGeneration: layout.networkGeneration, ReportedAt: reader.time(), VerifiedPublicKey: layout.verifiedPublicKey}
	if static := layout.counters; static != nil {
		observed := reader.time()
		// Each dynamic peer needs at least its two counter varints. Check before
		// allocating, even when a large valid layout accompanies a tiny row.
		if reader.err != nil || len(static.peers) > len(reader.body)/2 {
			return errors.New("counter sample cannot hold its layout's peers")
		}
		value.Counters = &WireGuardCounters{Interface: static.interfaceName, Epoch: static.epoch, ObservedAt: observed, Peers: make([]WireGuardPeerCounter, len(static.peers))}
		for i, peer := range static.peers {
			// Consumers receive independent mutable slices; cached batch layout
			// bytes and fields remain private and immutable.
			value.Counters.Peers[i] = WireGuardPeerCounter{PublicKey: peer.publicKey, RXBytes: U64(reader.u64()), TXBytes: U64(reader.u64()), Links: append([]WireGuardCounterLink{}, peer.links...)}
		}
	}
	if reader.err != nil {
		return reader.err
	}
	if len(reader.body) != 0 {
		return errors.New("trailing counter sample bytes")
	}
	if err := value.Validate(); err != nil {
		return err
	}
	*out = value
	return nil
}

// Field widths, exact layout binding, and shortest integers give every accepted
// pair one encoding. Output changes only after all bounds and domain checks.
func decodeReportCounterIndex(row, layout []byte, out *reportCounterIndexValue) error {
	static, err := decodeReportCounterLayout(layout)
	if err != nil {
		return err
	}
	return decodeReportCounterSample(row, static, out)
}

func appendCounterIndexID(body []byte, value string) []byte {
	if ValidateDigest(value) == nil {
		digest, _ := hex.DecodeString(value[len("sha256:"):])
		return append(append(body, 0), digest...)
	}
	return append(append(body, byte(len(value))), value...)
}

func appendCounterIndexKey(body []byte, value string) []byte {
	key, _ := base64.RawURLEncoding.DecodeString(value)
	return append(body, key...)
}

type counterIndexReader struct {
	body []byte
	err  error
}

func (reader *counterIndexReader) take(size int) []byte {
	if reader.err != nil {
		return nil
	}
	if size < 0 || size > len(reader.body) {
		reader.err = errors.New("truncated counter projection")
		return nil
	}
	value := reader.body[:size]
	reader.body = reader.body[size:]
	return value
}

func (reader *counterIndexReader) u64() uint64 {
	if reader.err != nil {
		return 0
	}
	value, size := binary.Uvarint(reader.body)
	if size <= 0 || size > 1 && reader.body[size-1] == 0 {
		reader.err = errors.New("invalid or nonminimal counter projection integer")
		return 0
	}
	reader.body = reader.body[size:]
	return value
}

func (reader *counterIndexReader) time() int64 {
	value := reader.u64()
	if value > math.MaxInt64 {
		reader.err = errors.New("counter projection time exceeds int64")
		return 0
	}
	return int64(value)
}

func (reader *counterIndexReader) count(minimumWidth int) int {
	value := reader.u64()
	if value > uint64(len(reader.body)/minimumWidth) {
		reader.err = errors.New("counter projection count exceeds remaining input")
		return 0
	}
	return int(value)
}

func (reader *counterIndexReader) id() string {
	length := reader.take(1)
	if reader.err != nil {
		return ""
	}
	if length[0] == 0 {
		return "sha256:" + hex.EncodeToString(reader.take(32))
	}
	if length[0] > 128 {
		reader.err = errors.New("counter projection ID exceeds its text boundary")
		return ""
	}
	value := string(reader.take(int(length[0])))
	if ValidateDigest(value) == nil {
		reader.err = errors.New("counter projection digest ID must use its unique encoding")
	}
	return value
}

func (reader *counterIndexReader) key() string {
	return base64.RawURLEncoding.EncodeToString(reader.take(32))
}
