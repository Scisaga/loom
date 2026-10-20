package control

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

// This is only the disposable per-original WG projection's physical encoding.
// It never encodes a DeviceReport or changes its canonical signed bytes.
func encodeReportCounterIndex(value reportCounterIndexValue) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	body := appendCounterIndexID(make([]byte, 0, 1024), value.NetworkGeneration)
	body = binary.AppendUvarint(body, uint64(value.ReportedAt))
	body = appendCounterIndexKey(body, value.VerifiedPublicKey)
	if value.Counters == nil {
		return append(body, 0), nil
	}
	body = append(body, 1)
	counters := value.Counters
	body = binary.AppendUvarint(body, uint64(len(counters.Interface)))
	body = append(body, counters.Interface...)
	epoch, _ := hex.DecodeString(counters.Epoch)
	body = append(body, epoch...)
	body = binary.AppendUvarint(body, uint64(counters.ObservedAt))
	body = binary.AppendUvarint(body, uint64(len(counters.Peers)))
	for _, peer := range counters.Peers {
		body = appendCounterIndexKey(body, peer.PublicKey)
		body = binary.AppendUvarint(body, uint64(peer.RXBytes))
		body = binary.AppendUvarint(body, uint64(peer.TXBytes))
		body = binary.AppendUvarint(body, uint64(len(peer.Links)))
		for _, link := range peer.Links {
			body = appendCounterIndexID(body, link.LinkID)
			digest, _ := hex.DecodeString(link.SpecDigest[len("sha256:"):])
			body = append(body, digest...)
		}
	}
	if len(body) > controlHTTPBodyLimit {
		return nil, errors.New("counter projection exceeds its input boundary")
	}
	return body, nil
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

// Field widths and shortest integers give every accepted projection exactly
// one encoding. Output is assigned only after all bounds and domain checks.
func decodeReportCounterIndex(body []byte, out *reportCounterIndexValue) error {
	if out == nil || len(body) == 0 || len(body) > controlHTTPBodyLimit {
		return errors.New("invalid counter projection input boundary or output")
	}
	reader := counterIndexReader{body: body}
	value := reportCounterIndexValue{NetworkGeneration: reader.id(), ReportedAt: reader.time(), VerifiedPublicKey: reader.key()}
	present := reader.take(1)
	if reader.err != nil {
		return reader.err
	}
	switch present[0] {
	case 0:
	case 1:
		counters := &WireGuardCounters{}
		value.Counters = counters
		counters.Interface = string(reader.take(reader.count(1)))
		counters.Epoch = hex.EncodeToString(reader.take(16))
		counters.ObservedAt = reader.time()
		// A peer needs a 32-byte key and at least three one-byte integers.
		counters.Peers = make([]WireGuardPeerCounter, reader.count(35))
		for i := range counters.Peers {
			peer := &counters.Peers[i]
			peer.PublicKey = reader.key()
			peer.RXBytes = U64(reader.u64())
			peer.TXBytes = U64(reader.u64())
			// The shortest ID is a length byte plus one byte of text; the
			// specification digest always occupies another 32 bytes.
			peer.Links = make([]WireGuardCounterLink, reader.count(34))
			for j := range peer.Links {
				peer.Links[j] = WireGuardCounterLink{reader.id(), "sha256:" + hex.EncodeToString(reader.take(32))}
			}
		}
	default:
		return errors.New("invalid counter projection presence")
	}
	if reader.err != nil {
		return reader.err
	}
	if len(reader.body) != 0 {
		return errors.New("trailing counter projection bytes")
	}
	if err := value.Validate(); err != nil {
		return err
	}
	*out = value
	return nil
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
