package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// Hy2FrameType is a schema-3 execution extension carried by Hy2 itself.
// WG uses the same messages at its authenticated execution address.
const Hy2FrameType = 0x403
const WireGuardPreface = "LOOM\x03"
const MaxFrameBytes = 8 << 20

type Operation byte

const (
	TransportEcho Operation = 1
	AdmissionEcho Operation = 2
	ResolveTarget Operation = 3
	ConnectTCP    Operation = 4
	RegisterUDP   Operation = 5
)

var requestMagic = []byte{'L', 'O', 'O', 'M', Schema}

type Request struct {
	PolicyID  string
	Operation Operation
	Nonce     [16]byte
	Context   *PathContext
	Host      string
	Port      uint16
	SessionID uint32
}

func (value Request) Validate(maxNodes int) error {
	switch value.Operation {
	case TransportEcho, AdmissionEcho:
		if value.Operation == TransportEcho && value.PolicyID != "" || value.Operation == AdmissionEcho && ValidateID(value.PolicyID) != nil {
			return errors.New("echo has an invalid Policy purpose")
		}
		if value.Context != nil || value.Host != "" || value.Port != 0 || value.SessionID != 0 {
			return errors.New("echo cannot request business forwarding")
		}
	case ResolveTarget, ConnectTCP, RegisterUDP:
		if ValidateID(value.PolicyID) != nil || value.Context == nil || value.Context.Validate(maxNodes) != nil || !CanonicalHost(value.Host) || value.Port == 0 {
			return errors.New("business execution requires its context and exact target")
		}
	default:
		return errors.New("unknown execution operation")
	}
	if value.Operation != RegisterUDP && value.SessionID != 0 {
		return errors.New("session ID requires UDP registration")
	}
	return nil
}
func (value Request) Marshal(maxNodes int) ([]byte, error) {
	if err := value.Validate(maxNodes); err != nil {
		return nil, err
	}
	body := append([]byte{}, requestMagic...)
	body = append(body, byte(value.Operation))
	body = append(body, value.Nonce[:]...)
	if value.Operation != TransportEcho {
		body = appendText(body, value.PolicyID)
	}
	if value.Context != nil {
		context, err := value.Context.Marshal(maxNodes)
		if err != nil {
			return nil, err
		}
		body = append(body, context...)
		body = appendText(body, value.Host)
		body = binary.BigEndian.AppendUint16(body, value.Port)
		if value.Operation == RegisterUDP {
			body = binary.BigEndian.AppendUint32(body, value.SessionID)
		}
	}
	if len(body) > MaxFrameBytes {
		return nil, errors.New("execution request exceeds its input bound")
	}
	return body, nil
}
func UnmarshalRequest(body []byte, maxNodes int) (Request, error) {
	if len(body) < len(requestMagic)+17 || len(body) > MaxFrameBytes || !bytes.Equal(body[:len(requestMagic)], requestMagic) {
		return Request{}, errors.New("invalid execution request header")
	}
	value := Request{Operation: Operation(body[len(requestMagic)])}
	copy(value.Nonce[:], body[len(requestMagic)+1:len(requestMagic)+17])
	r := reader{body: body, offset: len(requestMagic) + 17}
	if value.Operation != TransportEcho {
		var err error
		value.PolicyID, err = r.text(MaxIDBytes)
		if err != nil {
			return Request{}, err
		}
	}
	if value.Operation == ResolveTarget || value.Operation == ConnectTCP || value.Operation == RegisterUDP {
		context, err := r.context(maxNodes)
		if err != nil {
			return Request{}, err
		}
		value.Context = &context
		host, err := r.text(253)
		if err != nil {
			return Request{}, err
		}
		value.Host = host
		if len(body)-r.offset < 2 {
			return Request{}, errors.New("truncated execution target port")
		}
		value.Port = binary.BigEndian.Uint16(body[r.offset:])
		r.offset += 2
		if value.Operation == RegisterUDP {
			if len(body)-r.offset < 4 {
				return Request{}, errors.New("truncated UDP session ID")
			}
			value.SessionID = binary.BigEndian.Uint32(body[r.offset:])
			r.offset += 4
		}
	}
	if r.offset != len(body) {
		return Request{}, errors.New("trailing execution request bytes")
	}
	return value, value.Validate(maxNodes)
}
func WriteFrame(writer io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > MaxFrameBytes {
		return errors.New("execution frame exceeds its input bound")
	}
	header := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	for _, part := range [][]byte{header, body} {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
func ReadFrame(reader io.Reader, maximum int) ([]byte, error) {
	if maximum < 1 || maximum > MaxFrameBytes {
		return nil, errors.New("invalid execution input bound")
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || uint64(length) > uint64(maximum) {
		return nil, errors.New("execution frame exceeds its input bound")
	}
	body := make([]byte, int(length))
	_, err := io.ReadFull(reader, body)
	return body, err
}

type Status byte

const (
	Accepted    Status = 0
	Denied      Status = 1
	Unavailable Status = 2
)

// ProcessingNanos is supplied by the receiver's monotonic clock. It is not a
// UTC timestamp and cannot renew an Observation or authorize a request.
type Response struct {
	Nonce           [16]byte
	Status          Status
	Address         netip.Addr
	ProcessingNanos uint64
}

func (value Response) Marshal() ([]byte, error) {
	if value.Status > Unavailable || value.Status != Accepted && value.Address.IsValid() || value.Address.IsValid() && (!value.Address.Is6() || value.Address.Is4In6() || !value.Address.IsPrivate() || value.Address.Zone() != "") {
		return nil, errors.New("invalid execution response")
	}
	body := append([]byte{}, requestMagic...)
	body = append(body, byte(value.Status))
	body = append(body, value.Nonce[:]...)
	body = binary.BigEndian.AppendUint64(body, value.ProcessingNanos)
	if value.Address.IsValid() {
		a := value.Address.As16()
		body = append(body, 1)
		body = append(body, a[:]...)
	} else {
		body = append(body, 0)
	}
	return body, nil
}
func UnmarshalResponse(body []byte, nonce [16]byte) (Response, error) {
	const base = 5 + 1 + 16 + 8 + 1
	if len(body) < base || !bytes.Equal(body[:5], requestMagic) {
		return Response{}, errors.New("invalid execution response header")
	}
	value := Response{Status: Status(body[5]), ProcessingNanos: binary.BigEndian.Uint64(body[22:30])}
	copy(value.Nonce[:], body[6:22])
	if value.Nonce != nonce {
		return Response{}, errors.New("execution response belongs to another request")
	}
	switch body[30] {
	case 0:
		if len(body) != base {
			return Response{}, errors.New("trailing execution response bytes")
		}
	case 1:
		if len(body) != base+16 {
			return Response{}, errors.New("invalid execution address length")
		}
		var addr [16]byte
		copy(addr[:], body[31:])
		value.Address = netip.AddrFrom16(addr)
	default:
		return Response{}, errors.New("unknown execution response field")
	}
	if _, err := value.Marshal(); err != nil {
		return Response{}, err
	}
	return value, nil
}
