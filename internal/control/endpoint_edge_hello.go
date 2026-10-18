package control

import (
	"encoding/binary"
	"errors"
	"io"
)

const maximumEdgeHello = 64 << 10

// readEdgeClientHello retains every consumed byte for exact replay. Parsing
// grants no identity: the selected backend must perform the actual TLS and
// bootstrap, device or member authentication itself.
func readEdgeClientHello(reader io.Reader) ([]string, []byte, error) {
	var original, handshake []byte
	for {
		var header [5]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, nil, err
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || header[2] > 4 || size > (16<<10)+2048 || len(original)+5+size > maximumEdgeHello {
			return nil, nil, errors.New("invalid or oversized TLS ClientHello record")
		}
		original = append(original, header[:]...)
		start := len(original)
		original = append(original, make([]byte, size)...)
		if _, err := io.ReadFull(reader, original[start:]); err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, original[start:]...)
		if len(handshake) < 4 {
			continue
		}
		size = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || size+4 > maximumEdgeHello {
			return nil, nil, errors.New("TLS preface is not a bounded ClientHello")
		}
		if len(handshake) < size+4 {
			continue
		}
		protocols, err := edgeHelloProtocols(handshake[4 : size+4])
		return protocols, original, err
	}
}

func edgeHelloProtocols(hello []byte) ([]string, error) {
	invalid := errors.New("invalid TLS ClientHello extensions")
	if len(hello) < 35 || hello[0] != 3 {
		return nil, invalid
	}
	hello = hello[34:]
	session := int(hello[0])
	if session > 32 || len(hello) < 1+session+2 {
		return nil, invalid
	}
	hello = hello[1+session:]
	ciphers := int(binary.BigEndian.Uint16(hello))
	if ciphers < 2 || ciphers%2 != 0 || len(hello) < 2+ciphers+1 {
		return nil, invalid
	}
	hello = hello[2+ciphers:]
	compression := int(hello[0])
	if compression == 0 || len(hello) < 1+compression {
		return nil, invalid
	}
	hello = hello[1+compression:]
	if len(hello) == 0 {
		return nil, nil
	}
	if len(hello) < 2 || int(binary.BigEndian.Uint16(hello)) != len(hello)-2 {
		return nil, invalid
	}
	hello = hello[2:]
	seen := map[uint16]bool{}
	var protocols []string
	for len(hello) != 0 {
		if len(hello) < 4 {
			return nil, invalid
		}
		kind, size := binary.BigEndian.Uint16(hello), int(binary.BigEndian.Uint16(hello[2:]))
		if seen[kind] || len(hello) < 4+size {
			return nil, invalid
		}
		seen[kind] = true
		value := hello[4 : 4+size]
		hello = hello[4+size:]
		if kind != 16 {
			continue
		}
		if len(value) < 3 || int(binary.BigEndian.Uint16(value)) != len(value)-2 {
			return nil, invalid
		}
		value = value[2:]
		for len(value) != 0 {
			size := int(value[0])
			if size == 0 || len(value) < 1+size {
				return nil, invalid
			}
			protocols = append(protocols, string(value[1:1+size]))
			value = value[1+size:]
		}
	}
	return protocols, nil
}
