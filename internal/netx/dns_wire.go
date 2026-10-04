package netx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// Only answers for the exact question or its in-message CNAME chain may become
// connection addresses. Compression, question and section bounds are checked
// before reading data; unrelated additional addresses never supply a target.
func DNSAnswers(query, answer []byte, kind uint16) ([]netip.Addr, error) {
	invalid := errors.New("certified DNS response is malformed, mismatched, failed or truncated")
	if len(query) < 17 || len(answer) < len(query) || !bytes.Equal(query[:2], answer[:2]) ||
		binary.BigEndian.Uint16(answer[2:4])&0xfa0f != 0x8000 || binary.BigEndian.Uint16(answer[4:6]) != 1 ||
		!bytes.Equal(query[12:], answer[12:len(query)]) {
		return nil, invalid
	}
	name, _, err := dnsName(query, 12)
	if err != nil {
		return nil, invalid
	}
	type record struct {
		owner   string
		address netip.Addr
	}
	var records []record
	aliases := map[string]string{}
	counts := []int{int(binary.BigEndian.Uint16(answer[6:8])), int(binary.BigEndian.Uint16(answer[8:10])), int(binary.BigEndian.Uint16(answer[10:12]))}
	at := len(query)
	for section, count := range counts {
		for range count {
			owner, next, err := dnsName(answer, at)
			if err != nil || next+10 > len(answer) {
				return nil, invalid
			}
			typ, class := binary.BigEndian.Uint16(answer[next:]), binary.BigEndian.Uint16(answer[next+2:])
			length := int(binary.BigEndian.Uint16(answer[next+8:]))
			at = next + 10
			end := at + length
			if end > len(answer) {
				return nil, invalid
			}
			if section == 0 && class == 1 {
				if typ == 5 {
					alias, consumed, err := dnsName(answer, at)
					if err != nil || consumed != end || aliases[owner] != "" && aliases[owner] != alias {
						return nil, invalid
					}
					aliases[owner] = alias
				} else if typ == kind {
					if kind == 1 && length != 4 || kind == 28 && length != 16 {
						return nil, invalid
					}
					address, ok := netip.AddrFromSlice(answer[at:end])
					if !ok {
						return nil, invalid
					}
					records = append(records, record{owner, address.Unmap()})
				}
			}
			at = end
		}
	}
	if at != len(answer) {
		return nil, invalid
	}
	seen := map[string]bool{}
	for aliases[name] != "" {
		if seen[name] {
			return nil, invalid
		}
		seen[name] = true
		name = aliases[name]
	}
	var addresses []netip.Addr
	for _, value := range records {
		if value.owner == name {
			addresses = append(addresses, value.address)
		}
	}
	return addresses, nil
}

func dnsName(message []byte, at int) (string, int, error) {
	invalid := errors.New("invalid DNS name")
	var labels []string
	next, size := -1, 0
	for steps := 0; steps < 128 && at < len(message); steps++ {
		length := int(message[at])
		if length == 0 {
			if next < 0 {
				next = at + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		if length&0xc0 == 0xc0 {
			if at+1 >= len(message) {
				return "", 0, invalid
			}
			pointer := (length&0x3f)<<8 | int(message[at+1])
			if pointer >= at {
				return "", 0, invalid
			}
			if next < 0 {
				next = at + 2
			}
			at = pointer
			continue
		}
		if length > 63 || at+1+length > len(message) {
			return "", 0, invalid
		}
		size += length + 1
		if size > 254 {
			return "", 0, invalid
		}
		labels = append(labels, string(message[at+1:at+1+length]))
		at += length + 1
	}
	return "", 0, invalid
}
