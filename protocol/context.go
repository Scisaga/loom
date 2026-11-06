// Package protocol defines the bounded schema-3 execution messages shared by
// Loom's independent transports. These values are connection data, never grants.
package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Schema = 3
const MaxIDBytes = 128

// PathContext contains only information that must survive hop termination.
// Policy is explicit on its request; the accepted Policy supplies Service.
type PathContext struct {
	OriginID    string
	FinalExitID string
	Visited     []string
}

func ValidateID(value string) error {
	if value == "" || len(value) > MaxIDBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("invalid execution identity")
	}
	return nil
}

func (value PathContext) Validate(maxNodes int) error {
	if maxNodes < 1 || ValidateID(value.OriginID) != nil || ValidateID(value.FinalExitID) != nil || value.OriginID == "direct" || value.Visited == nil || len(value.Visited) > maxNodes {
		return errors.New("invalid path context")
	}
	seen := make(map[string]bool, len(value.Visited))
	for index, node := range value.Visited {
		if ValidateID(node) != nil || node == "direct" || seen[node] || node == value.FinalExitID && index != len(value.Visited)-1 {
			return errors.New("path repeats or continues past its final exit")
		}
		seen[node] = true
	}
	return nil
}

func appendText(body []byte, value string) []byte {
	body = binary.AppendUvarint(body, uint64(len(value)))
	return append(body, value...)
}

func (value PathContext) Marshal(maxNodes int) ([]byte, error) {
	if err := value.Validate(maxNodes); err != nil {
		return nil, err
	}
	body := []byte{Schema}
	body = appendText(body, value.OriginID)
	body = appendText(body, value.FinalExitID)
	body = binary.AppendUvarint(body, uint64(len(value.Visited)))
	for _, node := range value.Visited {
		body = appendText(body, node)
	}
	return body, nil
}

type reader struct {
	body   []byte
	offset int
}

func (r *reader) uint() (uint64, error) {
	if r.offset >= len(r.body) {
		return 0, errors.New("truncated execution integer")
	}
	value, n := binary.Uvarint(r.body[r.offset:])
	if n <= 0 || len(binary.AppendUvarint(nil, value)) != n {
		return 0, errors.New("noncanonical execution integer")
	}
	r.offset += n
	return value, nil
}
func (r *reader) text(maximum int) (string, error) {
	length, err := r.uint()
	if err != nil || length > uint64(maximum) || length > uint64(len(r.body)-r.offset) {
		return "", errors.New("invalid execution text length")
	}
	value := string(r.body[r.offset : r.offset+int(length)])
	r.offset += int(length)
	return value, nil
}
func (r *reader) context(maxNodes int) (PathContext, error) {
	if maxNodes < 1 || r.offset >= len(r.body) || r.body[r.offset] != Schema {
		return PathContext{}, errors.New("execution context schema is not current")
	}
	r.offset++
	origin, err := r.text(MaxIDBytes)
	if err != nil {
		return PathContext{}, err
	}
	exit, err := r.text(MaxIDBytes)
	if err != nil {
		return PathContext{}, err
	}
	count, err := r.uint()
	if err != nil || count > uint64(maxNodes) || count > uint64(len(r.body)-r.offset)/2 {
		return PathContext{}, errors.New("invalid visited-node count")
	}
	value := PathContext{OriginID: origin, FinalExitID: exit, Visited: make([]string, 0, int(count))}
	for index := uint64(0); index < count; index++ {
		node, err := r.text(MaxIDBytes)
		if err != nil {
			return PathContext{}, err
		}
		value.Visited = append(value.Visited, node)
	}
	return value, value.Validate(maxNodes)
}
func UnmarshalContext(body []byte, maxNodes int) (PathContext, error) {
	r := reader{body: body}
	value, err := r.context(maxNodes)
	if err != nil {
		return PathContext{}, err
	}
	if r.offset != len(body) {
		return PathContext{}, errors.New("trailing execution context bytes")
	}
	return value, nil
}

// CanonicalHost validates a transport target without granting access to it.
// DNS names have already passed the caller's IDNA conversion. Literal private
// addresses remain subject to the receiving Service and exclusion rules.
func CanonicalHost(value string) bool {
	if addr, err := netip.ParseAddr(value); err == nil {
		return !addr.Is4In6() && addr.Zone() == "" && addr.String() == value
	}
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
