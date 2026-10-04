package control

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// U64 retains the entire unsigned range while using a JSON decimal string.
type U64 uint64

func ParseU64(value string) (U64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("contract U64 is not canonical")
	}
	return U64(parsed), nil
}

func (value U64) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatUint(uint64(value), 10) + `"`), nil
}

func (value *U64) UnmarshalJSON(body []byte) error {
	var text string
	if err := json.Unmarshal(body, &text); err != nil {
		return errors.New("contract U64 must be a decimal string")
	}
	parsed, err := ParseU64(text)
	if err != nil {
		return err
	}
	want, _ := parsed.MarshalJSON()
	if string(want) != string(body) {
		return errors.New("contract U64 is not canonical")
	}
	*value = parsed
	return nil
}

func ValidateID(value string) error { return validateContractText(value, 128) }

func ValidateText(value string) error { return validateContractText(value, 256) }

func validateContractText(value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("contract ID or text is invalid")
	}
	return nil
}

func ValidateDigest(value string) error {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return errors.New("contract digest is invalid")
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(encoded)
	if err != nil || hex.EncodeToString(decoded) != encoded {
		return errors.New("contract digest is not canonical")
	}
	return nil
}

func ValidatePublicKey(value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("contract public key is not canonical")
	}
	return nil
}

// PolicyScope is a value inside a Policy, without independent authority or
// lifecycle. Allows checks this range only; node eligibility is checked by the
// authorization projection against its authenticated dependencies.
type PolicyScope struct {
	Mode    string   `json:"mode"`
	NodeIDs []string `json:"node_ids"`
}

func (scope PolicyScope) Validate() error {
	if scope.NodeIDs == nil {
		return errors.New("policy scope node IDs must be an explicit collection")
	}
	switch scope.Mode {
	case "any", "none":
		if len(scope.NodeIDs) != 0 {
			return errors.New("policy scope mode cannot carry node IDs")
		}
	case "only":
		if len(scope.NodeIDs) == 0 {
			return errors.New("policy only scope requires node IDs")
		}
	default:
		return errors.New("policy scope mode is invalid")
	}
	for index, nodeID := range scope.NodeIDs {
		if ValidateID(nodeID) != nil || nodeID == "direct" || index > 0 && scope.NodeIDs[index-1] >= nodeID {
			return errors.New("policy scope node IDs are invalid or not uniquely sorted")
		}
	}
	return nil
}

func (scope PolicyScope) Allows(nodeID string) bool {
	if scope.Validate() != nil || ValidateID(nodeID) != nil || nodeID == "direct" {
		return false
	}
	switch scope.Mode {
	case "any":
		return true
	case "only":
		index := sort.SearchStrings(scope.NodeIDs, nodeID)
		return index < len(scope.NodeIDs) && scope.NodeIDs[index] == nodeID
	default:
		return false
	}
}

type ServiceMatcher struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (matcher ServiceMatcher) Validate() error {
	switch matcher.Kind {
	case "dns_exact", "dns_suffix":
		if !contractDNSName(matcher.Value) {
			return errors.New("service matcher DNS name is not canonical")
		}
	case "ip_prefix":
		prefix, err := netip.ParsePrefix(matcher.Value)
		if err != nil || prefix.String() != matcher.Value || prefix.Masked() != prefix {
			return errors.New("service matcher IP prefix is not canonical")
		}
	default:
		return errors.New("service matcher kind is invalid")
	}
	return nil
}

// Matches consumes an already canonical DNS name or IP, never a URL, address
// with a port, or a DNS answer inferred by this function. It does not resolve
// names or normalize authority values.
func (matcher ServiceMatcher) Matches(target string) bool {
	if matcher.Validate() != nil {
		return false
	}
	switch matcher.Kind {
	case "dns_exact":
		return contractDNSName(target) && target == matcher.Value
	case "dns_suffix":
		return contractDNSName(target) && (target == matcher.Value || strings.HasSuffix(target, "."+matcher.Value))
	case "ip_prefix":
		address, err := netip.ParseAddr(target)
		if err != nil || address.Zone() != "" || address.String() != target {
			return false
		}
		prefix, _ := netip.ParsePrefix(matcher.Value)
		return prefix.Contains(address)
	default:
		return false
	}
}

var contractDNSProfile = idna.New(idna.ValidateForRegistration())

func contractDNSName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	labels := strings.Split(value, ".")
	allDecimal := len(labels) == 4
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			character := label[index]
			allDecimal = allDecimal && character >= '0' && character <= '9'
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	// Do not reinterpret an invalid dotted IPv4 spelling as a DNS identity.
	if allDecimal {
		return false
	}
	canonical, err := contractDNSProfile.ToASCII(value)
	return err == nil && canonical == value
}
