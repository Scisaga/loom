package control

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestDigestValidationPreservesCanonicalHex(t *testing.T) {
	// Compare every single-byte substitution with the established hex round
	// trip, including uppercase, control bytes, and invalid UTF-8.
	value := []byte("sha256:" + strings.Repeat("a", 64))
	for index := range value {
		original := value[index]
		for replacement := range 256 {
			value[index] = byte(replacement)
			text := string(value)
			decoded, err := hex.DecodeString(text[len("sha256:"):])
			want := strings.HasPrefix(text, "sha256:") && err == nil && hex.EncodeToString(decoded) == text[len("sha256:"):]
			if got := ValidateDigest(text) == nil; got != want {
				t.Fatalf("digest acceptance changed at byte %d, value %d", index, replacement)
			}
		}
		value[index] = original
	}
}

func TestObservationTuplePreservesDelimitedOrder(t *testing.T) {
	ordered := func(value Observation) string {
		return strings.Join([]string{value.NetworkGeneration, value.Level, value.ServiceID, value.CandidateID, value.ResourceID, value.LinkID, value.Target, value.Action, value.SpecDigest}, "\x00")
	}
	fields := func(values [9]string) Observation {
		return Observation{NetworkGeneration: values[0], Level: values[1], ServiceID: values[2], CandidateID: values[3], ResourceID: values[4], LinkID: values[5], Target: values[6], Action: values[7], SpecDigest: values[8]}
	}
	// Empty fields, prefixes, and multi-byte text exercise the delimiter
	// boundary that must retain exactly the original signed collection order.
	for _, prefix := range []string{"", "demo", "中文"} {
		for index := range 9 {
			for _, left := range []string{"", "a", "aa", "b", "中文"} {
				for _, right := range []string{"", "a", "aa", "b", "中文"} {
					var a, b [9]string
					for before := 0; before < index; before++ {
						a[before], b[before] = prefix, prefix
					}
					a[index], b[index] = left, right
					a[8], b[8] = "z"+a[8], "a"+b[8]
					l, r := fields(a), fields(b)
					if compareObservationOrder(l, r) != strings.Compare(ordered(l), ordered(r)) {
						t.Fatalf("observation order changed at field %d", index)
					}
				}
			}
		}
	}
}

func TestContractScalarBoundaries(t *testing.T) {
	for _, test := range []struct {
		name     string
		validate func(string) error
		valid    []string
		invalid  []string
	}{
		{"ID", ValidateID, []string{"demo-id", "中文", strings.Repeat("a", 128)}, []string{"", " demo", "demo\u00a0", "demo\x00", "demo\x7f", "\xff", strings.Repeat("中", 43)}},
		{"Text", ValidateText, []string{"Demo name", strings.Repeat("a", 256)}, []string{"", "demo\nname", strings.Repeat("a", 257)}},
		{"Digest", ValidateDigest, []string{"sha256:" + strings.Repeat("a", 64)}, []string{"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63)}},
		{"PublicKey", ValidatePublicKey, []string{base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, []string{"", base64.URLEncoding.EncodeToString(make([]byte, 32)), base64.RawURLEncoding.EncodeToString(make([]byte, 31)), strings.Repeat("A", 42) + "B"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, value := range test.valid {
				if err := test.validate(value); err != nil {
					t.Fatal("rejected valid scalar", err)
				}
			}
			for _, value := range test.invalid {
				if err := test.validate(value); err == nil {
					t.Fatal("accepted invalid scalar")
				}
			}
		})
	}
	for _, value := range []U64{0, 1, U64(math.MaxUint64)} {
		body, err := CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
		var next U64
		if err := DecodeCanonical(body, &next, contractTestLimits); err != nil || next != value {
			t.Fatalf("U64 round trip failed: %s, %v", body, err)
		}
	}
	for _, body := range []string{`0`, `null`, `""`, `"00"`, `"01"`, `"+1"`, `"-1"`, `"1e0"`, `"1.0"`, `"18446744073709551616"`, `"\u0031"`} {
		var value U64
		if err := DecodeCanonical([]byte(body), &value, contractTestLimits); err == nil {
			t.Fatalf("accepted noncanonical U64: %s", body)
		}
	}
}

func TestPolicyScopeCanonicalModesAndMembership(t *testing.T) {
	for _, test := range []struct {
		value   PolicyScope
		body    string
		allowed bool
	}{
		{PolicyScope{Mode: "any", NodeIDs: []string{}}, `{"mode":"any","node_ids":[]}`, true},
		{PolicyScope{Mode: "none", NodeIDs: []string{}}, `{"mode":"none","node_ids":[]}`, false},
		{PolicyScope{Mode: "only", NodeIDs: []string{"demo-a", "demo-b"}}, `{"mode":"only","node_ids":["demo-a","demo-b"]}`, true},
	} {
		body, err := CanonicalEncode(test.value)
		if err != nil || string(body) != test.body {
			t.Fatalf("scope byte vector differs: %s, %v", body, err)
		}
		var next PolicyScope
		if err := DecodeCanonical(body, &next, contractTestLimits); err != nil || !reflect.DeepEqual(test.value, next) {
			t.Fatalf("scope round trip differs: %#v, %v", next, err)
		}
		if next.Allows("demo-a") != test.allowed || next.Allows("direct") || next.Allows("") {
			t.Fatal("scope membership broadened")
		}
		if next.Mode == "only" && next.Allows("demo-c") {
			t.Fatal("only scope accepted an unlisted node")
		}
	}
	for _, value := range []PolicyScope{
		{Mode: "any"}, {Mode: "only", NodeIDs: []string{}},
		{Mode: "any", NodeIDs: []string{"demo-a"}}, {Mode: "none", NodeIDs: []string{"demo-a"}},
		{Mode: "unknown", NodeIDs: []string{}},
		{Mode: "only", NodeIDs: []string{"demo-b", "demo-a"}},
		{Mode: "only", NodeIDs: []string{"demo-a", "demo-a"}},
		{Mode: "only", NodeIDs: []string{"direct"}},
	} {
		if value.Validate() == nil || value.Allows("demo-a") {
			t.Fatal("invalid scope permits a node")
		}
		if _, err := CanonicalEncode(value); err == nil {
			t.Fatal("encoder normalized an invalid scope")
		}
	}
	for _, body := range []string{
		`{"mode":"any"}`, `{"mode":"any","node_ids":null}`, `{"Mode":"any","node_ids":[]}`,
		`{"mode":"only","node_ids":[]}`, `{"mode":"any","mode":"none","node_ids":[]}`,
		`{"node_ids":[],"mode":"any"}`, `{"mode":"only","node_ids":["demo-b","demo-a"]}`,
	} {
		var value PolicyScope
		if err := DecodeCanonical([]byte(body), &value, contractTestLimits); err == nil {
			t.Fatal("accepted invalid scope bytes")
		}
	}
}

func TestServiceMatcherExactSuffixAndIPBoundaries(t *testing.T) {
	for _, test := range []struct {
		matcher ServiceMatcher
		matches []string
		rejects []string
	}{
		{ServiceMatcher{Kind: "dns_exact", Value: "demo.example"}, []string{"demo.example"}, []string{"a.demo.example", "Demo.example", "demo.example.", "demo.example:443"}},
		{ServiceMatcher{Kind: "dns_exact", Value: "xn--bcher-kva.example"}, []string{"xn--bcher-kva.example"}, []string{"bücher.example"}},
		{ServiceMatcher{Kind: "dns_suffix", Value: "demo.example"}, []string{"demo.example", "a.demo.example"}, []string{"notdemo.example", "demo.example.invalid", ".demo.example", "*.demo.example"}},
		{ServiceMatcher{Kind: "ip_prefix", Value: "192.0.2.0/24"}, []string{"192.0.2.1", "192.0.2.255"}, []string{"198.51.100.1", "192.0.02.1", "::ffff:192.0.2.1", "demo.example"}},
		{ServiceMatcher{Kind: "ip_prefix", Value: "2001:db8::/48"}, []string{"2001:db8::1"}, []string{"2001:db8:1::1", "2001:DB8::1", "2001:db8::1%demo", "192.0.2.1"}},
	} {
		if err := test.matcher.Validate(); err != nil {
			t.Fatal(err)
		}
		body, err := CanonicalEncode(test.matcher)
		var next ServiceMatcher
		if err != nil || DecodeCanonical(body, &next, contractTestLimits) != nil || next != test.matcher {
			t.Fatal("matcher round trip differs", err)
		}
		for _, target := range test.matches {
			if !next.Matches(target) {
				t.Fatalf("matcher rejected authorized target %s", target)
			}
		}
		for _, target := range test.rejects {
			if next.Matches(target) {
				t.Fatalf("matcher broadened to target %s", target)
			}
		}
	}
	for _, matcher := range []ServiceMatcher{
		{Kind: "unknown", Value: "demo.example"}, {Kind: "dns_exact", Value: ""}, {Kind: "dns_exact", Value: "Demo.example"},
		{Kind: "dns_exact", Value: "192.0.2.1"}, {Kind: "dns_exact", Value: "demo.example."}, {Kind: "dns_suffix", Value: ".demo.example"},
		{Kind: "dns_exact", Value: "192.0.02.1"}, {Kind: "dns_exact", Value: "xn--0.example"}, {Kind: "dns_exact", Value: "xn--a.example"},
		{Kind: "dns_exact", Value: "xn--abc.example"},
		{Kind: "dns_suffix", Value: "*.example"}, {Kind: "dns_exact", Value: "demo..example"}, {Kind: "dns_exact", Value: "-demo.example"},
		{Kind: "dns_exact", Value: "demo-.example"}, {Kind: "dns_exact", Value: "中文.example"},
		{Kind: "ip_prefix", Value: "192.0.2.1/24"}, {Kind: "ip_prefix", Value: "192.0.2.1"},
		{Kind: "ip_prefix", Value: "2001:0db8::/32"}, {Kind: "ip_prefix", Value: "2001:db8::1/32"},
	} {
		if matcher.Validate() == nil || matcher.Matches("demo.example") || matcher.Matches("192.0.2.1") {
			t.Fatal("invalid matcher permits a target")
		}
		if _, err := CanonicalEncode(matcher); err == nil {
			t.Fatal("encoder accepted an invalid matcher")
		}
	}
}
