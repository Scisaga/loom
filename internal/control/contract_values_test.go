package control

import (
	"encoding/base64"
	"math"
	"reflect"
	"strings"
	"testing"
)

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
		{ServiceMatcher{"dns_exact", "demo.example"}, []string{"demo.example"}, []string{"a.demo.example", "Demo.example", "demo.example.", "demo.example:443"}},
		{ServiceMatcher{"dns_exact", "xn--bcher-kva.example"}, []string{"xn--bcher-kva.example"}, []string{"bücher.example"}},
		{ServiceMatcher{"dns_suffix", "demo.example"}, []string{"demo.example", "a.demo.example"}, []string{"notdemo.example", "demo.example.invalid", ".demo.example", "*.demo.example"}},
		{ServiceMatcher{"ip_prefix", "192.0.2.0/24"}, []string{"192.0.2.1", "192.0.2.255"}, []string{"198.51.100.1", "192.0.02.1", "::ffff:192.0.2.1", "demo.example"}},
		{ServiceMatcher{"ip_prefix", "2001:db8::/48"}, []string{"2001:db8::1"}, []string{"2001:db8:1::1", "2001:DB8::1", "2001:db8::1%demo", "192.0.2.1"}},
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
		{"unknown", "demo.example"}, {"dns_exact", ""}, {"dns_exact", "Demo.example"},
		{"dns_exact", "192.0.2.1"}, {"dns_exact", "demo.example."}, {"dns_suffix", ".demo.example"},
		{"dns_exact", "192.0.02.1"}, {"dns_exact", "xn--0.example"}, {"dns_exact", "xn--a.example"},
		{"dns_exact", "xn--abc.example"},
		{"dns_suffix", "*.example"}, {"dns_exact", "demo..example"}, {"dns_exact", "-demo.example"},
		{"dns_exact", "demo-.example"}, {"dns_exact", "中文.example"},
		{"ip_prefix", "192.0.2.1/24"}, {"ip_prefix", "192.0.2.1"},
		{"ip_prefix", "2001:0db8::/32"}, {"ip_prefix", "2001:db8::1/32"},
	} {
		if matcher.Validate() == nil || matcher.Matches("demo.example") || matcher.Matches("192.0.2.1") {
			t.Fatal("invalid matcher permits a target")
		}
		if _, err := CanonicalEncode(matcher); err == nil {
			t.Fatal("encoder accepted an invalid matcher")
		}
	}
}
