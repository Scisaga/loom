package validate

import (
	"strings"
	"testing"

	"loom/internal/model"
)

func TestCanonicalServiceHostSyntax(t *testing.T) {
	valid := []struct {
		input  string
		key    string
		suffix bool
	}{
		{input: "api.example.com", key: "api.example.com"},
		{input: ".Example.COM", key: ".example.com", suffix: true},
		{input: "node-1.internal", key: "node-1.internal"},
		{input: "localhost", key: "localhost"},
		{input: "xn--bcher-kva.example", key: "xn--bcher-kva.example"},
	}
	for _, tc := range valid {
		t.Run("valid_"+tc.input, func(t *testing.T) {
			key, suffix, reason := canonicalServiceHost(tc.input)
			if reason != "" {
				t.Fatalf("%q 被误拒:%s", tc.input, reason)
			}
			if key != tc.key || suffix != tc.suffix {
				t.Fatalf("canonicalServiceHost(%q) = (%q, %v), 期望 (%q, %v)",
					tc.input, key, suffix, tc.key, tc.suffix)
			}
		})
	}

	tooLongHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)
	invalid := []string{
		"", ".",
		"*.example.com", ".example.*", "foo*bar.example",
		"https://api.example.com/v1", "api.example.com/path", "api.example.com?x=1",
		"api.example.com#fragment", "api.example.com:443",
		"192.0.2.1", "2001:db8::1",
		"bad_name.example", "-api.example", "api-.example", "api..example",
		"api.example.", "..example.com", "例子.example",
		strings.Repeat("a", 64) + ".example", tooLongHost,
	}
	for _, input := range invalid {
		name := input
		if name == "" {
			name = "empty"
		}
		t.Run("invalid_"+name, func(t *testing.T) {
			if _, _, reason := canonicalServiceHost(input); reason == "" {
				t.Fatalf("%q 未被拒绝", input)
			}
		})
	}
}

func TestServiceHostOwnershipIsCaseInsensitive(t *testing.T) {
	s := &model.SSOT{Services: []model.Service{
		{ID: "a", Addresses: []string{"API.Example.COM"}},
		{ID: "b", Addresses: []string{"api.example.com"}},
	}}
	if got := Format(Validate(s)); !strings.Contains(got, "已被服务") {
		t.Fatalf("DNS 大小写变体没有被当作同一个地址:\n%s", got)
	}
}

func TestServiceSuffixOwnershipIncludesApex(t *testing.T) {
	s := &model.SSOT{Services: []model.Service{
		{ID: "exact", Addresses: []string{"example.com"}},
		{ID: "suffix", Addresses: []string{".example.com"}},
	}}
	if got := Format(Validate(s)); !strings.Contains(got, "后缀 \".example.com\" 之内") {
		t.Fatalf("后缀规则会覆盖 apex,但重叠未被报告:\n%s", got)
	}
}
