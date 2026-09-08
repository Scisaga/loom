package agent

import "testing"

func TestEquivalentTargetURLOnlyEquatesEmptyAndRootPath(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://demo.example", "https://demo.example/", true},
		{"http://demo.example?x=1&y=2#part", "http://demo.example/?x=1&y=2#part", true},
		{"https://demo.example?", "https://demo.example/?", true},
		{"https://demo.example/api", "https://demo.example/api", true},
		{"https://demo.example", "https://demo.example/api", false},
		{"https://demo.example/api", "https://demo.example/api/", false},
		{"https://demo.example", "https://demo.example//", false},
		{"https://demo.example/%2F", "https://demo.example//", false},
		{"https://demo.example/%61", "https://demo.example/a", false},
		{"https://demo.example", "https://demo.example/?", false},
		{"https://demo.example?x=1", "https://demo.example/?x=2", false},
		{"https://demo.example?x=1&y=2", "https://demo.example/?y=2&x=1", false},
		{"https://demo.example?x=%20", "https://demo.example/?x=+", false},
		{"https://demo.example#one", "https://demo.example/#two", false},
		{"http://demo.example", "https://demo.example/", false},
		{"https://demo.example:443", "https://demo.example/", false},
		{"demo.example", "demo.example/", false},
		{"https:demo.example", "https:demo.example/", false},
		{"ftp://demo.example", "ftp://demo.example/", false},
		{"https://%zz", "https://%zz/", false},
	} {
		if got := EquivalentTargetURL(tc.a, tc.b); got != tc.want {
			t.Errorf("EquivalentTargetURL(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := EquivalentTargetURL(tc.b, tc.a); got != tc.want {
			t.Errorf("reverse EquivalentTargetURL(%q, %q) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
}
