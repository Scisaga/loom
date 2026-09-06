package clientcore

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func verifiedPolicy() Policy {
	return Policy{Schema: PolicySchema, Exits: []Exit{
		{ID: "demo-exit-a", Name: "Singapore"},
		{ID: "demo-exit-b", Name: "Germany"},
	}}
}

func TestPreferenceRoundTripAndStrictDecoding(t *testing.T) {
	want := Preference{Schema: PreferenceSchema, Mode: FixedExit, Exit: "demo-exit-a"}
	body, err := EncodePreference(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePreference(body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	for _, body := range []string{
		`{"schema":1,"schema":1,"mode":"auto"}`,
		`{"schema":1,"mode":"auto","unknown":true}`,
		`{"schema":1,"mode":"auto"} {}`,
	} {
		if _, err := ParsePreference([]byte(body)); err == nil {
			t.Errorf("accepted ambiguous preference %s", body)
		}
	}
}

func TestPreferenceShapeIsUnambiguous(t *testing.T) {
	for _, tc := range []struct {
		preference Preference
		want       string
	}{
		{Preference{Schema: 99, Mode: Auto}, "schema"},
		{Preference{Schema: 1, Mode: "whatever"}, "mode"},
		{Preference{Schema: 1, Mode: Auto, Exit: "demo-exit-a"}, "must not carry"},
		{Preference{Schema: 1, Mode: FixedExit}, "requires"},
		{Preference{Schema: 1, Mode: FixedExit, Exit: "../sg"}, "valid exit"},
	} {
		if err := tc.preference.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Validate(%+v) = %v, want %q", tc.preference, err, tc.want)
		}
	}
}

func TestAuthorizeChangeCannotExpandSignedExitSet(t *testing.T) {
	policy := verifiedPolicy()
	for _, next := range []Preference{
		{Schema: 1, Mode: Direct},
		{Schema: 1, Mode: Auto},
		{Schema: 1, Mode: FixedExit, Exit: "demo-exit-b"},
	} {
		if err := AuthorizeChange(next, policy); err != nil {
			t.Errorf("authorized change %+v failed: %v", next, err)
		}
	}
	err := AuthorizeChange(Preference{Schema: 1, Mode: FixedExit, Exit: "demo-exit-c"}, policy)
	if !errors.Is(err, ErrExitNotAuthorized) {
		t.Fatalf("arbitrary exit error = %v, want ErrExitNotAuthorized", err)
	}
}

func TestRemovedExitStaysVisibleAndFailsClosed(t *testing.T) {
	saved := Preference{Schema: 1, Mode: FixedExit, Exit: "demo-exit-a"}
	decision, err := Evaluate(saved, Policy{Schema: 1, Exits: []Exit{{ID: "demo-exit-b"}}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Mode != FixedExit || decision.Exit != "demo-exit-a" || !decision.Blocked || decision.BlockReason == "" {
		t.Fatalf("removed exit silently changed behavior: %+v", decision)
	}
}

func TestPreferenceStoreCreatesAndAtomicallyReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "preference.json")
	initial, err := EnsurePreference(path)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Mode != Auto {
		t.Fatalf("first-run mode = %s, want auto", initial.Mode)
	}
	next := Preference{Schema: 1, Mode: FixedExit, Exit: "demo-exit-a"}
	if err := WritePreference(path, next); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPreference(path)
	if err != nil || !reflect.DeepEqual(got, next) {
		t.Fatalf("ReadPreference = %+v, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "preference.json" {
		t.Fatalf("temporary preference leaked: %v", entries)
	}
}

func TestEnsurePreferenceDoesNotOverwriteCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preference.json")
	if err := os.WriteFile(path, []byte(`{"schema":1,"mode":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsurePreference(path); err == nil {
		t.Fatal("corrupt preference was silently replaced")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"schema":1,"mode":"broken"}` {
		t.Fatalf("corrupt preference changed: %q", body)
	}
}
