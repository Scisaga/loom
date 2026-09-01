package main

import (
	"slices"
	"testing"

	"loom/internal/model"
)

func TestAccessCredentialRefsIncludesAuthorizedInactivePolicies(t *testing.T) {
	s := &model.SSOT{
		Nodes: []model.Node{{
			ID: "access",
			Access: &model.AccessRole{
				Credentials: []string{"active", "inactive", "rotating", "revoked"},
			},
		}},
		Credentials: []model.Credential{
			{ID: "active", SecretRef: "cred/active"},
			{ID: "inactive", SecretRef: "cred/inactive"},
			{ID: "rotating", SecretRef: "cred/rotating", Generation: 2, AcceptPrevious: true},
			{ID: "revoked", SecretRef: "cred/revoked", RevokedAt: "2026-08-31T00:00:00Z"},
		},
	}

	want := []string{"cred/active", "cred/inactive", "cred/rotating", "cred/rotating@2"}
	if got := accessCredentialRefs(s, "access"); !slices.Equal(got, want) {
		t.Fatalf("access credential refs = %v, want %v", got, want)
	}
}

func TestRemovableDeviceSecretRefsAreExactAndRequireSSOTAbsence(t *testing.T) {
	all := map[string]string{
		"api/d-canary":              "a",
		"probe/d-canary":            "b",
		"telemetry/d-canary":        "c",
		"cred/d-canary/best-egress": "d",
		"api/d-canary-other":        "keep",
		"cred/other/d-canary":       "keep",
	}
	want := []string{"api/d-canary", "cred/d-canary/best-egress", "probe/d-canary", "telemetry/d-canary"}
	got, err := removableDeviceSecretRefs(&model.SSOT{}, "d-canary", all)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("removable refs = %v, want %v", got, want)
	}
	if _, err := removableDeviceSecretRefs(&model.SSOT{Nodes: []model.Node{{ID: "d-canary"}}}, "d-canary", all); err == nil {
		t.Fatal("secrets were considered removable while Device remains in SSOT")
	}
}
