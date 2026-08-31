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
