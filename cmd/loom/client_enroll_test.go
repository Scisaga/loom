package main

import (
	"errors"
	"strings"
	"testing"

	"loom/internal/clientenroll"
)

func TestServerEnrollmentInstallsWireGuardToolsBeforeClaim(t *testing.T) {
	server := &clientenroll.ServerEnrollment{PublicEndpoint: "edge.example.net"}
	installed := false
	executables := map[string]bool{}
	err := ensureServerWireGuardTools(server, func(path string) bool { return executables[path] }, func() error {
		installed = true
		executables["/usr/bin/wg"] = true
		executables["/usr/bin/wg-quick"] = true
		return nil
	})
	if err != nil || !installed {
		t.Fatalf("server prerequisites installed=%v err=%v", installed, err)
	}
	installed = false
	if err := ensureServerWireGuardTools(server, func(string) bool { return true }, func() error {
		installed = true
		return nil
	}); err != nil || installed {
		t.Fatalf("existing tools installed=%v err=%v", installed, err)
	}
}

func TestAccessOnlyEnrollmentDoesNotInstallWireGuardTools(t *testing.T) {
	called := false
	err := ensureServerWireGuardTools(nil, func(string) bool { called = true; return false }, func() error {
		called = true
		return errors.New("must not run")
	})
	if err != nil || called {
		t.Fatalf("access-only prerequisite called=%v err=%v", called, err)
	}
}

func TestServerEnrollmentFailsBeforeClaimWhenToolsRemainMissing(t *testing.T) {
	err := ensureServerWireGuardTools(&clientenroll.ServerEnrollment{}, func(string) bool { return false }, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "加入码尚未消费") {
		t.Fatalf("missing tools error=%v", err)
	}
}
