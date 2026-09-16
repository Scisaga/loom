//go:build linux

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxDefaultEnrollmentRejectsLegacyCarrierBeforeCreatingIdentity(t *testing.T) {
	directory := t.TempDir()
	invite := filepath.Join(directory, "old.loom-invite")
	if err := os.WriteFile(invite, []byte(`{"schema":1,"enrollment_url":"https://control.example/enroll","token":"demo-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"enroll", "enroll-v2"} {
		state := filepath.Join(directory, command)
		if err := cmdClient([]string{command, "-invite-file", invite, "-state-dir", state}); err == nil {
			t.Fatal("旧 carrier 被正常入网入口接受")
		}
		if _, err := os.Stat(state); !os.IsNotExist(err) {
			t.Fatalf("拒绝旧 carrier 前创建了身份状态: %v", err)
		}
	}
}

func TestLinuxClientV2CommonFlagsUseParsedStateDirectory(t *testing.T) {
	var common linuxClientV2CommonFlags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	addLinuxClientV2Flags(fs, &common)
	directory := filepath.Join(t.TempDir(), "state")
	envelopeDirectory := filepath.Join(t.TempDir(), "envelopes")
	if err := fs.Parse([]string{"-state-dir", directory, "-timeout", "45s",
		"-secret-envelope-dir", envelopeDirectory}); err != nil {
		t.Fatal(err)
	}
	if err := common.resolvePaths(); err != nil {
		t.Fatal(err)
	}
	if common.paths.state != filepath.Join(directory, "state.json") ||
		common.paths.identity != filepath.Join(directory, "identity.json") ||
		common.paths.pending != filepath.Join(directory, "pending.json") ||
		common.timeout != 45*time.Second || common.secretEnvelopeDirectory != envelopeDirectory {
		t.Fatalf("parsed common flags=%#v", common)
	}
}

func TestLinuxClientV2EnvelopeInputsAreMutuallyExclusive(t *testing.T) {
	var common linuxClientV2CommonFlags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	addLinuxClientV2Flags(fs, &common)
	if err := fs.Parse([]string{"-state-dir", t.TempDir(), "-secret-envelope-dir", t.TempDir(),
		"-secret-envelope", "/tmp/one.json"}); err != nil {
		t.Fatal(err)
	}
	if err := common.resolvePaths(); err == nil {
		t.Fatal("accepted both sealed envelope input modes")
	}
}

func TestLinuxClientV2TrustRequiresCompleteMigrationRoot(t *testing.T) {
	_, err := linuxClientV2Trust(linuxClientV2TrustFlags{platformKeyID: "platform-v1"}, false)
	if err == nil || !strings.Contains(err.Error(), "必须成组提供") {
		t.Fatalf("incomplete migration root err=%v", err)
	}
	if _, err := linuxClientV2Trust(linuxClientV2TrustFlags{}, true); err == nil {
		t.Fatal("resume accepted without the v1 migration trust root")
	}
}

func TestLinuxClientV2RequestIDIsValidAndDoesNotCreateIdentity(t *testing.T) {
	directory := t.TempDir()
	paths := linuxClientV2Paths{state: filepath.Join(directory, "state.json"),
		identity: filepath.Join(directory, "identity.json"), pending: filepath.Join(directory, "pending.json")}
	requestID, err := linuxClientV2RequestID(paths, "cluster", "invite")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(requestID, "linux-") || len(requestID) != len("linux-")+32 {
		t.Fatalf("request ID shape=%q", requestID)
	}
	if installed, err := linuxClientV2Installed(paths, "cluster", "invite"); err != nil || installed {
		t.Fatalf("installed=%v err=%v", installed, err)
	}
}

func TestLinuxClientV2CommandsRejectAmbiguousCarriers(t *testing.T) {
	if err := cmdClientEnrollV2(nil); err == nil {
		t.Fatal("enroll-v2 accepted missing carrier")
	}
	if err := cmdClientEnrollV2([]string{"-invite-file", "a", "-invite-uri", "b"}); err == nil {
		t.Fatal("enroll-v2 accepted two carriers")
	}
	if err := cmdClientResumeV2(nil); err == nil {
		t.Fatal("resume-v2 accepted missing descriptor")
	}
}

func TestLinuxEnrollmentCanDeferRuntimeActivation(t *testing.T) {
	if err := activateLinuxEnrollmentRuntime("relative-invalid-state", time.Second, true); err != nil {
		t.Fatalf("显式推迟 runtime 时不应触碰宿主状态: %v", err)
	}
	if err := activateLinuxEnrollmentRuntime("relative-invalid-state", time.Second, false); err == nil {
		t.Fatal("默认 Enrollment 没有进入 runtime 激活")
	}
}

func TestLinuxClientV2RuntimeUninstallRequiresExplicitModeAndBoundedState(t *testing.T) {
	if err := cmdClientUninstallV2Runtime(nil); err == nil {
		t.Fatal("runtime uninstall accepted an implicit destructive mode")
	}
	if err := cmdClientUninstallV2Runtime([]string{"-apply", "-dry-run"}); err == nil {
		t.Fatal("runtime uninstall accepted conflicting modes")
	}
	if err := cmdClientUninstallV2Runtime([]string{"-dry-run", "-state-dir", "relative"}); err == nil {
		t.Fatal("runtime uninstall accepted a relative state directory")
	}
	if err := cmdClientUninstallV2Runtime([]string{"-dry-run", "-state-dir", t.TempDir()}); err != nil {
		t.Fatalf("idempotent dry-run without an installed runtime failed: %v", err)
	}
}
