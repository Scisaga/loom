package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Uses the same built CLI input as the control-member native acceptance. The
// private fixture never installs host capture or changes system networking.
func TestInvitationCLIResumesPersistedReferenceAndReadsOwnConfiguration(t *testing.T) {
	binary := os.Getenv("LOOM_MEMBER_CLI")
	if binary == "" {
		t.Skip("set LOOM_MEMBER_CLI to the exact freshly built executable")
	}
	fixture := newEndpointFixture(t)
	original, _, _ := fixture.invite(t, "cli-privacy")
	uri, err := EncodeInvite(original)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.json")
	cli := func(stdin string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		command.Stdin = bytes.NewBufferString(stdin)
		result, err := command.CombinedOutput()
		if bytes.Contains(result, []byte(uri)) {
			t.Fatal("CLI leaked bearer invitation")
		}
		return result, err
	}
	// The identity must be durable even when the first connection is unavailable.
	if err := fixture.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cli(uri+"\n", "client", "enroll", "-stdin", "-state", path); err == nil {
		t.Fatal("unavailable endpoint completed enrollment")
	}
	pendingBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pending map[string]json.RawMessage
	if json.Unmarshal(pendingBytes, &pending) != nil || pending["invitation_reference"] == nil || pending["invite"] != nil || pending["certified_lkg"] != nil {
		t.Fatal("first attempt did not persist only pending reference")
	}
	public, err := cli("", "client", "inspect", "-state", path, "-identity")
	if err != nil {
		t.Fatal("pending identity cannot be inspected", err)
	}
	if bytes.Contains(public, []byte("capability")) || bytes.Contains(public, pending["private_key"]) {
		t.Fatal("inspection leaked private credential")
	}
	endpoints, err := NewEndpointRuntime(fixture.server.Runtime.Authority, fixture.server.Config.ControlID, fixture.server.now)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoints.Close()
	fixture.server.Endpoints = endpoints
	service := &http.Server{Handler: fixture.server.DeviceHandler(), ConnContext: endpointConnContext, ReadHeaderTimeout: time.Second}
	defer service.Close()
	go service.Serve(endpoints)
	output, err := cli(uri+"\n", "client", "enroll", "-stdin", "-state", path)
	if err != nil {
		t.Fatalf("normal CLI retry failed: %s", output)
	}
	joinedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var joined map[string]json.RawMessage
	if json.Unmarshal(joinedBytes, &joined) != nil || joined["invitation_reference"] != nil || joined["invite"] == nil || joined["certified_lkg"] == nil {
		t.Fatal("bound proof and configuration were not durably accepted")
	}
	for _, field := range []string{"private_key", "public_key", "claim_request_id", "platform", "authenticated_latch"} {
		if !bytes.Equal(pending[field], joined[field]) {
			t.Fatalf("retry changed %s", field)
		}
	}
	var proof BootstrapInvite
	if err := DecodeCanonical(joined["invite"], &proof, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	want, _, _ := EncodeMaterial(original.Material)
	actual, _, _ := EncodeMaterial(proof.Material)
	if !bytes.Equal(want, actual) {
		t.Fatal("binding rewrote original signed invitation")
	}
	if result, err := cli("", "client", "sync", "-state", path); err != nil {
		t.Fatalf("reopened CLI did not consume own authenticated device configuration: %s", result)
	}
	result, err := cli("", "client", "inspect", "-state", path, "-identity")
	if err != nil {
		t.Fatal(err)
	}
	var identity DeviceIdentityReadback
	if json.Unmarshal(result, &identity) != nil || identity.Validate() != nil || !identity.Joined || identity.TransactionID != original.Material.TargetID {
		t.Fatal("normal readback did not recover the same joined identity")
	}
	if state, _ := fixture.server.Runtime.Authority.EnrollmentState(identity.TransactionID); state != "completed" {
		t.Fatal("daemon did not persist completed enrollment")
	}
}
