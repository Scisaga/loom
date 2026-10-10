package control

import (
	"context"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlMemberRotationActivatesOnlyCertifiedPreparedIdentity(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	parent := filepath.Dir(root)
	ca := testTransportCA(t, parent)
	key, err := config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := testTransportIdentity(t, parent, config.ControlID, 10, key, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	config.PeerTLS = &files
	if _, err = InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server := &Server{Runtime: runtime, Config: config}
	accepted := submitAuthority(t, runtime, authorityService("demo-before-rotation", "demo-before"))
	original, err := runtime.Authority.Material(accepted.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	newKey := testKey(t)
	newFiles, _, _ := testTransportIdentity(t, t.TempDir(), config.ControlID, 11, newKey, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	next := config
	next.SigningKeyFile, next.PeerTLS = newFiles.KeyFile, &newFiles
	ctx := context.Background()
	if err = PrepareControlKey(ctx, root, next); err != nil {
		t.Fatal(err)
	}
	if err = ActivatePreparedControlKey(ctx, root); err != nil {
		t.Fatal(err)
	}
	current, err := LoadNodeConfig(root)
	if err != nil || current.SigningKeyFile != config.SigningKeyFile || !runtime.Writable() {
		t.Fatal("preparation changed current identity or qualification")
	}
	member, _ := next.Member()
	request := ControlChangeRequest{Schema: 3, BaseConfigID: runtime.Authority.Snapshot().ControlConfigID, Operation: "rotate", TargetNodeID: config.NodeID, PublicKey: member.PublicKey}
	response := memberAdminHTTP(t, server, request)
	if response.Code != http.StatusOK {
		t.Fatalf("formal rotation: %s", response.Body.String())
	}
	if runtime.Writable() {
		t.Fatal("old key still signs after certified rotation")
	}
	if err = ActivatePreparedControlKey(ctx, root); err != nil {
		t.Fatal(err)
	}
	if err = ActivatePreparedControlKey(ctx, root); err != nil {
		t.Fatal("activation retry failed", err)
	}
	if _, err = os.Stat(filepath.Join(root, "node-next.json")); !os.IsNotExist(err) {
		t.Fatal("consumed preparation remained a second input")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.Config.SigningKeyFile != next.SigningKeyFile || !restarted.Writable() {
		t.Fatal("restart did not consume the certified prepared key")
	}
	if _, err = peerTLSConfig(restarted.Config); err != nil {
		t.Fatal("certified signer cannot authenticate private transport", err)
	}
	if after, err := restarted.Authority.Material(accepted.MaterialID); err != nil || string(after) != string(original) {
		t.Fatal("rotation changed authenticated history")
	}
	submitAuthority(t, restarted, authorityService("demo-after-rotation", "demo-after"))
	proof, err := restarted.Authority.ControlProof()
	if err != nil || len(proof.Successors) != 1 {
		t.Fatal("restarted member proof lost its original certificate")
	}
	if _, err = VerifyControlProof(proof, config.NetworkID, config.GenesisID); err != nil {
		t.Fatal(err)
	}
}

func TestControlMemberLearnsRotatedPeerKeyThroughProofOnlyTLS(t *testing.T) {
	f := newMaterialFixture(t)
	peers, ca := membershipTLSPeersWithCA(t, f, 1)
	a, b := peers[0].server.Runtime, peers[1].server.Runtime
	oldChannel := peers[0].channel
	next := a.Config
	files, _, _ := testTransportIdentity(t, t.TempDir(), next.ControlID, 95, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	next.SigningKeyFile, next.PeerTLS = files.KeyFile, &files
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := PrepareControlKey(ctx, a.Authority.root, next); err != nil {
		t.Fatal(err)
	}
	member, _ := next.Member()
	if _, err := a.ChangeControl(ctx, ControlChangeRequest{Schema: 3, BaseConfigID: f.configID, Operation: "rotate", TargetNodeID: next.NodeID, PublicKey: member.PublicKey}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if proof, _ := b.Authority.ControlProof(); len(proof.Successors) != 0 {
		t.Fatal("fixture did not lose the certificate notification")
	}
	if err := ActivatePreparedControlKey(ctx, a.Authority.root); err != nil {
		t.Fatal(err)
	}
	peers[0].close()
	updated, err := OpenRuntime(a.Authority.root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer updated.Close()
	channel, err := OpenPrivateChannel(oldChannel.config, updated.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	channel.AttachAuthority(updated.Authority)
	updated.Channel = channel
	server := &Server{Runtime: updated, Config: updated.Config, Channel: channel}
	h := &http.Server{Handler: server.Handler(), ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
	defer h.Close()
	go h.Serve(channel.ControlListener())
	if _, err := b.peerBody(ctx, f.members[0], http.MethodGet, "/internal/frontier", nil); err == nil {
		t.Fatal("ordinary TLS accepted a key not in its authenticated member table")
	}
	proofClient, err := b.Channel.peerClientFor(next.NodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := proofClient.Get("https://control.loom/internal/frontier"); err == nil {
		response.Body.Close()
		t.Fatal("proof transport carried a privileged request")
	}
	if err := b.reconcileControlProof(ctx, f.members[0]); err != nil {
		t.Fatal("stale member could not learn rotated peer proof", err)
	}
	if _, err := b.peerBody(ctx, member, http.MethodGet, "/internal/frontier", nil); err != nil {
		t.Fatal("normal member TLS did not consume the verified new key", err)
	}
}
