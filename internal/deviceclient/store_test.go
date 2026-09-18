package deviceclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"loom/internal/control"
)

func signTestHead(t *testing.T, head control.GovernanceHead, memberID string, private ed25519.PrivateKey) control.GovernanceHead {
	t.Helper()
	head.Signatures = nil
	body, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte("loom-certified-head-v1\n"), body...))
	head.Signatures = []control.HeadSignature{{MemberID: memberID, Value: base64.RawURLEncoding.EncodeToString(signature)}}
	return head
}

func singleViewRoot(t *testing.T, view control.DeviceView) string {
	t.Helper()
	digest, err := control.DeviceViewDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	leaf := sha256.Sum256(append([]byte("loom-device-view-node-v1\nleaf\n"), []byte(digest)...))
	return "sha256:" + hex.EncodeToString(leaf[:])
}

func TestCertifiedLKGIsAtomicRestartableAndCannotRollBack(t *testing.T) {
	memberPublic, memberPrivate, _ := ed25519.GenerateKey(rand.Reader)
	memberID := "demo-control"
	config := control.StableConfig([]control.Member{{ID: memberID, Node: "demo-node",
		PublicKey: base64.RawURLEncoding.EncodeToString(memberPublic)}})
	digest := "sha256:" + strings.Repeat("0", 64)
	endpoint := control.EndpointReference{EndpointID: "demo-entry", Generation: 1, Transport: "tls_tunnel",
		Address: "192.0.2.1:443", ServerName: "demo.example", SPKISHA256: strings.Repeat("1", 64), State: "serving"}
	capability, err := control.SignBootstrapCapability(control.BootstrapCapability{Schema: 1, TransactionID: "demo-transaction",
		IssuedHead: digest, ConfigMaterial: digest, ControlConfig: config, ExpiresAt: "2030-01-01T00:00:00Z",
		Actions: []string{"claim", "resume"}, Endpoints: []control.EndpointReference{endpoint}, ConstraintDigest: digest,
		IssuerMemberID: memberID}, control.NodeConfig{MemberID: memberID,
		IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(memberPrivate)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "device", "state.json")
	store, err := Open(path, control.BootstrapInvite{Schema: 1, Capability: capability})
	if err != nil {
		t.Fatal(err)
	}
	view := control.DeviceView{Schema: 1, DeviceID: "demo-device", Name: "Demo device", Platform: "linux",
		Roles: []string{"access"}, DevicePublicKey: store.PublicKey(), Floor: 7,
		Endpoints: []control.EndpointReference{endpoint}, Routes: []control.RouteCandidate{}}
	head := control.GovernanceHead{Schema: 1, Index: 7, LogDigest: digest, ProjectionDigest: digest,
		DeviceViewsDigest: singleViewRoot(t, view), ConfigMaterial: digest}
	head = signTestHead(t, head, memberID, memberPrivate)
	envelope := control.DeviceViewEnvelope{Schema: 1, View: view, Head: head, ControlConfig: config,
		Proof: control.DeviceViewProof{Index: 0, Size: 1, Siblings: []string{}}}
	if err := store.SaveLKG(envelope); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.LKG(), &envelope) {
		t.Fatal("certified LKG changed across restart")
	}
	rollback := envelope
	rollback.Head.Index = 6
	rollback.View.Floor = 6
	rollback.Head.DeviceViewsDigest = singleViewRoot(t, rollback.View)
	rollback.Head = signTestHead(t, rollback.Head, memberID, memberPrivate)
	if err := reopened.SaveLKG(rollback); err == nil {
		t.Fatal("device accepted a certified view below its persisted floor")
	}
	if !reflect.DeepEqual(reopened.LKG(), &envelope) {
		t.Fatal("failed rollback changed the certified LKG")
	}
}
