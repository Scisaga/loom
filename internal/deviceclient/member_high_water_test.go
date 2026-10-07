package deviceclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestMemberRetirementPreservesAuthenticatedHighWaterOnDisk(t *testing.T) {
	for _, platform := range []string{"linux", "android"} {
		t.Run(platform, func(t *testing.T) { testMemberRetirementHighWater(t, platform) })
	}
}

func testMemberRetirementHighWater(t *testing.T, platform string) {
	invite, envelope := schema3Fixture(t, platform)
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, platform)
	if err != nil {
		t.Fatal(err)
	}
	old := envelope(store.PublicKey(), 9, revokeView)
	if err = store.SaveLKG(old); err != nil {
		t.Fatal(err)
	}
	previousState, err := EncodeIdentityState(store.state)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(previousState)
	base := invite.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig
	baseID, _ := control.ConfigID(base)
	keys := []ed25519.PrivateKey{}
	for _, suffix := range []string{"a", "b"} {
		seed := sha256.Sum256([]byte("demo-device-control-" + suffix))
		keys = append(keys, ed25519.NewKeyFromSeed(seed[:]))
	}
	retained, _ := control.KeyID(base.Members[0].PublicKey)
	retired, _ := control.KeyID(base.Members[1].PublicKey)
	inviteID, _ := control.MaterialID(invite.Material)
	seal := control.ControlSealedKey{KeyID: retired, Sequence: 1, TipMaterialID: inviteID}
	round := control.ControlRound{Counter: 1, ProposerControlID: base.Members[0].ControlID}
	sign := func(domain string, value any, key ed25519.PrivateKey) string {
		body, err := control.CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), body...)))
	}
	promises := []control.ControlPromise{}
	for i, member := range base.Members {
		p := control.ControlPromise{Schema: 3, NetworkID: base.NetworkID, BaseConfigID: baseID, Round: round, ResponderControlID: member.ControlID, Votes: []control.ControlVoteHistoryItem{}, Prefixes: []control.ControlSealedKey{{KeyID: retained, TipMaterialID: control.EmptyMaterialChainID()}, seal}}
		sort.Slice(p.Prefixes, func(i, j int) bool { return p.Prefixes[i].KeyID < p.Prefixes[j].KeyID })
		p.Signature = sign("loom-control-promise-v3\x00", map[string]any{"schema": p.Schema, "network_id": p.NetworkID, "base_config_id": p.BaseConfigID, "round": p.Round, "responder_control_id": p.ResponderControlID, "votes": p.Votes, "prefixes": p.Prefixes}, keys[i])
		promises = append(promises, p)
	}
	config := control.ControlConfig{Schema: 3, NetworkID: base.NetworkID, PreviousConfigID: baseID, Operation: "revoke", TargetNodeID: base.Members[1].NodeID, Members: []control.Member{base.Members[0]}, SealedKeys: []control.ControlSealedKey{seal}, OriginPromises: promises}
	configID, _ := control.ConfigID(config)
	cert := control.ControlCertificate{Config: config, Round: round, Promises: promises, Votes: []control.ControlVote{}}
	for i, member := range base.Members {
		v := control.ControlVote{Schema: 3, NetworkID: base.NetworkID, BaseConfigID: baseID, Round: round, ProposalID: configID, VoterControlID: member.ControlID}
		v.Signature = sign("loom-control-vote-v3\x00", map[string]any{"schema": v.Schema, "network_id": v.NetworkID, "base_config_id": v.BaseConfigID, "round": v.Round, "proposal_id": v.ProposalID, "voter_control_id": v.VoterControlID}, keys[i])
		cert.Votes = append(cert.Votes, v)
	}
	next := envelope(store.PublicKey(), 9)
	next.ControlProof = control.ControlProof{Genesis: invite.ControlProof.Genesis, Successors: []control.ControlCertificate{cert}}
	next.FactFrontier = []control.FactFrontier{{KeyID: retained, TipMaterialID: control.EmptyMaterialChainID()}, seal}
	sort.Slice(next.FactFrontier, func(i, j int) bool { return next.FactFrontier[i].KeyID < next.FactFrontier[j].KeyID })
	next.IssuerControlID, next.IssuerKeyID = base.Members[0].ControlID, retained
	next.View.Endpoints = []control.EndpointGeneration{}
	next, err = control.SignDeviceViewEnvelope(next, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := AcceptLKG(store.state, next)
	if err != nil {
		t.Fatal(err)
	}
	review := ReviewMemberTransition(prepared, store.state)
	changedPolicy, addedRoute := false, false
	for _, change := range review.Changes {
		changedPolicy = changedPolicy || change.Kind == "policy" && change.ID == "demo-policy" && change.Change == "changed"
		addedRoute = addedRoute || change.Kind == "route" && change.Change == "added"
	}
	reviewBody, _ := json.Marshal(review)
	if !review.PossiblePermissionRestoration || !changedPolicy || !addedRoute || strings.Contains(string(reviewBody), store.state.PrivateKey) || strings.Contains(string(reviewBody), "credential") {
		t.Fatal("member review missed visible restored permissions or exposed secret fields")
	}
	if err = store.SaveLKG(next); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.PossiblePermissionRestoration() || ReviewMemberTransition(reopened.state, reopened.state).PossiblePermissionRestoration {
		t.Fatal("restart lost the warning or replayed an already reviewed transition")
	}
	found := false
	for _, prefix := range reopened.state.HighWater {
		if prefix.KeyID == retired {
			found = true
			if prefix.Sequence != 9 || prefix.TipMaterialID != old.FactFrontier[0].TipMaterialID {
				t.Fatal("certificate rewrote authenticated historical high-water")
			}
		}
	}
	if !found || reopened.state.LKG.FactFrontier[0].KeyID == "" {
		t.Fatal("missing persisted successor or original evidence")
	}
	bad := reopened.state
	bad.HighWater = append([]control.FactFrontier{}, next.FactFrontier...)
	if checkStateAdvance(bad, reopened.state) == nil {
		t.Fatal("persistent transition allowed deleting protected history under the seal exception")
	}
	if directory := os.Getenv("LOOM_MEMBER_NATIVE_FIXTURES"); directory != "" && platform == "android" {
		if !filepath.IsAbs(directory) {
			t.Fatal("native fixture output must be an absolute protected directory")
		}
		if err = os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatal("native fixture output is not protected")
		}
		nextState, err := EncodeIdentityState(reopened.state)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(nextState)
		for name, body := range map[string][]byte{"demo-member-before.json": previousState, "demo-member-after.json": nextState} {
			if err = os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
