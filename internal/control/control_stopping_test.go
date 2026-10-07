package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestControlMemberStoppingProofDoesNotNeedRevokedSecretReads(t *testing.T) {
	f := newSuccessorFixture(t, 3)
	keyID, _ := KeyID(f.base.Members[0].PublicKey)
	genesis, err := SignMaterial(Material{Schema: 3, NetworkID: f.base.NetworkID, IssuerControlID: f.base.Members[0].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: Genesis{ControlConfig: f.base, NetworkIntent: EmptyNetworkIntent(), AdminCertificates: []AdminCertificate{}}}, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	authorities, configs := materialAuthorities(t, materialFixture{genesis: genesis, keys: f.keys, members: f.base.Members, configID: f.baseID})
	added := f.addition(t, 1)
	newKey := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(newKey.Public().(ed25519.PublicKey))
	added.Members[3].PublicKey, added.Join.DevicePublicKey = public, public
	first := ControlCertificate{Config: added, Round: added.OriginPromises[0].Round, Promises: added.OriginPromises, Votes: []ControlVote{f.vote(t, 0, 1, added), f.vote(t, 1, 1, added)}}
	id, _ := ConfigID(added)
	next := successorFixture{base: added, baseID: id, keys: append(append([]ed25519.PrivateKey{}, f.keys...), newKey)}
	promises := []ControlPromise{next.promise(t, 0, 1, []ControlVoteHistoryItem{}), next.promise(t, 1, 1, []ControlVoteHistoryItem{}), next.promise(t, 3, 1, []ControlVoteHistoryItem{})}
	retiredKey, _ := KeyID(f.base.Members[2].PublicKey)
	removed := ControlConfig{Schema: 3, NetworkID: f.base.NetworkID, PreviousConfigID: id, Operation: "revoke", TargetNodeID: f.base.Members[2].NodeID, Members: []Member{added.Members[0], added.Members[1], added.Members[3]}, SealedKeys: []ControlSealedKey{{KeyID: retiredKey, TipMaterialID: emptyMaterialTip()}}, OriginPromises: promises}
	second := ControlCertificate{Config: removed, Round: promises[0].Round, Promises: promises, Votes: []ControlVote{next.vote(t, 0, 1, removed), next.vote(t, 1, 1, removed), next.vote(t, 3, 1, removed)}}
	proof := ControlProof{Genesis: genesis, Successors: []ControlCertificate{first, second}}
	if _, err = VerifyControlProof(proof, configs[2].NetworkID, configs[2].GenesisID); err != nil {
		t.Fatal(err)
	}
	body, _ := CanonicalEncode(first)
	if err = authorities[2].AcceptControlCertificate(context.Background(), body, configs[2]); err == nil {
		t.Fatal("ordinary certificate activation skipped missing join originals")
	}
	if err = authorities[0].AcceptStoppingProof(context.Background(), proof, configs[0]); err == nil {
		t.Fatal("retained member bypassed its required original facts")
	}
	if err = authorities[2].AcceptStoppingProof(context.Background(), proof, configs[2]); err != nil {
		t.Fatal("removed member cannot learn its stopping evidence", err)
	}
	restarted, err := OpenAuthority(authorities[2].root)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.signingReady(configs[2]) {
		t.Fatal("removed key regained signing after restart")
	}
	if _, stopped, err := restarted.stoppedOrdinaryKey(retiredKey); err != nil || !stopped {
		t.Fatal("multi-table stopping proof did not retain durable signing stop")
	}
	actual, err := restarted.ControlProof()
	if err != nil || len(actual.Successors) != 2 {
		t.Fatal("original stop certificates were not retained")
	}
}
