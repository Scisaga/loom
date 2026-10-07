package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var errControlWithdrawalPending = errors.New("stopped retained signer requires an effective peer withdrawal before member activation")

func (a *Authority) ControlProof() (ControlProof, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.blocked != nil {
		return ControlProof{}, a.blocked
	}
	body, err := CanonicalEncode(ControlProof{Genesis: a.genesis, Successors: a.certificates})
	if err != nil {
		return ControlProof{}, err
	}
	var proof ControlProof
	err = DecodeCanonical(body, &proof, ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20})
	return proof, err
}

func (a *Authority) historicalMember(controlID, publicKey string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.blocked != nil {
		return false
	}
	initial, ok := a.genesis.Payload.(Genesis)
	if !ok {
		return false
	}
	if member, found := proofMember(initial.ControlConfig, controlID); found && member.PublicKey == publicKey {
		return true
	}
	for _, certificate := range a.certificates {
		if member, found := proofMember(certificate.Config, controlID); found && member.PublicKey == publicKey {
			return true
		}
	}
	return false
}

// Revocation must remain consumable after privileged fact reads have ended.
// This path can only stop this local key; retained/new signers still need every
// original proposal fact through AcceptControlCertificate or initialization.
func (a *Authority) AcceptStoppingProof(ctx context.Context, proof ControlProof, local NodeConfig) error {
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return err
	}
	previous := ControlProof{Genesis: a.genesis, Successors: a.certificates}
	current, err := VerifyControlProofExtension(proof, previous, local.NetworkID, local.GenesisID)
	if err != nil {
		return err
	}
	if _, err = activeLocalMember(local, current); err == nil {
		return errors.New("stopping proof cannot activate or retain a signing key without original facts")
	}
	if _, err = activeLocalMember(local, a.projection.Config); err != nil {
		return err
	}
	// Persist the local signing stop before writing a multi-certificate chain.
	// A crash after an intermediate table must not let this old key sign again.
	member, _ := activeLocalMember(local, a.projection.Config)
	key, _ := KeyID(member.PublicKey)
	if _, stopped, err := a.stoppedOrdinaryKey(key); err != nil {
		return err
	} else if !stopped {
		dir, err := protectedMemberDirectory(a.root, "control-retired")
		if err != nil {
			return err
		}
		body, err := CanonicalEncode(frontierFor(a.projection.Frontier, key))
		if err != nil {
			return err
		}
		if err = putControlBytes(filepath.Join(dir, strings.TrimPrefix(key, "sha256:")+".json"), body); err != nil {
			return err
		}
	}
	dir, err := protectedMemberDirectory(a.root, "control-certificates")
	if err != nil {
		return err
	}
	for _, cert := range proof.Successors[len(a.certificates):] {
		body, err := CanonicalEncode(cert)
		if err != nil {
			return err
		}
		if err = putControlBytes(filepath.Join(dir, strings.TrimPrefix(endpointByteDigest(body), "sha256:")+".json"), body); err != nil {
			return err
		}
	}
	return a.reloadLocked()
}

func (a *Authority) readControlCertificates(genesis Material) ([]ControlCertificate, error) {
	dir := filepath.Join(a.root, "control-certificates")
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return []ControlCertificate{}, nil
	}
	if err := validateControlRoot(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	byBase := map[string][]ControlCertificate{}
	for _, entry := range entries {
		body, err := readProtectedControlFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if entry.Name() != strings.TrimPrefix(endpointByteDigest(body), "sha256:")+".json" {
			return nil, errors.New("member certificate filename differs from original bytes")
		}
		var cert ControlCertificate
		if err = DecodeCanonical(body, &cert, ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
			return nil, err
		}
		byBase[cert.Config.PreviousConfigID] = append(byBase[cert.Config.PreviousConfigID], cert)
	}
	base := genesis.Payload.(Genesis).ControlConfig
	chain := []ControlCertificate{}
	for {
		id, _ := ConfigID(base)
		values := byBase[id]
		if len(values) == 0 {
			break
		}
		selected := ""
		for _, cert := range values {
			// Each original certificate must stand on its own. Conflicting valid
			// majorities block all authority, beyond the member-only vote gate.
			verifier, err := newControlSuccessorVerifier(base)
			if err != nil {
				return nil, err
			}
			if err = verifier.verifyCertificate(cert); err != nil {
				return nil, err
			}
			next, _ := ConfigID(cert.Config)
			if selected != "" && selected != next {
				return nil, errControlCertificatesConflict
			}
			selected = next
		}
		chain = append(chain, values[0])
		if _, err = verifyControlSuccessors(genesis.Payload.(Genesis).ControlConfig, chain); err != nil {
			return nil, err
		}
		base = values[0].Config
		delete(byBase, id)
	}
	if len(byBase) != 0 {
		return nil, errors.New("saved member certificate has no verified predecessor")
	}
	return chain, nil
}

// The member vote checks original facts as well as the public certificate. A
// safely inherited value retains its original qualification and fixed seal;
// later ordinary conflicts cannot change an already selected member value.
func (a *Authority) verifyMemberProposalMaterials(config ControlConfig, inherited bool, now time.Time) error {
	graph, err := newMaterialGraph(a.genesis, a.certificates, a.materials)
	if err != nil {
		return err
	}
	for _, seal := range config.SealedKeys {
		if seal.Sequence == 0 {
			continue
		}
		m, found := graph.facts[seal.TipMaterialID]
		if !found {
			return ErrMissingDependencies
		}
		if m.IssuerKeyID != seal.KeyID || m.Sequence != seal.Sequence {
			return errors.New("sealed prefix does not match its original chain")
		}
		if err = graph.validate(seal.TipMaterialID); err != nil {
			return err
		}
	}
	if config.Join == nil && config.Invalidation == nil {
		return nil
	}
	var transaction, inviteID, bindingID string
	if config.Join != nil {
		transaction, inviteID, bindingID = config.Join.TransactionID, config.Join.InviteMaterialID, config.Join.BindingMaterialID
	} else {
		transaction, inviteID, bindingID = config.Invalidation.TransactionID, config.Invalidation.InviteMaterialID, config.Invalidation.BindingMaterialID
	}
	for _, id := range []string{inviteID, bindingID} {
		if err = graph.validate(id); err != nil {
			return err
		}
	}
	invite, ok := graph.facts[inviteID].Payload.(Invite)
	if !ok || invite.ID != transaction || invite.DeviceID != config.TargetNodeID || !containsString(invite.Responsibilities, "control") {
		return errors.New("member proposal has no matching control invitation")
	}
	binding, ok := graph.facts[bindingID].Payload.(EnrollmentBind)
	if !ok || binding.TransactionID != transaction || binding.InviteMaterialID != inviteID || binding.Platform != "linux" {
		return errors.New("member proposal has no exact Linux claim binding")
	}
	if !inherited {
		target, found := a.projection.CurrentTarget("invite", transaction)
		if !found || target.Deleted || config.Join != nil && target.Conflicted {
			return errors.New("member transaction is terminated or conflicted")
		}
		if config.Join != nil {
			for _, other := range a.projection.Invites {
				state, _ := a.projection.CurrentTarget("invite", other.ID)
				if other.ID != transaction && other.DeviceID == config.TargetNodeID && !state.Deleted {
					return errors.New("member node has a conflicting enrollment")
				}
			}
			if now.UnixMilli() >= invite.ExpiresAt {
				return errors.New("member invitation expired before the first vote")
			}
		}
		if config.Invalidation != nil && config.Invalidation.Reason == "expired" && now.UnixMilli() < invite.ExpiresAt {
			return errors.New("member transaction has not reached its signed expiry")
		}
	}
	if config.Join == nil {
		return nil
	}
	join := config.Join
	if binding.DevicePublicKey != join.DevicePublicKey {
		return errors.New("member key differs from its proven claim")
	}
	ordinary := len(invite.Responsibilities) > 1
	if ordinary != (join.AuthorizationMaterialID != "") {
		return errors.New("member addition must bind exactly the invited ordinary authorization")
	}
	if !ordinary {
		return nil
	}
	if err = graph.validate(join.AuthorizationMaterialID); err != nil {
		return err
	}
	fact := graph.facts[join.AuthorizationMaterialID]
	authorization, ok := fact.Payload.(DeviceAuthorization)
	if !ok || fact.Operation != "device.join" || authorization.ID != invite.DeviceID || authorization.TransactionID != transaction || authorization.DevicePublicKey != binding.DevicePublicKey || authorization.BindingMaterialID != bindingID || authorization.InviteMaterialID != inviteID {
		return errors.New("member addition has no matching original conditional authorization")
	}
	return nil
}

func (a *Authority) AcceptControlCertificate(ctx context.Context, body []byte, local NodeConfig) error {
	var cert ControlCertificate
	if err := DecodeCanonical(body, &cert, ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return err
	}
	base := a.genesis.Payload.(Genesis).ControlConfig
	previous := []ControlCertificate{}
	for {
		id, _ := ConfigID(base)
		if id == cert.Config.PreviousConfigID {
			break
		}
		if len(previous) >= len(a.certificates) {
			return errors.New("member certificate predecessor is unknown")
		}
		next := a.certificates[len(previous)]
		previous = append(previous, next)
		base = next.Config
	}
	next := append(append([]ControlCertificate{}, previous...), cert)
	if _, err = verifyControlSuccessors(a.genesis.Payload.(Genesis).ControlConfig, next); err != nil {
		return err
	}
	conflicting := false
	if len(previous) < len(a.certificates) {
		knownID, _ := ConfigID(a.certificates[len(previous)].Config)
		receivedID, _ := ConfigID(cert.Config)
		conflicting = knownID != receivedID
	}
	// A valid opposing majority is sufficient evidence to stop all writes.
	// Missing private join originals must not hide the signed conflict.
	if !conflicting {
		if err = a.verifyMemberProposalMaterials(cert.Config, true, time.Time{}); err != nil {
			return err
		}
	}
	current := cert.Config.PreviousConfigID == a.projection.ControlConfigID
	if current {
		if err = a.preserveRetiredWithdrawals(ctx, cert, next, local); err != nil {
			return err
		}
		if _, err = Project(a.genesis, next, a.materials); err != nil {
			return err
		}
	}
	dir, err := protectedMemberDirectory(a.root, "control-certificates")
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	name := strings.TrimPrefix(endpointByteDigest(body), "sha256:") + ".json"
	if err = putControlBytes(filepath.Join(dir, name), body); err != nil {
		return err
	}
	// A conflicting signed successor remains on disk and stops every future
	// reload; it is never selected by filename ordering.
	return a.reloadLocked()
}

func (a *Authority) preserveRetiredWithdrawals(ctx context.Context, cert ControlCertificate, next []ControlCertificate, local NodeConfig) error {
	member, err := activeLocalMember(local, cert.Config)
	if err != nil {
		return nil
	} // A removed signer cannot re-sign or serve new views.
	if _, err = activeLocalMember(local, a.projection.Config); err != nil {
		return err
	}
	key, _ := KeyID(member.PublicKey)
	seals := map[string]ControlSealedKey{}
	for _, seal := range cert.Config.SealedKeys {
		seals[seal.KeyID] = seal
	}
	graph, err := newMaterialGraph(a.genesis, a.certificates, a.materials)
	if err != nil {
		return err
	}
	configID, _ := ConfigID(cert.Config)
	for _, id := range graph.ordered {
		original := graph.facts[id]
		seal, found := seals[original.IssuerKeyID]
		if !found || original.Sequence <= seal.Sequence || !isWithdrawal(original.Operation) || graph.validate(id) != nil {
			continue
		}
		// A retained peer may already have supplied an independently effective
		// withdrawal. A voluntarily stopped local key must reuse that result,
		// never resume ordinary signing merely to activate a safe successor.
		projection, err := Project(a.genesis, next, a.materials)
		if err != nil {
			return err
		}
		if target, found := projection.CurrentTarget(original.TargetKind, original.TargetID); found && target.Deleted && !target.Conflicted {
			continue
		}
		if _, stopped, err := a.stoppedOrdinaryKey(key); err != nil {
			return err
		} else if stopped {
			return errControlWithdrawalPending
		}
		request := "member-withdraw-" + strings.TrimPrefix(endpointByteDigest([]byte(configID+"\x00"+id)), "sha256:")
		// A retry after interruption must reuse its original operation, including
		// dependencies, instead of manufacturing a second replacement fact.
		var op Operation
		for _, m := range a.materials {
			if m.IssuerKeyID == key && m.RequestID == request {
				op, err = m.OperationRequest()
				if err != nil {
					return err
				}
				break
			}
		}
		if op.RequestID == "" {
			dependencies := []string{id}
			if target, found := a.projection.CurrentTarget(original.TargetKind, original.TargetID); found {
				for _, targetID := range target.MaterialIDs {
					if targetID != id {
						dependencies = append(dependencies, targetID)
					}
				}
			}
			sort.Strings(dependencies)
			op = Operation{Schema: 3, RequestID: request, Operation: original.Operation, TargetKind: original.TargetKind, TargetID: original.TargetID, Dependencies: dependencies, Payload: original.Payload}
		}
		if _, err = a.submitOperationLocked(ctx, op, local); err != nil {
			return err
		}
		projection, err = Project(a.genesis, next, a.materials)
		if err != nil {
			return err
		}
		target, found := projection.CurrentTarget(original.TargetKind, original.TargetID)
		if !found || !target.Deleted || target.Conflicted {
			return errors.New("retired withdrawal replacement is not effective; certificate was not activated")
		}
	}
	return nil
}
