package control

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"
)

// Public command parameters are not a second member value or completion store.
type ControlChangeRequest struct {
	Schema        int    `json:"schema"`
	BaseConfigID  string `json:"base_config_id"`
	Operation     string `json:"operation"`
	TargetNodeID  string `json:"target_node_id"`
	TransactionID string `json:"transaction_id,omitempty"`
	Reason        string `json:"reason,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
}

func (r ControlChangeRequest) Validate() error {
	if r.Schema != 3 || ValidateDigest(r.BaseConfigID) != nil || ValidateID(r.TargetNodeID) != nil || r.TargetNodeID == "direct" {
		return errors.New("invalid member change boundary")
	}
	switch r.Operation {
	case "add":
		if ValidateID(r.TransactionID) != nil || r.Reason != "" || r.PublicKey != "" {
			return errors.New("member add requires only its existing transaction")
		}
	case "invalidate_join":
		if ValidateID(r.TransactionID) != nil || r.Reason != "cancelled" && r.Reason != "expired" || r.PublicKey != "" {
			return errors.New("invalid member transaction termination")
		}
	case "rotate":
		if ValidatePublicKey(r.PublicKey) != nil || r.TransactionID != "" || r.Reason != "" {
			return errors.New("member rotation requires only the new public key")
		}
	case "resign", "revoke", "delete":
		if r.TransactionID != "" || r.Reason != "" || r.PublicKey != "" {
			return errors.New("member removal has unrelated fields")
		}
	default:
		return errors.New("unknown member change")
	}
	return nil
}

type ControlChangeResult struct {
	Certificate            ControlCertificate `json:"certificate"`
	RequestedChangeApplied bool               `json:"requested_change_applied"`
}

func controlChangeMatches(request ControlChangeRequest, config ControlConfig) bool {
	if request.Operation != config.Operation || request.TargetNodeID != config.TargetNodeID {
		return false
	}
	switch request.Operation {
	case "add":
		return config.Join != nil && config.Join.TransactionID == request.TransactionID
	case "invalidate_join":
		return config.Invalidation != nil && config.Invalidation.TransactionID == request.TransactionID && config.Invalidation.Reason == request.Reason
	case "rotate":
		for _, member := range config.Members {
			if member.NodeID == request.TargetNodeID {
				return member.PublicKey == request.PublicKey
			}
		}
		return false
	}
	return true
}

func (runtime *Runtime) ChangeControl(ctx context.Context, request ControlChangeRequest, now time.Time) (ControlChangeResult, error) {
	if err := request.Validate(); err != nil {
		return ControlChangeResult{}, err
	}
	proof, err := runtime.Authority.ControlProof()
	if err != nil {
		return ControlChangeResult{}, err
	}
	for _, cert := range proof.Successors {
		if cert.Config.PreviousConfigID == request.BaseConfigID {
			return ControlChangeResult{cert, controlChangeMatches(request, cert.Config)}, nil
		}
	}
	base := runtime.Authority.Snapshot().Config
	baseID, _ := ConfigID(base)
	if request.BaseConfigID != baseID {
		return ControlChangeResult{}, errors.New("member request does not name the current table")
	}
	if _, err = activeLocalMember(runtime.Config, base); err != nil {
		return ControlChangeResult{}, err
	}
	targetPresent := false
	for _, member := range base.Members {
		if member.NodeID == request.TargetNodeID {
			targetPresent = true
			if request.Operation == "rotate" && member.PublicKey == request.PublicKey {
				return ControlChangeResult{}, errors.New("rotation must change its signing key")
			}
		}
	}
	if request.Operation != "add" && request.Operation != "invalidate_join" && !targetPresent {
		return ControlChangeResult{}, errors.New("member target is not in the reviewed table")
	}
	if (request.Operation == "resign" || request.Operation == "revoke" || request.Operation == "delete") && len(base.Members) == 1 {
		return ControlChangeResult{}, errors.New("last control must admit a successor before leaving")
	}
	if request.Operation == "resign" || request.Operation == "rotate" {
		if request.TargetNodeID != runtime.Config.NodeID {
			return ControlChangeResult{}, errors.New("voluntary retirement must reach its owning member")
		}
		if request.Operation == "rotate" {
			if err = runtime.preflightControlRotation(request.PublicKey); err != nil {
				return ControlChangeResult{}, err
			}
		}
		if _, err = runtime.Authority.StopOrdinarySigning(ctx, runtime.Config); err != nil {
			return ControlChangeResult{}, err
		}
	}
	first, err := runtime.Authority.BeginControlRound(ctx, runtime.Config)
	if err != nil {
		return ControlChangeResult{}, err
	}
	if first.BaseConfigID != request.BaseConfigID {
		return ControlChangeResult{}, errors.New("member table advanced while preparing the request")
	}
	promises := []ControlPromise{first}
	type response struct {
		member  Member
		promise ControlPromise
		err     error
	}
	replies := make(chan response, len(base.Members))
	count := 0
	body, _ := CanonicalEncode(ControlPrepareRequest{Schema: 3, BaseConfigID: baseID, Round: first.Round})
	for _, member := range base.Members {
		if member.ControlID == runtime.Config.ControlID {
			continue
		}
		count++
		go func(member Member) {
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			var promise ControlPromise
			err := runtime.peerJSON(call, member, http.MethodPost, "/internal/control-prepare", body, &promise)
			replies <- response{member, promise, err}
		}(member)
	}
	for i := 0; i < count; i++ {
		reply := <-replies
		if reply.err == nil && reply.promise.ResponderControlID == reply.member.ControlID {
			promises = append(promises, reply.promise)
		}
	}
	sort.Slice(promises, func(i, j int) bool { return promises[i].ResponderControlID < promises[j].ResponderControlID })
	if err = runtime.Authority.ObserveControlPromises(ctx, promises); err != nil {
		return ControlChangeResult{}, err
	}
	verifier, err := newControlSuccessorVerifier(base)
	if err != nil {
		return ControlChangeResult{}, err
	}
	if err = verifier.verifyPromises(promises, first.Round); err != nil {
		return ControlChangeResult{}, err
	}
	selected, _, err := chooseControlProposal(base, promises)
	if err != nil {
		return ControlChangeResult{}, err
	}
	var config ControlConfig
	if selected != nil {
		config = *selected
	} else {
		if request.Operation == "add" {
			if err = runtime.Authority.prepareMemberAuthorization(ctx, request.TransactionID, runtime.Config, now); err != nil {
				return ControlChangeResult{}, err
			}
		}
		config, err = runtime.Authority.controlChangeProposal(request, base, promises)
		if err != nil {
			return ControlChangeResult{}, err
		}
	}
	// Verify the entire value and original facts locally before asking peers to
	// vote. A missing original cannot be replaced by a declaration or UI state.
	localVote, err := runtime.Authority.VoteControl(ctx, config, first.Round, promises, runtime.Config, now)
	if err != nil {
		return ControlChangeResult{}, err
	}
	votes := []ControlVote{localVote}
	type voteResponse struct {
		member Member
		vote   ControlVote
		err    error
	}
	returned := make(chan voteResponse, len(base.Members))
	voteBody, _ := CanonicalEncode(ControlVoteRequest{Schema: 3, Config: config, Round: first.Round, Promises: promises})
	for _, member := range base.Members {
		if member.ControlID == runtime.Config.ControlID {
			continue
		}
		go func(member Member) {
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var vote ControlVote
			err := runtime.peerJSON(call, member, http.MethodPost, "/internal/control-vote", voteBody, &vote)
			returned <- voteResponse{member, vote, err}
		}(member)
	}
	for i := 0; i < count; i++ {
		reply := <-returned
		if reply.err == nil && reply.vote.VoterControlID == reply.member.ControlID {
			votes = append(votes, reply.vote)
		}
	}
	sort.Slice(votes, func(i, j int) bool { return votes[i].VoterControlID < votes[j].VoterControlID })
	cert := ControlCertificate{Config: config, Round: first.Round, Promises: promises, Votes: votes}
	if err = verifier.verifyCertificate(cert); err != nil {
		return ControlChangeResult{}, err
	}
	encoded, err := CanonicalEncode(cert)
	if err != nil {
		return ControlChangeResult{}, err
	}
	if err = runtime.Authority.AcceptControlCertificate(ctx, encoded, runtime.Config); err != nil {
		return ControlChangeResult{}, err
	}
	// Current peers receive the original certificate immediately. Removed peers
	// recover a lost notification from the proof-only historical identity path.
	for _, member := range runtime.Authority.Snapshot().Config.Members {
		if member.ControlID == runtime.Config.ControlID {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, _ = runtime.peerBody(call, member, http.MethodPut, "/internal/control-proof", encoded)
		cancel()
	}
	return ControlChangeResult{cert, controlChangeMatches(request, config)}, nil
}

func (a *Authority) controlChangeProposal(request ControlChangeRequest, base ControlConfig, promises []ControlPromise) (ControlConfig, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if request.BaseConfigID != a.projection.ControlConfigID {
		return ControlConfig{}, errors.New("member table changed while collecting promises")
	}
	config := ControlConfig{Schema: 3, NetworkID: base.NetworkID, PreviousConfigID: request.BaseConfigID, Operation: request.Operation, TargetNodeID: request.TargetNodeID, Members: []Member{}, SealedKeys: []ControlSealedKey{}, OriginPromises: promises}
	for _, member := range base.Members {
		if member.NodeID != request.TargetNodeID || request.Operation == "add" || request.Operation == "invalidate_join" {
			config.Members = append(config.Members, member)
			continue
		}
		if request.Operation == "rotate" {
			member.PublicKey = request.PublicKey
			config.Members = append(config.Members, member)
		}
	}
	if request.Operation == "add" || request.Operation == "invalidate_join" {
		invite, err := a.inviteLocked(request.TransactionID)
		if request.Operation == "invalidate_join" {
			invite, err = a.inviteOriginalLocked(request.TransactionID)
		}
		if err != nil {
			return ControlConfig{}, err
		}
		inviteID, _ := MaterialID(invite)
		binding, found, err := a.bindingLocked(request.TransactionID)
		if err != nil {
			return ControlConfig{}, err
		}
		if !found {
			return ControlConfig{}, errors.New("member transaction has not claimed its identity")
		}
		bindingID, _ := MaterialID(binding)
		if request.Operation == "add" {
			value := binding.Payload.(EnrollmentBind)
			join := ControlJoinBinding{TransactionID: request.TransactionID, InviteMaterialID: inviteID, BindingMaterialID: bindingID, DevicePublicKey: value.DevicePublicKey}
			join.AuthorizationMaterialID, err = a.conditionalAuthorizationLocked(invite, binding)
			if err != nil {
				return ControlConfig{}, err
			}
			config.Join = &join
			config.Members = append(config.Members, Member{ControlID: request.TargetNodeID, NodeID: request.TargetNodeID, PublicKey: value.DevicePublicKey})
		} else {
			config.Invalidation = &ControlJoinInvalidation{TransactionID: request.TransactionID, InviteMaterialID: inviteID, BindingMaterialID: bindingID, Reason: request.Reason}
		}
	}
	sort.Slice(config.Members, func(i, j int) bool { return config.Members[i].ControlID < config.Members[j].ControlID })
	for _, member := range base.Members {
		retained := false
		for _, next := range config.Members {
			if next == member {
				retained = true
			}
		}
		if retained {
			continue
		}
		key, _ := KeyID(member.PublicKey)
		maximum := ControlSealedKey{KeyID: key, TipMaterialID: emptyMaterialTip()}
		for _, promise := range promises {
			for _, prefix := range promise.Prefixes {
				if prefix.KeyID == key && prefix.Sequence > maximum.Sequence {
					maximum = prefix
				}
			}
		}
		config.SealedKeys = append(config.SealedKeys, maximum)
	}
	sort.Slice(config.SealedKeys, func(i, j int) bool { return config.SealedKeys[i].KeyID < config.SealedKeys[j].KeyID })
	return config, config.Validate()
}

// A recovered member operation can prepare the existing conditional device.join
// from original claim facts even when the invitation's original issuer is away.
func (a *Authority) conditionalAuthorizationLocked(original, binding Material) (string, error) {
	graph, err := newMaterialGraph(a.genesis, a.certificates, a.materials)
	if err != nil {
		return "", err
	}
	invite := original.Payload.(Invite)
	claim := binding.Payload.(EnrollmentBind)
	inviteID, _ := MaterialID(original)
	bindingID, _ := MaterialID(binding)
	// ordered is the content-ID order. Incomplete, forked and sealed-out
	// originals must not win selection merely because their ID sorts first.
	for _, id := range graph.ordered {
		material := graph.facts[id]
		authorization, ok := material.Payload.(DeviceAuthorization)
		if !ok || material.Operation != "device.join" || authorization.TransactionID != invite.ID || authorization.ID != invite.DeviceID || authorization.InviteMaterialID != inviteID || authorization.BindingMaterialID != bindingID || authorization.DevicePublicKey != claim.DevicePublicKey {
			continue
		}
		if seal, found := graph.seals[material.IssuerKeyID]; found && material.Sequence > seal.Sequence {
			continue
		}
		if graph.validate(id) == nil {
			return id, nil
		}
	}
	return "", nil
}

func (a *Authority) prepareMemberAuthorization(ctx context.Context, transaction string, local NodeConfig, now time.Time) error {
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
	original, err := a.inviteLocked(transaction)
	if err != nil {
		return err
	}
	invite := original.Payload.(Invite)
	if !a.memberEnrollmentLocked(original) || !now.Before(time.UnixMilli(invite.ExpiresAt)) {
		return errors.New("new member authorization requires an unexpired control invitation")
	}
	state, err := a.enrollmentStateLocked(transaction)
	if err != nil || state != "bound" {
		return errors.New("new member authorization requires its original bound transaction")
	}
	binding, found, err := a.bindingLocked(transaction)
	if err != nil {
		return err
	}
	if !found {
		return ErrMissingDependencies
	}
	id, _ := MaterialID(original)
	dependencies, err := enrollmentPolicyDependencies(a.projection, invite, id)
	if err != nil {
		return err
	}
	_, err = a.completeBoundAuthorizationLocked(ctx, original, binding, dependencies, local)
	return err
}
