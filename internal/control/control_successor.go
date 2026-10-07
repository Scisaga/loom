package control

import (
	"errors"
	"reflect"
	"sort"
)

var errControlRoundAmbiguous = errors.New("highest possible control round has conflicting proposals")
var errControlCertificatesConflict = errors.New("conflicting control successors have majority votes")
var errControlDoubleVote = errors.New("member signed different proposals in the same round; member writes are blocked")

// A disposable verifier for one base table. The cache holds no signing state.
type controlSuccessorVerifier struct {
	base    ControlConfig
	id      string
	checked map[string]bool
	votes   map[string]map[ControlRound]string
}

func newControlSuccessorVerifier(base ControlConfig) (*controlSuccessorVerifier, error) {
	id, err := ConfigID(base)
	if err != nil {
		return nil, err
	}
	return &controlSuccessorVerifier{base: base, id: id, checked: map[string]bool{}, votes: map[string]map[ControlRound]string{}}, nil
}

// Counts each exact round separately. Missing replies can contain additional
// votes in any old round; votes from different rounds are never combined.
func chooseControlProposal(base ControlConfig, promises []ControlPromise) (*ControlConfig, bool, error) {
	majority := len(base.Members)/2 + 1
	if len(promises) < majority || len(promises) > len(base.Members) {
		return nil, false, errors.New("member promises do not form an old-table majority")
	}
	type votesFor struct {
		round    ControlRound
		id       string
		proposal ControlConfig
		voters   map[string]bool
	}
	groups := map[ControlRound]map[string]*votesFor{}
	for _, promise := range promises {
		for _, item := range promise.Votes {
			vote := item.Vote
			if groups[vote.Round] == nil {
				groups[vote.Round] = map[string]*votesFor{}
			}
			group := groups[vote.Round][vote.ProposalID]
			if group == nil {
				group = &votesFor{vote.Round, vote.ProposalID, item.Proposal, map[string]bool{}}
				groups[vote.Round][vote.ProposalID] = group
			}
			group.voters[vote.VoterControlID] = true
		}
	}
	var chosen, possible *votesFor
	ambiguous := false
	for _, round := range groups {
		for _, group := range round {
			if len(group.voters) >= majority {
				if chosen != nil && chosen.id != group.id {
					return nil, false, errControlCertificatesConflict
				}
				chosen = group
			}
			if len(group.voters)+len(base.Members)-len(promises) < majority {
				continue
			}
			if possible == nil || compareControlRound(group.round, possible.round) > 0 {
				possible = group
				ambiguous = false
			} else if compareControlRound(group.round, possible.round) == 0 && group.id != possible.id {
				ambiguous = true
			}
		}
	}
	if chosen != nil {
		v := chosen.proposal
		return &v, true, nil
	}
	if ambiguous {
		return nil, false, errControlRoundAmbiguous
	}
	if possible != nil {
		v := possible.proposal
		return &v, false, nil
	}
	return nil, false, nil
}

func (v *controlSuccessorVerifier) verifyVote(vote ControlVote, proposal ControlConfig) error {
	if vote.Validate() != nil || vote.NetworkID != v.base.NetworkID || vote.BaseConfigID != v.id {
		return errors.New("control vote has another base")
	}
	member, ok := proofMember(v.base, vote.VoterControlID)
	if !ok {
		return errors.New("control voter is outside the old table")
	}
	if _, ok := proofMember(v.base, vote.Round.ProposerControlID); !ok {
		return errors.New("control round proposer is outside the old table")
	}
	id, err := ConfigID(proposal)
	if err != nil || id != vote.ProposalID || compareControlRound(proposal.OriginPromises[0].Round, vote.Round) > 0 {
		return errors.New("control vote differs from the complete proposal")
	}
	if err := verifyContractSignature("loom-control-vote-v3\x00", unsignedControlVote(vote), vote.Signature, member.PublicKey); err != nil {
		return err
	}
	if v.votes[vote.VoterControlID] == nil {
		v.votes[vote.VoterControlID] = map[ControlRound]string{}
	}
	if previous := v.votes[vote.VoterControlID][vote.Round]; previous != "" && previous != vote.ProposalID {
		return errControlDoubleVote
	}
	v.votes[vote.VoterControlID][vote.Round] = vote.ProposalID
	return nil
}

func (v *controlSuccessorVerifier) verifyPromises(promises []ControlPromise, round ControlRound) error {
	if len(promises) < len(v.base.Members)/2+1 || len(promises) > len(v.base.Members) {
		return errors.New("control promises lack an old-table majority")
	}
	if _, ok := proofMember(v.base, round.ProposerControlID); !ok {
		return errors.New("control promise round has no member proposer")
	}
	for i, promise := range promises {
		if compareControlRound(promise.Round, round) != 0 || i > 0 && promises[i-1].ResponderControlID >= promise.ResponderControlID {
			return errors.New("control promise set is invalid")
		}
		if err := v.verifyPromise(promise); err != nil {
			return err
		}
	}
	return nil
}

func (v *controlSuccessorVerifier) verifyPromise(promise ControlPromise) error {
	keys := []string{}
	for _, member := range v.base.Members {
		key, _ := KeyID(member.PublicKey)
		keys = append(keys, key)
	}
	sort.Strings(keys)
	member, found := proofMember(v.base, promise.ResponderControlID)
	_, proposer := proofMember(v.base, promise.Round.ProposerControlID)
	if promise.Validate() != nil || !found || !proposer || promise.NetworkID != v.base.NetworkID || promise.BaseConfigID != v.id || len(promise.Prefixes) != len(keys) {
		return errors.New("control promise set is invalid")
	}
	for j, prefix := range promise.Prefixes {
		if prefix.KeyID != keys[j] {
			return errors.New("control promise omits or substitutes a member prefix")
		}
	}
	if err := verifyContractSignature("loom-control-promise-v3\x00", unsignedControlPromise(promise), promise.Signature, member.PublicKey); err != nil {
		return err
	}
	for _, item := range promise.Votes {
		if err := v.verifyProposal(item.Proposal); err != nil {
			return err
		}
		if err := v.verifyVote(item.Vote, item.Proposal); err != nil {
			return err
		}
	}
	return nil
}

func (v *controlSuccessorVerifier) verifyProposal(config ControlConfig) error {
	id, err := ConfigID(config)
	if err != nil {
		return err
	}
	if v.checked[id] {
		return nil
	}
	if config.Operation == "genesis" || config.NetworkID != v.base.NetworkID || config.PreviousConfigID != v.id {
		return errors.New("control proposal has another base")
	}
	if err = v.verifyDifference(config); err != nil {
		return err
	}
	round := config.OriginPromises[0].Round
	if err = v.verifyPromises(config.OriginPromises, round); err != nil {
		return err
	}
	forced, _, err := chooseControlProposal(v.base, config.OriginPromises)
	if err != nil {
		return err
	}
	if forced != nil {
		return errors.New("new control proposal replaced a previously possible value")
	}
	if err = v.verifySeals(config); err != nil {
		return err
	}
	v.checked[id] = true
	return nil
}

func (v *controlSuccessorVerifier) verifyDifference(config ControlConfig) error {
	old := map[string]Member{}
	next := map[string]Member{}
	for _, member := range v.base.Members {
		old[member.NodeID] = member
	}
	for _, member := range config.Members {
		next[member.NodeID] = member
	}
	before, existed := old[config.TargetNodeID]
	after, exists := next[config.TargetNodeID]
	switch config.Operation {
	case "add":
		if existed || !exists || config.Join == nil || after.ControlID != after.NodeID || after.PublicKey != config.Join.DevicePublicKey || len(next) != len(old)+1 {
			return errors.New("control addition has no exact new bound member")
		}
	case "resign", "revoke", "delete":
		if !existed || exists || len(next) != len(old)-1 {
			return errors.New("control removal does not remove exactly its target")
		}
	case "rotate":
		if !existed || !exists || before.ControlID != after.ControlID || before.PublicKey == after.PublicKey || len(next) != len(old) {
			return errors.New("control rotation does not replace exactly its target key")
		}
	case "invalidate_join":
		if !reflect.DeepEqual(v.base.Members, config.Members) {
			return errors.New("join invalidation changed the member table")
		}
	default:
		return errors.New("unknown control successor")
	}
	for node, member := range old {
		if node != config.TargetNodeID && next[node] != member {
			return errors.New("control successor changed an unrelated member")
		}
	}
	for node, member := range next {
		if node != config.TargetNodeID && old[node] != member {
			return errors.New("control successor added an unrelated member")
		}
	}
	if config.Operation == "resign" || config.Operation == "rotate" {
		if config.OriginPromises[0].Round.ProposerControlID != before.ControlID {
			return errors.New("voluntary retirement must be proposed by its owning member")
		}
		key, _ := KeyID(before.PublicKey)
		found := false
		for _, promise := range config.OriginPromises {
			if promise.ResponderControlID != before.ControlID {
				continue
			}
			for _, prefix := range promise.Prefixes {
				if prefix.KeyID == key && len(config.SealedKeys) == 1 && prefix == config.SealedKeys[0] {
					found = true
				}
			}
		}
		if !found {
			return errors.New("voluntary retirement lacks the owning member's exact final prefix")
		}
	}
	return nil
}

func (v *controlSuccessorVerifier) verifySeals(config ControlConfig) error {
	var retired []string
	for _, member := range v.base.Members {
		retained := false
		for _, next := range config.Members {
			if next.ControlID == member.ControlID && next.PublicKey == member.PublicKey {
				retained = true
			}
		}
		if !retained {
			id, _ := KeyID(member.PublicKey)
			retired = append(retired, id)
		}
	}
	sort.Strings(retired)
	if len(retired) != len(config.SealedKeys) {
		return errors.New("control proposal must seal exactly the retired keys")
	}
	for i, key := range retired {
		maximum := ControlSealedKey{KeyID: key, TipMaterialID: emptyMaterialTip()}
		tips := map[U64]string{}
		for _, promise := range config.OriginPromises {
			for _, prefix := range promise.Prefixes {
				if prefix.KeyID == key {
					if tip, found := tips[prefix.Sequence]; found && tip != prefix.TipMaterialID {
						return errors.New("control sealing reports expose a fork")
					}
					tips[prefix.Sequence] = prefix.TipMaterialID
					if prefix.Sequence > maximum.Sequence {
						maximum = prefix
					}
				}
			}
		}
		if config.SealedKeys[i] != maximum {
			return errors.New("control sealed prefix is not the original maximum")
		}
	}
	return nil
}

func (v *controlSuccessorVerifier) verifyCertificate(cert ControlCertificate) error {
	if cert.Validate() != nil {
		return errors.New("control certificate shape is invalid")
	}
	if err := v.verifyVotingValue(cert.Config, cert.Round, cert.Promises); err != nil {
		return err
	}
	if len(cert.Votes) < len(v.base.Members)/2+1 || len(cert.Votes) > len(v.base.Members) {
		return errors.New("control certificate lacks same-round majority votes")
	}
	for _, vote := range cert.Votes {
		if err := v.verifyVote(vote, cert.Config); err != nil {
			return err
		}
	}
	return nil
}

func (v *controlSuccessorVerifier) verifyVotingValue(config ControlConfig, round ControlRound, promises []ControlPromise) error {
	if err := v.verifyProposal(config); err != nil {
		return err
	}
	if err := v.verifyPromises(promises, round); err != nil {
		return err
	}
	forced, _, err := chooseControlProposal(v.base, promises)
	if err != nil {
		return err
	}
	id, _ := ConfigID(config)
	if forced != nil {
		wanted, _ := ConfigID(*forced)
		if wanted != id {
			return errors.New("control certificate did not inherit the required value")
		}
	} else {
		if compareControlRound(config.OriginPromises[0].Round, round) != 0 {
			return errors.New("control certificate reused an unselected old proposal")
		}
		for _, origin := range config.OriginPromises {
			found := false
			for _, promise := range promises {
				if reflect.DeepEqual(origin, promise) {
					found = true
				}
			}
			if !found {
				return errors.New("control certificate substituted an original same-round promise")
			}
		}
	}
	return nil
}

func verifyControlSuccessors(base ControlConfig, certificates []ControlCertificate) (ControlConfig, error) {
	retired := map[string]bool{}
	deleted := map[string]bool{}
	transactions := map[string]bool{}
	for _, cert := range certificates {
		verifier, err := newControlSuccessorVerifier(base)
		if err != nil {
			return ControlConfig{}, err
		}
		if err = verifier.verifyCertificate(cert); err != nil {
			return ControlConfig{}, err
		}
		for _, member := range cert.Config.Members {
			key, _ := KeyID(member.PublicKey)
			if retired[key] || deleted[member.NodeID] {
				return ControlConfig{}, errors.New("member successor restores a retired key or deleted node")
			}
		}
		if cert.Config.Join != nil {
			id := cert.Config.Join.TransactionID
			if transactions[id] {
				return ControlConfig{}, errors.New("control join transaction was already completed or invalidated")
			}
			transactions[id] = true
		}
		if cert.Config.Invalidation != nil {
			id := cert.Config.Invalidation.TransactionID
			if transactions[id] {
				return ControlConfig{}, errors.New("control invalidation reuses a completed transaction")
			}
			transactions[id] = true
		}
		for _, prefix := range cert.Config.SealedKeys {
			retired[prefix.KeyID] = true
		}
		if cert.Config.Operation == "delete" {
			deleted[cert.Config.TargetNodeID] = true
		}
		base = cert.Config
	}
	return base, nil
}
