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

var errControlRoundSuperseded = errors.New("control round is below the durable promise")

func controlRoundFile(round ControlRound) string {
	body, _ := CanonicalEncode(round)
	return strings.TrimPrefix(endpointByteDigest(body), "sha256:") + ".json"
}

func protectedMemberDirectory(root string, parts ...string) (string, error) {
	dir := root
	for _, part := range parts {
		parent := dir
		dir = filepath.Join(dir, part)
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if err := validateControlRoot(dir); err != nil {
			return "", err
		}
		if err := syncControlDirectory(parent); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (a *Authority) memberRoundDirectory(kind, base string) (string, error) {
	if kind != "control-promises" && kind != "control-votes" && kind != "control-observed-promises" || ValidateDigest(base) != nil {
		return "", errors.New("invalid member evidence coordinate")
	}
	return protectedMemberDirectory(a.root, kind, strings.TrimPrefix(base, "sha256:"))
}

// Read original values under the existing Authority lock. Highest promise and
// vote history are disposable projections of these immutable signed files.
func (a *Authority) localMemberMessages(base ControlConfig, local NodeConfig) ([]ControlPromise, []ControlVoteHistoryItem, error) {
	verifier, err := newControlSuccessorVerifier(base)
	if err != nil {
		return nil, nil, err
	}
	member, err := activeLocalMember(local, base)
	if err != nil {
		return nil, nil, err
	}
	promises := []ControlPromise{}
	votes := []ControlVoteHistoryItem{}
	for _, kind := range []string{"control-promises", "control-votes"} {
		dir, err := a.memberRoundDirectory(kind, verifier.id)
		if err != nil {
			return nil, nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range entries {
			body, err := readProtectedControlFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, nil, err
			}
			var round ControlRound
			if kind == "control-promises" {
				var p ControlPromise
				if err := DecodeCanonical(body, &p, ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
					return nil, nil, err
				}
				if p.NetworkID != base.NetworkID || p.BaseConfigID != verifier.id || p.ResponderControlID != member.ControlID {
					return nil, nil, errors.New("saved member promise has another identity")
				}
				if err := verifyContractSignature("loom-control-promise-v3\x00", unsignedControlPromise(p), p.Signature, member.PublicKey); err != nil {
					return nil, nil, err
				}
				for _, item := range p.Votes {
					if err := verifier.verifyProposal(item.Proposal); err != nil {
						return nil, nil, err
					}
					if err := verifier.verifyVote(item.Vote, item.Proposal); err != nil {
						return nil, nil, err
					}
				}
				round = p.Round
				promises = append(promises, p)
			} else {
				var item ControlVoteHistoryItem
				if err := DecodeCanonical(body, &item, ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
					return nil, nil, err
				}
				if item.Vote.VoterControlID != member.ControlID {
					return nil, nil, errors.New("saved member vote has another identity")
				}
				if err := verifier.verifyProposal(item.Proposal); err != nil {
					return nil, nil, err
				}
				if err := verifier.verifyVote(item.Vote, item.Proposal); err != nil {
					return nil, nil, err
				}
				round = item.Vote.Round
				votes = append(votes, item)
			}
			if entry.Name() != controlRoundFile(round) {
				return nil, nil, errors.New("member evidence filename does not match its round")
			}
		}
	}
	sort.Slice(promises, func(i, j int) bool { return compareControlRound(promises[i].Round, promises[j].Round) < 0 })
	sort.Slice(votes, func(i, j int) bool { return compareControlRound(votes[i].Vote.Round, votes[j].Vote.Round) < 0 })
	// Every old vote mentioned in an original promise must still exist, and each
	// promise must contain every local vote that preceded its round.
	for _, p := range promises {
		prior := []ControlVoteHistoryItem{}
		for _, item := range votes {
			if compareControlRound(item.Vote.Round, p.Round) < 0 {
				prior = append(prior, item)
			}
		}
		left, _ := CanonicalEncode(prior)
		right, _ := CanonicalEncode(p.Votes)
		if string(left) != string(right) {
			return nil, nil, errors.New("saved member promise and complete vote history disagree")
		}
	}
	for _, item := range votes {
		found := false
		for _, p := range promises {
			if compareControlRound(p.Round, item.Vote.Round) == 0 {
				found = true
			}
		}
		if !found {
			return nil, nil, errors.New("member vote has lost its durable promise")
		}
	}
	return promises, votes, nil
}

func (a *Authority) PrepareControl(ctx context.Context, baseID string, round ControlRound, local NodeConfig) (ControlPromise, error) {
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return ControlPromise{}, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return ControlPromise{}, err
	}
	return a.prepareControlLocked(ctx, baseID, round, local)
}

func (a *Authority) prepareControlLocked(ctx context.Context, baseID string, round ControlRound, local NodeConfig) (ControlPromise, error) {
	if err := a.checkMemberVoteEvidenceLocked(); err != nil {
		return ControlPromise{}, err
	}
	base := a.projection.Config
	if baseID != a.projection.ControlConfigID || round.Validate() != nil {
		return ControlPromise{}, errors.New("member prepare does not name the current table and a valid round")
	}
	if _, found := proofMember(base, round.ProposerControlID); !found {
		return ControlPromise{}, errors.New("member prepare proposer is outside current table")
	}
	promises, votes, err := a.localMemberMessages(base, local)
	if err != nil {
		return ControlPromise{}, err
	}
	if len(promises) > 0 && compareControlRound(round, promises[len(promises)-1].Round) < 0 {
		return ControlPromise{}, errControlRoundSuperseded
	}
	for _, p := range promises {
		if compareControlRound(p.Round, round) == 0 {
			return p, nil
		}
	}
	if err = ctx.Err(); err != nil {
		return ControlPromise{}, err
	}
	p := ControlPromise{Schema: 3, NetworkID: base.NetworkID, BaseConfigID: baseID, Round: round, ResponderControlID: local.ControlID, Votes: votes, Prefixes: []ControlSealedKey{}}
	for _, member := range base.Members {
		key, _ := KeyID(member.PublicKey)
		p.Prefixes = append(p.Prefixes, frontierFor(a.projection.Frontier, key))
	}
	sort.Slice(p.Prefixes, func(i, j int) bool { return p.Prefixes[i].KeyID < p.Prefixes[j].KeyID })
	key, err := local.PrivateKey()
	if err != nil {
		return ControlPromise{}, err
	}
	p.Signature, err = signControlValue("loom-control-promise-v3\x00", unsignedControlPromise(p), key)
	if err != nil {
		return ControlPromise{}, err
	}
	body, err := CanonicalEncode(p)
	if err != nil {
		return ControlPromise{}, err
	}
	dir, err := a.memberRoundDirectory("control-promises", baseID)
	if err != nil {
		return ControlPromise{}, err
	}
	if err = putControlBytes(filepath.Join(dir, controlRoundFile(round)), body); err != nil {
		return ControlPromise{}, err
	}
	return p, nil
}

func (a *Authority) BeginControlRound(ctx context.Context, local NodeConfig) (ControlPromise, error) {
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return ControlPromise{}, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return ControlPromise{}, err
	}
	promises, _, err := a.localMemberMessages(a.projection.Config, local)
	if err != nil {
		return ControlPromise{}, err
	}
	counter := U64(1)
	if len(promises) > 0 {
		counter = promises[len(promises)-1].Round.Counter + 1
		if counter == 0 {
			return ControlPromise{}, errors.New("control round counter exhausted")
		}
	}
	return a.prepareControlLocked(ctx, a.projection.ControlConfigID, ControlRound{Counter: counter, ProposerControlID: local.ControlID}, local)
}

func (a *Authority) VoteControl(ctx context.Context, config ControlConfig, round ControlRound, promises []ControlPromise, local NodeConfig, now time.Time) (ControlVote, error) {
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return ControlVote{}, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return ControlVote{}, err
	}
	if err = a.observeControlPromisesLocked(promises); err != nil {
		return ControlVote{}, err
	}
	verifier, err := newControlSuccessorVerifier(a.projection.Config)
	if err != nil {
		return ControlVote{}, err
	}
	if err = verifier.verifyVotingValue(config, round, promises); err != nil {
		return ControlVote{}, err
	}
	prior, votes, err := a.localMemberMessages(a.projection.Config, local)
	if err != nil {
		return ControlVote{}, err
	}
	id, _ := ConfigID(config)
	for _, item := range votes {
		if compareControlRound(item.Vote.Round, round) == 0 {
			if item.Vote.ProposalID != id {
				return ControlVote{}, errors.New("member already voted for another value in this round")
			}
			return item.Vote, nil
		}
	}
	if len(prior) > 0 && compareControlRound(round, prior[len(prior)-1].Round) < 0 {
		return ControlVote{}, errControlRoundSuperseded
	}
	inherited, _, err := chooseControlProposal(a.projection.Config, promises)
	if err != nil {
		return ControlVote{}, err
	}
	if err = a.verifyMemberProposalMaterials(config, inherited != nil, now); err != nil {
		return ControlVote{}, err
	}
	if (config.Operation == "resign" || config.Operation == "rotate") && config.TargetNodeID == local.NodeID {
		member, err := local.Member()
		if err != nil {
			return ControlVote{}, err
		}
		key, _ := KeyID(member.PublicKey)
		prefix, stopped, err := a.stoppedOrdinaryKey(key)
		if err != nil || !stopped || len(config.SealedKeys) != 1 || config.SealedKeys[0] != prefix {
			return ControlVote{}, errors.New("own voluntary retirement has no durable matching final prefix")
		}
	}
	if _, err = a.prepareControlLocked(ctx, verifier.id, round, local); err != nil {
		return ControlVote{}, err
	}
	key, err := local.PrivateKey()
	if err != nil {
		return ControlVote{}, err
	}
	v := ControlVote{Schema: 3, NetworkID: config.NetworkID, BaseConfigID: verifier.id, Round: round, ProposalID: id, VoterControlID: local.ControlID}
	v.Signature, err = signControlValue("loom-control-vote-v3\x00", unsignedControlVote(v), key)
	if err != nil {
		return ControlVote{}, err
	}
	body, err := CanonicalEncode(ControlVoteHistoryItem{Proposal: config, Vote: v})
	if err != nil {
		return ControlVote{}, err
	}
	dir, err := a.memberRoundDirectory("control-votes", verifier.id)
	if err != nil {
		return ControlVote{}, err
	}
	if err = ctx.Err(); err != nil {
		return ControlVote{}, err
	}
	if err = putControlBytes(filepath.Join(dir, controlRoundFile(round)), body); err != nil {
		return ControlVote{}, err
	}
	return v, nil
}
