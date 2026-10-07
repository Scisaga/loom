package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Received promises are original signed messages, not a second voting state.
// Retaining them prevents a later reply or restart from hiding an observed
// same-round double vote. The write prohibition is derived from these originals.
func (a *Authority) ObserveControlPromises(ctx context.Context, promises []ControlPromise) error {
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
	return a.observeControlPromisesLocked(promises)
}

func (a *Authority) observeControlPromisesLocked(promises []ControlPromise) error {
	verifier, err := newControlSuccessorVerifier(a.projection.Config)
	if err != nil {
		return err
	}
	dir, err := a.memberRoundDirectory("control-observed-promises", verifier.id)
	if err != nil {
		return err
	}
	var rejected error
	for _, promise := range promises {
		// Verify each original independently before saving the full collection.
		// A conflict between valid replies must not discard either signed reply.
		one, err := newControlSuccessorVerifier(a.projection.Config)
		if err != nil {
			return err
		}
		if err = one.verifyPromise(promise); err != nil && !errors.Is(err, errControlDoubleVote) {
			rejected = err
			continue
		}
		// Double-vote errors occur only after authenticating the promise and
		// both contradictory votes. Keep that original even if the contradiction
		// is nested inside a proposal's original history.
		body, err := CanonicalEncode(promise)
		if err != nil {
			return err
		}
		if err = putControlBytes(filepath.Join(dir, strings.TrimPrefix(endpointByteDigest(body), "sha256:")+".json"), body); err != nil {
			return err
		}
	}
	if err = a.checkMemberVoteEvidenceLocked(); err != nil {
		return err
	}
	return rejected
}

func (a *Authority) checkMemberVoteEvidenceLocked() error {
	type coordinate struct {
		base, voter string
		round       ControlRound
	}
	votes := map[coordinate]string{}
	seenPromises := map[string]bool{}
	var inspectPromise func(ControlPromise) error
	var inspectVote func(ControlVoteHistoryItem) error
	inspectVote = func(item ControlVoteHistoryItem) error {
		vote := item.Vote
		key := coordinate{vote.BaseConfigID, vote.VoterControlID, vote.Round}
		if previous := votes[key]; previous != "" && previous != vote.ProposalID {
			return errControlDoubleVote
		}
		votes[key] = vote.ProposalID
		for _, promise := range item.Proposal.OriginPromises {
			if err := inspectPromise(promise); err != nil {
				return err
			}
		}
		return nil
	}
	inspectPromise = func(promise ControlPromise) error {
		body, _ := CanonicalEncode(promise)
		id := endpointByteDigest(body)
		if seenPromises[id] {
			return nil
		}
		seenPromises[id] = true
		for _, item := range promise.Votes {
			if err := inspectVote(item); err != nil {
				return err
			}
		}
		return nil
	}
	bases := []ControlConfig{a.genesis.Payload.(Genesis).ControlConfig}
	for _, certificate := range a.certificates {
		bases = append(bases, certificate.Config)
		for _, promise := range certificate.Promises {
			if err := inspectPromise(promise); err != nil {
				return err
			}
		}
		for _, vote := range certificate.Votes {
			if err := inspectVote(ControlVoteHistoryItem{Proposal: certificate.Config, Vote: vote}); err != nil {
				return err
			}
		}
	}
	for _, base := range bases {
		verifier, err := newControlSuccessorVerifier(base)
		if err != nil {
			return err
		}
		for _, kind := range []string{"control-promises", "control-votes", "control-observed-promises"} {
			dir := filepath.Join(a.root, kind, strings.TrimPrefix(verifier.id, "sha256:"))
			if _, err = os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err = validateControlRoot(filepath.Dir(dir)); err != nil {
				return err
			}
			if err = validateControlRoot(dir); err != nil {
				return err
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				body, err := readProtectedControlFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					return err
				}
				limits := ContractDecodeLimits{MaxBytes: maxControlInputBytes, MaxDepth: 128, MaxItems: 1 << 20}
				var round ControlRound
				if kind == "control-votes" {
					var item ControlVoteHistoryItem
					if err = DecodeCanonical(body, &item, limits); err != nil {
						return err
					}
					if err = verifier.verifyProposal(item.Proposal); err != nil {
						return err
					}
					if err = verifier.verifyVote(item.Vote, item.Proposal); err != nil {
						return err
					}
					round, err = item.Vote.Round, inspectVote(item)
				} else {
					var promise ControlPromise
					if err = DecodeCanonical(body, &promise, limits); err != nil {
						return err
					}
					if err = verifier.verifyPromise(promise); err != nil {
						return err
					}
					round, err = promise.Round, inspectPromise(promise)
				}
				if err != nil {
					return err
				}
				name := controlRoundFile(round)
				if kind == "control-observed-promises" {
					name = strings.TrimPrefix(endpointByteDigest(body), "sha256:") + ".json"
				}
				if entry.Name() != name {
					return errors.New("member vote evidence filename differs from its original")
				}
			}
		}
	}
	return nil
}
