// Package clientv2 实现 Linux v2 reader/LKG 边界。只有 strict wire、QC、
// Merkle、floor 与本机 identity 全部通过，才能提交 Device view（D105、D106）。
package clientv2

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"loom/internal/wire"
)

type State struct {
	Schema   int                       `json:"schema"`
	Floors   wire.ClientFloorsV2       `json:"floors"`
	Envelope wire.DeviceViewEnvelopeV2 `json:"envelope"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state *State
}

func Open(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("[D106 Linux] v2 state path 必须是规范绝对路径")
	}
	store := &Store{path: path}
	info, err := os.Lstat(path)
	if err == nil {
		if err := validatePrivateStateFile(info); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	canonical, err := wire.DecodeStrict(body, 32<<20, &state)
	if err != nil {
		return nil, fmt.Errorf("[D106 Linux] v2 LKG state 无效: %w", err)
	}
	if !bytes.Equal(canonical, body) {
		return nil, errors.New("[D106 Linux] v2 LKG state 必须是 exact canonical JSON")
	}
	if err := validateStoredState(&state); err != nil {
		return nil, err
	}
	store.state = &state
	return store, nil
}

func (s *Store) Floors() wire.ClientFloorsV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floorsLocked()
}

func (s *Store) floorsLocked() wire.ClientFloorsV2 {
	if s.state == nil {
		return wire.ClientFloorsV2{}
	}
	return s.state.Floors
}

func (s *Store) Envelope() *wire.DeviceViewEnvelopeV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil
	}
	body, _ := wire.MarshalCanonical(s.state.Envelope)
	var copy wire.DeviceViewEnvelopeV2
	_, _ = wire.DecodeStrict(body, 32<<20, &copy)
	return &copy
}

func (s *Store) Accept(envelope *wire.DeviceViewEnvelopeV2, set *wire.ControlSetV1, expectedDeviceID, expectedIdentitySPKIHash string) (wire.ClientFloorsV2, error) {
	return s.AcceptWithPrevious(envelope, set, nil, expectedDeviceID, expectedIdentitySPKIHash)
}

func (s *Store) AcceptWithPrevious(envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1, expectedDeviceID, expectedIdentitySPKIHash string) (wire.ClientFloorsV2, error) {
	return s.acceptWithAdvance(envelope, set, previousSet, expectedDeviceID, expectedIdentitySPKIHash,
		func(current, candidate wire.ClientFloorsV2) (wire.ClientFloorsV2, error) {
			if current.Schema == 0 {
				return current, errors.New("[D106 Linux] 首次 v2 latch 必须携 verified Invite/bootstrap evidence")
			}
			return wire.AdvanceFloors(current, candidate)
		})
}

// AcceptFromInviteProof 是新 Enrollment 的唯一首次 latch 入口；调用方传入的 ControlSet
// 必须逐字节等于 public proof verifier 的 opaque 输出（D105、D106、D115）。
func (s *Store) AcceptFromInviteProof(envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string, proof wire.VerifiedInviteProofV2) (wire.ClientFloorsV2, error) {
	return s.acceptWithAdvance(envelope, set, previousSet, expectedDeviceID, expectedIdentitySPKIHash,
		func(current, candidate wire.ClientFloorsV2) (wire.ClientFloorsV2, error) {
			if current.Schema != 0 {
				return current, errors.New("[D106 Linux] Invite proof 只能建立首次 v2 latch")
			}
			proofSet := proof.ControlSet()
			proofHead := proof.Head()
			if proof.CertifiedInviteRecordHash() == "" || !wire.EqualCanonical(proofSet, *set) ||
				candidate.ClusterID != proofHead.Body.Payload.ClusterID ||
				candidate.AcceptedRecoveryEpoch != proofHead.Body.Payload.RecoveryEpoch ||
				candidate.RecoveryStatementHash != proofHead.Body.Payload.RecoveryStatementHash ||
				candidate.RecoveryPolicyHash != proofHead.Body.Payload.RecoveryPolicyHash ||
				candidate.AcceptedControlEpoch != proofHead.Body.Payload.ControlEpoch ||
				candidate.ControlSetHash != proofHead.Body.Payload.ControlSetHash ||
				candidate.BootstrapTransitionHash != proofHead.Body.TransitionProofHash ||
				candidate.AcceptedControlRevision < proofHead.Body.Payload.ControlRevision {
				return current, errors.New("[D115 Linux] initial Device view 未延续 verified Invite authority")
			}
			return wire.AdvanceFloors(current, candidate)
		})
}

func (s *Store) AcceptControlTransition(envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string, transition wire.VerifiedControlSetTransitionV1) (wire.ClientFloorsV2, error) {
	return s.acceptWithAdvance(envelope, set, previousSet, expectedDeviceID, expectedIdentitySPKIHash,
		func(current, candidate wire.ClientFloorsV2) (wire.ClientFloorsV2, error) {
			return wire.AdvanceFloorsWithControl(current, candidate, transition)
		})
}

func (s *Store) AcceptEmergencyRecovery(envelope *wire.DeviceViewEnvelopeV2, set *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string, transition wire.VerifiedRecoveryTransitionV1) (wire.ClientFloorsV2, error) {
	return s.acceptWithAdvance(envelope, set, nil, expectedDeviceID, expectedIdentitySPKIHash,
		func(current, candidate wire.ClientFloorsV2) (wire.ClientFloorsV2, error) {
			return wire.AdvanceFloorsWithRecovery(current, candidate, transition)
		})
}

func (s *Store) AcceptRecoveryPolicyTransition(envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string, transition wire.VerifiedRecoveryPolicyTransitionV1) (wire.ClientFloorsV2, error) {
	return s.acceptWithAdvance(envelope, set, previousSet, expectedDeviceID, expectedIdentitySPKIHash,
		func(current, candidate wire.ClientFloorsV2) (wire.ClientFloorsV2, error) {
			return wire.AdvanceFloorsWithRecoveryPolicy(current, candidate, transition)
		})
}

type floorAdvanceFunc func(wire.ClientFloorsV2, wire.ClientFloorsV2) (wire.ClientFloorsV2, error)

func (s *Store) acceptWithAdvance(envelope *wire.DeviceViewEnvelopeV2, set, previousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string, advance floorAdvanceFunc) (wire.ClientFloorsV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if envelope == nil || set == nil || expectedDeviceID == "" || expectedIdentitySPKIHash == "" || advance == nil {
		return s.floorsLocked(), errors.New("[D105 Linux] view/local identity binding 缺失")
	}
	floors, err := wire.VerifyDeviceViewEnvelopeWithPrevious(envelope, set, previousSet)
	if err != nil {
		return s.floorsLocked(), err
	}
	if envelope.Payload.DeviceID != expectedDeviceID {
		return s.floorsLocked(), errors.New("[D105 Linux] Device view 不属于本机 Device")
	}
	if envelope.Payload.State == "active" && envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return s.floorsLocked(), errors.New("[D105 Linux] Device view identity SPKI 与本机 key 不匹配")
	}
	next, err := advance(s.floorsLocked(), floors)
	if err != nil {
		return s.floorsLocked(), err
	}
	state := State{Schema: 1, Floors: next, Envelope: *envelope}
	if err := persist(s.path, state); err != nil {
		return s.floorsLocked(), err
	}
	s.state = &state
	return next, nil
}

func persist(path string, state State) error {
	if err := validateStoredState(&state); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("[D106 Linux] v2 state directory 必须由服务账号持有且权限不宽于 0700")
	}
	temporary, err := os.CreateTemp(directory, ".client-v2-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validatePrivateStateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) {
		return errors.New("[D106 Linux] v2 LKG 必须是服务账号持有的 0600 普通文件")
	}
	if info.Size() < 1 || info.Size() > 32<<20 {
		return errors.New("[D106 Linux] v2 LKG 文件大小越界")
	}
	return nil
}

func validateStoredState(state *State) error {
	if state == nil || state.Schema != 1 || !state.Floors.V2Latched || state.Floors.Schema != 2 {
		return errors.New("[D106 Linux] v2 LKG schema/latch 无效")
	}
	payloadHash, err := wire.DeviceViewHash(&state.Envelope.Payload)
	if err != nil {
		return err
	}
	leafBytes, err := wire.MarshalCanonical(state.Envelope.Leaf)
	if err != nil {
		return err
	}
	leafHash := fmt.Sprintf("sha256:%x", wire.MerkleLeafHash(leafBytes))
	head := state.Envelope.SignedCurrent.Head
	floor := state.Floors
	if floor.ClusterID != state.Envelope.Payload.ClusterID || floor.AcceptedRecoveryEpoch != head.Body.Payload.RecoveryEpoch ||
		floor.RecoveryStatementHash != head.Body.Payload.RecoveryStatementHash || floor.RecoveryPolicyHash != head.Body.Payload.RecoveryPolicyHash ||
		floor.AcceptedControlEpoch != head.Body.Payload.ControlEpoch || floor.ControlSetHash != head.Body.Payload.ControlSetHash ||
		floor.AcceptedControlRevision != head.Body.Payload.ControlRevision || floor.HeadHash != head.HeadHash ||
		floor.DeviceGeneration != state.Envelope.Payload.DeviceGeneration || floor.DeviceLeafHash != leafHash ||
		floor.DeviceViewHash != payloadHash || floor.BootstrapTransitionHash != head.Body.TransitionProofHash {
		return errors.New("[D106 Linux] durable floors 与同一 LKG envelope 不一致")
	}
	return nil
}
