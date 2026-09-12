// Package clientv2 实现 Linux v2 reader/LKG 边界。只有 strict wire、QC、
// Merkle、floor 与本机 identity 全部通过，才能提交 Device view（D105、D106）。
package clientv2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"loom/internal/wire"
)

const (
	maximumLinuxV2StateBytes     = 64 << 20
	maximumLinuxConfigArtifacts  = 16
	maximumLinuxConfigArtifact   = 16 << 20
	maximumLinuxConfigTotalBytes = 32 << 20
)

type State struct {
	Schema             int                       `json:"schema"`
	Floors             wire.ClientFloorsV2       `json:"floors"`
	Envelope           wire.DeviceViewEnvelopeV2 `json:"envelope"`
	ControlSet         *wire.ControlSetV1        `json:"control_set,omitempty"`
	PreviousControlSet *wire.ControlSetV1        `json:"previous_control_set,omitempty"`
	Enrollment         *EnrollmentInstallationV1 `json:"enrollment,omitempty"`
}

// EnrollmentInstallationV1 是 Linux 首次 v2 身份的单文件提交单元。证书、
// DeviceView/floors 与解封后的 Device credentials 必须一起出现，不能靠多个
// rename 假装成跨文件原子事务（D106、D124、D130）。
type EnrollmentInstallationV1 struct {
	Schema                int                             `json:"schema"`
	ClaimCore             wire.EnrollmentClaimCoreV2      `json:"claim_core"`
	ClaimCoreHash         string                          `json:"claim_core_hash"`
	IdentityKeyHash       string                          `json:"identity_key_hash"`
	WrappingKeyHash       string                          `json:"wrapping_key_hash"`
	TransactionStateHash  string                          `json:"transaction_state_hash"`
	ResultArtifactHash    string                          `json:"result_artifact_hash"`
	DeviceCertificateHash string                          `json:"device_certificate_hash"`
	ResultArtifact        wire.EnrollmentResultArtifactV1 `json:"result_artifact"`
	Credentials           []InstalledSecretV1             `json:"credentials"`
	// nil 仅表示旧版 installation；指向空 slice 表示已轮换为零凭据。
	CurrentSecretArtifactRefs *[]wire.SecretArtifactRefV2    `json:"current_secret_artifact_refs,omitempty"`
	Configs                   []InstalledConfigV1            `json:"configs,omitempty"`
	DistributionMirrors       []wire.DistributionMirrorRefV1 `json:"distribution_mirrors,omitempty"`
}

type InstalledSecretV1 struct {
	SecretID     string `json:"secret_id"`
	Purpose      string `json:"purpose"`
	Generation   int64  `json:"generation"`
	ImmutableRef string `json:"immutable_ref"`
	SecretBytes  string `json:"secret_bytes"`
	SecretDigest string `json:"secret_digest"`
}

type InstalledConfigV1 struct {
	ArtifactID       string          `json:"artifact_id"`
	Generation       int64           `json:"generation"`
	Platform         string          `json:"platform"`
	MediaType        string          `json:"media_type"`
	RenderContractID string          `json:"render_contract_id"`
	SizeBytes        int64           `json:"size_bytes"`
	ContentHash      string          `json:"content_hash"`
	Config           json.RawMessage `json:"config"`
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
	canonical, err := wire.DecodeStrict(body, maximumLinuxV2StateBytes, &state)
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
	_, _ = wire.DecodeStrict(body, maximumLinuxV2StateBytes, &copy)
	return &copy
}

func (s *Store) Enrollment() *EnrollmentInstallationV1 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.state.Enrollment == nil {
		return nil
	}
	body, _ := wire.MarshalCanonical(s.state.Enrollment)
	var copy EnrollmentInstallationV1
	_, _ = wire.DecodeStrict(body, maximumLinuxV2StateBytes, &copy)
	return &copy
}

func (s *Store) ControlSets() (*wire.ControlSetV1, *wire.ControlSetV1) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.state.ControlSet == nil {
		return nil, nil
	}
	current := cloneStoreValue(*s.state.ControlSet)
	var previous *wire.ControlSetV1
	if s.state.PreviousControlSet != nil {
		value := cloneStoreValue(*s.state.PreviousControlSet)
		previous = &value
	}
	return &current, previous
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
	if s.state != nil {
		if err := wire.VerifyDeviceViewSuccessor(&s.state.Envelope, envelope); err != nil {
			return s.floorsLocked(), err
		}
	}
	next, err := advance(s.floorsLocked(), floors)
	if err != nil {
		return s.floorsLocked(), err
	}
	setCopy := cloneStoreValue(*set)
	state := State{Schema: 1, Floors: next, Envelope: cloneStoreValue(*envelope), ControlSet: &setCopy}
	if previousSet != nil {
		value := cloneStoreValue(*previousSet)
		state.PreviousControlSet = &value
	}
	if s.state != nil && s.state.Enrollment != nil {
		state.Enrollment = s.state.Enrollment
	}
	if err := persist(s.path, state); err != nil {
		return s.floorsLocked(), err
	}
	s.state = &state
	return next, nil
}

// AcceptDeviceConfigDelivery 从 durable exact Head 定位 delivery 窗口，并在内存中
// 完整重放后一次性提交 final floors/view/ControlSet。任何中间失败都保留原 LKG（D106、D112、D131）。
func (s *Store) AcceptDeviceConfigDelivery(delivery *wire.DeviceConfigDeliveryV1,
	fallbackSet, fallbackPreviousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string,
) (wire.ClientFloorsV2, error) {
	return s.acceptDeviceConfigDelivery(delivery, fallbackSet, fallbackPreviousSet,
		expectedDeviceID, expectedIdentitySPKIHash, nil, nil)
}

// AcceptDeviceConfigDeliveryWithArtifacts 要求变更的 config/secret 全量到齐，
// 并与 final view/floors/ControlSet 在同一个 0600 state 文件中原子替换。
// nil 表示对应 refs 未变；指向空 slice 表示 certified refs 已变为空。
func (s *Store) AcceptDeviceConfigDeliveryWithArtifacts(delivery *wire.DeviceConfigDeliveryV1,
	fallbackSet, fallbackPreviousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string,
	configs *[]InstalledConfigV1, credentials *[]InstalledSecretV1,
) (wire.ClientFloorsV2, error) {
	return s.acceptDeviceConfigDelivery(delivery, fallbackSet, fallbackPreviousSet,
		expectedDeviceID, expectedIdentitySPKIHash, configs, credentials)
}

func (s *Store) acceptDeviceConfigDelivery(delivery *wire.DeviceConfigDeliveryV1,
	fallbackSet, fallbackPreviousSet *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string,
	configs *[]InstalledConfigV1, credentials *[]InstalledSecretV1,
) (wire.ClientFloorsV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || delivery == nil || expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return s.floorsLocked(), errors.New("[D131 Linux config] delivery/protected state/identity 不完整")
	}
	currentSet, currentPreviousSet := s.state.ControlSet, s.state.PreviousControlSet
	if currentSet == nil {
		currentSet, currentPreviousSet = fallbackSet, fallbackPreviousSet
	}
	if currentSet == nil {
		return s.floorsLocked(), errors.New("[D131 Linux config] protected ControlSet 缺失")
	}
	verified, err := wire.VerifyDeviceConfigDeliveryFromProtected(delivery, &s.state.Envelope,
		s.state.Floors, currentSet, currentPreviousSet, expectedDeviceID, expectedIdentitySPKIHash)
	if err != nil {
		return s.floorsLocked(), err
	}
	envelope := verified.Envelope()
	configChanged, secretsChanged := changedInstalledArtifactRefs(&s.state.Envelope, &envelope)
	var installation *EnrollmentInstallationV1
	if s.state.Enrollment != nil {
		cloned := cloneStoreValue(*s.state.Enrollment)
		installation = &cloned
	}
	if envelope.Payload.State == "tombstone" {
		if configs != nil || credentials != nil {
			return s.floorsLocked(), errors.New("[D124 Linux config] tombstone 禁止新 artifact")
		}
		if installation != nil {
			installation.Configs = nil
		}
	} else {
		if (configChanged || secretsChanged) && installation == nil {
			return s.floorsLocked(), errors.New("[D124 Linux config] artifact 轮换缺 durable enrollment")
		}
		if configChanged {
			if configs == nil {
				return s.floorsLocked(), errors.New("[D124 Linux config] config refs 已变化但 artifact 未到齐")
			}
			installation.Configs = cloneStoreValue(*configs)
		} else if configs != nil {
			return s.floorsLocked(), errors.New("[D124 Linux config] config refs 未变却提交了 artifact")
		}
		if secretsChanged {
			if credentials == nil {
				return s.floorsLocked(), errors.New("[D124 Linux config] secret refs 已变化但 credential 未到齐")
			}
			if len(delivery.SecretEnvelopes) != len(envelope.SecretArtifactRefs) {
				return s.floorsLocked(), errors.New("[D124 Linux config] sealed envelopes 未 exact 覆盖 final refs")
			}
			refs, err := decodeLinuxSecretArtifactRefs(envelope.SecretArtifactRefs)
			if err != nil {
				return s.floorsLocked(), err
			}
			installation.Credentials = cloneStoreValue(*credentials)
			installation.CurrentSecretArtifactRefs = cloneLinuxSecretArtifactRefs(refs)
		} else if credentials != nil {
			return s.floorsLocked(), errors.New("[D124 Linux config] secret refs 未变却提交了 credential")
		}
	}
	set := verified.ControlSet()
	state := State{Schema: 1, Floors: verified.Floors(), Envelope: envelope, ControlSet: &set,
		Enrollment: installation}
	state.PreviousControlSet = verified.PreviousControlSet()
	if err := persist(s.path, state); err != nil {
		return s.floorsLocked(), err
	}
	s.state = &state
	return state.Floors, nil
}

func changedInstalledArtifactRefs(current, candidate *wire.DeviceViewEnvelopeV2) (bool, bool) {
	if current == nil || candidate == nil {
		return true, true
	}
	if candidate.Payload.State == "tombstone" {
		return false, false
	}
	if current.Payload.State != "active" || current.Payload.Active == nil || candidate.Payload.Active == nil {
		return true, true
	}
	configChanged := !wire.EqualCanonical(current.Payload.Active.ConfigArtifactRefs,
		candidate.Payload.Active.ConfigArtifactRefs)
	secretsChanged := len(current.SecretArtifactRefs) != len(candidate.SecretArtifactRefs)
	for index := range current.SecretArtifactRefs {
		if !secretsChanged && !bytes.Equal(current.SecretArtifactRefs[index], candidate.SecretArtifactRefs[index]) {
			secretsChanged = true
		}
	}
	return configChanged, secretsChanged
}

func decodeLinuxSecretArtifactRefs(raw []json.RawMessage) ([]wire.SecretArtifactRefV2, error) {
	refs := make([]wire.SecretArtifactRefV2, len(raw))
	for index := range raw {
		canonical, err := wire.DecodeStrict(raw[index], 4<<20, &refs[index])
		if err != nil || !bytes.Equal(canonical, raw[index]) {
			return nil, errors.New("[D124 Linux config] secret ref 不是 exact canonical wire")
		}
	}
	return refs, nil
}

func cloneLinuxSecretArtifactRefs(refs []wire.SecretArtifactRefV2) *[]wire.SecretArtifactRefV2 {
	cloned := cloneStoreValue(refs)
	return &cloned
}

// acceptInitialInstallation 提交已经由 completion receipt 与本机 wrapping key
// 验过的首次身份。上层必须先完成 opaque evidence 绑定和全部 secret 解封；这里
// 只负责一个 durable 原子点以及 exact replay 幂等（D106、D130）。
func (s *Store) acceptInitialInstallation(envelope *wire.DeviceViewEnvelopeV2, set *wire.ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string, installation *EnrollmentInstallationV1) (wire.ClientFloorsV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if envelope == nil || set == nil || installation == nil || expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return s.floorsLocked(), errors.New("[D130 Linux install] completion installation 输入不完整")
	}
	if s.state != nil {
		if s.state.Enrollment != nil && wire.EqualCanonical(s.state.Envelope, *envelope) &&
			wire.EqualCanonical(*s.state.Enrollment, *installation) {
			return s.floorsLocked(), nil
		}
		return s.floorsLocked(), errors.New("[D106 Linux install] 首次 Enrollment 已由不同状态占用")
	}
	floors, err := wire.VerifyDeviceViewEnvelope(envelope, set)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if envelope.Payload.DeviceID != expectedDeviceID || envelope.Payload.Active == nil ||
		envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return wire.ClientFloorsV2{}, errors.New("[D105 Linux install] completion view 不属于本机 identity")
	}
	installationBody, err := wire.MarshalCanonical(installation)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	var installedCopy EnrollmentInstallationV1
	if _, err := wire.DecodeStrict(installationBody, maximumLinuxV2StateBytes, &installedCopy); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	setCopy := cloneStoreValue(*set)
	state := State{Schema: 1, Floors: floors, Envelope: cloneStoreValue(*envelope),
		ControlSet: &setCopy, Enrollment: &installedCopy}
	if err := validateStoredState(&state); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := persist(s.path, state); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	s.state = &state
	return floors, nil
}

func persist(path string, state State) error {
	if err := validateStoredState(&state); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	if len(body) > maximumLinuxV2StateBytes {
		return errors.New("[D106 Linux] v2 LKG 超过文件大小边界")
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
	if info.Size() < 1 || info.Size() > maximumLinuxV2StateBytes {
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
	if state.ControlSet != nil {
		verified, verifyErr := wire.VerifyDeviceViewEnvelopeWithPrevious(
			&state.Envelope, state.ControlSet, state.PreviousControlSet)
		if verifyErr != nil || !wire.EqualCanonical(verified, state.Floors) {
			return errors.New("[D106 Linux] durable Device view/ControlSet/QC 不可重放")
		}
	} else if state.PreviousControlSet != nil {
		return errors.New("[D106 Linux] durable previous ControlSet 缺 current authority")
	}
	if state.Enrollment != nil {
		if err := validateEnrollmentInstallation(state.Enrollment, &state.Envelope); err != nil {
			return err
		}
	}
	return nil
}

func cloneStoreValue[T any](value T) T {
	body, _ := wire.MarshalCanonical(value)
	var cloned T
	_, _ = wire.DecodeStrict(body, 64<<20, &cloned)
	return cloned
}

func validateEnrollmentInstallation(installation *EnrollmentInstallationV1, envelope *wire.DeviceViewEnvelopeV2) error {
	if installation == nil || envelope == nil || installation.Schema != 1 || installation.Credentials == nil {
		return errors.New("[D130 Linux install] durable installation header 无效")
	}
	for _, hash := range []string{installation.ClaimCoreHash, installation.IdentityKeyHash,
		installation.WrappingKeyHash, installation.TransactionStateHash, installation.ResultArtifactHash,
		installation.DeviceCertificateHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(&installation.ResultArtifact)
	initialView := &installation.ResultArtifact.InitialDeviceView
	if err != nil || resultHash != installation.ResultArtifactHash ||
		initialView.ClusterID != envelope.Payload.ClusterID || initialView.DeviceID != envelope.Payload.DeviceID ||
		initialView.DeviceGeneration > envelope.Payload.DeviceGeneration ||
		initialView.DeviceGeneration == envelope.Payload.DeviceGeneration &&
			!wire.EqualCanonical(*initialView, envelope.Payload) {
		return errors.New("[D130 Linux install] durable initial result/current view lineage 无效")
	}
	claimCoreHash, err := wire.EnrollmentClaimCoreHash(&installation.ClaimCore)
	if err != nil || claimCoreHash != installation.ClaimCoreHash {
		return errors.New("[D130 Linux install] durable stable claim core/hash 不匹配")
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&installation.ClaimCore)
	if err != nil || identityHash != installation.IdentityKeyHash || wrappingHash != installation.WrappingKeyHash {
		return errors.New("[D130 Linux install] durable stable claim/key binding 无效")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(&installation.ResultArtifact)
	if err != nil {
		return err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil || certificateHash != installation.DeviceCertificateHash {
		return errors.New("[D102 Linux install] durable certificate hash 不匹配")
	}
	refs := installation.ResultArtifact.SecretArtifactRefs
	if installation.CurrentSecretArtifactRefs != nil {
		refs = *installation.CurrentSecretArtifactRefs
	}
	if len(refs) != len(installation.Credentials) ||
		envelope.Payload.Active != nil && len(refs) != len(envelope.SecretArtifactRefs) {
		return errors.New("[D124 Linux install] durable credentials/refs 数量不匹配")
	}
	totalSecretBytes := 0
	for index := range refs {
		canonicalRef, refErr := wire.MarshalCanonical(refs[index])
		canonicalEnvelopeRef, envelopeErr := canonicalRef, refErr
		if envelope.Payload.Active != nil {
			canonicalEnvelopeRef, envelopeErr = wire.CanonicalizeStrict(envelope.SecretArtifactRefs[index])
		}
		credential := &installation.Credentials[index]
		if refErr != nil || wire.ValidateSecretArtifactRef(&refs[index]) != nil ||
			refs[index].ClusterID != envelope.Payload.ClusterID || refs[index].Owner.Kind != "device" ||
			refs[index].Owner.Device == nil || refs[index].Owner.Device.DeviceID != envelope.Payload.DeviceID ||
			envelopeErr != nil || !bytes.Equal(canonicalRef, canonicalEnvelopeRef) ||
			credential.SecretID != refs[index].SecretID || credential.Purpose != refs[index].Purpose ||
			credential.Generation != refs[index].Generation || credential.ImmutableRef != refs[index].ImmutableRef {
			return errors.New("[D124 Linux install] durable credential 未绑定 exact secret ref")
		}
		secret, decodeErr := base64.RawURLEncoding.DecodeString(credential.SecretBytes)
		if decodeErr != nil || len(secret) == 0 || base64.RawURLEncoding.EncodeToString(secret) != credential.SecretBytes ||
			wire.HashRaw("loom-linux-installed-secret-v1", secret) != credential.SecretDigest {
			return errors.New("[D124 Linux install] durable credential bytes/digest 无效")
		}
		totalSecretBytes += len(secret)
		clear(secret)
		if totalSecretBytes > 8<<20 {
			return errors.New("[D124 Linux install] durable credentials 超过 bootstrap 总预算")
		}
	}
	if installation.Configs != nil {
		configRefs := initialView.Active.ConfigArtifactRefs
		if envelope.Payload.Active != nil {
			configRefs = envelope.Payload.Active.ConfigArtifactRefs
		}
		if err := validateLinuxInstalledConfigs(installation.Configs, configRefs); err != nil {
			return err
		}
	}
	if installation.DistributionMirrors != nil {
		if err := wire.ValidateDistributionMirrorRefs(installation.DistributionMirrors); err != nil {
			return errors.New("[D124 Linux install] durable distribution mirrors 无效")
		}
	}
	return nil
}

func validateLinuxInstalledConfigs(configs []InstalledConfigV1,
	refs []wire.DeviceConfigArtifactRefV1,
) error {
	if len(refs) > maximumLinuxConfigArtifacts || len(configs) != len(refs) {
		return errors.New("[D124 Linux config] installed configs 未 exact 覆盖 Device view refs")
	}
	totalBytes := 0
	for index := range refs {
		ref, installed := &refs[index], &configs[index]
		if err := wire.ValidateDeviceConfigArtifactRef(ref); err != nil {
			return err
		}
		if ref.Platform != "linux-server" || ref.SizeBytes > maximumLinuxConfigArtifact ||
			installed.ArtifactID != ref.ArtifactID || installed.Generation != ref.Generation ||
			installed.Platform != ref.Platform || installed.MediaType != ref.MediaType ||
			installed.RenderContractID != ref.RenderContractID || installed.SizeBytes != ref.SizeBytes ||
			installed.ContentHash != ref.ContentHash {
			return errors.New("[D124 Linux config] installed config 未绑定 exact ref")
		}
		raw := []byte(installed.Config)
		canonical, canonicalErr := wire.CanonicalizeStrict(raw)
		hash, hashErr := wire.DeviceConfigArtifactContentHash(raw)
		if len(raw) != int(ref.SizeBytes) || canonicalErr != nil || !bytes.Equal(canonical, raw) ||
			hashErr != nil || hash != ref.ContentHash {
			return errors.New("[D124 Linux config] installed config bytes/hash 无效")
		}
		totalBytes += len(raw)
		if totalBytes > maximumLinuxConfigTotalBytes {
			return errors.New("[D124 Linux config] installed configs 超过总预算")
		}
	}
	return nil
}
