package windowsv2

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"loom/internal/clientsecret"
	"loom/internal/clientv2"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const (
	StatePurpose                = "windows-v2-state-v1"
	installedSecretDigestDomain = "loom-windows-installed-secret-v1"
	maximumStateBytes           = 60 << 20
	maximumConfigArtifacts      = 16
	maximumConfigArtifactBytes  = 16 << 20
	maximumConfigTotalBytes     = 32 << 20
	maximumSecretTotalBytes     = 8 << 20
)

type StateV1 struct {
	Schema             int                       `json:"schema"`
	Floors             wire.ClientFloorsV2       `json:"floors"`
	Envelope           wire.DeviceViewEnvelopeV2 `json:"envelope"`
	ControlSet         *wire.ControlSetV1        `json:"control_set"`
	PreviousControlSet *wire.ControlSetV1        `json:"previous_control_set,omitempty"`
	Enrollment         *EnrollmentInstallationV1 `json:"enrollment,omitempty"`
	Migration          *MigrationInstallationV1  `json:"migration,omitempty"`
}

// DeviceInstallationV1 保存共同运行材料；加入证明与存量迁移证明分别保存。
// 历史 v2 enrollment blob 的字段保持原位置，升级不丢失已保存的配置与凭据。
type DeviceInstallationV1 struct {
	Schema                    int                                  `json:"schema"`
	IdentityKeyHash           string                               `json:"identity_key_hash"`
	WrappingKeyHash           string                               `json:"wrapping_key_hash"`
	DeviceCertificateHash     string                               `json:"device_certificate_hash"`
	DeviceProfileHash         string                               `json:"device_profile_hash"`
	DeviceProfile             wire.DeviceCertificateProfileStateV1 `json:"device_profile"`
	DeviceIssuance            wire.IssuanceLogCoordinateV1         `json:"device_issuance"`
	DeviceApprovedAt          string                               `json:"device_approved_at"`
	Credentials               []InstalledSecretV1                  `json:"credentials"`
	CurrentSecretArtifactRefs []wire.SecretArtifactRefV2           `json:"current_secret_artifact_refs"`
	Configs                   []InstalledConfigV1                  `json:"configs"`
	DistributionMirrors       []wire.DistributionMirrorRefV1       `json:"distribution_mirrors"`
}

type EnrollmentInstallationV1 struct {
	DeviceInstallationV1
	ClaimCore            wire.EnrollmentClaimCoreV2      `json:"claim_core"`
	ClaimCoreHash        string                          `json:"claim_core_hash"`
	TransactionStateHash string                          `json:"transaction_state_hash"`
	ResultArtifactHash   string                          `json:"result_artifact_hash"`
	ResultArtifact       wire.EnrollmentResultArtifactV1 `json:"result_artifact"`
}

// material 不会把迁移伪装成 Enrollment；两种证明不能同时占用本机身份。
func (state *StateV1) material() *DeviceInstallationV1 {
	if state == nil || (state.Enrollment == nil) == (state.Migration == nil) {
		return nil
	}
	if state.Enrollment != nil {
		return &state.Enrollment.DeviceInstallationV1
	}
	return &state.Migration.DeviceInstallationV1
}

func (state *StateV1) certificateDER() ([]byte, error) {
	if state.material() == nil {
		return nil, errors.New("[Windows] 正式身份来源缺失或冲突")
	}
	if state.Enrollment != nil {
		return wire.EnrollmentResultCertificateDER(&state.Enrollment.ResultArtifact)
	}
	return base64.RawURLEncoding.DecodeString(state.Migration.Package.DeviceCertificateDER)
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

type StateStore struct {
	mu        sync.Mutex
	path      string
	protector clientsecret.Protector
	state     *StateV1
}

func OpenState(path string, protector clientsecret.Protector) (*StateStore, error) {
	if err := validateProtectedPath(path); err != nil || protector == nil {
		return nil, errors.New("[Windows] v2 state path/protector 无效")
	}
	store := &StateStore{path: path, protector: protector}
	state, err := store.load()
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (store *StateStore) load() (*StateV1, error) {
	info, err := os.Lstat(store.path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("[Windows] v2 LKG 必须是普通文件")
	}
	body, err := clientsecret.ReadLargeProtected(store.path, StatePurpose, store.protector)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if len(body) > maximumStateBytes {
		return nil, errors.New("[Windows] v2 LKG 超过大小边界")
	}
	var state StateV1
	canonical, err := wire.DecodeStrict(body, maximumStateBytes, &state)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[Windows] v2 LKG 不是 exact canonical wire")
	}
	if err := validateState(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (store *StateStore) write(state *StateV1) error {
	if err := validateState(state); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	defer clear(body)
	if len(body) > maximumStateBytes {
		return errors.New("[Windows] v2 LKG 超过大小边界")
	}
	if err := clientsecret.WriteLargeProtected(store.path, StatePurpose, body, store.protector); err != nil {
		return err
	}
	replayed, err := store.load()
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(*state, *replayed) {
		return errors.New("[Windows] v2 LKG 写后回读分叉")
	}
	store.state = replayed
	return nil
}

func (store *StateStore) Snapshot() *StateV1 {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil {
		return nil
	}
	copy := cloneValue(*store.state)
	return &copy
}

func (store *StateStore) Latched() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state != nil && store.state.Floors.V2Latched
}

func (store *StateStore) Active() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state != nil && store.state.Envelope.Payload.State == "active" &&
		store.state.Envelope.Payload.Active != nil
}

func (store *StateStore) Floors() wire.ClientFloorsV2 {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil {
		return wire.ClientFloorsV2{}
	}
	return store.state.Floors
}

type CompletionInstall struct {
	StatePath         string
	IdentityPath      string
	JournalPath       string
	Protector         clientsecret.Protector
	Result            wire.EnrollmentClaimResultV2
	Completion        enrollmentv2.VerifiedEnrollmentCompletionV1
	VerifiedProof     wire.VerifiedInviteProofV2
	SecretEnvelopes   []wire.SealedSecretEnvelopeV1
	Configs           []InstalledConfigV1
	ValidateCandidate func(*StateV1) error
}

// InstallCompletion 把 certificate/view/floors/config/credentials 作为一个
// purpose-bound DPAPI blob 提交；只有写后回读成功才清理 token/capability journal。
func InstallCompletion(input CompletionInstall) (wire.ClientFloorsV2, error) {
	if input.Protector == nil || input.Result.Status != "completed" || input.Result.ResultArtifact == nil {
		return wire.ClientFloorsV2{}, errors.New("[Windows install] completed result/protector 缺失")
	}
	for _, path := range []string{input.StatePath, input.IdentityPath, input.JournalPath} {
		if err := validateProtectedPath(path); err != nil {
			return wire.ClientFloorsV2{}, errors.New("[Windows install] state/identity/journal path 无效")
		}
	}
	identity, err := LoadIdentity(input.IdentityPath, input.Protector)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	defer identity.Close()
	journalStore, err := newJournalStore(input.JournalPath, input.Protector)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	journal, journalErr := journalStore.load(identity)
	stateStore, err := OpenState(input.StatePath, input.Protector)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if journalErr != nil {
		if errors.Is(journalErr, os.ErrNotExist) && stateStore.Latched() {
			return stateStore.Floors(), nil
		}
		return wire.ClientFloorsV2{}, journalErr
	}
	if journal.Result == nil || !wire.EqualCanonical(*journal.Result, input.Result) {
		return wire.ClientFloorsV2{}, errors.New("[Windows install] durable journal/result 不匹配")
	}
	if err := input.Completion.VerifyInstallationContext(&input.Result, &journal.ClaimCore,
		input.VerifiedProof); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	installation, err := prepareInstallation(identity, journal, input)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	envelope, set := input.Completion.DeviceViewEnvelope(), input.Completion.ControlSet()
	state, err := prepareInitialState(envelope, set, input.VerifiedProof, installation)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := validateCandidateWithoutMutation(&state, input.ValidateCandidate); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	stateStore.mu.Lock()
	if stateStore.state != nil {
		if !wire.EqualCanonical(*stateStore.state, state) {
			stateStore.mu.Unlock()
			return stateStore.state.Floors, errors.New("[Windows install] v2 latch 已由不同状态占用")
		}
	} else if err := stateStore.write(&state); err != nil {
		stateStore.mu.Unlock()
		return wire.ClientFloorsV2{}, err
	}
	floors := stateStore.state.Floors
	stateStore.mu.Unlock()
	if err := journalStore.remove(); err != nil {
		return floors, fmt.Errorf("[Windows install] 正式 LKG 已提交但 bootstrap journal 清理失败: %w", err)
	}
	return floors, nil
}

func prepareInstallation(identity *Identity, journal *EnrollmentJournalV1,
	input CompletionInstall) (EnrollmentInstallationV1, error) {
	result := &input.Result
	artifact := result.ResultArtifact
	if len(artifact.SecretArtifactRefs) != len(input.SecretEnvelopes) {
		return EnrollmentInstallationV1{}, errors.New("[Windows install] sealed envelopes 未 exact 覆盖 result refs")
	}
	credentials, err := installSecrets(identity, artifact.SecretArtifactRefs,
		input.SecretEnvelopes, artifact.InitialDeviceView.DeviceID)
	if err != nil {
		return EnrollmentInstallationV1{}, err
	}
	if err := validateInstalledConfigs(input.Configs,
		artifact.InitialDeviceView.Active.ConfigArtifactRefs); err != nil {
		return EnrollmentInstallationV1{}, err
	}
	if err := wire.ValidateDistributionMirrorRefs(journal.Descriptor.DistributionMirrors); err != nil {
		return EnrollmentInstallationV1{}, err
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&journal.ClaimCore)
	if err != nil {
		return EnrollmentInstallationV1{}, err
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(artifact)
	if err != nil {
		return EnrollmentInstallationV1{}, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return EnrollmentInstallationV1{}, err
	}
	profile := input.Completion.DeviceCertificateProfile()
	profileHash, err := wire.DeviceCertificateProfileStateHash(&profile)
	if err != nil {
		return EnrollmentInstallationV1{}, err
	}
	mirrors := journal.Descriptor.DistributionMirrors
	if journal.ResumeDescriptor != nil {
		mirrors = journal.ResumeDescriptor.DistributionMirrors
	}
	return EnrollmentInstallationV1{
		ClaimCore: cloneValue(journal.ClaimCore), ClaimCoreHash: journal.ClaimCoreHash,
		TransactionStateHash: result.TransactionStateHash, ResultArtifactHash: result.ResultArtifactHash,
		ResultArtifact: cloneValue(*artifact),
		DeviceInstallationV1: DeviceInstallationV1{Schema: 1, IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
			DeviceCertificateHash: certificateHash, DeviceProfileHash: profileHash,
			DeviceProfile: profile, DeviceIssuance: input.Completion.DeviceCertificateIssuance(),
			DeviceApprovedAt: input.Completion.DeviceCertificateApprovedAt(),
			Credentials:      credentials, CurrentSecretArtifactRefs: cloneValue(artifact.SecretArtifactRefs),
			Configs: cloneValue(input.Configs), DistributionMirrors: cloneValue(mirrors)},
	}, nil
}

func prepareInitialState(envelope wire.DeviceViewEnvelopeV2, set wire.ControlSetV1,
	proof wire.VerifiedInviteProofV2, installation EnrollmentInstallationV1,
) (StateV1, error) {
	proofSet, proofHead := proof.ControlSet(), proof.Head()
	if proof.CertifiedInviteRecordHash() == "" || !wire.EqualCanonical(proofSet, set) {
		return StateV1{}, errors.New("[Windows] initial ControlSet 未绑定 verified Invite proof")
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&envelope, &set)
	if err != nil {
		return StateV1{}, err
	}
	if envelope.Payload.State != "active" || envelope.Payload.Active == nil ||
		envelope.Payload.DeviceGeneration != 1 ||
		envelope.Payload.DeviceID != installation.ResultArtifact.InitialDeviceView.DeviceID ||
		envelope.Payload.Active.IdentitySPKIHash != installation.IdentityKeyHash {
		return StateV1{}, errors.New("[Windows] initial Device view 与 Enrollment identity 不匹配")
	}
	if floors.ClusterID != proofHead.Body.Payload.ClusterID ||
		floors.AcceptedRecoveryEpoch != proofHead.Body.Payload.RecoveryEpoch ||
		floors.RecoveryStatementHash != proofHead.Body.Payload.RecoveryStatementHash ||
		floors.RecoveryPolicyHash != proofHead.Body.Payload.RecoveryPolicyHash ||
		floors.AcceptedControlEpoch != proofHead.Body.Payload.ControlEpoch ||
		floors.ControlSetHash != proofHead.Body.Payload.ControlSetHash ||
		floors.BootstrapTransitionHash != proofHead.Body.TransitionProofHash ||
		floors.AcceptedControlRevision < proofHead.Body.Payload.ControlRevision {
		return StateV1{}, errors.New("[Windows] initial Device view 未延续 Invite authority floors")
	}
	setCopy := cloneValue(set)
	state := StateV1{Schema: 1, Floors: floors, Envelope: cloneValue(envelope),
		ControlSet: &setCopy, Enrollment: &installation}
	if err := validateState(&state); err != nil {
		return StateV1{}, err
	}
	return state, nil
}

func installSecrets(identity *Identity, refs []wire.SecretArtifactRefV2,
	envelopes []wire.SealedSecretEnvelopeV1, deviceID string,
) ([]InstalledSecretV1, error) {
	if refs == nil || len(refs) != len(envelopes) || identity == nil {
		return nil, errors.New("[Windows install] sealed envelopes 未 exact 覆盖 refs")
	}
	wrappingSPKI := base64.RawURLEncoding.EncodeToString(identity.WrappingSPKIDER())
	credentials := make([]InstalledSecretV1, len(refs))
	total := 0
	for index := range refs {
		ref, envelope := &refs[index], &envelopes[index]
		if err := wire.VerifySealedSecretBinding(ref, envelope); err != nil {
			return nil, err
		}
		if ref.Owner.Kind != "device" || ref.Owner.Device == nil ||
			ref.Owner.Device.DeviceID != deviceID || ref.ClusterID != envelope.Context.ClusterID {
			return nil, errors.New("[Windows install] secret 未绑定当前 Device/cluster")
		}
		recipient, err := windowsWrappingRecipient(ref, deviceID, wrappingSPKI)
		if err != nil {
			return nil, err
		}
		secret, err := identity.unsealSecret(envelope, recipient)
		if err != nil {
			return nil, err
		}
		if len(secret) == 0 {
			return nil, errors.New("[Windows install] 解封 credential 不能为空")
		}
		total += len(secret)
		if total > maximumSecretTotalBytes {
			clear(secret)
			return nil, errors.New("[Windows install] credentials 超过总预算")
		}
		credentials[index] = InstalledSecretV1{
			SecretID: ref.SecretID, Purpose: ref.Purpose, Generation: ref.Generation,
			ImmutableRef: ref.ImmutableRef, SecretBytes: base64.RawURLEncoding.EncodeToString(secret),
			SecretDigest: wire.HashRaw(installedSecretDigestDomain, secret),
		}
		clear(secret)
	}
	return credentials, nil
}

func windowsWrappingRecipient(ref *wire.SecretArtifactRefV2, deviceID,
	wrappingSPKI string) (wire.SealedBlobRecipientKeyRefV1, error) {
	if ref == nil || ref.SealedBlob == nil || deviceID == "" || wrappingSPKI == "" {
		return wire.SealedBlobRecipientKeyRefV1{}, errors.New("[Windows install] wrapping recipient context 无效")
	}
	var match *wire.SealedBlobRecipientKeyRefV1
	for index := range ref.SealedBlob.RecipientKeyVersions {
		candidate := &ref.SealedBlob.RecipientKeyVersions[index]
		if candidate.RecipientID == deviceID && candidate.RecipientKeyProfile == WrappingKeyProfile &&
			candidate.RecipientPublicKey.PublicKeySPKIDER == wrappingSPKI {
			if match != nil {
				return wire.SealedBlobRecipientKeyRefV1{}, errors.New("[Windows install] wrapping recipient 命中多个版本")
			}
			copy := *candidate
			match = &copy
		}
	}
	if match == nil {
		return wire.SealedBlobRecipientKeyRefV1{}, errors.New("[Windows install] secret 未封装给本机 exact wrapping key")
	}
	return *match, nil
}

// FetchConfigArtifacts 只按 certified content-addressed refs 读取公开 mirror；
// 请求不携带 token、Device certificate 或 credential。
func FetchConfigArtifacts(ctx context.Context, mirrors []wire.DistributionMirrorRefV1,
	refs []wire.DeviceConfigArtifactRefV1, fetcher clientv2.MirrorFetcher,
) ([]InstalledConfigV1, error) {
	if ctx == nil || refs == nil || len(refs) > maximumConfigArtifacts {
		return nil, errors.New("[Windows config] config fetch 输入无效")
	}
	configs := make([]InstalledConfigV1, len(refs))
	total := 0
	for index := range refs {
		ref := &refs[index]
		if err := wire.ValidateDeviceConfigArtifactRef(ref); err != nil {
			return nil, err
		}
		if ref.Platform != "windows-desktop" || ref.SizeBytes > maximumConfigArtifactBytes {
			return nil, errors.New("[Windows config] config ref 平台或大小无效")
		}
		total += int(ref.SizeBytes)
		if total > maximumConfigTotalBytes {
			return nil, errors.New("[Windows config] configs 超过总预算")
		}
		body, err := fetcher.FetchCanonicalObject(ctx, mirrors, ref.ContentHash,
			wire.DomainDeviceConfigArtifact, ref.SizeBytes)
		if err != nil {
			return nil, err
		}
		if len(body) != int(ref.SizeBytes) {
			return nil, errors.New("[Windows config] mirror bytes 与 exact ref size 不匹配")
		}
		configs[index] = InstalledConfigV1{
			ArtifactID: ref.ArtifactID, Generation: ref.Generation, Platform: ref.Platform,
			MediaType: ref.MediaType, RenderContractID: ref.RenderContractID,
			SizeBytes: ref.SizeBytes, ContentHash: ref.ContentHash,
			Config: append(json.RawMessage(nil), body...),
		}
	}
	if err := validateInstalledConfigs(configs, refs); err != nil {
		return nil, err
	}
	return configs, nil
}

// InstallSecretArtifacts 在 DPAPI host 边界内完成 wrapping-key 解封并立即重绑
// exact refs。返回值只应送入同一次 StateStore 提交，不得另作配置来源。
func InstallSecretArtifacts(identity *Identity, refs []wire.SecretArtifactRefV2,
	envelopes []wire.SealedSecretEnvelopeV1, deviceID string) ([]InstalledSecretV1, error) {
	return installSecrets(identity, refs, envelopes, deviceID)
}

// AcceptDeviceConfigDelivery 从当前 protected Head/ControlSet 重放整个 delivery
// window，并把 final view、floors、authority 与变化后的 artifacts 一次替换。
// nil 表示对应 refs 未变化；非 nil 必须 exact 覆盖 final refs。
func (store *StateStore) AcceptDeviceConfigDelivery(delivery *wire.DeviceConfigDeliveryV1,
	identity *Identity, configs *[]InstalledConfigV1, credentials *[]InstalledSecretV1,
) (wire.ClientFloorsV2, error) {
	return store.AcceptDeviceConfigDeliveryValidated(delivery, identity, configs, credentials, nil)
}

// AcceptDeviceConfigDeliveryValidated 在 durable pointer 前执行宿主静态校验与
// sing-box check。validator 只能观察 candidate，不能把本机选择写回 authority。
func (store *StateStore) AcceptDeviceConfigDeliveryValidated(delivery *wire.DeviceConfigDeliveryV1,
	identity *Identity, configs *[]InstalledConfigV1, credentials *[]InstalledSecretV1,
	validateCandidate func(*StateV1) error,
) (wire.ClientFloorsV2, error) {
	if store == nil || delivery == nil || identity == nil {
		return wire.ClientFloorsV2{}, errors.New("[Windows config] delivery/store/identity 不完整")
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		return store.Floors(), err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || store.state.ControlSet == nil || store.state.material() == nil ||
		store.state.material().IdentityKeyHash != identityHash {
		return wire.ClientFloorsV2{}, errors.New("[Windows config] protected active identity/authority 缺失")
	}
	current := store.state
	verified, err := wire.VerifyDeviceConfigDeliveryFromProtected(delivery, &current.Envelope,
		current.Floors, current.ControlSet, current.PreviousControlSet,
		current.Envelope.Payload.DeviceID, identityHash)
	if err != nil {
		return current.Floors, err
	}
	finalEnvelope := verified.Envelope()
	next := cloneValue(*current)
	installation := next.material()
	configChanged, secretChanged := artifactRefsChanged(&current.Envelope, &finalEnvelope)
	if finalEnvelope.Payload.State != "active" {
		if configs != nil || credentials != nil {
			return current.Floors, errors.New("[Windows config] tombstone 禁止提交新 artifact")
		}
		installation.Configs = []InstalledConfigV1{}
		installation.Credentials = []InstalledSecretV1{}
		installation.CurrentSecretArtifactRefs = []wire.SecretArtifactRefV2{}
	} else {
		if finalEnvelope.Payload.Active == nil {
			return current.Floors, errors.New("[Windows config] active Device view 缺 active payload")
		}
		if configChanged {
			if configs == nil {
				return current.Floors, errors.New("[Windows config] config refs 已变化但 artifact 未到齐")
			}
			if err := validateInstalledConfigs(*configs,
				finalEnvelope.Payload.Active.ConfigArtifactRefs); err != nil {
				return current.Floors, err
			}
			installation.Configs = cloneValue(*configs)
		} else if configs != nil {
			return current.Floors, errors.New("[Windows config] config refs 未变却提交了 artifact")
		}
		if secretChanged {
			if credentials == nil || len(delivery.SecretEnvelopes) != len(finalEnvelope.SecretArtifactRefs) {
				return current.Floors, errors.New("[Windows config] secret refs 已变化但 credential/envelope 未 exact 到齐")
			}
			refs, err := decodeSecretArtifactRefs(finalEnvelope.SecretArtifactRefs)
			if err != nil {
				return current.Floors, err
			}
			installation.Credentials = cloneValue(*credentials)
			installation.CurrentSecretArtifactRefs = refs
		} else if credentials != nil {
			return current.Floors, errors.New("[Windows config] secret refs 未变却提交了 credential")
		}
	}
	set := verified.ControlSet()
	next.Floors, next.Envelope = verified.Floors(), finalEnvelope
	next.ControlSet, next.PreviousControlSet = &set, verified.PreviousControlSet()
	if next.Envelope.Payload.State == "active" {
		if err := validateCandidateWithoutMutation(&next, validateCandidate); err != nil {
			return current.Floors, err
		}
	}
	if err := store.write(&next); err != nil {
		return current.Floors, err
	}
	return store.state.Floors, nil
}

func validateCandidateWithoutMutation(candidate *StateV1, validate func(*StateV1) error) error {
	if validate == nil {
		return nil
	}
	before := cloneValue(*candidate)
	if err := validate(candidate); err != nil {
		return fmt.Errorf("[Windows activation] candidate preflight 失败: %w", err)
	}
	if !wire.EqualCanonical(before, *candidate) {
		return errors.New("[Windows activation] candidate validator 修改了 certified state")
	}
	return nil
}

func artifactRefsChanged(current, next *wire.DeviceViewEnvelopeV2) (bool, bool) {
	if current == nil || next == nil || next.Payload.State != "active" ||
		current.Payload.State != "active" || current.Payload.Active == nil || next.Payload.Active == nil {
		return next != nil && next.Payload.State == "active", next != nil && next.Payload.State == "active"
	}
	configChanged := !wire.EqualCanonical(current.Payload.Active.ConfigArtifactRefs,
		next.Payload.Active.ConfigArtifactRefs)
	secretChanged := len(current.SecretArtifactRefs) != len(next.SecretArtifactRefs)
	for index := range current.SecretArtifactRefs {
		if !secretChanged && !bytes.Equal(current.SecretArtifactRefs[index], next.SecretArtifactRefs[index]) {
			secretChanged = true
		}
	}
	return configChanged, secretChanged
}

func decodeSecretArtifactRefs(raw []json.RawMessage) ([]wire.SecretArtifactRefV2, error) {
	refs := make([]wire.SecretArtifactRefV2, len(raw))
	for index := range raw {
		canonical, err := wire.DecodeStrict(raw[index], 4<<20, &refs[index])
		if err != nil || !bytes.Equal(canonical, raw[index]) {
			return nil, errors.New("[Windows config] secret ref 不是 exact canonical wire")
		}
	}
	return refs, nil
}

func validateInstalledConfigs(configs []InstalledConfigV1,
	refs []wire.DeviceConfigArtifactRefV1) error {
	if configs == nil || len(refs) == 0 || len(refs) > maximumConfigArtifacts || len(configs) != len(refs) {
		return errors.New("[Windows config] installed configs 未 exact 覆盖 Device view refs")
	}
	total := 0
	for index := range refs {
		ref, installed := &refs[index], &configs[index]
		if err := wire.ValidateDeviceConfigArtifactRef(ref); err != nil {
			return err
		}
		if ref.Platform != "windows-desktop" || ref.SizeBytes > maximumConfigArtifactBytes ||
			installed.ArtifactID != ref.ArtifactID || installed.Generation != ref.Generation ||
			installed.Platform != ref.Platform || installed.MediaType != ref.MediaType ||
			installed.RenderContractID != ref.RenderContractID || installed.SizeBytes != ref.SizeBytes ||
			installed.ContentHash != ref.ContentHash {
			return errors.New("[Windows config] installed config 未绑定 exact ref")
		}
		raw := []byte(installed.Config)
		canonical, canonicalErr := wire.CanonicalizeStrict(raw)
		hash, hashErr := wire.DeviceConfigArtifactContentHash(raw)
		if len(raw) != int(ref.SizeBytes) || canonicalErr != nil || !bytes.Equal(canonical, raw) ||
			hashErr != nil || hash != ref.ContentHash {
			return errors.New("[Windows config] installed config bytes/hash 无效")
		}
		total += len(raw)
		if total > maximumConfigTotalBytes {
			return errors.New("[Windows config] installed configs 超过总预算")
		}
	}
	return nil
}

func validateState(state *StateV1) error {
	if state == nil || state.Schema != 1 || state.ControlSet == nil ||
		state.Floors.Schema != 2 || !state.Floors.V2Latched {
		return errors.New("[Windows] v2 LKG schema/latch/ControlSet 无效")
	}
	verified, err := wire.VerifyDeviceViewEnvelopeWithPrevious(&state.Envelope,
		state.ControlSet, state.PreviousControlSet)
	if err == nil && state.Envelope.SignedCurrent.Head.Body.Payload.HeadKind != "bootstrap" {
		verified.BootstrapTransitionHash = state.Floors.BootstrapTransitionHash
	}
	if err != nil || !wire.EqualCanonical(verified, state.Floors) {
		return errors.New("[Windows] durable Device view/ControlSet/QC/floors 不可重放")
	}
	if state.Floors.ClusterID != state.Envelope.Payload.ClusterID {
		return errors.New("[Windows] durable floors cluster 分叉")
	}
	if state.material() == nil {
		return errors.New("[Windows] 正式身份来源缺失或冲突")
	}
	if state.Enrollment != nil {
		return validateInstallation(state.Enrollment, &state.Envelope)
	}
	return validateMigrationInstallation(state.Migration, &state.Envelope, state.Floors)
}

func validateInstallation(installation *EnrollmentInstallationV1,
	envelope *wire.DeviceViewEnvelopeV2) error {
	if installation == nil || envelope == nil || installation.Schema != 1 ||
		installation.ClaimCore.ClientPlatform != "windows-desktop" ||
		installation.Credentials == nil || installation.CurrentSecretArtifactRefs == nil ||
		installation.Configs == nil || installation.DistributionMirrors == nil {
		return errors.New("[Windows install] durable installation header 无效")
	}
	for _, hash := range []string{installation.ClaimCoreHash, installation.IdentityKeyHash,
		installation.WrappingKeyHash, installation.TransactionStateHash, installation.ResultArtifactHash,
		installation.DeviceCertificateHash, installation.DeviceProfileHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(&installation.ResultArtifact)
	initial := &installation.ResultArtifact.InitialDeviceView
	if err != nil || resultHash != installation.ResultArtifactHash || initial.Active == nil ||
		initial.ClusterID != envelope.Payload.ClusterID || initial.DeviceID != envelope.Payload.DeviceID ||
		initial.DeviceGeneration > envelope.Payload.DeviceGeneration ||
		initial.DeviceGeneration == envelope.Payload.DeviceGeneration && !wire.EqualCanonical(*initial, envelope.Payload) ||
		initial.Active.IdentitySPKIHash != installation.IdentityKeyHash {
		return errors.New("[Windows install] durable initial result/current view lineage 无效")
	}
	claimHash, err := wire.EnrollmentClaimCoreHash(&installation.ClaimCore)
	identityHash, wrappingHash, _, keyErr := wire.EnrollmentClaimBinaryHashes(&installation.ClaimCore)
	if err != nil || keyErr != nil || claimHash != installation.ClaimCoreHash ||
		identityHash != installation.IdentityKeyHash || wrappingHash != installation.WrappingKeyHash {
		return errors.New("[Windows install] durable stable claim/key binding 无效")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(&installation.ResultArtifact)
	if err != nil {
		return err
	}
	return validateDeviceMaterial(&installation.DeviceInstallationV1, certificateDER, initial, envelope)
}

func validateDeviceMaterial(installation *DeviceInstallationV1, certificateDER []byte,
	initial *wire.DeviceViewPayloadV2, envelope *wire.DeviceViewEnvelopeV2) error {
	if installation == nil || initial == nil || initial.Active == nil || envelope == nil ||
		installation.Schema != 1 || installation.Credentials == nil || installation.CurrentSecretArtifactRefs == nil ||
		installation.Configs == nil || initial.ClusterID != envelope.Payload.ClusterID ||
		initial.DeviceID != envelope.Payload.DeviceID || initial.DeviceGeneration > envelope.Payload.DeviceGeneration ||
		initial.Active.IdentitySPKIHash != installation.IdentityKeyHash ||
		envelope.Payload.Active != nil && envelope.Payload.Active.IdentitySPKIHash != installation.IdentityKeyHash {
		return errors.New("[Windows install] 正式材料与当前设备身份不匹配")
	}
	certificateHash, hashErr := wire.DeviceCertificateHash(certificateDER)
	certificate, parseErr := x509.ParseCertificate(certificateDER)
	profileHash, profileErr := wire.DeviceCertificateProfileStateHash(&installation.DeviceProfile)
	approvedAt, timeErr := wire.ParseTimeZ(installation.DeviceApprovedAt)
	if hashErr != nil || parseErr != nil || profileErr != nil || timeErr != nil ||
		certificateHash != installation.DeviceCertificateHash || profileHash != installation.DeviceProfileHash ||
		installation.DeviceProfile.ClusterID != envelope.Payload.ClusterID ||
		installation.DeviceProfile.Status != "active" {
		return errors.New("[Windows install] durable certificate/profile/hash 无效")
	}
	if _, err := wire.VerifyDeviceCertificateAt(certificateDER, &installation.DeviceProfile,
		initial.DeviceID, installation.IdentityKeyHash, "windows-desktop",
		initial.Active.Responsibilities.Values, installation.DeviceIssuance, approvedAt, approvedAt); err != nil {
		return errors.New("[Windows install] durable Device certificate verification context 无效")
	}
	certificateIdentityHash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI,
		certificate.RawSubjectPublicKeyInfo)
	if err != nil || certificateIdentityHash != installation.IdentityKeyHash {
		return errors.New("[Windows install] certificate 未绑定 protected identity")
	}
	refs := installation.CurrentSecretArtifactRefs
	if len(refs) != len(installation.Credentials) ||
		envelope.Payload.Active != nil && len(refs) != len(envelope.SecretArtifactRefs) {
		return errors.New("[Windows install] durable credentials/refs 数量不匹配")
	}
	total := 0
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
			return errors.New("[Windows install] durable credential 未绑定 exact secret ref")
		}
		secret, decodeErr := base64.RawURLEncoding.DecodeString(credential.SecretBytes)
		if decodeErr != nil || len(secret) == 0 ||
			base64.RawURLEncoding.EncodeToString(secret) != credential.SecretBytes ||
			wire.HashRaw(installedSecretDigestDomain, secret) != credential.SecretDigest {
			return errors.New("[Windows install] durable credential bytes/digest 无效")
		}
		total += len(secret)
		clear(secret)
		if total > maximumSecretTotalBytes {
			return errors.New("[Windows install] durable credentials 超过总预算")
		}
	}
	if envelope.Payload.Active == nil {
		if len(installation.Configs) != 0 || len(installation.Credentials) != 0 || len(refs) != 0 {
			return errors.New("[Windows install] tombstone 仍保留 runtime artifact/credential")
		}
	} else if err := validateInstalledConfigs(installation.Configs,
		envelope.Payload.Active.ConfigArtifactRefs); err != nil {
		return err
	}
	if err := wire.ValidateDistributionMirrorRefs(installation.DistributionMirrors); err != nil {
		return err
	}
	return nil
}

// Credential 返回短生命周期明文副本；调用者使用后必须 clear。tombstone
// 状态永远不会返回任何 credential。
func (state *StateV1) Credential(secretID, purpose string) ([]byte, error) {
	if state == nil || state.material() == nil || state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		return nil, errors.New("[Windows] tombstone/inactive Device 禁止读取 credential")
	}
	var selected *InstalledSecretV1
	for index := range state.material().Credentials {
		candidate := &state.material().Credentials[index]
		if candidate.SecretID == secretID && candidate.Purpose == purpose {
			if selected != nil {
				return nil, errors.New("[Windows] credential 选择不唯一")
			}
			selected = candidate
		}
	}
	if selected == nil {
		return nil, os.ErrNotExist
	}
	secret, err := base64.RawURLEncoding.DecodeString(selected.SecretBytes)
	if err != nil || wire.HashRaw(installedSecretDigestDomain, secret) != selected.SecretDigest {
		clear(secret)
		return nil, errors.New("[Windows] credential digest 无效")
	}
	return secret, nil
}

func (state *StateV1) Config(artifactID string) ([]byte, error) {
	if state == nil || state.material() == nil || state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		return nil, errors.New("[Windows] tombstone/inactive Device 禁止读取 config")
	}
	var selected *InstalledConfigV1
	for index := range state.material().Configs {
		candidate := &state.material().Configs[index]
		if candidate.ArtifactID == artifactID {
			if selected != nil {
				return nil, errors.New("[Windows] config artifact ID 不唯一")
			}
			selected = candidate
		}
	}
	if selected == nil {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), selected.Config...), nil
}

func TrustedTime(now func() time.Time) (time.Time, error) {
	if now == nil {
		return time.Time{}, errors.New("[Windows] trusted time source 缺失")
	}
	instant := now().UTC()
	if instant.IsZero() {
		return time.Time{}, errors.New("[Windows] trusted time 无效")
	}
	return instant, nil
}
