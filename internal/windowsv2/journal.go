package windowsv2

import (
	"bytes"
	"errors"
	"os"

	"loom/internal/clientsecret"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const (
	JournalPurpose      = "windows-v2-enrollment-v1"
	maximumJournalBytes = 48 << 20
)

// EnrollmentJournalV1 是 token 首次离开进程前的唯一 durable pending。
// Descriptor/proof/preflight/core 全部按 exact canonical 值绑定；完成安装前保留
// bootstrap material，正式 LKG 提交后再整体删除。
type EnrollmentJournalV1 struct {
	Schema               int                                      `json:"schema"`
	Descriptor           wire.InviteBootstrapDescriptorV2         `json:"descriptor"`
	DescriptorHash       string                                   `json:"descriptor_hash"`
	ResumeDescriptor     *wire.EnrollmentResumeDescriptorV1       `json:"resume_descriptor,omitempty"`
	ResumeDescriptorHash string                                   `json:"resume_descriptor_hash,omitempty"`
	ProofBundle          wire.InviteProofBundleV2                 `json:"proof_bundle"`
	ProofBundleHash      string                                   `json:"proof_bundle_hash"`
	Preflight            wire.EnrollmentIntentPreflightResponseV1 `json:"preflight"`
	ClaimCore            wire.EnrollmentClaimCoreV2               `json:"claim_core"`
	ClaimCoreHash        string                                   `json:"claim_core_hash"`
	Progress             *EnrollmentJournalProgressV1             `json:"progress,omitempty"`
	Result               *wire.EnrollmentClaimResultV2            `json:"result,omitempty"`
}

type EnrollmentJournalProgressV1 struct {
	Schema   int                             `json:"schema"`
	Status   string                          `json:"status"`
	Expected wire.EnrollmentResumeExpectedV1 `json:"expected"`
}

type EnrollmentRecoveryV1 struct {
	Descriptor       wire.InviteBootstrapDescriptorV2
	ProofBundle      wire.InviteProofBundleV2
	RequestID        string
	ResumeDescriptor *wire.EnrollmentResumeDescriptorV1
	Committed        bool
	Completed        bool
}

// LoadEnrollmentRecovery 只供同一 Windows profile 的恢复事务在进程内使用。
// 返回值可能包含尚未消费的 token，调用方不得记录、显示或转交给诊断层。
func LoadEnrollmentRecovery(identityPath, journalPath string,
	protector clientsecret.Protector) (EnrollmentRecoveryV1, error) {
	identity, err := LoadIdentity(identityPath, protector)
	if err != nil {
		return EnrollmentRecoveryV1{}, err
	}
	defer identity.Close()
	store, err := newJournalStore(journalPath, protector)
	if err != nil {
		return EnrollmentRecoveryV1{}, err
	}
	journal, err := store.load(identity)
	if err != nil {
		return EnrollmentRecoveryV1{}, err
	}
	var resume *wire.EnrollmentResumeDescriptorV1
	if journal.ResumeDescriptor != nil {
		copy := cloneValue(*journal.ResumeDescriptor)
		resume = &copy
	}
	return EnrollmentRecoveryV1{
		Descriptor: cloneValue(journal.Descriptor), ProofBundle: cloneValue(journal.ProofBundle),
		RequestID: journal.ClaimCore.RequestID, ResumeDescriptor: resume,
		Committed: journal.Progress != nil,
		Completed: journal.Result != nil && journal.Result.Status == "completed",
	}, nil
}

// CleanupInstalledEnrollmentJournal 补完 LKG 写后回读与 bootstrap journal
// 删除之间的崩溃窗口。只有 protected LKG、identity 与 completed journal 可分别
// 重放且指向同一 stable claim/result 时，才删除仍含 token/capability 的 journal。
func CleanupInstalledEnrollmentJournal(statePath, identityPath, journalPath string,
	protector clientsecret.Protector) error {
	if protector == nil {
		return errors.New("[Windows cleanup] protector 缺失")
	}
	for _, path := range []string{statePath, identityPath, journalPath} {
		if err := validateProtectedPath(path); err != nil {
			return errors.New("[Windows cleanup] state/identity/journal path 无效")
		}
	}
	info, err := os.Lstat(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[Windows cleanup] enrollment journal 不是普通文件")
	}
	stateStore, err := OpenState(statePath, protector)
	if err != nil {
		return err
	}
	state := stateStore.Snapshot()
	if state == nil {
		return errors.New("[Windows cleanup] 正式 v2 LKG 尚未提交")
	}
	identity, err := LoadIdentity(identityPath, protector)
	if err != nil {
		return err
	}
	defer identity.Close()
	journalStore, err := newJournalStore(journalPath, protector)
	if err != nil {
		return err
	}
	journal, err := journalStore.load(identity)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !installedEnrollmentJournalMatches(state, journal) {
		return errors.New("[Windows cleanup] completed journal 与正式 LKG 分叉")
	}
	return journalStore.remove()
}

func installedEnrollmentJournalMatches(state *StateV1, journal *EnrollmentJournalV1) bool {
	if state == nil || journal == nil || journal.Result == nil ||
		journal.Result.Status != "completed" || journal.Result.ResultArtifact == nil {
		return false
	}
	installation, result := &state.Enrollment, journal.Result
	return installation.ClaimCoreHash == journal.ClaimCoreHash &&
		wire.EqualCanonical(installation.ClaimCore, journal.ClaimCore) &&
		installation.TransactionStateHash == result.TransactionStateHash &&
		installation.ResultArtifactHash == result.ResultArtifactHash &&
		wire.EqualCanonical(installation.ResultArtifact, *result.ResultArtifact)
}

type journalStore struct {
	path      string
	protector clientsecret.Protector
}

func newJournalStore(path string, protector clientsecret.Protector) (*journalStore, error) {
	if err := validateProtectedPath(path); err != nil || protector == nil {
		return nil, errors.New("[Windows] enrollment journal path/protector 无效")
	}
	return &journalStore{path: path, protector: protector}, nil
}

func (store *journalStore) load(identity *Identity) (*EnrollmentJournalV1, error) {
	body, err := clientsecret.ReadLargeProtected(store.path, JournalPurpose, store.protector)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if len(body) > maximumJournalBytes {
		return nil, errors.New("[Windows] enrollment journal 超过大小边界")
	}
	var journal EnrollmentJournalV1
	canonical, err := wire.DecodeStrict(body, maximumJournalBytes, &journal)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[Windows] enrollment journal 不是 exact canonical wire")
	}
	if err := validateEnrollmentJournal(&journal, identity); err != nil {
		return nil, err
	}
	return &journal, nil
}

func (store *journalStore) write(journal *EnrollmentJournalV1, identity *Identity) error {
	if err := validateEnrollmentJournal(journal, identity); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(journal)
	if err != nil {
		return err
	}
	defer clear(body)
	if len(body) > maximumJournalBytes {
		return errors.New("[Windows] enrollment journal 超过大小边界")
	}
	if err := clientsecret.WriteLargeProtected(store.path, JournalPurpose, body, store.protector); err != nil {
		return err
	}
	replayed, err := store.load(identity)
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(*journal, *replayed) {
		return errors.New("[Windows] enrollment journal 写后回读分叉")
	}
	return nil
}

func (store *journalStore) remove() error {
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[Windows] enrollment journal 不是普通文件，拒绝清理")
	}
	return os.Remove(store.path)
}

func validateEnrollmentJournal(journal *EnrollmentJournalV1, identity *Identity) error {
	if journal == nil || identity == nil || journal.Schema != 1 {
		return errors.New("[Windows] enrollment journal header/identity 无效")
	}
	descriptorHash, err := wire.HashObject(wire.DomainInviteDescriptor, &journal.Descriptor)
	if err != nil || descriptorHash != journal.DescriptorHash {
		return errors.New("[Windows] journal descriptor/hash 不匹配")
	}
	if (journal.ResumeDescriptor == nil) != (journal.ResumeDescriptorHash == "") {
		return errors.New("[Windows] journal resume descriptor/hash 必须同时存在")
	}
	if journal.ResumeDescriptor != nil {
		resumeHash, hashErr := wire.HashObject(wire.DomainEnrollmentResumeDescriptor,
			journal.ResumeDescriptor)
		if hashErr != nil || resumeHash != journal.ResumeDescriptorHash {
			return errors.New("[Windows] journal resume descriptor/hash 不匹配")
		}
		if journal.Progress == nil {
			return errors.New("[Windows] 未 committed 的 journal 不得绑定 resume descriptor")
		}
		resume := journal.ResumeDescriptor
		expected := journal.Progress.Expected
		if resume.ClusterID != expected.ClusterID || resume.InviteID != expected.InviteID ||
			resume.RequestID != expected.RequestID || resume.ClaimCoreHash != expected.ClaimCoreHash ||
			resume.ClaimOperationHash != expected.ClaimOperationHash ||
			resume.AdmissionQCHash != expected.AdmissionQCHash {
			return errors.New("[Windows] journal resume descriptor 未绑定 pending stable transaction")
		}
	}
	proofHash, err := wire.HashObject(wire.DomainInviteProofBundle, &journal.ProofBundle)
	if err != nil || proofHash != journal.ProofBundleHash ||
		proofHash != journal.Descriptor.ProofBundleHash {
		return errors.New("[Windows] journal Invite proof/hash 不匹配")
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&journal.ClaimCore)
	if err != nil || coreHash != journal.ClaimCoreHash ||
		journal.ClaimCore.ClientPlatform != "windows-desktop" {
		return errors.New("[Windows] journal stable core/hash 无效")
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&journal.ClaimCore)
	wantedIdentityHash, identityErr := identity.IdentitySPKIHash()
	wantedWrappingHash, wrappingErr := identity.WrappingSPKIHash()
	if err != nil || identityErr != nil || wrappingErr != nil ||
		identityHash != wantedIdentityHash || wrappingHash != wantedWrappingHash {
		return errors.New("[Windows] journal core 不属于 protected identity/wrapping keys")
	}
	record := &journal.ProofBundle.CertifiedInviteRecord
	if journal.Descriptor.ClusterID != record.ClusterID || journal.Descriptor.InviteID != record.InviteID ||
		journal.ClaimCore.ClusterID != record.ClusterID || journal.ClaimCore.InviteID != record.InviteID ||
		journal.Descriptor.TokenCommitment != record.TokenCommitment ||
		journal.ClaimCore.CertifiedInviteRecordHash == "" {
		return errors.New("[Windows] journal Invite/core identity 分叉")
	}
	preflightRequest := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: record.ClusterID, InviteID: record.InviteID,
		CertifiedInviteRecordHash: journal.ClaimCore.CertifiedInviteRecordHash,
		CapabilityID:              journal.Descriptor.BootstrapTunnelCapability.CapabilityID,
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&journal.Preflight, &preflightRequest,
		record.DeviceEnrollmentIntentCommitmentHash); err != nil {
		return err
	}
	opening := &journal.Preflight.DeviceEnrollmentIntentOpening
	openingHash, err := wire.IntentOpeningHash(opening)
	intentHash, intentErr := wire.EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	if err != nil || intentErr != nil || opening.DeviceEnrollmentIntent.Platform != "windows-desktop" ||
		openingHash != journal.ClaimCore.DeviceEnrollmentIntentOpeningHash ||
		intentHash != journal.ClaimCore.AcceptedDeviceEnrollmentIntentHash {
		return errors.New("[Windows] journal preflight/opening/core binding 无效")
	}
	if journal.Progress != nil {
		if err := validateJournalProgress(journal); err != nil {
			return err
		}
	}
	if journal.Result != nil {
		if err := wire.ValidateEnrollmentClaimResult(journal.Result); err != nil {
			return err
		}
		if journal.Result.Status != "completed" && len(journal.Result.ProgressReceipt) == 0 {
			return errors.New("[Windows] journal pending result 缺 progress receipt")
		}
	}
	return nil
}

func validateJournalProgress(journal *EnrollmentJournalV1) error {
	progress := journal.Progress
	if progress == nil {
		return nil
	}
	expected := progress.Expected
	if progress.Schema != 1 || (progress.Status != "reserved" && progress.Status != "issued_provisional") ||
		expected.ClusterID != journal.ClaimCore.ClusterID || expected.InviteID != journal.ClaimCore.InviteID ||
		expected.RequestID != journal.ClaimCore.RequestID || expected.ClaimCoreHash != journal.ClaimCoreHash {
		return errors.New("[Windows] journal progress/core binding 无效")
	}
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&journal.ClaimCore)
	if err != nil || expected.IdentityKeyHash != identityHash || expected.WrappingKeyHash != wrappingHash ||
		expected.CSRHash != csrHash {
		return errors.New("[Windows] journal progress identity/wrapping/CSR binding 无效")
	}
	for _, hash := range []string{expected.ClaimOperationHash, expected.AdmissionQCHash,
		expected.EnrollmentTransactionStateHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	if _, err := wire.ParseTimeZ(expected.RetryNotAfter); err != nil {
		return err
	}
	return nil
}

func recordJournalProgress(journal *EnrollmentJournalV1,
	verified enrollmentv2.VerifiedEnrollmentProgressV1) error {
	status, expected := verified.Status(), verified.ResumeExpected()
	next := &EnrollmentJournalProgressV1{Schema: 1, Status: status, Expected: expected}
	previous := journal.Progress
	journal.Progress = next
	if err := validateJournalProgress(journal); err != nil {
		journal.Progress = previous
		return err
	}
	if previous != nil && !wire.EqualCanonical(*previous, *next) {
		left, right := previous.Expected, next.Expected
		left.EnrollmentTransactionStateHash = ""
		right.EnrollmentTransactionStateHash = ""
		if previous.Status != "reserved" || next.Status != "issued_provisional" ||
			!wire.EqualCanonical(left, right) {
			journal.Progress = previous
			return errors.New("[Windows] enrollment progress 回退、分叉或改写 stable binding")
		}
	}
	return nil
}
