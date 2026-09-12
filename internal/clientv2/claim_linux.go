//go:build linux

package clientv2

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type PendingClaimV2 struct {
	Schema        int                        `json:"schema"`
	ClaimCore     wire.EnrollmentClaimCoreV2 `json:"claim_core"`
	ClaimCoreHash string                     `json:"claim_core_hash"`
	Progress      *PendingProgressV1         `json:"progress,omitempty"`
}

type PendingProgressV1 struct {
	Schema   int                             `json:"schema"`
	Status   string                          `json:"status"`
	Expected wire.EnrollmentResumeExpectedV1 `json:"expected"`
}

// OpenOrCreatePendingClaim 保证 CSR/client nonce/core 只生成一次；跨 ingress 重试只重签新 challenge。
func OpenOrCreatePendingClaim(path string, identity *EnrollmentIdentityV1, input ClaimCoreInputV2) (*PendingClaimV2, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return nil, errors.New("[D129 Linux] pending claim path 必须是规范绝对路径")
	}
	if identity == nil {
		return nil, errors.New("[D129 Linux] enrollment identity 不能为空")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if pending, err := loadPendingClaim(path, identity, input); err == nil {
		return pending, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if input.ClientNonce == "" {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		input.ClientNonce = base64.RawURLEncoding.EncodeToString(nonce)
	}
	core, coreHash, err := identity.PrepareClaimCore(input)
	if err != nil {
		return nil, err
	}
	pending := &PendingClaimV2{Schema: 2, ClaimCore: core, ClaimCoreHash: coreHash}
	if err := persistProtectedCanonical(path, pending); err != nil {
		return nil, err
	}
	return loadPendingClaim(path, identity, input)
}

func loadPendingClaim(path string, identity *EnrollmentIdentityV1, input ClaimCoreInputV2) (*PendingClaimV2, error) {
	pending, err := readPendingClaim(path)
	if err != nil {
		return nil, err
	}
	if !claimCoreMatchesInput(pending.ClaimCore, input) {
		return nil, errors.New("[D129 Linux] pending claim 与本次 Invite/authority 不一致")
	}
	if err := validatePendingIdentity(pending, identity); err != nil {
		return nil, err
	}
	return pending, nil
}

// LoadPendingClaimForEnrollmentRetry reads an existing stable claim so the
// original Invite can retry after a local crash. Unlike descriptor-based
// resume, this path may precede the first verified progress receipt: the full
// Invite proof and preflight opening are rebound before the claim is reused.
func LoadPendingClaimForEnrollmentRetry(path string, identity *EnrollmentIdentityV1) (*PendingClaimV2, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) || identity == nil {
		return nil, errors.New("[D129 Linux] pending/identity retry 输入无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	pending, err := readPendingClaim(path)
	if err != nil {
		return nil, err
	}
	if err := validatePendingIdentity(pending, identity); err != nil {
		return nil, err
	}
	return pending, nil
}

// LoadPendingClaimForResume 在共享锁下读取已 committed 的本机 claim。resume 必须
// 已有经 progress receipt 固化的 binding，不能从只有 core 的未提交状态猜测事务（D130）。
func LoadPendingClaimForResume(path string, identity *EnrollmentIdentityV1) (*PendingClaimV2, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) || identity == nil {
		return nil, errors.New("[D130 Linux resume] pending/identity 输入无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	pending, err := readPendingClaim(path)
	if err != nil {
		return nil, err
	}
	if err := validatePendingIdentity(pending, identity); err != nil {
		return nil, err
	}
	if pending.Progress == nil {
		return nil, errors.New("[D130 Linux resume] pending claim 缺 verified progress binding")
	}
	return pending, nil
}

func readPendingClaim(path string) (*PendingClaimV2, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 1<<20 {
		return nil, errors.New("[D129 Linux] pending claim 必须是 0600 小型普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("[D129 Linux] pending claim owner 不是当前服务账号")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pending PendingClaimV2
	canonical, err := wire.DecodeStrict(body, 1<<20, &pending)
	if err != nil || !bytes.Equal(canonical, body) || pending.Schema != 2 {
		return nil, errors.New("[D129 Linux] pending claim wire 无效")
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&pending.ClaimCore)
	if err != nil || coreHash != pending.ClaimCoreHash {
		return nil, errors.New("[D129 Linux] pending claim core hash 不匹配")
	}
	if err := validatePendingProgress(&pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

func validatePendingIdentity(pending *PendingClaimV2, identity *EnrollmentIdentityV1) error {
	if pending == nil || identity == nil {
		return errors.New("[D129 Linux] pending/identity context 无效")
	}
	identityKey, wrappingKey, err := identity.keys()
	if err != nil {
		return err
	}
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if pending.ClaimCore.DeviceIdentityPublicKey != base64.RawURLEncoding.EncodeToString(identitySPKI) ||
		pending.ClaimCore.WrappingPublicKey != base64.RawURLEncoding.EncodeToString(wrappingSPKI) {
		return errors.New("[D129 Linux] pending claim 不属于当前 identity/wrapping keys")
	}
	return nil
}

// RecordPendingProgress 只接受完整 progress receipt verifier 产生的 opaque
// projection。reserved→issued_provisional 可以前进；同一阶段不同 hash 或倒退永久
// 失败，防止旧 ingress 响应覆盖较新的 resume binding（D130）。
func RecordPendingProgress(path string, identity *EnrollmentIdentityV1, input ClaimCoreInputV2,
	verified enrollmentv2.VerifiedEnrollmentProgressV1) (*PendingClaimV2, error) {
	status, expected := verified.Status(), verified.ResumeExpected()
	return recordPendingProgress(path, identity, input, status, expected)
}

func recordPendingProgress(path string, identity *EnrollmentIdentityV1, input ClaimCoreInputV2,
	status string, expected wire.EnrollmentResumeExpectedV1) (*PendingClaimV2, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) || identity == nil ||
		(status != "reserved" && status != "issued_provisional") {
		return nil, errors.New("[D130 Linux] pending progress 输入无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	pending, err := loadPendingClaim(path, identity, input)
	if err != nil {
		return nil, err
	}
	next := PendingProgressV1{Schema: 1, Status: status, Expected: expected}
	candidate := *pending
	candidate.Progress = &next
	if err := validatePendingProgress(&candidate); err != nil {
		return nil, err
	}
	if pending.Progress != nil {
		if wire.EqualCanonical(*pending.Progress, next) {
			return pending, nil
		}
		if pending.Progress.Status != "reserved" || status != "issued_provisional" ||
			!sameResumeIdentity(pending.Progress.Expected, expected) {
			return nil, errors.New("[D130 Linux] pending progress 回退、分叉或改写 stable binding")
		}
	}
	if err := persistProtectedCanonical(path, &candidate); err != nil {
		return nil, err
	}
	return loadPendingClaim(path, identity, input)
}

func validatePendingProgress(pending *PendingClaimV2) error {
	if pending == nil || pending.Progress == nil {
		return nil
	}
	progress := pending.Progress
	expected := progress.Expected
	if progress.Schema != 1 || (progress.Status != "reserved" && progress.Status != "issued_provisional") ||
		expected.ClusterID != pending.ClaimCore.ClusterID || expected.InviteID != pending.ClaimCore.InviteID ||
		expected.RequestID != pending.ClaimCore.RequestID || expected.ClaimCoreHash != pending.ClaimCoreHash {
		return errors.New("[D130 Linux] pending progress header/core binding 无效")
	}
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&pending.ClaimCore)
	if err != nil || expected.IdentityKeyHash != identityHash || expected.WrappingKeyHash != wrappingHash ||
		expected.CSRHash != csrHash {
		return errors.New("[D130 Linux] pending progress identity/wrapping/CSR binding 无效")
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

func sameResumeIdentity(left, right wire.EnrollmentResumeExpectedV1) bool {
	left.EnrollmentTransactionStateHash = ""
	right.EnrollmentTransactionStateHash = ""
	return wire.EqualCanonical(left, right)
}

func claimCoreMatchesInput(core wire.EnrollmentClaimCoreV2, input ClaimCoreInputV2) bool {
	if core.ClusterID != input.ClusterID || core.InviteID != input.InviteID || core.RequestID != input.RequestID ||
		core.CertifiedInviteRecordHash != input.CertifiedInviteRecordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != input.DeviceEnrollmentIntentCommitmentHash ||
		core.DeviceEnrollmentIntentOpeningHash != input.DeviceEnrollmentIntentOpeningHash ||
		core.AcceptedDeviceEnrollmentIntentHash != input.AcceptedDeviceEnrollmentIntentHash ||
		core.BaseRecoveryEpoch != input.BaseRecoveryEpoch || core.BaseControlEpoch != input.BaseControlEpoch ||
		core.BaseControlSetHash != input.BaseControlSetHash || core.BaseHeadHash != input.BaseHeadHash ||
		core.ClientPlatform != "linux-server" {
		return false
	}
	return input.ClientNonce == "" || core.ClientNonce == input.ClientNonce
}

func persistProtectedCanonical(path string, value any) error {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".pending-v2-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	_, err = temporary.Write(body)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}
