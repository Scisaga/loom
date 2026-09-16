//go:build linux

package clientv2

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// LinuxEnrollmentCompletionInstallV1 描述一次 completion 后的本机提交。
// TemporaryPaths 只能位于 PendingPath 的 root-only 目录，用于清理临时
// capability/profile/tunnel 文件；identity 是正式私钥，永远不在清理集合中。
type LinuxEnrollmentCompletionInstallV1 struct {
	StatePath           string
	IdentityPath        string
	PendingPath         string
	TemporaryPaths      []string
	Result              wire.EnrollmentClaimResultV2
	Completion          enrollmentv2.VerifiedEnrollmentCompletionV1
	VerifiedProof       wire.VerifiedInviteProofV2
	SecretEnvelopes     []wire.SealedSecretEnvelopeV1
	Configs             []InstalledConfigV1
	DistributionMirrors []wire.DistributionMirrorRefV1
}

// InstallLinuxEnrollmentCompletion 先用 opaque completion evidence、本机 stable
// core/key 与 exact Invite proof 重绑全部输入，再解封 credentials，并把证书、view、
// floors、credentials 作为一个 canonical 0600 文件提交。只有 durable commit 成功
// 后才清理 pending 与临时 bootstrap artifacts。
func InstallLinuxEnrollmentCompletion(input LinuxEnrollmentCompletionInstallV1) (wire.ClientFloorsV2, error) {
	if err := validateCompletionInstallPaths(input); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := secureEnrollmentDirectory(filepath.Dir(input.StatePath)); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	store, err := Open(input.StatePath)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	identity, err := LoadEnrollmentIdentityForResume(input.IdentityPath)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := secureEnrollmentDirectory(filepath.Dir(input.PendingPath)); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	pendingLock, err := openPrivateLock(input.PendingPath + ".lock")
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	defer pendingLock.Close()
	if err := unix.Flock(int(pendingLock.Fd()), unix.LOCK_EX); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	defer unix.Flock(int(pendingLock.Fd()), unix.LOCK_UN)
	pending, err := readPendingClaim(input.PendingPath)
	if errors.Is(err, os.ErrNotExist) {
		installed := store.Enrollment()
		if installed == nil {
			return wire.ClientFloorsV2{}, err
		}
		pending = &PendingClaimV2{Schema: 2, ClaimCore: installed.ClaimCore,
			ClaimCoreHash: installed.ClaimCoreHash}
	} else if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := validatePendingIdentity(pending, identity); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := input.Completion.VerifyInstallationContext(&input.Result, &pending.ClaimCore, input.VerifiedProof); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	installation, err := prepareLinuxEnrollmentInstallation(identity, pending, &input.Result,
		input.SecretEnvelopes, input.Configs, input.DistributionMirrors)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	envelope := input.Completion.DeviceViewEnvelope()
	set := input.Completion.ControlSet()
	floors, err := store.acceptInitialInstallation(&envelope, &set, envelope.Payload.DeviceID,
		installation.IdentityKeyHash, installation)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	// pending 最后删除：若某个附加清理失败，调用方仍能 exact replay 安装并继续清理。
	for _, path := range input.TemporaryPaths {
		if err := removeProtectedEnrollmentTemporary(path, filepath.Dir(input.PendingPath)); err != nil {
			return floors, fmt.Errorf("[Linux install] 正式状态已提交，但临时 artifact 清理未完成: %w", err)
		}
	}
	if err := removeProtectedEnrollmentTemporary(input.PendingPath, filepath.Dir(input.PendingPath)); err != nil {
		return floors, fmt.Errorf("[Linux install] 正式状态已提交，但 pending 清理未完成: %w", err)
	}
	return floors, nil
}

func validateCompletionInstallPaths(input LinuxEnrollmentCompletionInstallV1) error {
	paths := []string{input.StatePath, input.IdentityPath, input.PendingPath}
	seen := make(map[string]struct{}, len(paths)+len(input.TemporaryPaths))
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("[Linux install] state/identity/pending path 必须是规范绝对路径")
		}
		if _, duplicate := seen[path]; duplicate {
			return errors.New("[Linux install] 正式与临时状态 path 禁止复用")
		}
		seen[path] = struct{}{}
	}
	pendingDirectory := filepath.Dir(input.PendingPath)
	for _, path := range input.TemporaryPaths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			filepath.Dir(path) != pendingDirectory {
			return errors.New("[Linux install] temporary path 必须位于 pending 的受保护目录")
		}
		if _, duplicate := seen[path]; duplicate || path == input.PendingPath+".lock" {
			return errors.New("[Linux install] temporary path 重复或指向 lock/formal state")
		}
		seen[path] = struct{}{}
	}
	return nil
}

func prepareLinuxEnrollmentInstallation(identity *EnrollmentIdentityV1, pending *PendingClaimV2,
	result *wire.EnrollmentClaimResultV2, envelopes []wire.SealedSecretEnvelopeV1,
	configs []InstalledConfigV1, mirrors []wire.DistributionMirrorRefV1,
) (*DeviceInstallationV1, error) {
	if identity == nil || pending == nil || result == nil || result.ResultArtifact == nil ||
		result.ResultArtifact.InitialDeviceView.Active == nil {
		return nil, errors.New("[Linux install] result/pending/identity 不完整")
	}
	refs := result.ResultArtifact.SecretArtifactRefs
	if len(refs) != len(envelopes) {
		return nil, errors.New("[Linux install] sealed envelopes 未 exact 覆盖 result refs")
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&pending.ClaimCore)
	if err != nil {
		return nil, err
	}
	_, wrappingPrivate, err := identity.keys()
	if err != nil {
		return nil, err
	}
	credentials, err := installLinuxSecrets(refs, envelopes,
		result.ResultArtifact.InitialDeviceView.DeviceID, identity.WrappingPublicKeySPKI,
		wrappingPrivate)
	if err != nil {
		return nil, err
	}
	if configs == nil || len(configs) != len(result.ResultArtifact.InitialDeviceView.Active.ConfigArtifactRefs) {
		return nil, errors.New("[Linux install] config artifacts 未 exact 覆盖 initial view refs")
	}
	if err := validateLinuxInstalledConfigs(configs,
		result.ResultArtifact.InitialDeviceView.Active.ConfigArtifactRefs); err != nil {
		return nil, err
	}
	if err := wire.ValidateDistributionMirrorRefs(mirrors); err != nil {
		return nil, errors.New("[Linux install] distribution mirrors 无效")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(result.ResultArtifact)
	if err != nil {
		return nil, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return nil, err
	}
	installation := &DeviceInstallationV1{
		Schema: 1, ClaimCore: clonePrivateClientValue(pending.ClaimCore),
		ClaimCoreHash: pending.ClaimCoreHash, IdentityKeyHash: identityHash,
		WrappingKeyHash: wrappingHash, TransactionStateHash: result.TransactionStateHash,
		ResultArtifactHash: result.ResultArtifactHash, DeviceCertificateHash: certificateHash,
		ResultArtifact: clonePrivateClientValue(*result.ResultArtifact), Credentials: credentials,
		CurrentSecretArtifactRefs: cloneLinuxSecretArtifactRefs(refs),
		Configs:                   cloneStoreValue(configs),
		DistributionMirrors:       append([]wire.DistributionMirrorRefV1(nil), mirrors...),
	}
	return installation, nil
}

func installLinuxSecrets(refs []wire.SecretArtifactRefV2,
	envelopes []wire.SealedSecretEnvelopeV1, deviceID, wrappingSPKI string,
	wrappingPrivate *ecdsa.PrivateKey,
) ([]InstalledSecretV1, error) {
	if refs == nil || len(refs) != len(envelopes) || wrappingPrivate == nil {
		return nil, errors.New("[Linux install] sealed envelopes 未 exact 覆盖 refs")
	}
	credentials := make([]InstalledSecretV1, len(refs))
	totalBytes := 0
	for index := range refs {
		ref, envelope := &refs[index], &envelopes[index]
		if err := wire.VerifySealedSecretBinding(ref, envelope); err != nil {
			return nil, err
		}
		if ref.ClusterID != envelope.Context.ClusterID || ref.Owner.Kind != "device" ||
			ref.Owner.Device == nil || ref.Owner.Device.DeviceID != deviceID {
			return nil, errors.New("[Linux install] secret 未绑定当前 Device/cluster")
		}
		recipient, err := linuxWrappingRecipient(ref, deviceID, wrappingSPKI)
		if err != nil {
			return nil, err
		}
		secret, err := wire.UnsealSecretP256(envelope, recipient, wrappingPrivate)
		if err != nil {
			return nil, err
		}
		if len(secret) == 0 {
			return nil, errors.New("[Linux install] 解封 credential 不能为空")
		}
		totalBytes += len(secret)
		if totalBytes > 8<<20 {
			clear(secret)
			return nil, errors.New("[Linux install] credentials 超过总预算")
		}
		credentials[index] = InstalledSecretV1{
			SecretID: ref.SecretID, Purpose: ref.Purpose, Generation: ref.Generation,
			ImmutableRef: ref.ImmutableRef, SecretBytes: base64.RawURLEncoding.EncodeToString(secret),
			SecretDigest: wire.HashRaw("loom-linux-installed-secret-v1", secret),
		}
		clear(secret)
	}
	return credentials, nil
}

func linuxWrappingRecipient(ref *wire.SecretArtifactRefV2, deviceID, wrappingSPKI string) (wire.SealedBlobRecipientKeyRefV1, error) {
	if ref == nil || ref.SealedBlob == nil || deviceID == "" || wrappingSPKI == "" {
		return wire.SealedBlobRecipientKeyRefV1{}, errors.New("[Linux install] wrapping recipient context 无效")
	}
	var match *wire.SealedBlobRecipientKeyRefV1
	for index := range ref.SealedBlob.RecipientKeyVersions {
		candidate := &ref.SealedBlob.RecipientKeyVersions[index]
		if candidate.RecipientID == deviceID && candidate.RecipientKeyProfile == "p256-root-only-pkcs8-ecdh-v1" &&
			candidate.RecipientPublicKey.PublicKeySPKIDER == wrappingSPKI {
			if match != nil {
				return wire.SealedBlobRecipientKeyRefV1{}, errors.New("[Linux install] wrapping recipient 命中多个版本")
			}
			copy := *candidate
			match = &copy
		}
	}
	if match == nil {
		return wire.SealedBlobRecipientKeyRefV1{}, errors.New("[Linux install] secret 未封装给本机 exact wrapping key")
	}
	return *match, nil
}

func removeProtectedEnrollmentTemporary(path, expectedDirectory string) error {
	if filepath.Dir(path) != expectedDirectory {
		return errors.New("temporary path 逃逸受保护目录")
	}
	if err := secureEnrollmentDirectory(expectedDirectory); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!ownedByCurrentUser(info) {
		return errors.New("temporary artifact 必须是服务账号持有的 0600 普通文件")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(expectedDirectory)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}
