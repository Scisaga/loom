//go:build linux

package clientv2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"loom/internal/clientmigration"
	"loom/internal/wire"
)

type LinuxMigrationInstall struct {
	StatePath         string
	IdentityPath      string
	Package           wire.RuntimeDeviceMigrationPackageV1
	Expected          wire.RuntimeDeviceMigrationExpectedV1
	LegacyFloor       clientmigration.Floor
	Trust             wire.InviteProofTrustV2
	Now               time.Time
	Configs           []InstalledConfigV1
	ValidateCandidate func(*State) error
}

// PrepareLinuxMigration 验证原 floor、身份和 certified 迁移后才解封，生成完整候选。
// 正常宿主在安装前校验实际 runtime，不能先安装半套身份再补写配置。
func PrepareLinuxMigration(input LinuxMigrationInstall) (*State, error) {
	identity, err := LoadEnrollmentIdentityForResume(input.IdentityPath)
	if err != nil {
		return nil, err
	}
	public, err := base64.RawURLEncoding.DecodeString(identity.IdentityPublicKeySPKI)
	if err != nil {
		return nil, err
	}
	wrapping, err := base64.RawURLEncoding.DecodeString(identity.WrappingPublicKeySPKI)
	if err != nil {
		return nil, err
	}
	wrappingHash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrapping)
	if err != nil || input.Expected.Platform != "linux-server" || !bytes.Equal(input.Expected.IdentitySPKIDER, public) || input.Expected.WrappingKeyHash != wrappingHash {
		return nil, errors.New("[Linux migration] 原本机身份或 wrapping key 不一致")
	}
	original, err := base64.RawURLEncoding.DecodeString(input.Package.LegacySignedCurrent)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != input.Package.LegacySignedCurrent {
		return nil, errors.New("[Linux migration] 原 signed current 编码无效")
	}
	input.Expected.LegacyFloor, err = clientmigration.VerifyFloor(original, input.Trust.V1PlatformKey, input.Expected.DeviceID, input.LegacyFloor)
	if err != nil {
		return nil, err
	}
	verified, err := wire.VerifyRuntimeDeviceMigration(&input.Package, input.Expected, input.Trust, input.Now)
	if err != nil {
		return nil, err
	}
	envelope := verified.Configuration().Envelope()
	refs, err := decodeLinuxSecretArtifactRefs(envelope.SecretArtifactRefs)
	if err != nil {
		return nil, err
	}
	key, wrappingKey, err := identity.keys()
	if err != nil {
		return nil, err
	}
	defer clear(key.D.Bits())
	defer clear(wrappingKey.D.Bits())
	credentials, err := installLinuxSecrets(refs, input.Package.Configuration.SecretEnvelopes, input.Expected.DeviceID, identity.WrappingPublicKeySPKI, wrappingKey)
	if err != nil {
		return nil, err
	}
	set, leaf := verified.Configuration().ControlSet(), verified.Leaf()
	state := &State{Schema: 1, Floors: verified.Configuration().Floors(), Envelope: envelope, ControlSet: &set,
		PreviousControlSet: verified.Configuration().PreviousControlSet(), Migration: &DeviceInstallationV1{Schema: 1,
			IdentityKeyHash: leaf.IdentitySPKIHash, WrappingKeyHash: leaf.WrappingKeyHash, DeviceCertificateHash: leaf.DeviceCertificateHash,
			Configs: cloneStoreValue(input.Configs), Credentials: credentials, CurrentSecretArtifactRefs: cloneLinuxSecretArtifactRefs(refs),
			DistributionMirrors: cloneStoreValue(input.Package.DistributionMirrors),
			MigrationProof: &LinuxMigrationEvidenceV1{Package: cloneStoreValue(input.Package), LegacyFloor: input.LegacyFloor,
				PlatformPublicKey: base64.RawURLEncoding.EncodeToString(input.Trust.V1PlatformKey), ApprovedAt: verified.ApprovedAt()}}}
	if input.Configs == nil {
		return nil, errors.New("[Linux migration] 运行制品尚未全部验证")
	}
	if err := validateStoredState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func InstallLinuxMigration(input LinuxMigrationInstall) (wire.ClientFloorsV2, error) {
	if input.StatePath == "" || !filepath.IsAbs(input.StatePath) || filepath.Clean(input.StatePath) != input.StatePath ||
		input.StatePath == input.IdentityPath || input.ValidateCandidate == nil {
		return wire.ClientFloorsV2{}, errors.New("[Linux migration] 缺安装路径或实际 runtime 预检")
	}
	state, err := PrepareLinuxMigration(input)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	before, err := wire.MarshalCanonical(state)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := input.ValidateCandidate(state); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	after, err := wire.MarshalCanonical(state)
	if err != nil || !bytes.Equal(before, after) {
		return wire.ClientFloorsV2{}, errors.New("[Linux migration] runtime 预检修改了已认证候选")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(input.StatePath)); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	lock, err := openPrivateLock(input.StatePath + ".lock")
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	store, err := Open(input.StatePath)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if store.state != nil {
		if !wire.EqualCanonical(store.state, state) {
			return store.Floors(), errors.New("[Linux migration] 已有 v2 状态不能被迁移包覆盖")
		}
		return store.Floors(), nil
	}
	if _, err := os.Lstat(input.StatePath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return wire.ClientFloorsV2{}, errors.New("[Linux migration] 安装路径在提交前变化")
	}
	if err := persist(input.StatePath, *state); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	replayed, err := Open(input.StatePath)
	if err != nil || !wire.EqualCanonical(replayed.state, state) {
		return wire.ClientFloorsV2{}, errors.New("[Linux migration] 安装后回读不一致")
	}
	return replayed.Floors(), nil
}

// ValidateLinuxMigrationRuntime 在提交身份之前验证完整配置与实际凭据的关系。
// 这里只准备配置；本机二进制预检和服务激活仍由正常 runtime deploy 事务执行。
func ValidateLinuxMigrationRuntime(state *State, peers *wire.ControlPeerDirectoryPrivateObjectV1, now time.Time) error {
	if state == nil || state.Migration == nil || state.Enrollment != nil {
		return errors.New("[Linux migration] 原身份迁移候选缺失")
	}
	linkRaw, err := LinuxInstalledConfigArtifact(state.Migration, LinuxLinkIntentArtifactID)
	if err != nil {
		return err
	}
	runtimeRaw, err := LinuxInstalledConfigArtifact(state.Migration, wire.LinuxRuntimeArtifactID)
	if err != nil {
		return err
	}
	plan, err := BuildLinuxLinkRuntimePlan(&state.Envelope, state.ControlSet, state.PreviousControlSet,
		peers, linkRaw, state.Migration.Credentials, now, nil)
	if err != nil {
		return err
	}
	var link wire.LinuxLinkIntentArtifactV1
	if _, err := wire.DecodeStrict(linkRaw, 4<<20, &link); err != nil {
		return err
	}
	var artifact wire.LinuxRuntimeArtifactV1
	canonical, err := wire.DecodeStrict(runtimeRaw, maximumLinuxConfigArtifact, &artifact)
	if err != nil || !bytes.Equal(canonical, runtimeRaw) || wire.ValidateLinuxRuntimeArtifact(&artifact) != nil {
		return errors.New("[Linux migration] Linux runtime 制品无效")
	}
	linkHash, err := wire.DeviceConfigArtifactContentHash(linkRaw)
	if err != nil {
		return err
	}
	if artifact.ClusterID != plan.ClusterID || artifact.DeviceID != plan.DeviceID ||
		artifact.DeviceGeneration != plan.DeviceGeneration || artifact.LinkIntentGeneration != plan.ArtifactGeneration ||
		artifact.LinkIntentContentHash != linkHash {
		return errors.New("[Linux migration] Linux runtime 与 certified LinkIntent 不一致")
	}
	if err := bindLinuxRuntimeArtifactRef(&artifact, runtimeRaw, state.Envelope.Payload.Active.ConfigArtifactRefs); err != nil {
		return err
	}
	if err := wire.ValidateLinuxRuntimeRedaction(&artifact, &link); err != nil {
		return err
	}
	if err := validateLinuxRuntimeBindings(&plan, &artifact); err != nil {
		return err
	}
	_, err = hydrateLinuxRuntimeFiles(&plan, &artifact, state.Migration.Credentials)
	return err
}
