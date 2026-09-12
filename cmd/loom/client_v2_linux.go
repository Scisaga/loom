//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"loom/internal/clientv2"
	"loom/internal/wire"
)

const linuxClientV2Protocol = 2

type linuxClientV2Paths struct {
	state    string
	identity string
	pending  string
}

type linuxClientV2TrustFlags struct {
	platformPublicKey string
	platformKeyID     string
	migrationAnchor   string
}

type linuxClientV2CommonFlags struct {
	stateDirectory          string
	paths                   linuxClientV2Paths
	trust                   linuxClientV2TrustFlags
	secretEnvelopes         repeatedFlag
	secretEnvelopeDirectory string
	timeout                 time.Duration
}

func cmdClientEnrollV2(args []string) error {
	fs := flag.NewFlagSet("client enroll-v2", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inviteFile := fs.String("invite-file", "", "exact canonical .loom-invite；- 表示 stdin")
	inviteURI := fs.String("invite-uri", "", "紧凑 loom://enroll/v2 URI；可能进入 shell history")
	var common linuxClientV2CommonFlags
	addLinuxClientV2Flags(fs, &common)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*inviteFile == "") == (*inviteURI == "") ||
		common.timeout < time.Second {
		return errors.New("用法: loom client enroll-v2 {-invite-file <file|->|-invite-uri <URI>} [-secret-envelope <file>] [-state-dir <dir>]")
	}
	if err := common.resolvePaths(); err != nil {
		return err
	}
	if *inviteURI != "" {
		fmt.Fprintln(os.Stderr, "! -invite-uri 可能进入 shell history；生产环境优先使用 -invite-file 或 stdin。")
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	var err error
	if *inviteFile != "" {
		descriptor, err = clientv2.ReadLinuxInviteDescriptor(*inviteFile, os.Stdin)
	} else {
		descriptor, err = clientv2.DecodeInviteURI(*inviteURI)
	}
	if err != nil {
		return err
	}
	if installed, err := linuxClientV2Installed(common.paths, descriptor.ClusterID, descriptor.InviteID); err != nil {
		return err
	} else if installed {
		fmt.Println("✓ Linux v2 Device 已安装；未重新消费 Invite 或生成 identity")
		return nil
	}
	trust, err := linuxClientV2Trust(common.trust, false)
	if err != nil {
		return err
	}
	requestID, err := linuxClientV2RequestID(common.paths, descriptor.ClusterID, descriptor.InviteID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	fetcher := clientv2.MirrorFetcher{Timeout: linuxClientV2NetworkTimeout(common.timeout)}
	bundle, verifiedProof, err := fetcher.FetchAndVerifyInviteProof(ctx, &descriptor, now, trust)
	if err != nil {
		return err
	}
	catalog, err := fetcher.FetchBootstrapCatalogFromInviteProof(ctx, &descriptor, now,
		linuxClientV2Protocol, verifiedProof)
	if err != nil {
		return err
	}
	tunnel, err := clientv2.NewLinuxBootstrapTunnelDialer(catalog,
		&descriptor.BootstrapTunnelCapability, &bundle.BootstrapIssuerAuthorizationProof,
		&bundle.InviteIssuancePolicy, verifiedProof, now, linuxClientV2Protocol, nil)
	if err != nil {
		return err
	}
	api, err := clientv2.NewPrivateEnrollmentClient(descriptor.EnrollmentServiceRef, nil,
		tunnel.DialContext, time.Now, linuxClientV2NetworkTimeout(common.timeout))
	if err != nil {
		return err
	}
	defer api.CloseIdleConnections()
	result, err := clientv2.RunLinuxEnrollmentAttempt(ctx, clientv2.LinuxEnrollmentAttemptV2{
		Descriptor: &descriptor, ProofBundle: bundle, VerifiedProof: verifiedProof, API: api,
		IdentityPath: common.paths.identity, PendingPath: common.paths.pending,
		RequestID: requestID, Now: time.Now,
	})
	if err != nil {
		return err
	}
	return finishLinuxClientV2Enrollment(ctx, common, result, verifiedProof, tunnel, api)
}

func cmdClientResumeV2(args []string) error {
	fs := flag.NewFlagSet("client resume-v2", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resumeFile := fs.String("resume-file", "", "exact canonical .loom-resume；- 表示 stdin")
	var common linuxClientV2CommonFlags
	addLinuxClientV2Flags(fs, &common)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *resumeFile == "" || common.timeout < time.Second {
		return errors.New("用法: loom client resume-v2 -resume-file <file|-> -v1-platform-pubkey <file> -v1-platform-key-id <id> -v1-migration-anchor <sha256:...> [-secret-envelope <file>] [-state-dir <dir>]")
	}
	if err := common.resolvePaths(); err != nil {
		return err
	}
	descriptor, err := clientv2.ReadLinuxResumeDescriptor(*resumeFile, os.Stdin)
	if err != nil {
		return err
	}
	if installed, err := linuxClientV2Installed(common.paths, descriptor.ClusterID, descriptor.InviteID); err != nil {
		return err
	} else if installed {
		fmt.Println("✓ Linux v2 Device 已安装；未重新打开 bootstrap capability")
		return nil
	}
	trust, err := linuxClientV2Trust(common.trust, true)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	fetcher := clientv2.MirrorFetcher{Timeout: linuxClientV2NetworkTimeout(common.timeout)}
	bundle, verifiedProof, err := fetcher.FetchAndVerifyResumeInviteProof(ctx, &descriptor, now, trust)
	if err != nil {
		return err
	}
	catalog, err := fetcher.FetchResumeBootstrapCatalog(ctx, &descriptor, now,
		linuxClientV2Protocol, verifiedProof)
	if err != nil {
		return err
	}
	tunnel, err := clientv2.NewLinuxBootstrapTunnelDialer(catalog,
		&descriptor.ResumeTunnelCapability, &bundle.BootstrapIssuerAuthorizationProof,
		&bundle.InviteIssuancePolicy, verifiedProof, now, linuxClientV2Protocol, nil)
	if err != nil {
		return err
	}
	api, err := clientv2.NewPrivateEnrollmentClient(descriptor.EnrollmentServiceRef, nil,
		tunnel.DialContext, time.Now, linuxClientV2NetworkTimeout(common.timeout))
	if err != nil {
		return err
	}
	defer api.CloseIdleConnections()
	result, err := clientv2.RunLinuxResumeAttempt(ctx, clientv2.LinuxResumeAttemptV1{
		Descriptor: &descriptor, ProofBundle: bundle, Catalog: catalog, Trust: trust, API: api,
		IdentityPath: common.paths.identity, PendingPath: common.paths.pending,
		ClientProtocol: linuxClientV2Protocol, Now: time.Now,
	})
	if err != nil {
		return err
	}
	return finishLinuxClientV2Enrollment(ctx, common, result, verifiedProof, tunnel, api)
}

func addLinuxClientV2Flags(fs *flag.FlagSet, common *linuxClientV2CommonFlags) {
	common.stateDirectory = "/var/lib/loom/client-v2"
	common.timeout = 5 * time.Minute
	fs.StringVar(&common.stateDirectory, "state-dir", common.stateDirectory, "root-owned v2 identity/pending/LKG 目录")
	fs.DurationVar(&common.timeout, "timeout", common.timeout, "本次 bootstrap/Enrollment 总时限")
	fs.StringVar(&common.trust.platformPublicKey, "v1-platform-pubkey", "", "可选/恢复时必需：带外 v1 platform Ed25519 公钥")
	fs.StringVar(&common.trust.platformKeyID, "v1-platform-key-id", "", "可选/恢复时必需：v1 platform key ID")
	fs.StringVar(&common.trust.migrationAnchor, "v1-migration-anchor", "", "可选/恢复时必需：v1 migration anchor digest")
	fs.Var(&common.secretEnvelopes, "secret-envelope", "完成态 sealed envelope 文件；按 result ref 规范顺序重复")
	fs.StringVar(&common.secretEnvelopeDirectory, "secret-envelope-dir", "",
		"完成态私有 artifact 目录；文件名为 <ciphertext sha256 hex>.json")
}

func (common *linuxClientV2CommonFlags) resolvePaths() error {
	if common == nil || common.stateDirectory == "" || !filepath.IsAbs(common.stateDirectory) ||
		filepath.Clean(common.stateDirectory) != common.stateDirectory {
		return errors.New("[D106 Linux] state-dir 必须是规范绝对路径")
	}
	common.paths = linuxClientV2Paths{
		state:    filepath.Join(common.stateDirectory, "state.json"),
		identity: filepath.Join(common.stateDirectory, "identity.json"),
		pending:  filepath.Join(common.stateDirectory, "pending.json"),
	}
	if common.secretEnvelopeDirectory != "" && len(common.secretEnvelopes) != 0 {
		return errors.New("[D124 Linux install] -secret-envelope 与 -secret-envelope-dir 不能同时使用")
	}
	if common.secretEnvelopeDirectory != "" && (!filepath.IsAbs(common.secretEnvelopeDirectory) ||
		filepath.Clean(common.secretEnvelopeDirectory) != common.secretEnvelopeDirectory) {
		return errors.New("[D124 Linux install] secret-envelope-dir 必须是规范绝对路径")
	}
	return nil
}

func linuxClientV2Trust(flags linuxClientV2TrustFlags, required bool) (wire.InviteProofTrustV2, error) {
	present := 0
	for _, value := range []string{flags.platformPublicKey, flags.platformKeyID, flags.migrationAnchor} {
		if value != "" {
			present++
		}
	}
	if present == 0 && !required {
		return wire.InviteProofTrustV2{}, nil
	}
	if present != 3 {
		return wire.InviteProofTrustV2{}, errors.New("[D115 Linux] v1 platform pubkey/key ID/migration anchor 必须成组提供")
	}
	publicKey, err := readKey(flags.platformPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return wire.InviteProofTrustV2{}, err
	}
	if _, err := wire.ParseHash(flags.migrationAnchor); err != nil {
		return wire.InviteProofTrustV2{}, errors.New("[D115 Linux] v1 migration anchor digest 无效")
	}
	return wire.InviteProofTrustV2{V1PlatformKey: ed25519.PublicKey(publicKey),
		V1PlatformKeyID: flags.platformKeyID, V1MigrationAnchorDigest: flags.migrationAnchor}, nil
}

func linuxClientV2RequestID(paths linuxClientV2Paths, clusterID, inviteID string) (string, error) {
	if _, err := os.Lstat(paths.pending); err == nil {
		identity, err := clientv2.LoadEnrollmentIdentityForResume(paths.identity)
		if err != nil {
			return "", err
		}
		pending, err := clientv2.LoadPendingClaimForResume(paths.pending, identity)
		if err != nil {
			return "", err
		}
		if pending.ClaimCore.ClusterID != clusterID || pending.ClaimCore.InviteID != inviteID {
			return "", errors.New("[D130 Linux] existing pending 属于另一个 cluster/Invite")
		}
		return pending.ClaimCore.RequestID, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", errors.New("[D129 Linux] request ID entropy 不可用")
	}
	return "linux-" + hex.EncodeToString(random), nil
}

func linuxClientV2Installed(paths linuxClientV2Paths, clusterID, inviteID string) (bool, error) {
	store, err := clientv2.Open(paths.state)
	if err != nil {
		return false, err
	}
	installation := store.Enrollment()
	if installation == nil {
		return false, nil
	}
	core := installation.ClaimCore
	if core.ClusterID != clusterID || core.InviteID != inviteID {
		return false, errors.New("[D130 Linux] existing installation 属于另一个 cluster/Invite")
	}
	return true, nil
}

func finishLinuxClientV2Enrollment(ctx context.Context, common linuxClientV2CommonFlags,
	result clientv2.LinuxEnrollmentAttemptResultV2, proof wire.VerifiedInviteProofV2,
	tunnel *clientv2.LinuxBootstrapTunnelDialer, api *clientv2.PrivateEnrollmentClient) error {
	selection, ok := tunnel.Selection()
	if !ok {
		return errors.New("[D131 Linux bootstrap] Enrollment 未产生真实 ingress 选择")
	}
	if result.Result.Status != "completed" {
		fmt.Printf("✓ Linux v2 Enrollment 已安全提交，等待 certified completion\n")
		fmt.Printf("  ingress      %s / generation %d（endpoint 已脱敏）\n",
			selection.Transport, selection.ListenerGeneration)
		fmt.Printf("  status       %s\n", result.Result.Status)
		fmt.Printf("  resume state %s\n", common.paths.pending)
		return nil
	}
	var envelopes []wire.SealedSecretEnvelopeV1
	var err error
	if len(common.secretEnvelopes) == 0 && common.secretEnvelopeDirectory == "" {
		envelopes, err = api.FetchReleasedArtifacts(ctx, result.Result)
	} else {
		envelopes, err = readLinuxClientV2Envelopes(common.secretEnvelopes,
			common.secretEnvelopeDirectory, result.Result.ResultArtifact.SecretArtifactRefs)
	}
	if err != nil {
		return err
	}
	wantEnvelopeCount := len(result.Result.ResultArtifact.SecretArtifactRefs)
	if len(envelopes) != wantEnvelopeCount {
		return fmt.Errorf("[D124 Linux install] completion 需要 %d 个 exact sealed envelope，得到 %d 个；正式 state 尚未提交",
			wantEnvelopeCount, len(envelopes))
	}
	floors, err := clientv2.InstallLinuxEnrollmentCompletion(clientv2.LinuxEnrollmentCompletionInstallV1{
		StatePath: common.paths.state, IdentityPath: common.paths.identity, PendingPath: common.paths.pending,
		Result: result.Result, Completion: result.Completion, VerifiedProof: proof, SecretEnvelopes: envelopes,
	})
	if err != nil {
		return err
	}
	fmt.Printf("✓ Linux v2 Enrollment 已经原子安装正式 identity/view/config/floors\n")
	fmt.Printf("  ingress      %s / generation %d（endpoint 已脱敏）\n",
		selection.Transport, selection.ListenerGeneration)
	fmt.Printf("  floors       recovery=%d control=%d revision=%d device=%d\n",
		floors.AcceptedRecoveryEpoch, floors.AcceptedControlEpoch,
		floors.AcceptedControlRevision, floors.DeviceGeneration)
	return nil
}

func readLinuxClientV2Envelopes(paths []string, directory string,
	refs []wire.SecretArtifactRefV2) ([]wire.SealedSecretEnvelopeV1, error) {
	if directory != "" {
		paths = make([]string, len(refs))
		for index := range refs {
			if refs[index].SealedBlob == nil {
				return nil, errors.New("[D124 Linux install] result ref 不是 sealed blob")
			}
			digest, err := wire.ParseHash(refs[index].SealedBlob.CiphertextDigest)
			if err != nil {
				return nil, err
			}
			paths[index] = filepath.Join(directory, hex.EncodeToString(digest)) + ".json"
		}
	}
	result := make([]wire.SealedSecretEnvelopeV1, len(paths))
	for index, path := range paths {
		body, err := readV2RegularFile(path, 4<<20)
		if err != nil {
			return nil, err
		}
		canonical, err := wire.DecodeStrict(body, 4<<20, &result[index])
		if err != nil || string(canonical) != string(body) {
			return nil, fmt.Errorf("[D124 Linux install] sealed envelope[%d] 不是 exact canonical wire", index)
		}
		if err := wire.ValidateSealedSecretEnvelope(&result[index]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func linuxClientV2NetworkTimeout(total time.Duration) time.Duration {
	if total < time.Second {
		return 0
	}
	if total > 5*time.Minute {
		return 5 * time.Minute
	}
	return total
}
