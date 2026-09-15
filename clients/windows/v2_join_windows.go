//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"loom/internal/clientcomponent"
	"loom/internal/clientsecret"
	"loom/internal/clientv2"
	"loom/internal/windowsv2"
	"loom/internal/wire"
)

const windowsV2ClientProtocol = 2

func encodeWindowsV2Carrier(carrier windowsv2.EnrollmentCarrier) (string, error) {
	if err := carrier.ValidateShape(); err != nil {
		return "", err
	}
	var value any = carrier.Invite
	if carrier.Resume != nil {
		value = carrier.Resume
	}
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func windowsV2StatePath(root string) string {
	return filepath.Join(root, "state", "client-v2.json.dpapi")
}

func windowsV2IdentityPath(root string) string {
	return filepath.Join(root, "join", "identity-v2.json.dpapi")
}

func windowsV2JournalPath(root string) string {
	return filepath.Join(root, "join", "enrollment-v2.json.dpapi")
}

func windowsV2ReportJournalPath(root string) string {
	return filepath.Join(root, "state", "device-report-v2.json.dpapi")
}

func windowsV2Installed(root string, protector clientsecret.Protector) (*windowsv2.StateV1, error) {
	store, err := windowsv2.OpenState(windowsV2StatePath(root), protector)
	if err != nil {
		return nil, err
	}
	state := store.Snapshot()
	if state != nil && state.Envelope.Payload.State == "active" {
		if err := windowsv2.CleanupInstalledEnrollmentJournal(windowsV2StatePath(root),
			windowsV2IdentityPath(root), windowsV2JournalPath(root), protector); err != nil {
			return nil, fmt.Errorf("补完 Windows v2 enrollment journal 清理: %w", err)
		}
	}
	return state, nil
}

func windowsJoinedDeviceID(root string,
	protector clientsecret.Protector) (string, bool, error) {
	state, err := windowsV2Installed(root, protector)
	if err != nil {
		return "", true, err
	}
	if state != nil {
		if state.Envelope.Payload.DeviceID == "" {
			return "", true, errors.New("Windows v2 LKG 缺 Device identity")
		}
		return state.Envelope.Payload.DeviceID, true, nil
	}
	if _, err := os.Lstat(filepath.Join(root, "config", "client.json")); err == nil {
		return "", false, errWindowsMigrationRequired
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	return "", false, os.ErrNotExist
}

func windowsV2RecoveryExists(root string) (bool, error) {
	found := false
	for _, path := range []string{windowsV2IdentityPath(root), windowsV2JournalPath(root)} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("Windows v2 加入恢复材料必须是普通文件")
		}
		found = true
	}
	return found, nil
}

// ensureWindowsV2Joined 是 GUI、Portable 与 Installed broker 共用的 v2
// transaction。加入本身不启动数据面，也不改路由。
func ensureWindowsV2Joined(ctx context.Context, root string, protector clientsecret.Protector,
	carrier windowsv2.EnrollmentCarrier, progress windowsJoinProgress,
) (windowsJoinResult, error) {
	if ctx == nil || protector == nil || root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return windowsJoinResult{}, errors.New("Windows v2 加入依赖不完整")
	}
	hasCarrier := carrier.Invite != nil || carrier.Resume != nil
	if hasCarrier {
		if err := carrier.ValidateShape(); err != nil {
			return windowsJoinResult{}, err
		}
	}
	state, err := windowsV2Installed(root, protector)
	if err != nil {
		return windowsJoinResult{}, fmt.Errorf("读取 Windows v2 LKG: %w", err)
	}
	if state != nil {
		if hasCarrier {
			return windowsJoinResult{}, errors.New("客户端已经加入 v2 网络；不能导入另一份加入或续传凭据")
		}
		return windowsJoinResult{NodeID: state.Envelope.Payload.DeviceID}, nil
	}
	if _, err := os.Lstat(filepath.Join(root, "config", "client.json")); err == nil {
		return windowsJoinResult{}, errWindowsMigrationRequired
	} else if !errors.Is(err, os.ErrNotExist) {
		return windowsJoinResult{}, err
	}
	if !hasCarrier {
		pending, err := windowsV2RecoveryExists(root)
		if err != nil {
			return windowsJoinResult{}, err
		}
		if !pending {
			return windowsJoinResult{}, errWindowsJoinInputRequired
		}
	}

	lock, err := acquireWindowsJoinLock()
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer lock.close()
	state, err = windowsV2Installed(root, protector)
	if err != nil {
		return windowsJoinResult{}, err
	}
	if state != nil {
		if hasCarrier {
			return windowsJoinResult{}, errors.New("客户端已经加入 v2 网络；不能导入另一份凭据")
		}
		return windowsJoinResult{NodeID: state.Envelope.Payload.DeviceID}, nil
	}

	progress.report("正在验证本地数据面组件…")
	componentPath, err := bundledWindowsComponentPath()
	if err != nil {
		return windowsJoinResult{}, err
	}
	platformKey, err := embeddedWindowsPlatformKey()
	if err != nil {
		return windowsJoinResult{}, err
	}
	componentBody, _, err := prepareWindowsJoinComponent(windowsJoinCommitOptions{
		Root: root, ComponentPath: componentPath, Protector: protector,
		Arch: runtime.GOARCH, PlatformKey: platformKey, Progress: progress,
	})
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer clear(componentBody)

	recovery, recoveryErr := windowsv2.LoadEnrollmentRecovery(
		windowsV2IdentityPath(root), windowsV2JournalPath(root), protector)
	if recoveryErr != nil && !errors.Is(recoveryErr, os.ErrNotExist) {
		return windowsJoinResult{}, fmt.Errorf("读取 Windows v2 加入恢复事务: %w", recoveryErr)
	}
	if errors.Is(recoveryErr, os.ErrNotExist) && !hasCarrier {
		return windowsJoinResult{}, errWindowsJoinInputRequired
	}
	if recoveryErr == nil {
		if carrier.Invite != nil && recovery.Committed {
			return windowsJoinResult{}, windowsv2.ErrResumeRequired
		}
		if !hasCarrier {
			if recovery.ResumeDescriptor != nil {
				carrier.Resume = recovery.ResumeDescriptor
			} else if recovery.Committed {
				return windowsJoinResult{}, windowsv2.ErrResumeRequired
			} else {
				descriptor := recovery.Descriptor
				carrier.Invite = &descriptor
			}
		}
	}
	if carrier.Resume != nil && recoveryErr != nil {
		return windowsJoinResult{}, errors.New("本机没有与 .loom-resume 匹配的 protected pending transaction")
	}

	joinContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	fetcher := clientv2.MirrorFetcher{Timeout: 30 * time.Second}
	progress.report("正在验证 Invite authority 与 bootstrap catalog…")
	var descriptorMirrors []wire.DistributionMirrorRefV1
	var bundle *wire.InviteProofBundleV2
	var verifiedProof wire.VerifiedInviteProofV2
	var catalog *wire.BootstrapEndpointCatalogV1
	var capability *wire.BootstrapTunnelCapabilityV1
	var serviceRef wire.PrivateEnrollmentServiceRefV1
	var requestID string
	if carrier.Invite != nil {
		descriptor := carrier.Invite
		bundle, verifiedProof, err = fetchAndVerifyWindowsInviteProof(joinContext, fetcher,
			descriptor.DistributionMirrors, descriptor.ProofBundleHash, platformKey,
			func(bundle *wire.InviteProofBundleV2, trust wire.InviteProofTrustV2) (wire.VerifiedInviteProofV2, error) {
				return wire.VerifyInviteProofBundle(bundle, descriptor, time.Now().UTC(), trust)
			})
		if err == nil {
			catalog, err = fetcher.FetchBootstrapCatalogFromInviteProof(joinContext,
				descriptor, time.Now().UTC(), windowsV2ClientProtocol, verifiedProof)
		}
		if err != nil {
			return windowsJoinResult{}, err
		}
		descriptorMirrors = descriptor.DistributionMirrors
		capability, serviceRef = &descriptor.BootstrapTunnelCapability, descriptor.EnrollmentServiceRef
		if recoveryErr == nil {
			requestID = recovery.RequestID
		} else {
			requestID, err = windowsv2.NewRequestID(nil)
			if err != nil {
				return windowsJoinResult{}, err
			}
		}
	} else {
		descriptor := carrier.Resume
		var trust wire.InviteProofTrustV2
		bundle, verifiedProof, trust, err = fetchAndVerifyWindowsResumeProof(joinContext,
			fetcher, descriptor, platformKey)
		if err == nil {
			catalog, err = fetcher.FetchResumeBootstrapCatalog(joinContext, descriptor,
				time.Now().UTC(), windowsV2ClientProtocol, verifiedProof)
		}
		if err != nil {
			return windowsJoinResult{}, err
		}
		_ = trust
		descriptorMirrors = descriptor.DistributionMirrors
		capability, serviceRef = &descriptor.ResumeTunnelCapability, descriptor.EnrollmentServiceRef
		requestID = recovery.RequestID
	}

	tunnel, err := clientv2.NewBootstrapTunnelDialer(catalog, capability,
		&bundle.BootstrapIssuerAuthorizationProof, &bundle.InviteIssuancePolicy,
		verifiedProof, time.Now().UTC(), windowsV2ClientProtocol, nil)
	if err != nil {
		return windowsJoinResult{}, err
	}
	api, err := clientv2.NewPrivateEnrollmentClient(serviceRef, nil, tunnel.DialContext,
		time.Now, 30*time.Second)
	if err != nil {
		return windowsJoinResult{}, err
	}
	defer api.CloseIdleConnections()
	progress.report("正在通过受限 bootstrap 隧道验证并提交 Device 身份…")
	var result windowsv2.EnrollmentAttemptResult
	if carrier.Invite != nil {
		result, err = windowsv2.RunEnrollmentAttempt(joinContext, windowsv2.EnrollmentAttempt{
			Descriptor: carrier.Invite, ProofBundle: bundle, VerifiedProof: verifiedProof, API: api,
			IdentityPath: windowsV2IdentityPath(root), JournalPath: windowsV2JournalPath(root),
			Protector: protector, RequestID: requestID, Now: time.Now,
		})
	} else {
		trust := windowsInviteProofTrust(bundle, platformKey)
		result, err = windowsv2.RunResumeAttempt(joinContext, windowsv2.ResumeAttempt{
			Descriptor: carrier.Resume, ProofBundle: bundle, Catalog: catalog, Trust: trust, API: api,
			IdentityPath: windowsV2IdentityPath(root), JournalPath: windowsV2JournalPath(root),
			Protector: protector, ClientProtocol: windowsV2ClientProtocol, Now: time.Now,
		})
	}
	if err != nil {
		return windowsJoinResult{}, err
	}
	if result.Result.Status != "completed" || result.Result.ResultArtifact == nil {
		return windowsJoinResult{}, errors.New("Device claim 已 durable 提交并等待管理员处理；完成后请导入对应 .loom-resume")
	}
	if result.Result.ResultArtifact.InitialDeviceView.State != "active" ||
		result.Result.ResultArtifact.InitialDeviceView.Active == nil {
		return windowsJoinResult{}, errors.New("completed Enrollment 缺 active initial Device view")
	}
	progress.report("正在获取并核对 sealed credentials 与配置制品…")
	secretEnvelopes, err := api.FetchReleasedArtifacts(joinContext, result.Result)
	if err != nil {
		return windowsJoinResult{}, err
	}
	configs, err := windowsv2.FetchConfigArtifacts(joinContext, descriptorMirrors,
		result.Result.ResultArtifact.InitialDeviceView.Active.ConfigArtifactRefs, fetcher)
	if err != nil {
		return windowsJoinResult{}, err
	}
	if _, err := clientcomponent.InstallWindows(root, componentBody, platformKey); err != nil {
		return windowsJoinResult{}, fmt.Errorf("安装已签名 Windows data plane: %w", err)
	}
	progress.report("正在原子提交 Windows v2 LKG…")
	if _, err := windowsv2.InstallCompletion(windowsv2.CompletionInstall{
		StatePath: windowsV2StatePath(root), IdentityPath: windowsV2IdentityPath(root),
		JournalPath: windowsV2JournalPath(root), Protector: protector,
		Result: result.Result, Completion: result.Completion, VerifiedProof: verifiedProof,
		SecretEnvelopes: secretEnvelopes, Configs: configs,
		ValidateCandidate: func(candidate *windowsv2.StateV1) error {
			return preflightWindowsV2InstallCandidate(joinContext, root, candidate, platformKey)
		},
	}); err != nil {
		return windowsJoinResult{}, err
	}
	return windowsJoinResult{NodeID: result.Result.ResultArtifact.InitialDeviceView.DeviceID}, nil
}

func fetchAndVerifyWindowsInviteProof(ctx context.Context, fetcher clientv2.MirrorFetcher,
	mirrors []wire.DistributionMirrorRefV1, proofHash string, platformKey ed25519.PublicKey,
	verify func(*wire.InviteProofBundleV2, wire.InviteProofTrustV2) (wire.VerifiedInviteProofV2, error),
) (*wire.InviteProofBundleV2, wire.VerifiedInviteProofV2, error) {
	body, err := fetcher.FetchCanonicalObject(ctx, mirrors, proofHash,
		wire.DomainInviteProofBundle, clientv2.MaximumBootstrapObjectSize)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, err
	}
	var bundle wire.InviteProofBundleV2
	canonical, err := wire.DecodeStrict(body, clientv2.MaximumBootstrapObjectSize, &bundle)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, wire.VerifiedInviteProofV2{}, errors.New("Windows v2 Invite proof 不是 exact canonical wire")
	}
	verified, err := verify(&bundle, windowsInviteProofTrust(&bundle, platformKey))
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, err
	}
	return &bundle, verified, nil
}

func fetchAndVerifyWindowsResumeProof(ctx context.Context, fetcher clientv2.MirrorFetcher,
	descriptor *wire.EnrollmentResumeDescriptorV1, platformKey ed25519.PublicKey,
) (*wire.InviteProofBundleV2, wire.VerifiedInviteProofV2, wire.InviteProofTrustV2, error) {
	body, err := fetcher.FetchCanonicalObject(ctx, descriptor.DistributionMirrors,
		descriptor.ProofBundleHash, wire.DomainInviteProofBundle, clientv2.MaximumBootstrapObjectSize)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, wire.InviteProofTrustV2{}, err
	}
	var bundle wire.InviteProofBundleV2
	canonical, err := wire.DecodeStrict(body, clientv2.MaximumBootstrapObjectSize, &bundle)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, wire.VerifiedInviteProofV2{}, wire.InviteProofTrustV2{},
			errors.New("Windows v2 resume proof 不是 exact canonical wire")
	}
	trust := windowsInviteProofTrust(&bundle, platformKey)
	verified, err := wire.VerifyResumeInviteProofBundle(&bundle, descriptor, time.Now().UTC(), trust)
	if err != nil {
		return nil, wire.VerifiedInviteProofV2{}, wire.InviteProofTrustV2{}, err
	}
	return &bundle, verified, trust, nil
}

func windowsInviteProofTrust(bundle *wire.InviteProofBundleV2,
	platformKey ed25519.PublicKey) wire.InviteProofTrustV2 {
	digest := sha256.Sum256(platformKey)
	return wire.InviteProofTrustV2{
		V1PlatformKey:           append(ed25519.PublicKey(nil), platformKey...),
		V1PlatformKeyID:         bundle.PlatformKeyID(),
		V1MigrationAnchorDigest: "sha256:" + hex.EncodeToString(digest[:]),
	}
}
