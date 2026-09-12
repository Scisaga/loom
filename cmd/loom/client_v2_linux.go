//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"loom/internal/clientv2"
	"loom/internal/deploy"
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

type linuxPrivateDeviceFlags struct {
	stateDirectory         string
	directoryPath          string
	pinnedDirectoryHash    string
	controlSetPath         string
	previousControlSetPath string
	internalCAPath         string
	serviceID              string
	timeout                time.Duration
}

type linuxPrivateDeviceInputs struct {
	statePath           string
	identityPath        string
	directory           wire.ControlServiceDirectoryV1
	pinnedDirectoryHash string
	controlSet          wire.ControlSetV1
	previousControlSet  *wire.ControlSetV1
	roots               *x509.CertPool
	serviceID           string
	timeout             time.Duration
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
	return finishLinuxClientV2Enrollment(ctx, common, result, verifiedProof,
		descriptor.DistributionMirrors, tunnel, api)
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
	return finishLinuxClientV2Enrollment(ctx, common, result, verifiedProof,
		descriptor.DistributionMirrors, tunnel, api)
}

func cmdClientSyncV2(args []string) error {
	fs := flag.NewFlagSet("client sync-v2-view", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var private linuxPrivateDeviceFlags
	addLinuxPrivateDeviceFlags(fs, &private)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("用法: loom client sync-v2-view [-state-dir <dir>] [-service-id <id>]（旧安装可另给 -directory/-directory-hash/-control-set/-internal-ca）")
	}
	inputs, err := readLinuxPrivateDeviceInputs(private)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), inputs.timeout)
	defer cancel()
	floors, err := clientv2.SyncLinuxDeviceView(ctx, clientv2.LinuxDeviceViewSyncOptions{
		StatePath: inputs.statePath, IdentityPath: inputs.identityPath,
		Directory: inputs.directory, PinnedDirectoryHash: inputs.pinnedDirectoryHash,
		ControlSet: inputs.controlSet, PreviousControlSet: inputs.previousControlSet,
		ServiceID: inputs.serviceID, Roots: inputs.roots, Now: time.Now, Timeout: inputs.timeout,
	})
	if err != nil {
		return err
	}
	fmt.Println("✓ Linux v2 private Device view 已同步并原子替换 LKG")
	fmt.Printf("  floors       recovery=%d control=%d revision=%d device=%d\n",
		floors.AcceptedRecoveryEpoch, floors.AcceptedControlEpoch,
		floors.AcceptedControlRevision, floors.DeviceGeneration)
	return nil
}

func cmdClientReportV2(args []string) error {
	fs := flag.NewFlagSet("client report-v2", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var private linuxPrivateDeviceFlags
	addLinuxPrivateDeviceFlags(fs, &private)
	payloadPath := fs.String("payload", "", "exact canonical Device report JSON object")
	kind := fs.String("kind", "", "certified reader contract kind")
	payloadSchema := fs.Int64("payload-schema", 0, "certified reader contract schema")
	journalPath := fs.String("journal", "", "root-only report sequence/pending journal")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *payloadPath == "" ||
		*kind == "" || *payloadSchema < 1 {
		return errors.New("用法: loom client report-v2 -payload <json> -kind <kind> -payload-schema <n> [-state-dir <dir>]（旧安装可另给 private directory 参数）")
	}
	inputs, err := readLinuxPrivateDeviceInputs(private)
	if err != nil {
		return err
	}
	payload, err := readV2RegularFile(*payloadPath, 1<<20)
	if err != nil {
		return err
	}
	if _, err := wire.DeviceReportPayloadHash(json.RawMessage(payload)); err != nil {
		return err
	}
	if *journalPath == "" {
		*journalPath = filepath.Join(private.stateDirectory, "device-report-journal.json")
	}
	if !filepath.IsAbs(*journalPath) || filepath.Clean(*journalPath) != *journalPath {
		return errors.New("[D131 Linux report] journal 必须是规范绝对路径")
	}
	ctx, cancel := context.WithTimeout(context.Background(), inputs.timeout)
	defer cancel()
	report, err := clientv2.SendLinuxDeviceReportDurable(ctx, *journalPath, clientv2.LinuxDeviceReportOptions{
		StatePath: inputs.statePath, IdentityPath: inputs.identityPath,
		Directory: inputs.directory, PinnedDirectoryHash: inputs.pinnedDirectoryHash,
		ControlSet: inputs.controlSet, PreviousControlSet: inputs.previousControlSet,
		ServiceID: inputs.serviceID, Roots: inputs.roots, Now: time.Now, Timeout: inputs.timeout,
		Kind: *kind, PayloadSchema: *payloadSchema, Payload: json.RawMessage(payload),
		Schemas: wire.DeviceReportSchemaRegistry{*kind: *payloadSchema},
	})
	if err != nil {
		return err
	}
	fmt.Println("✓ Linux v2 Device report 已持久化并获 private service 接受")
	fmt.Printf("  report       id=%s sequence=%d\n", report.Body.ReportID, report.Body.ReportSequence)
	return nil
}

func cmdClientAcceptV2Runtime(args []string) error {
	fs := flag.NewFlagSet("client accept-v2-runtime", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDirectory := fs.String("state-dir", "/var/lib/loom/client-v2", "root-owned v2 identity/LKG 目录")
	runtimeStatePath := fs.String("runtime-state", "", "root-only runtime plan/floors LKG")
	artifactPath := fs.String("link-intents", "", "current Device view 承诺的 exact LinkIntent artifact")
	runtimeArtifactPath := fs.String("runtime-artifact", "", "current Device view 承诺的 exact Linux runtime artifact")
	installStatePath := fs.String("install-state", "", "root-only installed runtime inventory/CAS LKG")
	controlSetPath := fs.String("control-set", "", "current exact ControlSetV1")
	previousControlSetPath := fs.String("previous-control-set", "", "joint Head 所需 previous exact ControlSetV1")
	peerDirectoryPath := fs.String("control-peer-directory", "", "control LinkIntent 所需 private directory object")
	applyRuntime := fs.Bool("apply", false, "验收后在本机事务安装 runtime")
	dryRun := fs.Bool("dry-run", false, "验收并构造事务，但不安装配置或改动服务")
	timeout := fs.Duration("timeout", 2*time.Minute, "本机事务安装超时")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("用法: loom client accept-v2-runtime [-apply|-dry-run] [-link-intents <json>] [-runtime-artifact <json>] [-control-peer-directory <json>] [-state-dir <dir>]（旧 LKG 可另给 -control-set）")
	}
	if *applyRuntime && *dryRun || *timeout < time.Second || *timeout > 10*time.Minute {
		return errors.New("[D131 Linux runtime] apply/dry-run/timeout 输入无效")
	}
	if !*applyRuntime && !*dryRun && (*runtimeArtifactPath != "" || *installStatePath != "") {
		return errors.New("[D131 Linux runtime] runtime-artifact/install-state 仅与 apply 或 dry-run 同用")
	}
	if *applyRuntime && os.Geteuid() != 0 {
		return errors.New("[D131 Linux runtime] -apply 必须由 root 在目标 Linux 节点执行")
	}
	if *stateDirectory == "" || !filepath.IsAbs(*stateDirectory) || filepath.Clean(*stateDirectory) != *stateDirectory {
		return errors.New("[D131 Linux runtime] state-dir 必须是规范绝对路径")
	}
	if *runtimeStatePath == "" {
		*runtimeStatePath = filepath.Join(*stateDirectory, "link-runtime-state.json")
	}
	if !filepath.IsAbs(*runtimeStatePath) || filepath.Clean(*runtimeStatePath) != *runtimeStatePath {
		return errors.New("[D131 Linux runtime] runtime-state 必须是规范绝对路径")
	}
	if *installStatePath == "" {
		*installStatePath = filepath.Join(*stateDirectory, clientv2.LinuxRuntimeInstallStateName)
	}
	if !filepath.IsAbs(*installStatePath) || filepath.Clean(*installStatePath) != *installStatePath {
		return errors.New("[D131 Linux runtime] install-state 必须是规范绝对路径")
	}
	var set *wire.ControlSetV1
	if *controlSetPath != "" {
		var decoded wire.ControlSetV1
		if err := readExactLinuxV2JSON(*controlSetPath, 1<<20, &decoded); err != nil {
			return err
		}
		set = &decoded
	}
	var previousSet *wire.ControlSetV1
	if *previousControlSetPath != "" {
		var decoded wire.ControlSetV1
		if err := readExactLinuxV2JSON(*previousControlSetPath, 1<<20, &decoded); err != nil {
			return err
		}
		previousSet = &decoded
	}
	var peerDirectory *wire.ControlPeerDirectoryPrivateObjectV1
	if *peerDirectoryPath != "" {
		var decoded wire.ControlPeerDirectoryPrivateObjectV1
		if err := readExactLinuxV2JSON(*peerDirectoryPath, 4<<20, &decoded); err != nil {
			return err
		}
		peerDirectory = &decoded
	}
	statePath := filepath.Join(*stateDirectory, "state.json")
	deviceStore, err := clientv2.Open(statePath)
	if err != nil {
		return err
	}
	envelope := deviceStore.Envelope()
	if envelope == nil {
		return errors.New("[D131 Linux runtime] durable Device LKG 缺失")
	}
	if envelope.Payload.State != "active" {
		if *artifactPath != "" || *runtimeArtifactPath != "" || *peerDirectoryPath != "" ||
			*controlSetPath != "" || *previousControlSetPath != "" {
			return errors.New("[D131 Linux runtime] terminal Device 下线不接受 runtime/authority 外部输入")
		}
		if !*applyRuntime && !*dryRun {
			return errors.New("[D131 Linux runtime] Device 已 terminal；使用 -dry-run 或 -apply 收敛本机 runtime")
		}
		plan, err := clientv2.PrepareLinuxRuntimeDecommission(*installStatePath, statePath)
		if err != nil {
			return err
		}
		if *dryRun {
			fmt.Printf("  dry-run      terminal=%s remove=%d retire-services=%d（未改动服务）\n",
				envelope.Payload.State, len(plan.Remove), len(plan.RetireServices()))
			return nil
		}
		if len(plan.Remove) == 0 {
			fmt.Printf("✓ Linux v2 runtime 已处于下线状态（Device %s）\n", envelope.Payload.State)
			return nil
		}
		runID := "client-v2-terminal-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if err := runScript(envelope.Payload.DeviceID, deploy.Script(plan, runID), "", true, *timeout); err != nil {
			return err
		}
		fmt.Printf("✓ Linux v2 runtime 已按 certified Device %s 事务下线\n", envelope.Payload.State)
		return nil
	}
	var artifactRaw []byte
	if *artifactPath != "" {
		artifactRaw, err = readV2RegularFile(*artifactPath, 4<<20)
	} else {
		artifactRaw, err = clientv2.LinuxInstalledConfigArtifact(
			deviceStore.Enrollment(), clientv2.LinuxLinkIntentArtifactID)
	}
	if err != nil {
		return err
	}
	runtimeState, err := clientv2.AcceptLinuxLinkRuntimePlan(*runtimeStatePath, statePath,
		envelope, set, previousSet, peerDirectory, artifactRaw, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Println("✓ Linux v2 LinkIntent 已验收并原子替换 runtime LKG")
	fmt.Printf("  generation   device=%d artifact=%d actions=%d\n",
		runtimeState.Plan.DeviceGeneration, runtimeState.Plan.ArtifactGeneration,
		len(runtimeState.Plan.Actions))
	if !*applyRuntime && !*dryRun {
		return nil
	}
	var runtimeRaw []byte
	if *runtimeArtifactPath != "" {
		runtimeRaw, err = readV2RegularFile(*runtimeArtifactPath, 16<<20)
	} else {
		runtimeRaw, err = clientv2.LinuxInstalledConfigArtifact(
			deviceStore.Enrollment(), wire.LinuxRuntimeArtifactID)
	}
	if err != nil {
		return err
	}
	plan, err := clientv2.PrepareLinuxRuntimeDeployment(*installStatePath, statePath,
		*runtimeStatePath, artifactRaw, runtimeRaw)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("  dry-run      files=%d remove=%d prechecks=%d services=%d（runtime LKG 已验收；未安装配置或改动服务）\n",
			len(plan.Files), len(plan.Remove), len(plan.PreCheck), len(plan.Services()))
		return nil
	}
	runID := "client-v2-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := runScript(runtimeState.DeviceID, deploy.Script(plan, runID), "", true, *timeout); err != nil {
		return err
	}
	fmt.Println("✓ Linux v2 runtime 已通过预检并事务安装；失败路径保留旧 LKG")
	return nil
}

func cmdClientUninstallV2Runtime(args []string) error {
	fs := flag.NewFlagSet("client uninstall-v2-runtime", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDirectory := fs.String("state-dir", "/var/lib/loom/client-v2", "root-owned v2 identity/LKG 目录")
	installStatePath := fs.String("install-state", "", "root-only installed runtime inventory/CAS LKG")
	applyRuntime := fs.Bool("apply", false, "事务停止服务并删除 inventory 中的 v2 runtime")
	dryRun := fs.Bool("dry-run", false, "只显示受影响的 v2 runtime，不修改本机")
	timeout := fs.Duration("timeout", 2*time.Minute, "本机事务卸载超时")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *applyRuntime == *dryRun {
		return errors.New("用法: loom client uninstall-v2-runtime <-apply|-dry-run> [-state-dir <dir>] [-timeout <duration>]")
	}
	if *timeout < time.Second || *timeout > 10*time.Minute {
		return errors.New("[D131 Linux runtime] uninstall timeout 输入无效")
	}
	if *applyRuntime && os.Geteuid() != 0 {
		return errors.New("[D131 Linux runtime] uninstall -apply 必须由 root 在目标 Linux 节点执行")
	}
	if *stateDirectory == "" || !filepath.IsAbs(*stateDirectory) ||
		filepath.Clean(*stateDirectory) != *stateDirectory {
		return errors.New("[D131 Linux runtime] state-dir 必须是规范绝对路径")
	}
	if *installStatePath == "" {
		*installStatePath = filepath.Join(*stateDirectory, clientv2.LinuxRuntimeInstallStateName)
	}
	if !filepath.IsAbs(*installStatePath) || filepath.Clean(*installStatePath) != *installStatePath ||
		filepath.Dir(*installStatePath) != *stateDirectory {
		return errors.New("[D131 Linux runtime] uninstall install-state 必须位于 state-dir")
	}
	plan, err := clientv2.PrepareLinuxRuntimeLocalUninstall(*installStatePath)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("  dry-run      remove=%d retire-services=%d（未改动；Device identity/LKG/floors 保留）\n",
			len(plan.Remove), len(plan.RetireServices()))
		return nil
	}
	if len(plan.Remove) == 0 {
		fmt.Println("✓ Linux v2 本机 runtime 已处于卸载状态；Device identity/LKG/floors 保留")
		return nil
	}
	runID := "client-v2-local-uninstall-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := runScript(plan.Node, deploy.Script(plan, runID), "", true, *timeout); err != nil {
		return err
	}
	fmt.Println("✓ Linux v2 本机 runtime 已事务卸载；Device identity/LKG/floors 保留，控制面授权未改变")
	return nil
}

func addLinuxPrivateDeviceFlags(fs *flag.FlagSet, flags *linuxPrivateDeviceFlags) {
	flags.stateDirectory = "/var/lib/loom/client-v2"
	flags.timeout = 30 * time.Second
	fs.StringVar(&flags.stateDirectory, "state-dir", flags.stateDirectory, "root-owned v2 identity/LKG 目录")
	fs.StringVar(&flags.directoryPath, "directory", "", "旧安装迁移用 exact private ControlServiceDirectoryV1")
	fs.StringVar(&flags.pinnedDirectoryHash, "directory-hash", "", "旧安装迁移用 root-owned directory hash pin")
	fs.StringVar(&flags.controlSetPath, "control-set", "", "旧安装迁移用 exact ControlSetV1")
	fs.StringVar(&flags.previousControlSetPath, "previous-control-set", "", "joint Head 所需 previous ControlSetV1")
	fs.StringVar(&flags.internalCAPath, "internal-ca", "", "旧安装迁移用 private service internal CA PEM")
	fs.StringVar(&flags.serviceID, "service-id", "", "directory 含多个同 role service 时的 exact ID")
	fs.DurationVar(&flags.timeout, "timeout", flags.timeout, "private request timeout")
}

func readLinuxPrivateDeviceInputs(flags linuxPrivateDeviceFlags) (linuxPrivateDeviceInputs, error) {
	if flags.stateDirectory == "" || !filepath.IsAbs(flags.stateDirectory) ||
		filepath.Clean(flags.stateDirectory) != flags.stateDirectory ||
		flags.timeout < time.Second || flags.timeout > 5*time.Minute {
		return linuxPrivateDeviceInputs{}, errors.New("[D131 Linux private] state/timeout 输入无效")
	}
	externalCount := 0
	for _, value := range []string{flags.directoryPath, flags.pinnedDirectoryHash,
		flags.controlSetPath, flags.internalCAPath} {
		if value != "" {
			externalCount++
		}
	}
	if externalCount == 0 {
		if flags.previousControlSetPath != "" {
			return linuxPrivateDeviceInputs{}, errors.New("[D131 Linux private] previous ControlSet 缺完整旧安装迁移上下文")
		}
		return linuxPrivateDeviceInputs{
			statePath:    filepath.Join(flags.stateDirectory, "state.json"),
			identityPath: filepath.Join(flags.stateDirectory, "identity.json"),
			serviceID:    flags.serviceID, timeout: flags.timeout,
		}, nil
	}
	if externalCount != 4 {
		return linuxPrivateDeviceInputs{}, errors.New("[D131 Linux private] 旧安装迁移必须同时提供 directory/hash/ControlSet/internal CA")
	}
	if _, err := wire.ParseHash(flags.pinnedDirectoryHash); err != nil {
		return linuxPrivateDeviceInputs{}, errors.New("[D131 Linux private] directory hash pin 无效")
	}
	var directory wire.ControlServiceDirectoryV1
	if err := readExactLinuxV2JSON(flags.directoryPath, 4<<20, &directory); err != nil {
		return linuxPrivateDeviceInputs{}, err
	}
	var set wire.ControlSetV1
	if err := readExactLinuxV2JSON(flags.controlSetPath, 1<<20, &set); err != nil {
		return linuxPrivateDeviceInputs{}, err
	}
	var previousSet *wire.ControlSetV1
	if flags.previousControlSetPath != "" {
		var decoded wire.ControlSetV1
		if err := readExactLinuxV2JSON(flags.previousControlSetPath, 1<<20, &decoded); err != nil {
			return linuxPrivateDeviceInputs{}, err
		}
		previousSet = &decoded
	}
	caBody, err := readV2RegularFile(flags.internalCAPath, 1<<20)
	if err != nil {
		return linuxPrivateDeviceInputs{}, err
	}
	roots, err := linuxInternalCAPool(caBody)
	if err != nil {
		return linuxPrivateDeviceInputs{}, err
	}
	return linuxPrivateDeviceInputs{
		statePath:    filepath.Join(flags.stateDirectory, "state.json"),
		identityPath: filepath.Join(flags.stateDirectory, "identity.json"),
		directory:    directory, pinnedDirectoryHash: flags.pinnedDirectoryHash,
		controlSet: set, previousControlSet: previousSet, roots: roots,
		serviceID: flags.serviceID, timeout: flags.timeout,
	}, nil
}

func readExactLinuxV2JSON(path string, maximum int64, target any) error {
	body, err := readV2RegularFile(path, maximum)
	if err != nil {
		return err
	}
	canonical, err := wire.DecodeStrict(body, int(maximum), target)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, body) {
		return errors.New("[D104 Linux private] 输入不是 exact canonical JSON")
	}
	return nil
}

func linuxInternalCAPool(body []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	count := 0
	remaining := body
	for len(remaining) != 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----\n")) {
			return nil, errors.New("[D131 Linux private] internal CA PEM 必须使用 exact canonical encoding")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("[D131 Linux private] internal CA PEM 含非证书或非规范 block")
		}
		consumed := len(remaining) - len(rest)
		if !bytes.Equal(remaining[:consumed], pem.EncodeToMemory(block)) {
			return nil, errors.New("[D131 Linux private] internal CA PEM 必须使用 exact canonical encoding")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || len(certificate.UnhandledCriticalExtensions) != 0 {
			return nil, errors.New("[D131 Linux private] internal CA certificate profile 无效")
		}
		roots.AddCert(certificate)
		count++
		remaining = rest
	}
	if count == 0 {
		return nil, errors.New("[D131 Linux private] internal CA PEM 为空")
	}
	return roots, nil
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
		pending, err := clientv2.LoadPendingClaimForEnrollmentRetry(paths.pending, identity)
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
	mirrors []wire.DistributionMirrorRefV1,
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
	if result.Result.ResultArtifact == nil || result.Result.ResultArtifact.InitialDeviceView.Active == nil {
		return errors.New("[D124 Linux install] completed result 缺 active config refs")
	}
	configs, err := clientv2.FetchLinuxDeviceConfigArtifacts(ctx, mirrors,
		result.Result.ResultArtifact.InitialDeviceView.Active.ConfigArtifactRefs,
		clientv2.MirrorFetcher{Timeout: linuxClientV2NetworkTimeout(common.timeout)})
	if err != nil {
		return err
	}
	floors, err := clientv2.InstallLinuxEnrollmentCompletion(clientv2.LinuxEnrollmentCompletionInstallV1{
		StatePath: common.paths.state, IdentityPath: common.paths.identity, PendingPath: common.paths.pending,
		Result: result.Result, Completion: result.Completion, VerifiedProof: proof,
		SecretEnvelopes: envelopes, Configs: configs, DistributionMirrors: mirrors,
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
