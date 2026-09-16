//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/net/proxy"

	"loom/internal/clientcomponent"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/clientv2"
	"loom/internal/windowsv2"
	"loom/internal/wire"
)

const windowsV2ControlInterval = time.Minute

func prepareWindowsV2ClientAt(root string, protector clientsecret.Protector,
	edition clientEdition, state *windowsv2.StateV1,
) (func(context.Context) error, error) {
	if state == nil {
		return nil, errors.New("Windows v2 LKG 缺失")
	}
	if state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		return nil, errors.Join(windowsV2TerminalError(state),
			cleanupWindowsV2TerminalMaterial(root, protector))
	}
	initial, err := prepareWindowsV2ActivationFromState(root, protector, state, edition)
	if err != nil {
		return nil, fmt.Errorf("恢复 Windows v2 LKG 数据面: %w", err)
	}
	return func(ctx context.Context) error {
		dataPlaneLock, err := acquireWindowsDataPlaneLock()
		if err != nil {
			initial.clear()
			return err
		}
		defer dataPlaneLock.close()
		preferencePath := filepath.Join(root, "state", "preference.json")
		control := &routeControl{requests: make(chan routeRequest), done: make(chan struct{}),
			persist: func(preference clientcore.Preference) error {
				return clientcore.WritePreference(preferencePath, preference)
			}}
		routeControls.Store(root, control)
		defer func() {
			routeControls.Delete(root)
			close(control.done)
		}()
		return runWindowsV2ControlLoop(ctx, root, protector, edition, initial, control)
	}, nil
}

func prepareWindowsV2Activation(root string, protector clientsecret.Protector,
	edition clientEdition,
) (*clientActivation, error) {
	state, err := windowsV2Installed(root, protector)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, os.ErrNotExist
	}
	return prepareWindowsV2ActivationFromState(root, protector, state, edition)
}

func prepareWindowsV2ActivationFromState(root string, protector clientsecret.Protector, state *windowsv2.StateV1,
	edition clientEdition,
) (*clientActivation, error) {
	material, err := prepareWindowsV2RuntimeMaterial(root, protector, state)
	if err != nil {
		return nil, err
	}
	defer material.Clear()
	caPath, err := windowsV2PublicCAPath(root, material.ContentHash)
	if err != nil {
		return nil, err
	}
	platformKey, err := embeddedWindowsPlatformKey()
	if err != nil {
		return nil, err
	}
	activation, err := prepareWindowsV2ActivationMaterial(root, &material, edition, caPath, platformKey)
	if err != nil {
		return nil, err
	}
	if err := writeWindowsV2PublicCA(caPath, material.CABundlePEM); err != nil {
		activation.clear()
		return nil, err
	}
	return activation, nil
}

func prepareWindowsV2ActivationMaterial(root string, material *windowsv2.RuntimeMaterialV1,
	edition clientEdition, caPath string, platformKey []byte,
) (*clientActivation, error) {
	components, err := clientcomponent.LoadWindows(root, platformKey, runtime.GOARCH,
		material.Artifact.SingBoxVersion)
	if err != nil {
		return nil, fmt.Errorf("选择已签名 Windows v2 数据面: %w", err)
	}
	profile, err := runtimeProfile(edition)
	if err != nil {
		return nil, err
	}
	runtimeConfig, err := clientruntime.DeriveWindowsRuntimeConfig(material.SingBoxConfig,
		profile, caPath)
	if err != nil {
		return nil, err
	}
	health, err := clientruntime.BuildWindowsHealthPlan(runtimeConfig, profile, caPath)
	if err != nil {
		clear(runtimeConfig)
		return nil, err
	}
	plan, err := clientruntime.BuildWindowsSelectorPlan(runtimeConfig, material.AgentConfig,
		profile, caPath)
	if err != nil {
		clear(runtimeConfig)
		return nil, err
	}
	preference, err := clientcore.ReadPreference(filepath.Join(root, "state", "preference.json"))
	if err != nil {
		clear(runtimeConfig)
		return nil, err
	}
	filtered, agentConfig, err := plan.Derive(runtimeConfig, preference)
	if err != nil {
		clear(runtimeConfig)
		return nil, err
	}
	contentDigest, err := wire.ParseHash(material.ContentHash)
	if err != nil {
		clear(runtimeConfig)
		clear(filtered)
		return nil, err
	}
	contentHex := hex.EncodeToString(contentDigest)
	version := clientruntime.CandidateVersion{
		Generation: uint64(material.Artifact.Generation), PayloadSHA256: contentHex,
		Snapshot: contentHex[:12], BundleSHA256: contentHex,
		ConfigSHA256: material.HydratedSHA256,
	}
	if err := version.Validate(); err != nil {
		clear(runtimeConfig)
		clear(filtered)
		return nil, err
	}
	return &clientActivation{
		BaseConfig: runtimeConfig, Policy: plan, Preference: preference, AgentConfig: agentConfig,
		ProbeRegistry: processWindowsProbeRegistry(), Version: version,
		SlotID: components.SlotID, Executable: components.SingBox, Config: filtered,
		RuntimeDir: filepath.Join(root, "runtime"), Profile: profile, CAPath: caPath,
		WaitForStart: true, Health: health,
	}, nil
}

// Enrollment 在正式 v2 state pointer 出现前执行同一 renderer、组件和上游
// sing-box check。Mixed 派生不创建 TUN，也不改系统路由，适合三个 edition 共用。
func preflightWindowsV2InstallCandidate(ctx context.Context, root string, protector clientsecret.Protector,
	state *windowsv2.StateV1, platformKey []byte,
) error {
	material, err := prepareWindowsV2RuntimeMaterial(root, protector, state)
	if err != nil {
		return err
	}
	defer material.Clear()
	caPath, err := writeWindowsV2TemporaryCA(material.CABundlePEM)
	if err != nil {
		return err
	}
	defer removeWindowsV2RuntimeFile(caPath)
	components, err := clientcomponent.LoadWindows(root, platformKey, runtime.GOARCH,
		material.Artifact.SingBoxVersion)
	if err != nil {
		return err
	}
	config, err := clientruntime.DeriveWindowsRuntimeConfig(material.SingBoxConfig,
		clientruntime.WindowsPortableMixedProfile, caPath)
	if err != nil {
		return err
	}
	defer clear(config)
	if _, err := clientruntime.BuildWindowsSelectorPlan(config, material.AgentConfig,
		clientruntime.WindowsPortableMixedProfile, caPath); err != nil {
		return err
	}
	if _, err := clientruntime.BuildWindowsHealthPlan(config,
		clientruntime.WindowsPortableMixedProfile, caPath); err != nil {
		return err
	}
	return clientruntime.PreflightWindowsRuntime(ctx, components.SingBox, config,
		filepath.Join(root, "runtime"), clientruntime.WindowsPortableMixedProfile, caPath)
}

func preflightWindowsV2RuntimeCandidate(ctx context.Context, root string, protector clientsecret.Protector,
	state *windowsv2.StateV1, edition clientEdition,
) error {
	material, err := prepareWindowsV2RuntimeMaterial(root, protector, state)
	if err != nil {
		return err
	}
	defer material.Clear()
	caPath, err := writeWindowsV2TemporaryCA(material.CABundlePEM)
	if err != nil {
		return err
	}
	defer removeWindowsV2RuntimeFile(caPath)
	platformKey, err := embeddedWindowsPlatformKey()
	if err != nil {
		return err
	}
	activation, err := prepareWindowsV2ActivationMaterial(root, &material, edition, caPath, platformKey)
	if err != nil {
		return err
	}
	defer activation.clear()
	return preflightClientActivation(ctx, activation)
}

func windowsV2PublicCAPath(root, contentHash string) (string, error) {
	digest, err := wire.ParseHash(contentHash)
	if err != nil {
		return "", errors.New("Windows v2 runtime artifact hash 无效")
	}
	return filepath.Join(root, "tls", "ca-v2-"+hex.EncodeToString(digest)+".crt"), nil
}

func writeWindowsV2TemporaryCA(body []byte) (_ string, retErr error) {
	if len(body) == 0 || len(body) > 1<<20 {
		return "", errors.New("Windows v2 preflight CA bundle 无效")
	}
	file, err := os.CreateTemp("", "loom-windows-v2-ca-*.crt")
	if err != nil {
		return "", err
	}
	path := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(body); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	replayed, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(replayed, body) {
		return "", errors.New("Windows v2 preflight CA 写后回读不一致")
	}
	return path, nil
}

func writeWindowsV2PublicCA(path string, body []byte) error {
	if len(body) == 0 || len(body) > 1<<20 {
		return errors.New("Windows v2 runtime CA bundle 无效")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 && info.Size() == int64(len(body)) {
		existing, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(existing, body) {
			return nil
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeWindowsJoinFile(path, body); err != nil {
		return fmt.Errorf("提交 Windows v2 runtime CA: %w", err)
	}
	replayed, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(replayed, body) {
		return errors.New("Windows v2 runtime CA 写后回读不一致")
	}
	return nil
}

func runWindowsV2ControlLoop(ctx context.Context, root string,
	protector clientsecret.Protector, edition clientEdition, initial *clientActivation,
	control *routeControl,
) (retErr error) {
	manager, err := newActivationManager(preflightClientActivation, runClientActivation,
		dataPlaneStartupGrace)
	if err != nil {
		initial.clear()
		return err
	}
	manager.observe = control.update
	defer func() {
		if err := manager.Stop(); err != nil && retErr == nil {
			retErr = fmt.Errorf("停止 Windows v2 数据面: %w", err)
		}
	}()
	if _, err := manager.Replace(ctx, initial); err != nil {
		_ = cleanupWindowsV2PublicCAs(root)
		if errors.Is(err, ctx.Err()) {
			return nil
		}
		return fmt.Errorf("激活 Windows v2 LKG: %w", err)
	}
	logActivation("已激活 Windows v2 LKG", manager.active.spec)
	if err := cleanupWindowsV2PublicCAs(root, manager.active.spec.CAPath); err != nil {
		log.Printf("清理旧 Windows v2 public CA 失败: %v", err)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case request := <-control.requests:
			request.done <- applyRouteRequest(ctx, manager, control, request)
		case activeErr := <-manager.Done():
			if err := manager.Recover(ctx, activeErr); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("Windows v2 数据面失败: %w", err)
			}
			logActivation("Windows v2 数据面恢复了已验证配置", manager.active.spec)
		case <-timer.C:
			if err := reconcileWindowsV2Control(ctx, root, protector, edition, manager); err != nil {
				var terminal *windowsV2TerminalStateError
				if errors.As(err, &terminal) {
					return err
				}
				if ctx.Err() != nil {
					return nil
				}
				log.Printf("Windows v2 private control 同步失败: %v", err)
			}
			timer.Reset(windowsV2ControlInterval)
		}
	}
}

func reconcileWindowsV2Control(ctx context.Context, root string,
	protector clientsecret.Protector, edition clientEdition, manager *activationManager,
) error {
	if manager == nil || manager.active == nil {
		return errors.New("Windows v2 数据面尚未激活")
	}
	dial, err := windowsV2PrivateControlDial(edition)
	if err != nil {
		return err
	}
	reportOptions := windowsv2.DeviceReportOptions{
		StatePath: windowsV2StatePath(root), IdentityPath: windowsV2IdentityPath(root),
		Protector: protector, Dial: dial, Now: time.Now, Timeout: 30 * time.Second,
		Schemas: wire.DeviceReportSchemaRegistry{"health": 1},
		Observations: func(observations []json.RawMessage) {
			if manager.active == nil || manager.active.spec.AgentRuntime == nil {
				return
			}
			ca, err := os.ReadFile(manager.active.spec.CAPath)
			if err == nil {
				err = manager.active.spec.AgentRuntime.IngestObservations(observations, ca, time.Now())
			}
			if err != nil {
				log.Printf("Windows v2 服务器观测未采用: %v", err)
			}
		},
	}
	validate := func(candidate *windowsv2.StateV1) error {
		return preflightWindowsV2RuntimeCandidate(ctx, root, protector, candidate, edition)
	}
	_, syncErr := windowsv2.SyncDeviceConfig(ctx, windowsv2.DeviceConfigSyncOptions{
		StatePath: windowsV2StatePath(root), IdentityPath: windowsV2IdentityPath(root),
		Protector: protector, Dial: dial, Now: time.Now, Timeout: 30 * time.Second,
		Fetcher: clientv2.MirrorFetcher{Timeout: 30 * time.Second}, ValidateCandidate: validate,
	})
	state, stateErr := windowsV2Installed(root, protector)
	if stateErr != nil {
		return errors.Join(syncErr, stateErr)
	}
	if state == nil {
		return errors.Join(syncErr, errors.New("Windows v2 LKG 在运行期消失"))
	}
	if state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		terminalErr := windowsV2TerminalError(state)
		stopErr := manager.Stop()
		cleanupErr := cleanupWindowsV2TerminalMaterial(root, protector)
		return errors.Join(terminalErr, stopErr, cleanupErr)
	}
	if syncErr == nil {
		next, err := prepareWindowsV2ActivationFromState(root, protector, state, edition)
		if err != nil {
			return err
		}
		changed, err := manager.Replace(ctx, next)
		keep := []string{}
		if manager.active != nil {
			keep = append(keep, manager.active.spec.CAPath)
		}
		if manager.standby != nil {
			keep = append(keep, manager.standby.CAPath)
		}
		cleanupErr := cleanupWindowsV2PublicCAs(root, keep...)
		if err != nil {
			return errors.Join(err, cleanupErr)
		}
		if cleanupErr != nil {
			return cleanupErr
		}
		if changed {
			logActivation("已激活 Windows v2 private config", manager.active.spec)
		}
	}
	if manager.active == nil {
		return errors.Join(syncErr, errors.New("Windows v2 数据面未保持 active"))
	}
	problems := clientruntime.CheckWindowsHealth(ctx, manager.active.spec.Health)
	payload, err := wire.MarshalCanonical(struct {
		Healthy bool   `json:"healthy"`
		Version string `json:"version"`
	}{Healthy: len(problems) == 0, Version: manager.active.spec.Version.Snapshot})
	if err != nil {
		return errors.Join(syncErr, err)
	}
	reportOptions.Kind, reportOptions.PayloadSchema, reportOptions.Payload = "health", 1, payload
	_, reportErr := windowsv2.SendDeviceReportDurable(ctx,
		windowsV2ReportJournalPath(root), reportOptions)
	clear(payload)
	return errors.Join(syncErr, reportErr)
}

func windowsV2PrivateControlDial(edition clientEdition) (clientv2.TunnelDialContext, error) {
	networkDialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if edition != editionPortableMixed {
		return networkDialer.DialContext, nil
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, networkDialer)
	if err != nil {
		return nil, err
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("Windows v2 SOCKS5 dialer 不支持 context cancellation")
	}
	return contextDialer.DialContext, nil
}

type windowsV2TerminalStateError struct {
	state  string
	reason string
}

func (err *windowsV2TerminalStateError) Error() string {
	return fmt.Sprintf("Windows v2 Device 已进入终态 %s（%s）；凭据与运行配置已清除，禁止重新连接",
		err.state, err.reason)
}

func windowsV2TerminalError(state *windowsv2.StateV1) error {
	if state == nil {
		return &windowsV2TerminalStateError{state: "unknown", reason: "缺少 durable state"}
	}
	reason := "certified tombstone"
	if state.Envelope.Payload.Tombstone != nil && state.Envelope.Payload.Tombstone.Reason != "" {
		reason = state.Envelope.Payload.Tombstone.Reason
	}
	return &windowsV2TerminalStateError{state: state.Envelope.Payload.State, reason: reason}
}

func removeWindowsV2RuntimeFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("拒绝清理非普通 Windows v2 runtime 文件")
	}
	return os.Remove(path)
}

func cleanupWindowsV2TerminalMaterial(root string, protector clientsecret.Protector) error {
	journalErr := removeWindowsV2RuntimeFile(windowsV2JournalPath(root))
	identityErr := windowsv2.DestroyIdentity(windowsV2IdentityPath(root), protector)
	if errors.Is(identityErr, os.ErrNotExist) {
		identityErr = nil
	}
	return errors.Join(journalErr, identityErr, cleanupWindowsV2PublicCAs(root),
		removeWindowsV2RuntimeFile(windowsV2ReportJournalPath(root)),
		clientruntime.CleanupWindowsRuntimeConfigs(filepath.Join(root, "runtime")))
}

func cleanupWindowsV2PublicCAs(root string, keep ...string) error {
	directory := filepath.Join(root, "tls")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	retained := make(map[string]bool, len(keep))
	for _, path := range keep {
		retained[filepath.Clean(path)] = true
	}
	var cleanupErr error
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != len("ca-v2-")+64+len(".crt") || name[:len("ca-v2-")] != "ca-v2-" ||
			name[len(name)-len(".crt"):] != ".crt" {
			continue
		}
		if _, err := hex.DecodeString(name[len("ca-v2-") : len(name)-len(".crt")]); err != nil {
			continue
		}
		path := filepath.Join(directory, name)
		if retained[path] {
			continue
		}
		cleanupErr = errors.Join(cleanupErr, removeWindowsV2RuntimeFile(path))
	}
	return cleanupErr
}

// 宿主只在短生命周期的 hydrate 中加载本机 DPAPI 身份，随后清除内存。
func prepareWindowsV2RuntimeMaterial(root string, protector clientsecret.Protector, state *windowsv2.StateV1) (windowsv2.RuntimeMaterialV1, error) {
	if state.Enrollment == nil || state.Enrollment.ClaimCore.WireGuardPublicKey == "" {
		return windowsv2.PrepareRuntimeMaterial(state)
	}
	identity, err := windowsv2.LoadIdentity(windowsV2IdentityPath(root), protector)
	if err != nil {
		return windowsv2.RuntimeMaterialV1{}, err
	}
	defer identity.Close()
	return windowsv2.PrepareRuntimeMaterialWithIdentity(state, identity)
}
