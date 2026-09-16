//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"loom/internal/deploy"
	"loom/internal/wire"
)

type LinuxDeviceDaemonOptions struct {
	StateDirectory string
	Interval       time.Duration
	Timeout        time.Duration
	Version        string
	Once           bool
	Log            io.Writer
	Now            func() time.Time
	Dial           TunnelDialContext
	MirrorFetcher  MirrorFetcher
	Apply          func(context.Context, *deploy.Plan) error
	Healthy        func(context.Context, []string) bool
}

// 常驻宿主只读取已安装身份和认证 LKG；没有 v1 URL、外部 directory pin 或
// enrollment fallback。离线先恢复已有运行配置，随后按原周期同步和上报。
func RunLinuxDeviceDaemon(ctx context.Context, options LinuxDeviceDaemonOptions) error {
	if ctx == nil || options.StateDirectory == "" || !filepath.IsAbs(options.StateDirectory) ||
		filepath.Clean(options.StateDirectory) != options.StateDirectory || options.Interval < 10*time.Second || options.Interval > 10*time.Minute ||
		options.Timeout < time.Second || options.Timeout > 5*time.Minute || options.Apply == nil || options.Healthy == nil || options.Version == "" {
		return errors.New("[Linux daemon] state、周期、版本或正式宿主依赖无效")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if options.Log == nil {
		options.Log = io.Discard
	}
	if err := secureEnrollmentDirectory(options.StateDirectory); err != nil {
		return err
	}
	lock, err := openPrivateLock(filepath.Join(options.StateDirectory, "daemon.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("[Linux daemon] 同一身份已有常驻宿主")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	statePath := filepath.Join(options.StateDirectory, "state.json")
	identityPath := filepath.Join(options.StateDirectory, "identity.json")
	store, err := Open(statePath)
	if err != nil {
		return err
	}
	if store.Installation() == nil || store.Envelope() == nil {
		return errors.New("[Linux daemon] 缺完整 v2 installation；不能自动建立新身份")
	}
	if store.Envelope().Payload.State == "active" {
		if _, found, err := installedLinuxPrivateControlContext(store.Installation(), store.Floors(), store.Envelope().Payload.DeviceID); err != nil || !found {
			return errors.Join(errors.New("[Linux daemon] 缺认证私有控制目录和 CA"), err)
		}
	}
	if _, err := LoadEnrollmentIdentityForResume(identityPath); err != nil {
		return err
	}
	// 启动先使用 LKG 接通私有网络，不以一次在线查询阻塞离线恢复。
	_, terminal, startErr := reconcileLinuxInstalledRuntime(ctx, options)
	if startErr != nil {
		fmt.Fprintln(options.Log, "[Linux daemon] 本机配置恢复失败:", startErr)
	}
	if terminal {
		return startErr
	}
	for {
		cycle, cancel := context.WithTimeout(ctx, options.Timeout)
		_, syncErr := SyncLinuxDeviceView(cycle, LinuxDeviceViewSyncOptions{StatePath: statePath, IdentityPath: identityPath,
			Now: options.Now, Timeout: options.Timeout, Dial: options.Dial, MirrorFetcher: options.MirrorFetcher})
		cancel()
		if syncErr != nil {
			fmt.Fprintln(options.Log, "[Linux daemon] 私有配置同步失败，保留 LKG:", syncErr)
		}
		units, terminal, applyErr := reconcileLinuxInstalledRuntime(ctx, options)
		if terminal {
			return applyErr
		}
		if applyErr != nil {
			fmt.Fprintln(options.Log, "[Linux daemon] 配置激活失败，保留原事务回滚结果:", applyErr)
		}
		cycle, cancel = context.WithTimeout(ctx, options.Timeout)
		healthy := applyErr == nil && options.Healthy(cycle, units)
		payload, err := wire.MarshalCanonical(wire.DeviceHealthPayloadV1{Healthy: healthy, Version: options.Version})
		if err == nil {
			_, err = SendLinuxDeviceReportDurable(cycle, filepath.Join(options.StateDirectory, "device-report-journal.json"), LinuxDeviceReportOptions{
				StatePath: statePath, IdentityPath: identityPath, Now: options.Now, Timeout: options.Timeout, Dial: options.Dial,
				Kind: "health", PayloadSchema: 1, Payload: payload, Schemas: wire.DeviceReportSchemaRegistry{"health": 1},
				Observations: func(_ context.Context, raw []json.RawMessage) {
					if err := persistLinuxAgentObservations(statePath, raw); err != nil {
						fmt.Fprintln(options.Log, "[Linux daemon] 报告已接收，观测缓存保存失败:", err)
					}
				}})
		}
		cancel()
		if err != nil {
			fmt.Fprintln(options.Log, "[Linux daemon] 私有报告失败，保留 exact pending 请求:", err)
		}
		if options.Once {
			return errors.Join(startErr, syncErr, applyErr, err)
		}
		timer := time.NewTimer(options.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func reconcileLinuxInstalledRuntime(ctx context.Context, options LinuxDeviceDaemonOptions) ([]string, bool, error) {
	statePath := filepath.Join(options.StateDirectory, "state.json")
	store, err := Open(statePath)
	if err != nil {
		return nil, false, err
	}
	envelope := store.Envelope()
	if envelope == nil {
		return nil, false, errors.New("[Linux daemon] 缺 durable Device view")
	}
	installPath := filepath.Join(options.StateDirectory, LinuxRuntimeInstallStateName)
	terminal := envelope.Payload.State != "active"
	var plan *deploy.Plan
	if terminal {
		plan, err = PrepareLinuxRuntimeDecommission(installPath, statePath)
	} else {
		links, readErr := LinuxInstalledConfigArtifact(store.Installation(), wire.LinuxLinkIntentArtifactID)
		if readErr != nil {
			return nil, false, readErr
		}
		runtime, readErr := LinuxInstalledConfigArtifact(store.Installation(), wire.LinuxRuntimeArtifactID)
		if readErr != nil {
			return nil, false, readErr
		}
		state := filepath.Join(options.StateDirectory, "link-runtime-state.json")
		if _, err := AcceptLinuxLinkRuntimePlan(state, statePath, envelope, nil, nil, nil, links, options.Now().UTC()); err != nil {
			return nil, false, err
		}
		plan, err = PrepareLinuxRuntimeDeployment(installPath, statePath, state, links, runtime)
	}
	if err != nil {
		return nil, terminal, err
	}
	if linuxRuntimePlanChanged(plan) {
		bounded, cancel := context.WithTimeout(ctx, options.Timeout)
		err = options.Apply(bounded, plan)
		cancel()
	}
	return append([]string(nil), plan.Verify...), terminal, err
}

func linuxRuntimePlanChanged(plan *deploy.Plan) bool {
	for _, path := range plan.Remove {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	for path, content := range plan.Files {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != int64(len(content)) {
			return true
		}
		body, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(body, []byte(content)) {
			return true
		}
	}
	return false
}
