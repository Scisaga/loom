//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"loom/internal/clientcomponent"
	"loom/internal/clientjoin"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

const (
	maxWindowsComponent     = 32 << 20
	bundledWindowsComponent = "windows-dataplane.zip"
)

type windowsJoinProgress func(string)

func (progress windowsJoinProgress) report(detail string) {
	if progress != nil {
		progress(detail)
	}
}

type windowsJoinResult struct{ NodeID string }

var errWindowsJoinInputRequired = errors.New("需要导入中控生成的 Device 二维码")

func windowsProfileStatePath(root string) string {
	return filepath.Join(root, "state", "device-profile.json.dpapi")
}

func ensureWindowsJoined(ctx context.Context, root string, protector clientsecret.Protector,
	source string) (windowsJoinResult, error) {
	return ensureWindowsJoinedInput(ctx, root, protector, source, nil, nil)
}

// ensureWindowsJoinedInput is the sole normal UI enrollment entry. It keeps
// the same protected Ed25519 identity/request ID across claim/resume retries
// and uses the shared private device tunnel wire.
func ensureWindowsJoinedInput(ctx context.Context, root string, protector clientsecret.Protector,
	source string, provided *control.BootstrapInvite, progress windowsJoinProgress) (windowsJoinResult, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || protector == nil {
		return windowsJoinResult{}, errors.New("Windows profile root or DPAPI protector is invalid")
	}
	statePath := windowsProfileStatePath(root)
	existing, loadErr := deviceclient.LoadProtected(statePath, protector)
	hasInput := strings.TrimSpace(source) != "" || provided != nil
	if loadErr == nil && existing.LKG() != nil {
		if hasInput {
			return windowsJoinResult{}, errors.New("客户端已经加入网络；不能导入另一个 Device 的二维码")
		}
		return windowsJoinResult{NodeID: existing.LKG().View.DeviceID}, nil
	}
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return windowsJoinResult{}, fmt.Errorf("读取 DPAPI profile: %w", loadErr)
	}
	var invite control.BootstrapInvite
	if provided != nil {
		invite = *provided
	} else if hasInput {
		var err error
		invite, err = clientjoin.Read(source, nil)
		if err != nil {
			return windowsJoinResult{}, err
		}
	} else if loadErr == nil {
		invite = control.BootstrapInvite{Schema: 1, Capability: existing.Capability()}
	} else {
		return windowsJoinResult{}, errWindowsJoinInputRequired
	}

	progress.report("正在验证发行包并准备本机设备身份…")
	component, err := installBundledWindowsComponent(root)
	if err != nil {
		return windowsJoinResult{}, err
	}
	store, err := deviceclient.OpenProtected(statePath, invite, protector)
	if err != nil {
		return windowsJoinResult{}, fmt.Errorf("准备 DPAPI profile: %w", err)
	}
	profile, err := configuredEdition()
	if err != nil {
		return windowsJoinResult{}, err
	}
	runtimeTarget, err := runtimeProfile(profile)
	if err != nil {
		return windowsJoinResult{}, err
	}
	caPath := windowsClientCAPath(root, profile)
	store.SetLKGPreflight(func(envelope control.DeviceViewEnvelope) error {
		derived, err := clientruntime.DeriveWindowsRuntimeConfig([]byte(envelope.View.Runtime.Config), runtimeTarget, caPath)
		if err != nil {
			return err
		}
		defer clear(derived)
		return clientruntime.PreflightWindowsRuntime(ctx, component.SingBox, derived, filepath.Join(root, "runtime"), runtimeTarget, caPath)
	})
	joinContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	progress.report("正在通过私有 bootstrap tunnel 提交设备身份…")
	response, err := deviceclient.Claim(joinContext, store)
	if err != nil {
		return windowsJoinResult{}, err
	}
	for response.DeviceView == nil {
		switch response.Transaction.State {
		case "bound", "approved":
			progress.report("中控已绑定设备，正在等待审批和完整运行配置…")
		case "completed":
			return windowsJoinResult{}, errors.New("已完成的 Enrollment 未返回完整 DeviceView")
		default:
			return windowsJoinResult{}, fmt.Errorf("非规范 Enrollment 状态 %q", response.Transaction.State)
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-joinContext.Done():
			timer.Stop()
			return windowsJoinResult{}, fmt.Errorf("等待 Enrollment 完成: %w", joinContext.Err())
		case <-timer.C:
		}
		response, err = deviceclient.Resume(joinContext, store)
		if err != nil {
			return windowsJoinResult{}, err
		}
	}
	lkg := store.LKG()
	if lkg == nil || lkg.View.Platform != "windows" || lkg.View.Runtime == nil {
		return windowsJoinResult{}, errors.New("Enrollment 未持久化完整 Windows LKG")
	}
	progress.report("设备身份和完整运行配置已由 DPAPI 原子保存。")
	return windowsJoinResult{NodeID: lkg.View.DeviceID}, nil
}

func installBundledWindowsComponent(root string) (clientcomponent.RuntimePaths, error) {
	componentPath, err := bundledWindowsComponentPath()
	if err != nil {
		return clientcomponent.RuntimePaths{}, err
	}
	platformKey, err := embeddedWindowsPlatformKey()
	if err != nil {
		return clientcomponent.RuntimePaths{}, err
	}
	body, err := readWindowsComponent(componentPath)
	if err != nil {
		return clientcomponent.RuntimePaths{}, err
	}
	defer clear(body)
	verified, err := clientcomponent.Verify(body, platformKey)
	if err != nil {
		return clientcomponent.RuntimePaths{}, fmt.Errorf("验证 Windows 数据面组件: %w", err)
	}
	if verified.Manifest.Arch != runtime.GOARCH {
		return clientcomponent.RuntimePaths{}, fmt.Errorf("组件架构为 %s，当前客户端为 %s", verified.Manifest.Arch, runtime.GOARCH)
	}
	installed, err := clientcomponent.InstallWindows(root, body, platformKey)
	if err != nil {
		return clientcomponent.RuntimePaths{}, fmt.Errorf("安装 Windows 数据面组件: %w", err)
	}
	return installed.Paths, nil
}

func embeddedWindowsPlatformKey() (ed25519.PublicKey, error) {
	if strings.TrimSpace(buildPlatformPublicKey) == "" {
		return nil, errors.New("此 Loom 发行包缺少验证公钥；请重新下载完整客户端")
	}
	return decodeWindowsPlatformKey([]byte(buildPlatformPublicKey))
}

func bundledWindowsComponentPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	path, err := filepath.Abs(filepath.Join(filepath.Dir(executable), bundledWindowsComponent))
	if err != nil || !localWindowsPath(path) {
		return "", errors.New("Windows 客户端组件必须位于本机磁盘")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxWindowsComponent {
		return "", errors.New("Windows 客户端发行包不完整：缺少 windows-dataplane.zip")
	}
	return path, nil
}

func readWindowsComponent(path string) ([]byte, error) {
	if !localWindowsPath(path) {
		return nil, errors.New("bundled component must be on a local Windows path")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxWindowsComponent {
		return nil, errors.New("bundled component must be a bounded non-link regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("bundled component changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxWindowsComponent+1))
	if err != nil || len(body) == 0 || len(body) > maxWindowsComponent || int64(len(body)) != after.Size() {
		clear(body)
		return nil, errors.New("bundled component changed outside its size boundary")
	}
	return body, nil
}

func localWindowsPath(path string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	return filepath.IsAbs(path) && !strings.HasPrefix(lower, `\\`) && !strings.HasPrefix(lower, `//`) &&
		!strings.HasPrefix(lower, `\\?\`) && !strings.HasPrefix(lower, `\\.\`)
}

func decodeWindowsPlatformKey(body []byte) (ed25519.PublicKey, error) {
	encoded := strings.TrimSpace(string(body))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("Windows 组件验证公钥不是规范 Ed25519 base64")
	}
	return ed25519.PublicKey(key), nil
}

func writeWindowsJoinFile(path string, body []byte) (retErr error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(body) == 0 {
		return errors.New("invalid Windows local metadata path or body")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".metadata-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
