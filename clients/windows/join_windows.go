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
	"strings"

	"golang.org/x/sys/windows"
	"loom/internal/clientcomponent"
	"loom/internal/clientsecret"
	"loom/internal/windowsv2"
)

const (
	maxWindowsComponent     = 32 << 20
	bundledWindowsComponent = "windows-dataplane.zip"
)

// 只传递本地阶段文案，不传递二维码、证书或服务端响应正文。
type windowsJoinProgress func(string)

func (progress windowsJoinProgress) report(detail string) {
	if progress != nil {
		progress(detail)
	}
}

type windowsJoinResult struct{ NodeID string }
type windowsJoinCommitOptions struct {
	Root          string
	ComponentPath string
	Protector     clientsecret.Protector
	Arch          string
	PlatformKey   ed25519.PublicKey
	Progress      windowsJoinProgress
}

var errWindowsJoinInputRequired = errors.New("需要导入中控生成的 Device 二维码")
var errWindowsMigrationRequired = errors.New("此连接需要完成认证迁移后才能使用；原 Device 身份与数据已保留")

func ensureWindowsJoined(ctx context.Context, root string, protector clientsecret.Protector, source string) (windowsJoinResult, error) {
	return ensureWindowsJoinedInput(ctx, root, protector, source, nil)
}

func ensureWindowsJoinedInput(ctx context.Context, root string, protector clientsecret.Protector, source string, progress windowsJoinProgress) (windowsJoinResult, error) {
	var carrier windowsv2.EnrollmentCarrier
	if strings.TrimSpace(source) != "" {
		var err error
		carrier, err = windowsv2.ReadEnrollmentCarrier(source)
		if err != nil {
			return windowsJoinResult{}, err
		}
	}
	return ensureWindowsV2Joined(ctx, root, protector, carrier, progress)
}

func embeddedWindowsPlatformKey() (ed25519.PublicKey, error) {
	if strings.TrimSpace(buildPlatformPublicKey) == "" {
		return nil, errors.New("此 Loom 发行包缺少验证公钥；请重新下载完整客户端")
	}
	key, err := decodeWindowsPlatformKey([]byte(buildPlatformPublicKey))
	if err != nil {
		return nil, errors.New("此 Loom 发行包的验证公钥无效；请重新下载客户端")
	}
	return key, nil
}

func bundledWindowsComponentPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate Windows client executable: %w", err)
	}
	path := filepath.Join(filepath.Dir(executable), bundledWindowsComponent)
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve bundled Windows component: %w", err)
	}
	path = filepath.Clean(path)
	if !localWindowsPath(path) {
		return "", errors.New("Windows 客户端组件必须位于本机磁盘")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maxWindowsComponent {
		return "", errors.New("Windows 客户端发行包不完整：缺少 windows-dataplane.zip")
	}
	return path, nil
}

func prepareWindowsJoinComponent(options windowsJoinCommitOptions) ([]byte, *clientcomponent.Verified, error) {
	if options.Root == "" || !filepath.IsAbs(options.Root) || filepath.Clean(options.Root) != options.Root ||
		options.ComponentPath == "" || !filepath.IsAbs(options.ComponentPath) || filepath.Clean(options.ComponentPath) != options.ComponentPath ||
		options.Protector == nil || (options.Arch != "amd64" && options.Arch != "arm64") ||
		len(options.PlatformKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("Windows join commit dependencies are incomplete")
	}
	options.Progress.report("正在验证本地数据面组件…")
	body, err := readWindowsComponent(options.ComponentPath)
	if err != nil {
		return nil, nil, err
	}
	verified, err := clientcomponent.Verify(body, options.PlatformKey)
	if err != nil {
		clear(body)
		return nil, nil, fmt.Errorf("verify bundled Windows data-plane package before join: %w", err)
	}
	if verified.Manifest.Arch != options.Arch {
		clear(body)
		return nil, nil, fmt.Errorf("component package architecture is %s, this client is %s", verified.Manifest.Arch, options.Arch)
	}
	return body, verified, nil
}

func readWindowsComponent(path string) ([]byte, error) {
	if !localWindowsPath(path) {
		return nil, errors.New("bundled component must be on a local Windows path")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect bundled component package: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxWindowsComponent {
		return nil, errors.New("bundled component must be a non-link regular file between 1 byte and 32 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read bundled component package: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() <= 0 || after.Size() > maxWindowsComponent {
		return nil, errors.New("bundled component changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxWindowsComponent+1))
	if err != nil {
		return nil, fmt.Errorf("read bundled component package: %w", err)
	}
	if len(body) == 0 || len(body) > maxWindowsComponent || int64(len(body)) != after.Size() {
		clear(body)
		return nil, errors.New("component package changed outside its size boundary while reading")
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
		return nil, errors.New("ready bootstrap platform key is not canonical Ed25519 base64")
	}
	return ed25519.PublicKey(key), nil
}

func writeWindowsJoinFile(path string, body []byte) (retErr error) {
	return writeWindowsJoinFileMode(path, body, true)
}

func writeWindowsJoinCommit(path string, body []byte) error {
	return writeWindowsJoinFileMode(path, body, false)
}

func writeWindowsJoinFileMode(path string, body []byte, replace bool) (retErr error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(body) == 0 {
		return fmt.Errorf("invalid joined-device output path or empty body: %q", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("joined-device output target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
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
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		if !replace && (errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)) {
			return errors.New("joined-device state appeared during commit; refusing to replace it")
		}
		return err
	}
	return nil
}
