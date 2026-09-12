//go:build linux

package clientv2

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

const MaximumLinuxInviteDescriptorBytes = 1 << 20

// DecodeLinuxInviteDescriptor 读取 `.loom-invite` 的 exact descriptor object。
// 文件与 QR/URI 只是不同 carrier，必须产生同一 canonical descriptor hash，
// 不允许在文件路径悄悄引入第二种授权语义（D115）。
func DecodeLinuxInviteDescriptor(raw []byte) (wire.InviteBootstrapDescriptorV2, error) {
	if len(raw) == 0 || len(raw) > MaximumLinuxInviteDescriptorBytes {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[D115 Linux] Invite descriptor 大小无效")
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	canonical, err := wire.DecodeStrict(raw, MaximumLinuxInviteDescriptorBytes, &descriptor)
	if err != nil || !bytes.Equal(canonical, raw) || descriptor.Schema != 2 {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[D115 Linux] .loom-invite 必须是 exact canonical descriptor")
	}
	return descriptor, nil
}

// ReadLinuxInviteDescriptor 支持受控普通文件或标准输入。authority/QC/floor
// 仍由 proof verifier 建立；carrier 自身不成为 trust root（D115、D129）。
func ReadLinuxInviteDescriptor(path string, stdin io.Reader) (wire.InviteBootstrapDescriptorV2, error) {
	if path == "-" {
		if stdin == nil {
			return wire.InviteBootstrapDescriptorV2{}, errors.New("[D115 Linux] stdin 不能为空")
		}
		raw, err := io.ReadAll(io.LimitReader(stdin, MaximumLinuxInviteDescriptorBytes+1))
		if err != nil {
			return wire.InviteBootstrapDescriptorV2{}, err
		}
		return DecodeLinuxInviteDescriptor(raw)
	}
	if path == "" || filepath.Clean(path) != path {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[D115 Linux] Invite file path 非规范")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return wire.InviteBootstrapDescriptorV2{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[D115 Linux] 无法建立 Invite carrier handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > MaximumLinuxInviteDescriptorBytes {
		return wire.InviteBootstrapDescriptorV2{}, errors.New("[D115 Linux] Invite carrier 必须是有界普通文件")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaximumLinuxInviteDescriptorBytes+1))
	if err != nil {
		return wire.InviteBootstrapDescriptorV2{}, err
	}
	return DecodeLinuxInviteDescriptor(raw)
}
