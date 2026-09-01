package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/ssotedit"
)

const deviceUsage = `用法:
  loom device decommission <ssot.yaml> -id <Device ID> -revision <SHA256> [-registry <文件>]
  loom device remove <ssot.yaml> -id <Device ID> -revision <SHA256> -confirm-decommissioned [-registry <文件>]

只处理由 Enrollment 生成的 access-only Device。服务器、出口或带隧道的 Device
必须先显式迁移策略和拓扑，不能走这个窄回收入口。`

func cmdDevice(args []string) error {
	if len(args) == 0 {
		return errors.New(deviceUsage)
	}
	switch args[0] {
	case "decommission":
		return cmdDeviceDecommission(args[1:])
	case "remove":
		return cmdDeviceRemove(args[1:])
	default:
		return errors.New(deviceUsage)
	}
}

func cmdDeviceDecommission(args []string) error {
	fs := flag.NewFlagSet("device decommission", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "Enrollment Device ID")
	expected := fs.String("revision", "", "页面/检查时看到的精确 SSOT SHA256")
	registryPath := fs.String("registry", "/var/lib/loom/client-enrollment/registry.json", "Device identity registry")
	rest, err := parseInterspersed(fs, args)
	if err != nil || len(rest) != 1 || *id == "" || *expected == "" {
		return errors.New(deviceUsage)
	}
	store := clientregistry.Store{Path: *registryPath}
	if _, err := requireRetirableRegistryDevice(store, *id); err != nil {
		return err
	}
	var nextRevision string
	err = mutateDeviceSSOT(rest[0], *expected, func(current []byte) ([]byte, error) {
		next, err := ssotedit.DecommissionAccessDevice(current, *id)
		if err == nil {
			nextRevision = deviceSSOTRevision(next)
		}
		return next, err
	})
	if err != nil {
		return err
	}
	fmt.Printf("✓ Device %s 已写入 signed decommission 期望态\n", *id)
	fmt.Printf("  SSOT revision %s\n", nextRevision)
	fmt.Printf("  等目标机出现 /var/lib/loom/DECOMMISSIONED 后，才可执行 device remove。\n")
	return nil
}

func cmdDeviceRemove(args []string) error {
	fs := flag.NewFlagSet("device remove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "Enrollment Device ID")
	expected := fs.String("revision", "", "确认停机后看到的精确 SSOT SHA256")
	registryPath := fs.String("registry", "/var/lib/loom/client-enrollment/registry.json", "Device identity registry")
	confirmed := fs.Bool("confirm-decommissioned", false, "已从目标机核对 DECOMMISSIONED marker")
	rest, err := parseInterspersed(fs, args)
	if err != nil || len(rest) != 1 || *id == "" || *expected == "" || !*confirmed {
		return errors.New(deviceUsage)
	}
	store := clientregistry.Store{Path: *registryPath}
	if _, err := requireRetirableRegistryDevice(store, *id); err != nil {
		return err
	}
	var plan ssotedit.DeviceRemovalPlan
	err = mutateDeviceSSOT(rest[0], *expected, func(current []byte) ([]byte, error) {
		ssot, loadErr := model.Load(current)
		if loadErr != nil {
			return nil, loadErr
		}
		// A rename can commit before registry persistence fails. The exact retry
		// must be able to finish the registry revoke without restoring old intent.
		if ssot.NodeByID()[*id] == nil {
			plan.Content = append([]byte(nil), current...)
			return plan.Content, nil
		}
		var editErr error
		plan, editErr = ssotedit.RemoveDecommissionedAccessDevice(current, *id)
		return plan.Content, editErr
	})
	if err != nil {
		return err
	}
	if _, err := store.Revoke(*id); err != nil {
		return fmt.Errorf("SSOT 已移除 Device，但 registry revoke 失败；请勿恢复旧 SSOT，修复 registry 后重试 revoke: %w", err)
	}
	fmt.Printf("✓ Device %s 已从期望态移除，identity 已标记 revoked\n", *id)
	fmt.Printf("  删除的 credentials: %s\n", strings.Join(plan.CredentialIDs, " "))
	fmt.Printf("  snapshot 全网收敛后再从 master/node secrets 清理: %s\n", strings.Join(plan.SecretRefs, " "))
	return nil
}

func requireRetirableRegistryDevice(store clientregistry.Store, id string) (clientregistry.Client, error) {
	clients, _, err := store.List()
	if err != nil {
		return clientregistry.Client{}, fmt.Errorf("read Device registry: %w", err)
	}
	for _, client := range clients {
		if client.ID != id {
			continue
		}
		if client.ProfileVersion == "" {
			return clientregistry.Client{}, fmt.Errorf("Device %q is not pinned to an Enrollment ProfileVersion", id)
		}
		if client.Status != "ready" && client.Status != "revoked" {
			return clientregistry.Client{}, fmt.Errorf("Device %q registry status is %q, want ready", id, client.Status)
		}
		return client, nil
	}
	return clientregistry.Client{}, fmt.Errorf("Device %q is not present in the Enrollment registry", id)
}

func mutateDeviceSSOT(path, expected string, edit func([]byte) ([]byte, error)) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	if len(expected) != sha256.Size*2 || strings.ToLower(expected) != expected {
		return errors.New("SSOT revision must be a lowercase SHA-256 hex digest")
	}
	return withDeviceSSOTLock(path, func() error {
		current, mode, err := readDeviceSSOT(path)
		if err != nil {
			return err
		}
		if got := deviceSSOTRevision(current); got != expected {
			return fmt.Errorf("SSOT revision changed (current %s); inspect again before retrying", got)
		}
		next, err := edit(current)
		if err != nil {
			return err
		}
		if deviceSSOTRevision(next) == deviceSSOTRevision(current) {
			return nil
		}
		return writeFileAtomicDurable(path, next, mode)
	})
}

func readDeviceSSOT(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("SSOT must be a non-symlink regular file")
	}
	if info.Size() > 4<<20 {
		return nil, 0, errors.New("SSOT exceeds 4 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, 0, errors.New("SSOT changed while opening; retry")
	}
	body, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		return nil, 0, errors.New("read SSOT within 4 MiB boundary failed")
	}
	if _, err := model.Load(body); err != nil {
		return nil, 0, err
	}
	return body, info.Mode().Perm(), nil
}

func withDeviceSSOTLock(path string, fn func() error) error {
	lockPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".loom.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open SSOT transaction lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("SSOT transaction lock must be a private regular file")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock SSOT transaction: %w", err)
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}

func deviceSSOTRevision(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}
