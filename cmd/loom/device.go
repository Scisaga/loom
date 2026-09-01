package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/ssotedit"
)

const deviceUsage = `用法:
  loom device decommission <ssot.yaml> -id <Device ID> -revision <SHA256> [-registry <文件>]
  loom device remove <ssot.yaml> -id <Device ID> -revision <SHA256> -confirm-decommissioned [-registry <文件>]
  loom device discard-pending -id <Device ID> [-registry <文件>]
  loom device import-managed <ssot.yaml> -id <Device ID> -cert <node.crt> [-ca <ca.crt>] [-registry <文件>]

只处理由 Enrollment 生成的 access-only Device。服务器、出口或带隧道的 Device
必须先显式迁移策略和拓扑，不能走这个窄回收入口。

discard-pending 只删除从未领取的身份/邀请。import-managed 只导入同时通过
当前 SSOT 成员校验、Loom CA 链校验和精确 <id>.node.internal SAN 校验的既有证书。`

func cmdDevice(args []string) error {
	if len(args) == 0 {
		return errors.New(deviceUsage)
	}
	switch args[0] {
	case "decommission":
		return cmdDeviceDecommission(args[1:])
	case "remove":
		return cmdDeviceRemove(args[1:])
	case "discard-pending":
		return cmdDeviceDiscardPending(args[1:])
	case "import-managed":
		return cmdDeviceImportManaged(args[1:])
	default:
		return errors.New(deviceUsage)
	}
}

func cmdDeviceDiscardPending(args []string) error {
	fs := flag.NewFlagSet("device discard-pending", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "unclaimed Device ID")
	registryPath := fs.String("registry", "/var/lib/loom/client-enrollment/registry.json", "Device identity registry")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *id == "" {
		return errors.New(deviceUsage)
	}
	if err := (clientregistry.Store{Path: *registryPath}).DiscardPending(*id); err != nil {
		return err
	}
	fmt.Printf("✓ 未领取 Device %s 及其邀请已清理\n", *id)
	return nil
}

func cmdDeviceImportManaged(args []string) error {
	fs := flag.NewFlagSet("device import-managed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "existing SSOT Device ID")
	certPath := fs.String("cert", "", "existing Device certificate")
	caPath := fs.String("ca", "/etc/loom/tls/ca.crt", "Loom CA certificate")
	registryPath := fs.String("registry", "/var/lib/loom/client-enrollment/registry.json", "Device identity registry")
	rest, err := parseInterspersed(fs, args)
	if err != nil || len(rest) != 1 || *id == "" || *certPath == "" {
		return errors.New(deviceUsage)
	}
	ssotBytes, _, err := readDeviceSSOT(rest[0])
	if err != nil {
		return err
	}
	ssot, err := model.Load(ssotBytes)
	if err != nil {
		return fmt.Errorf("validate SSOT: %w", err)
	}
	node := ssot.NodeByID()[*id]
	if node == nil || node.Decommission {
		return fmt.Errorf("Device %q is not an active member of current SSOT", *id)
	}
	publicKey, certificateAt, err := verifiedManagedCertificate(*id, *certPath, *caPath)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(node.Name)
	if name == "" {
		name = node.ID
	}
	imported, err := (clientregistry.Store{Path: *registryPath}).ImportManaged(clientregistry.ManagedIdentity{
		ID: node.ID, Name: name, Platform: "linux-server", PublicKey: publicKey, CertificateAt: certificateAt,
	})
	if err != nil {
		return err
	}
	fmt.Printf("✓ Device %s 已按受信节点证书导入统一 identity registry\n", imported.ID)
	fmt.Printf("  %s\n", imported.KeyFingerprint)
	return nil
}

func verifiedManagedCertificate(deviceID, certPath, caPath string) (string, string, error) {
	if !model.ValidNodeID(deviceID) {
		return "", "", errors.New("managed Device id is malformed")
	}
	certPEM, err := readBoundedRegularFile(certPath, 64<<10)
	if err != nil {
		return "", "", fmt.Errorf("read Device certificate: %w", err)
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", "", errors.New("Device certificate must contain exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse Device certificate: %w", err)
	}
	caPEM, err := readBoundedRegularFile(caPath, 64<<10)
	if err != nil {
		return "", "", fmt.Errorf("read Loom CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return "", "", errors.New("Loom CA file contains no certificate")
	}
	expectedDNS := deviceID + ".node.internal"
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != expectedDNS || cert.Subject.CommonName != expectedDNS {
		return "", "", fmt.Errorf("Device certificate identity must be exactly %s", expectedDNS)
	}
	if cert.IsCA {
		return "", "", errors.New("Device certificate cannot be a CA")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: expectedDNS, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return "", "", fmt.Errorf("verify Device certificate: %w", err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", "", errors.New("Device certificate must use ECDSA P-256")
	}
	return base64.RawStdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo), cert.NotBefore.UTC().Format(time.RFC3339), nil
}

func readBoundedRegularFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("path must be a non-symlink regular file")
	}
	if info.Size() > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return os.ReadFile(path)
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
