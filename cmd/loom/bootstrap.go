package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/wire"
)

const bootstrapUsage = `loom bootstrap —— bootstrap 公网入口验证

用法:
  loom bootstrap probe-outer -plan <canonical-json> -observer-id <id>
      -key <Ed25519 私钥> -o <签名报告> [-ca <PEM>] [-timeout 10s]

probe-outer 只连接 plan 中固定的 public IP:port，完成 TLS 1.3/SNI/SPKI
验证并签名 observation；不会解析 DNS，也不会发送 capability、Invite 或 token。
`

func cmdBootstrap(args []string) error {
	if len(args) == 0 {
		return errors.New(bootstrapUsage)
	}
	switch args[0] {
	case "probe-outer":
		return cmdBootstrapProbeOuter(args[1:])
	case "help", "-h", "--help":
		fmt.Print(bootstrapUsage)
		return nil
	default:
		return fmt.Errorf("未知 bootstrap 子命令 %q\n\n%s", args[0], bootstrapUsage)
	}
}

func cmdBootstrapProbeOuter(args []string) error {
	fs := flag.NewFlagSet("bootstrap probe-outer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	planPath := fs.String("plan", "", "canonical BootstrapOuterProbePlanV1")
	observerID := fs.String("observer-id", "", "frozen evidence policy 中的 observer ID")
	keyPath := fs.String("key", "", "base64 Ed25519 private key，权限不宽于 0600")
	outPath := fs.String("o", "", "canonical signed observation 输出文件")
	caPath := fs.String("ca", "", "可选的 PEM trust roots；省略则使用系统 trust store")
	timeout := fs.Duration("timeout", 10*time.Second, "每个 public tuple 的握手超时（1s..30s）")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *planPath == "" || *observerID == "" ||
		*keyPath == "" || *outPath == "" {
		return errors.New(bootstrapUsage)
	}
	inputs := []string{*planPath, *keyPath}
	if *caPath != "" {
		inputs = append(inputs, *caPath)
	}
	for _, input := range inputs {
		same, err := bootstrapPathsSame(*outPath, input)
		if err != nil {
			return err
		}
		if same {
			return errors.New("[D120 external verify] observation 输出不能覆盖 plan、私钥或 CA")
		}
	}

	planBody, err := readBootstrapRegularFile(*planPath, 1<<20, false)
	if err != nil {
		return err
	}
	var plan bootstrapaccess.BootstrapOuterProbePlanV1
	canonicalPlan, err := wire.DecodeStrict(planBody, 1<<20, &plan)
	if err != nil {
		return err
	}
	if !bytes.Equal(planBody, canonicalPlan) {
		return errors.New("[D104 external verify] probe plan 必须是 exact canonical JSON，不接受空白或等价重编码")
	}
	planHash, err := bootstrapaccess.BootstrapOuterProbePlanHash(&plan)
	if err != nil {
		return err
	}
	privateKeyBody, err := readBootstrapRegularFile(*keyPath, 4096, true)
	if err != nil {
		return err
	}
	encodedPrivateKey := strings.TrimSpace(string(privateKeyBody))
	privateKeyRaw, err := decodeB64(encodedPrivateKey)
	if err != nil || len(privateKeyRaw) != ed25519.PrivateKeySize || b64(privateKeyRaw) != encodedPrivateKey {
		return errors.New("[D120 external verify] observer private key 必须是规范 base64 Ed25519 private key")
	}
	privateKey := ed25519.PrivateKey(privateKeyRaw)
	if !bytes.Equal(ed25519.NewKeyFromSeed(privateKey.Seed()), privateKey) {
		return errors.New("[D120 external verify] observer private key 自检失败")
	}
	roots, err := bootstrapRootCAs(*caPath)
	if err != nil {
		return err
	}
	report, err := bootstrapaccess.RunBootstrapOuterProbe(context.Background(), &plan,
		bootstrapaccess.BootstrapOuterProbeOptions{
			ObserverID: *observerID, PrivateKey: privateKey,
			TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
			Now:       time.Now, Timeout: *timeout,
		})
	if err != nil {
		return err
	}
	reportBody, err := wire.MarshalCanonical(report)
	if err != nil {
		return err
	}
	if err := writeBootstrapObservation(*outPath, reportBody); err != nil {
		return err
	}
	fmt.Printf("✓ bootstrap 外部探测完成并写入签名 observation\n")
	fmt.Printf("  observer  %s\n", report.Body.ObserverID)
	fmt.Printf("  key       %s\n", report.Signature.ObserverKeyID)
	fmt.Printf("  plan      %s\n", planHash)
	fmt.Printf("  targets   %d\n", len(report.Body.Results))
	return nil
}

// readBootstrapRegularFile 在打开前后核对同一 inode，避免 plan/trust/key 在
// 检查后被替换成 symlink；私钥还必须拒绝 group/other 权限（D120、D122）。
func readBootstrapRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum {
		return nil, fmt.Errorf("[D120 external verify] %s 必须是 1..%d bytes 非 symlink 普通文件", path, maximum)
	}
	if private && before.Mode().Perm()&^os.FileMode(0o600) != 0 {
		return nil, fmt.Errorf("[D122 external verify] observer private key %s 权限必须不宽于 0600", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() < 1 || after.Size() > maximum || private && after.Mode().Perm()&^os.FileMode(0o600) != 0 {
		return nil, fmt.Errorf("[D120 external verify] %s 在安全检查期间被替换或权限无效", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(body) < 1 || int64(len(body)) > maximum {
		return nil, fmt.Errorf("[D120 external verify] %s 大小在读取期间变化", path)
	}
	return body, nil
}

func bootstrapRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("[D122 external verify] 读取系统 trust store 失败: %w", err)
		}
		if roots == nil {
			return nil, errors.New("[D122 external verify] 系统 trust store 为空")
		}
		return roots, nil
	}
	body, err := readBootstrapRegularFile(path, 1<<20, false)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	rest := body
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		trimmed := bytes.TrimSpace(rest)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("[D122 external verify] CA 文件含非 PEM 内容")
		}
		block, trailing := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("[D122 external verify] CA 文件必须只含无 header 的 CERTIFICATE PEM blocks")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("[D122 external verify] CA certificate 无效: %w", err)
		}
		roots.AddCert(certificate)
		count++
		rest = trailing
	}
	if count == 0 {
		return nil, errors.New("[D122 external verify] CA 文件不含 certificate")
	}
	return roots, nil
}

func bootstrapPathsSame(left, right string) (bool, error) {
	leftAbsolute, err := filepath.Abs(left)
	if err != nil {
		return false, err
	}
	rightAbsolute, err := filepath.Abs(right)
	if err != nil {
		return false, err
	}
	if filepath.Clean(leftAbsolute) == filepath.Clean(rightAbsolute) {
		return true, nil
	}
	leftInfo, leftErr := os.Stat(leftAbsolute)
	rightInfo, rightErr := os.Stat(rightAbsolute)
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, leftErr
	}
	if rightErr != nil {
		return false, rightErr
	}
	return leftErr == nil && os.SameFile(leftInfo, rightInfo), nil
}

func writeBootstrapObservation(path string, body []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return writeFileAtomicDurable(path, body, 0o600)
}
