package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/clientcomponent"
	"loom/internal/clientdist"
	"loom/internal/clientenroll"
	"loom/internal/netx"
	"loom/internal/publish"
)

const clientUsage = `loom client —— 客户端加入与交付

用法:
  loom client enroll  -invite-file <文件>       Linux 兼容命令：生成本机身份并消费一次性加入码
  loom client package -sing-box <二进制>     生成可重现、已签名的 Linux 客户端包
  loom client verify  -archive <tar.gz> -pubkey <公钥>
                                               验签并检查包内全部文件
  loom client package-windows -arch <amd64|arm64>
      -sing-box-archive <官方 ZIP> -wintun-archive <官方 ZIP>
                                               生成已签名的 Windows 数据面包
  loom client verify-windows -archive <zip> -pubkey <公钥> [-arch <amd64|arm64>]
                                               验签并检查 Windows 数据面包
`

const installLocalWireGuardToolsScript = `set -eu
set -f

installed=0
if [ ! -x /usr/bin/wg ]; then
    if [ "$(id -u)" = 0 ]; then
        privilege=root
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        privilege=sudo-nopasswd
    else
        echo 'root or passwordless sudo is required to install wireguard-tools' >&2
        exit 43
    fi

    run_privileged() {
        if [ "$privilege" = root ]; then
            "$@"
        else
            sudo -n "$@"
        fi
    }

    if command -v apt-get >/dev/null 2>&1; then
        run_privileged env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=2 update >/dev/null
        run_privileged env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 -y --no-install-recommends install wireguard-tools >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        run_privileged dnf -y install wireguard-tools >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        run_privileged yum -y install wireguard-tools >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        run_privileged apk add --no-cache wireguard-tools >/dev/null
    elif command -v zypper >/dev/null 2>&1; then
        run_privileged zypper --non-interactive install wireguard-tools >/dev/null
    else
        echo 'no supported package manager found (apt-get, dnf, yum, apk or zypper)' >&2
        exit 44
    fi
    [ -x /usr/bin/wg ] || { echo 'wireguard-tools installation completed without providing /usr/bin/wg' >&2; exit 45; }
    installed=1
fi

printf '%s\n' 'LOOM_WG_TOOLS_V1'
printf 'installed=%s\n' "$installed"
`

func cmdClient(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", clientUsage)
	}
	switch args[0] {
	case "enroll":
		return cmdClientEnroll(args[1:])
	case "package":
		return cmdClientPackage(args[1:])
	case "verify":
		return cmdClientVerify(args[1:])
	case "package-windows":
		return cmdClientPackageWindows(args[1:])
	case "verify-windows":
		return cmdClientVerifyWindows(args[1:])
	case "help", "-h", "--help":
		fmt.Print(clientUsage)
		return nil
	default:
		return fmt.Errorf("未知 client 子命令 %q\n\n%s", args[0], clientUsage)
	}
}

func cmdClientPackageWindows(args []string) error {
	fs := flag.NewFlagSet("client package-windows", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	arch := fs.String("arch", "", "目标架构:amd64 或 arm64")
	singBoxPath := fs.String("sing-box-archive", "", "已审核的官方 sing-box Windows ZIP")
	wintunPath := fs.String("wintun-archive", "", "已审核的官方 Wintun ZIP")
	keyPath := fs.String("key", "deploy/keys/platform-signing.key", "平台 Ed25519 签名私钥")
	outPath := fs.String("o", "", "输出 ZIP；默认 deploy/staging/loom-windows-dataplane-1.11.4-<arch>.zip")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("用法:loom client package-windows -arch <amd64|arm64> -sing-box-archive <zip> -wintun-archive <zip> [-key <私钥>] [-o <zip>]:%w", err)
	}
	if fs.NArg() != 0 || (*arch != "amd64" && *arch != "arm64") || *singBoxPath == "" || *wintunPath == "" {
		return fmt.Errorf("用法:loom client package-windows -arch <amd64|arm64> -sing-box-archive <zip> -wintun-archive <zip> [-key <私钥>] [-o <zip>]")
	}
	singBoxArchive, err := readRegularClientInput(*singBoxPath, false)
	if err != nil {
		return err
	}
	wintunArchive, err := readRegularClientInput(*wintunPath, false)
	if err != nil {
		return err
	}
	privateKey, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return fmt.Errorf("读平台签名私钥:%w", err)
	}
	artifact, err := clientcomponent.BuildOfficial(*arch, singBoxArchive, wintunArchive, ed25519.PrivateKey(privateKey))
	if err != nil {
		return err
	}
	if *outPath == "" {
		*outPath = filepath.Join("deploy/staging", artifact.Name)
	}
	if filepath.Base(*outPath) != artifact.Name {
		return fmt.Errorf("[§10.2 渲染目标必须显式] 输出文件必须名为 %s，得到 %s", artifact.Name, filepath.Base(*outPath))
	}
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	outputs := []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{path: *outPath + ".sha256", body: []byte(fmt.Sprintf("%s  %s\n", artifact.SHA256, artifact.Name)), mode: 0o644},
		{path: *outPath + ".pub", body: append([]byte(base64.StdEncoding.EncodeToString(publicKey)), '\n'), mode: 0o644},
		{path: *outPath, body: artifact.Package, mode: 0o644},
	}
	for _, output := range outputs {
		if err := writeClientFileAtomic(output.path, output.body, output.mode); err != nil {
			return fmt.Errorf("写 Windows 数据面制品 %s:%w", output.path, err)
		}
	}
	fmt.Printf("✓ Windows 数据面包已生成:%s\n", *outPath)
	fmt.Printf("  平台         windows/%s\n", artifact.Manifest.Arch)
	fmt.Printf("  sing-box     %s(%s)\n", artifact.Manifest.SingBox.SHA256, artifact.Manifest.SingBox.Version)
	fmt.Printf("  Wintun       %s(%s，客户端仍会执行 Authenticode)\n", artifact.Manifest.Wintun.SHA256, artifact.Manifest.Wintun.Version)
	fmt.Printf("  包 SHA-256   %s\n", artifact.SHA256)
	fmt.Printf("  可信公钥必须通过另一条通道核对；同目录 .pub 不能自我证明可信。\n")
	return nil
}

func cmdClientVerifyWindows(args []string) error {
	fs := flag.NewFlagSet("client verify-windows", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	archivePath := fs.String("archive", "", "Windows 数据面 ZIP")
	pubPath := fs.String("pubkey", "", "通过带外通道取得的平台公钥(必需)")
	expectedArch := fs.String("arch", "", "可选的预期架构:amd64 或 arm64")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("用法:loom client verify-windows -archive <zip> -pubkey <可信公钥> [-arch <amd64|arm64>]:%w", err)
	}
	if fs.NArg() != 0 || *archivePath == "" || *pubPath == "" ||
		(*expectedArch != "" && *expectedArch != "amd64" && *expectedArch != "arm64") {
		return fmt.Errorf("用法:loom client verify-windows -archive <zip> -pubkey <可信公钥> [-arch <amd64|arm64>]")
	}
	body, err := readRegularClientInput(*archivePath, false)
	if err != nil {
		return err
	}
	publicKey, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("读带外可信平台公钥:%w", err)
	}
	verified, err := clientcomponent.Verify(body, ed25519.PublicKey(publicKey))
	if err != nil {
		return err
	}
	if *expectedArch != "" && verified.Manifest.Arch != *expectedArch {
		return fmt.Errorf("Windows 数据面架构为 %s，预期 %s", verified.Manifest.Arch, *expectedArch)
	}
	fmt.Printf("✓ Windows 数据面包验证通过\n")
	fmt.Printf("  平台         windows/%s\n", verified.Manifest.Arch)
	fmt.Printf("  sing-box     %s(%s)\n", verified.Manifest.SingBox.Version, verified.Manifest.SingBox.Commit)
	fmt.Printf("  Wintun       %s(要求 Windows Authenticode)\n", verified.Manifest.Wintun.Version)
	fmt.Printf("  槽 ID        %s\n", verified.ID)
	return nil
}

func cmdClientEnroll(args []string) error {
	fs := flag.NewFlagSet("client enroll", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inviteFile := fs.String("invite-file", "", "从 .loom-invite 文件读取；- 表示 stdin(推荐)")
	inviteText := fs.String("invite", "", "直接给加入链接；可能进入 shell history，不推荐")
	fromStdin := fs.Bool("stdin", false, "从 stdin 读取加入链接")
	stateDir := fs.String("state-dir", "/etc/loom/client", "设备 identity 与加入状态目录")
	deviceConfig := fs.String("device-config", "/etc/loom/device.yaml", "可选服务器职责声明")
	wgKey := fs.String("wg-key", "/etc/wireguard/node.key", "服务器 WireGuard 私钥落点")
	tlsKey := fs.String("tls-key", "/etc/loom/tls/node.key", "节点 TLS 私钥落点")
	tlsCert := fs.String("tls-cert", "/etc/loom/tls/node.crt", "节点 TLS 证书落点")
	caCert := fs.String("ca-cert", "/etc/loom/tls/ca.crt", "内部 CA 证书落点")
	pubKey := fs.String("pubkey", "/etc/loom/trust/platform.pub", "平台签名公钥落点")
	secrets := fs.String("secrets", "/etc/loom/secrets/node.env", "本设备秘密层落点")
	nodeID := fs.String("node-id", "/etc/loom/node-id", "节点 id 落点")
	expectedCurrent := fs.String("expected-current", "", "首次 pull 用的带外 signed current；默认 <state-dir>/expected-current.json")
	pullState := fs.String("pull-state", "/var/lib/loom/applied", "pull 安装状态")
	releaseFloor := fs.String("release-floor", "/var/lib/loom/release-floor.json", "signed current 防回退 floor")
	deployLock := fs.String("deploy-lock", "/var/lib/loom/deploy.lock", "pull/apply 部署锁")
	binPath := fs.String("bin", managedBinary, "首次 pull 可更新的 Loom 二进制")
	dnsServer := fs.String("dns", "", "解析设备加入 HTTPS 端点使用的 DNS")
	wait := fs.Duration("wait", 5*time.Minute, "等待中控完成 provisioning 的最长时间；0 只提交一次")
	retry := fs.Duration("retry", 3*time.Second, "provisioning 期间的重试间隔")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("用法:loom client enroll {-invite-file <文件>|-stdin|-invite <URI>}:%w", err)
	}
	if fs.NArg() != 0 || *wait < 0 || *retry <= 0 {
		return fmt.Errorf("用法:loom client enroll {-invite-file <文件>|-stdin|-invite <URI>}")
	}
	sources := 0
	if *inviteFile != "" {
		sources++
	}
	if *inviteText != "" {
		sources++
	}
	if *fromStdin {
		sources++
	}
	if sources != 1 {
		return fmt.Errorf("必须且只能选择 -invite-file、-invite 或 -stdin 之一")
	}
	var invite clientenroll.Invite
	var err error
	switch {
	case *inviteFile != "":
		invite, err = clientenroll.ReadInviteFile(*inviteFile, os.Stdin)
	case *fromStdin:
		invite, err = clientenroll.ReadInviteFile("-", os.Stdin)
	default:
		fmt.Fprintln(os.Stderr, "! -invite 可能已进入 shell history；下次请用 -invite-file 或 stdin。")
		invite, err = clientenroll.ParseInvite(*inviteText)
	}
	if err != nil {
		return err
	}
	server, err := clientenroll.PrepareServerEnrollment(*deviceConfig, *wgKey, nil)
	if err != nil {
		return err
	}
	if err := ensureLocalServerPrerequisites(server); err != nil {
		return err
	}
	if *expectedCurrent == "" {
		*expectedCurrent = filepath.Join(*stateDir, "expected-current.json")
	}
	paths := clientenroll.Paths{
		StateDir: *stateDir, TLSKey: *tlsKey, TLSCert: *tlsCert, CACert: *caCert,
		PlatformPublicKey: *pubKey, Secrets: *secrets, NodeID: *nodeID,
		ExpectedCurrent: *expectedCurrent,
	}
	httpClient := netx.Client(*dnsServer, 35*time.Second)
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// 307/308 会重发包含 token 的 POST；加入端点必须直达(§11)。
		return fmt.Errorf("设备加入 HTTPS 端点不允许重定向")
	}
	deadline := time.Now().Add(*wait)
	first := true
	temporaryReported := false
	var response clientenroll.Response
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		response, err = clientenroll.ClaimWithServer(ctx, httpClient, invite, *stateDir, server, nil)
		cancel()
		if err != nil {
			if !clientenroll.IsTransient(err) || *wait == 0 || time.Now().Add(*retry).After(deadline) {
				return err
			}
			if !temporaryReported {
				fmt.Fprintln(os.Stderr, "! 设备加入端点暂时不可用；将复用同一 key/request_id/CSR 重试。")
				temporaryReported = true
			}
			time.Sleep(*retry)
			continue
		}
		if response.Configuration == "ready" {
			break
		}
		if first {
			fmt.Printf("✓ 设备 identity 已绑定(client %s)，中控正在生成本设备配置。\n", response.ClientID)
			first = false
		}
		if *wait == 0 || time.Now().Add(*retry).After(deadline) {
			return fmt.Errorf("[§9.2 加入流程] 设备仍在 provisioning；identity 已安全保存，请用同一加入码重试，不要重置私钥")
		}
		time.Sleep(*retry)
	}
	if err := clientenroll.InstallReady(paths, response); err != nil {
		return err
	}
	bootstrap := response.Bootstrap
	pullArgs := make([]string, 0, 20)
	for _, mirror := range bootstrap.DistributionURLs {
		pullArgs = append(pullArgs, "-url", mirror)
	}
	pullArgs = append(pullArgs,
		"-node", bootstrap.NodeID, "-pubkey", *pubKey, "-secrets", *secrets,
		"-expected-current", *expectedCurrent, "-state", *pullState,
		"-release-floor", *releaseFloor, "-deploy-lock", *deployLock, "-bin", *binPath,
	)
	if len(bootstrap.DNS) > 0 {
		pullArgs = append(pullArgs, "-dns", bootstrap.DNS[0])
	}
	fmt.Printf("✓ bootstrap 已验签并落盘，开始首次 signed pull(节点 %s)。\n", bootstrap.NodeID)
	if err := cmdPull(pullArgs); err != nil {
		return fmt.Errorf("首次 signed pull 未完成；bootstrap 与 identity 已保留，重试会复用它们:%w", err)
	}
	if err := removeClientExpectedCurrent(*expectedCurrent); err != nil {
		return err
	}
	fmt.Printf("✓ Linux 客户端已加入网络，并完成验签配置安装与首次状态收敛。\n")
	return nil
}

func ensureLocalServerPrerequisites(server *clientenroll.ServerEnrollment) error {
	return ensureServerWireGuardTools(server, executableRegularFile, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "/bin/sh", "-s")
		command.Stdin = strings.NewReader(installLocalWireGuardToolsScript)
		command.Stdout = io.Discard
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Run(); err != nil {
			detail := strings.TrimSpace(stderr.String())
			if len(detail) > 2048 {
				detail = detail[:2048] + "…"
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errors.New("安装 wireguard-tools 超时")
			}
			if detail != "" {
				return fmt.Errorf("安装 wireguard-tools: %w: %s", err, detail)
			}
			return fmt.Errorf("安装 wireguard-tools: %w", err)
		}
		return nil
	})
}

func ensureServerWireGuardTools(server *clientenroll.ServerEnrollment, executable func(string) bool, install func() error) error {
	if server == nil {
		return nil
	}
	if executable == nil || install == nil {
		return errors.New("服务器 Device 的 wireguard-tools 前置检查未配置")
	}
	wgOK := executable("/usr/bin/wg")
	wgQuickOK := executable("/usr/bin/wg-quick")
	if wgOK && wgQuickOK {
		return nil
	}
	// This happens before the invitation is claimed. Failure can leave only a
	// local, unreferenced WireGuard key; it cannot create Identity or SSOT state.
	if err := install(); err != nil {
		return fmt.Errorf("服务器 Device 需要 wireguard-tools，加入码尚未消费: %w", err)
	}
	if !executable("/usr/bin/wg") || !executable("/usr/bin/wg-quick") {
		return errors.New("wireguard-tools 安装完成但 /usr/bin/wg 或 /usr/bin/wg-quick 仍不可执行；加入码尚未消费")
	}
	return nil
}

func executableRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func removeClientExpectedCurrent(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("首次 pull 完成，但删除临时 expected-current 失败:%w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func cmdClientPackage(args []string) error {
	fs := flag.NewFlagSet("client package", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	loomPath := fs.String("loom", stagedBinary, "要嵌入的 Loom 二进制")
	singBoxPath := fs.String("sing-box", "/usr/local/bin/sing-box", "要嵌入的真实 sing-box 二进制")
	keyPath := fs.String("key", "deploy/keys/platform-signing.key", "平台 Ed25519 签名私钥")
	outPath := fs.String("o", "", "输出 tar.gz；默认 deploy/staging/loom-client-linux-<arch>.tar.gz")
	allowDirty := fs.Bool("allow-dirty", false, "允许无法追溯到干净 commit 的 Loom 候选")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("用法:loom client package [-loom <文件>] -sing-box <文件> [-key <私钥>] [-o <tar.gz>]:%w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("用法:loom client package [-loom <文件>] -sing-box <文件> [-key <私钥>] [-o <tar.gz>]")
	}
	loomBody, err := readRegularClientInput(*loomPath, true)
	if err != nil {
		return err
	}
	singBoxBody, err := readRegularClientInput(*singBoxPath, true)
	if err != nil {
		return err
	}
	privateKey, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return fmt.Errorf("读平台签名私钥:%w", err)
	}
	artifact, err := clientdist.Build(clientdist.BuildInput{
		Loom: loomBody, SingBox: singBoxBody, PrivateKey: ed25519.PrivateKey(privateKey), AllowDirty: *allowDirty,
	})
	if err != nil {
		return err
	}
	if *outPath == "" {
		*outPath = filepath.Join("deploy/staging", artifact.Name)
	}
	if filepath.Base(*outPath) != artifact.Name {
		return fmt.Errorf("[§10.2 渲染目标必须显式] 输出文件必须名为 %s，得到 %s", artifact.Name, filepath.Base(*outPath))
	}
	if err := checkPackagedLoom(filepath.Dir(*outPath), loomBody); err != nil {
		return err
	}
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	outputs := []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{path: *outPath + ".sha256", body: artifact.Checksum, mode: 0o644},
		{path: *outPath + ".sig", body: artifact.Signature, mode: 0o644},
		{path: *outPath + ".pub", body: append([]byte(base64.StdEncoding.EncodeToString(publicKey)), '\n'), mode: 0o644},
		// 归档本体最后换入；Web 不会在新本体可见时还只看到旧附件。
		{path: *outPath, body: artifact.Archive, mode: 0o644},
	}
	for _, output := range outputs {
		if err := writeClientFileAtomic(output.path, output.body, output.mode); err != nil {
			return fmt.Errorf("写客户端制品 %s:%w", output.path, err)
		}
	}
	fmt.Printf("✓ Linux 客户端包已生成:%s\n", *outPath)
	fmt.Printf("  平台      %s/%s\n", artifact.Manifest.OS, artifact.Manifest.Arch)
	fmt.Printf("  Loom        %s\n", artifact.Manifest.Loom.SHA256)
	fmt.Printf("  sing-box    %s(%s)\n", artifact.Manifest.SingBox.SHA256, artifact.Manifest.SingBox.Version)
	fmt.Printf("  校验/签名   %s.sha256 / %s.sig\n", *outPath, *outPath)
	fmt.Printf("  可信公钥必须通过另一条通道核对；同目录 .pub 不能自我证明可信。\n")
	return nil
}

func cmdClientVerify(args []string) error {
	fs := flag.NewFlagSet("client verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	archivePath := fs.String("archive", "", "Linux 客户端 tar.gz")
	checksumPath := fs.String("checksum", "", "SHA-256 附件；默认 <archive>.sha256")
	signaturePath := fs.String("signature", "", "Ed25519 附件；默认 <archive>.sig")
	pubPath := fs.String("pubkey", "", "通过带外通道取得的平台公钥(必需)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("用法:loom client verify -archive <tar.gz> -pubkey <可信公钥>:%w", err)
	}
	if fs.NArg() != 0 || *archivePath == "" || *pubPath == "" {
		return fmt.Errorf("用法:loom client verify -archive <tar.gz> -pubkey <可信公钥>")
	}
	if *checksumPath == "" {
		*checksumPath = *archivePath + ".sha256"
	}
	if *signaturePath == "" {
		*signaturePath = *archivePath + ".sig"
	}
	archive, err := readRegularClientInput(*archivePath, false)
	if err != nil {
		return err
	}
	checksum, err := readRegularClientInput(*checksumPath, false)
	if err != nil {
		return err
	}
	signature, err := readRegularClientInput(*signaturePath, false)
	if err != nil {
		return err
	}
	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("读带外可信平台公钥:%w", err)
	}
	manifest, err := clientdist.Verify(archive, checksum, signature, ed25519.PublicKey(pub))
	if err != nil {
		return err
	}
	if fields := strings.Fields(string(checksum)); len(fields) != 2 || fields[1] != filepath.Base(*archivePath) {
		return fmt.Errorf("校验附件声明的文件名与 %s 不一致", filepath.Base(*archivePath))
	}
	fmt.Printf("✓ Linux 客户端包验证通过\n")
	fmt.Printf("  平台      %s/%s\n", manifest.OS, manifest.Arch)
	fmt.Printf("  Loom commit %s\n", manifest.Loom.Commit)
	fmt.Printf("  sing-box    %s\n", manifest.SingBox.Version)
	fmt.Printf("  生命周期    节点专属 unit 只从签名 bundle 安装\n")
	return nil
}

func readRegularClientInput(path string, executable bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("检查 %s:%w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("[§10.3 原子安装] %s 必须是非链接的普通文件", path)
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("[§15.4 二进制与配置兼容] %s 没有可执行位", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读 %s:%w", path, err)
	}
	return body, nil
}

func checkPackagedLoom(stageDir string, body []byte) error {
	sum := sha256.Sum256(body)
	candidate := publish.BinaryCandidate{Body: body, SHA256: fmt.Sprintf("%x", sum[:]), Size: len(body)}
	path, cleanup, err := stageReleaseCheck(stageDir, candidate)
	if err != nil {
		return err
	}
	defer cleanup()
	out, err := selfcheckBinaryCandidate(path, true)
	if err != nil {
		return fmt.Errorf("[§15.4 二进制与配置兼容] 包内 Loom selfcheck 失败:%v\n%s", err, strings.TrimSpace(string(out)))
	}
	out, err = exec.Command(path, "client", "help").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "client enroll") {
		return fmt.Errorf("[§15.4 二进制与配置兼容] 包内 Loom 不具备 client enroll:%v\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeClientFileAtomic(path string, body []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
