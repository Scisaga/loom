package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"loom/internal/clientcomponent"
	"loom/internal/clientdist"
	"loom/internal/clientrelease"
	"loom/internal/publish"
)

const clientUsage = `loom client —— 客户端交付

用法:
	loom client enroll {-invite-file <文件>|-stdin} [-state <文件>]
	                                             经受限 tunnel claim/resume 并原子保存 LKG
	loom client sync [-state <文件>]              经认证设备通道读取并保存最新 DeviceView
	loom client inspect [-state <文件>]           回读本机身份与认证 LKG（不显示秘密）
	loom client run                              正式 Linux service：启动统一 runtime
	loom client preflight                        验证 LKG 与真实 sing-box，不改变运行状态
	loom client stage-server-migration           从 owner-only 旧配置暂存受限用户/ACL overlay
	loom client finalize-server-migration        按源摘要删除 overlay，重启后进入 exact runtime
	loom client route <direct|auto|exit ID>       持久化偏好并重载正式 service
	loom client status                           回读 selector 已确认的实际路径与观测
  loom client package -sing-box <二进制>     生成可重现、已签名的 Linux 客户端包
  loom client verify  -archive <tar.gz> -pubkey <公钥>
                                               验签并检查包内全部文件
  loom client publish-linux -archive <amd64> -archive <arm64>
                                               原子更新现有签名 release catalog
  loom client package-windows -arch <amd64|arm64>
      -sing-box-archive <官方 ZIP> -wintun-archive <官方 ZIP>
                                               生成已签名的 Windows 数据面包
  loom client verify-windows -archive <zip> -pubkey <公钥> [-arch <amd64|arm64>]
                                               验签并检查 Windows 数据面包
`

func cmdClient(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", clientUsage)
	}
	switch args[0] {
	case "enroll":
		return cmdClientEnrollMinimal(args[1:])
	case "sync":
		return cmdClientSync(args[1:])
	case "inspect":
		return cmdClientInspect(args[1:])
	case "run":
		return cmdClientRun(args[1:])
	case "preflight":
		return cmdClientPreflight(args[1:])
	case "stage-server-migration":
		return cmdClientStageServerMigration(args[1:])
	case "finalize-server-migration":
		return cmdClientFinalizeServerMigration(args[1:])
	case "route":
		return cmdClientRoute(args[1:])
	case "status":
		return cmdClientStatus(args[1:])
	case "package":
		return cmdClientPackage(args[1:])
	case "verify":
		return cmdClientVerify(args[1:])
	case "publish-linux":
		return cmdClientPublishLinux(args[1:])
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

func cmdClientPublishLinux(args []string) error {
	fs := flag.NewFlagSet("client publish-linux", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var archives repeatedFlag
	fs.Var(&archives, "archive", "已签名 Linux 包；必须各提供 amd64、arm64 一份")
	root := fs.String("root", "/var/lib/loom/client-dist/releases", "现有签名 release catalog 根目录")
	keyPath := fs.String("key", "deploy/keys/platform-signing.key", "平台 Ed25519 签名私钥")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(archives) != 2 {
		return errors.New("用法: loom client publish-linux -archive <amd64.tar.gz> -archive <arm64.tar.gz> [-root <目录>] [-key <私钥>]")
	}
	privateKey, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return fmt.Errorf("读平台签名私钥:%w", err)
	}
	catalog, err := clientrelease.PublishLinux(*root, archives, ed25519.PrivateKey(privateKey))
	if err != nil {
		return err
	}
	fmt.Printf("✓ Linux amd64/arm64 已原子写入签名 release catalog；当前共 %d 个制品\n", len(catalog.Artifacts))
	return nil
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
	if artifact.Manifest.OS == runtime.GOOS && artifact.Manifest.Arch == runtime.GOARCH {
		if err := checkPackagedLoom(filepath.Dir(*outPath), loomBody); err != nil {
			return err
		}
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
	expectedArch := fs.String("arch", "", "可选的预期架构:amd64 或 arm64")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("用法:loom client verify -archive <tar.gz> -pubkey <可信公钥>:%w", err)
	}
	if fs.NArg() != 0 || *archivePath == "" || *pubPath == "" ||
		(*expectedArch != "" && *expectedArch != "amd64" && *expectedArch != "arm64") {
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
	if *expectedArch != "" && manifest.Arch != *expectedArch {
		return fmt.Errorf("Linux 客户端包架构为 %s，预期 %s", manifest.Arch, *expectedArch)
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
