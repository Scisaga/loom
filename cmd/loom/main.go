// Command loom exposes the current control and device entry points.
// Offline signature inspection and protected backups do not import old authority.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"loom/internal/publish"
)

const usage = `loom —— 私有控制与客户端

用法:
  loom control <init|serve|relay|edge|inspect|endpoint-inputs|write>
                                      schema 3 认证事实、私有服务与回读
  loom client <enroll|sync|inspect|run|preflight|route|status>
                                      私有加入、认证配置、运行与报告
  loom client <package|verify|package-windows|verify-windows>
                                      通用客户端制品打包与验签
  loom release <package-android|stage|publish|import|verify>
                                      schema 3 签名制品、全目标分发与回读
  loom config check [-env .env]        本机部署 YAML 引用与输入校验
  loom version [-short|-json]         当前可执行文件坐标
  loom selfcheck [-q]                 二进制架构与构建自检
  loom keygen -o <目录>                显式生成新的平台签名密钥对
  loom current -file <signed-current> -pubkey <公钥> [-node <ID>]
                                      离线验签旧发布证据，不激活、不迁移
  loom verify <发布根>/<snapshot> -pubkey <公钥>
                                      离线核验原始签名、节点包和二进制
  loom backup -o <文件> {-passphrase-file <文件>|-plaintext} [来源...]
                                      保存受保护原始材料
  loom restore <备份文件> -o <新目录>  解包到独立目录，不覆盖运行状态

普通授权只从 control write 和私有 Web 写入。旧 SSOT 渲染、发布、安装与回滚入口已删除；
下载发布不等于期望组件或运行激活；既有运行 floor 仍须验证前向切换。
`

const (
	manifestFile = "snapshot.json"
	sigFile      = "snapshot.sig"
	privKeyFile  = "platform-signing.key"
	pubKeyFile   = "platform-signing.pub"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := runCommand(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func runCommand(command string, args []string) error {
	switch command {
	case "control":
		return cmdControl(args)
	case "client":
		return cmdClient(args)
	case "release":
		return cmdRelease(args)
	case "config":
		return cmdConfig(args)
	case "version":
		return cmdVersion(args)
	case "selfcheck":
		return cmdSelfcheck(args)
	case "keygen":
		return cmdKeygen(args)
	case "current":
		return cmdCurrentInspect(args)
	case "verify":
		return cmdVerify(args)
	case "backup":
		return cmdBackup(args)
	case "restore":
		return cmdRestore(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("未知命令 %q；使用 loom help 查看当前入口", command)
	}
}

// parseInterspersed accepts flags after positional command arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return positional, nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("o", ".", "密钥输出目录")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privPath := filepath.Join(*dir, privKeyFile)
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("%s 已存在 —— 覆盖签名私钥会让所有已签快照无法校验,"+
			"请先手工移走", privPath)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(privPath, []byte(b64(priv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, pubKeyFile), []byte(b64(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("已生成签名密钥对:\n  私钥 %s(0600)\n  公钥 %s\n", privPath, filepath.Join(*dir, pubKeyFile))
	fmt.Println("\n私钥是平台的信任根。它泄露 = 攻击者能签出被节点接受的任意配置。")
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pubkey", "", "已固定的平台签名公钥（必需）")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *pubPath == "" {
		return fmt.Errorf("离线取证需要快照目录与 -pubkey")
	}
	dir, err := filepath.Abs(rest[0])
	if err != nil {
		return err
	}
	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	manifest, err := publish.VerifyPublishedSnapshot(filepath.Dir(dir), filepath.Base(dir), ed25519.PublicKey(pub))
	if err != nil {
		return err
	}
	fmt.Printf("published snapshot evidence verified: snapshot=%s bundles=%d binaries=%d\n",
		manifest.ID, len(manifest.Bundles), len(manifest.Binaries))
	return nil
}

func readKey(path string, want int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := decodeB64(string(raw))
	if err != nil {
		return nil, fmt.Errorf("解析密钥 %s:%w", path, err)
	}
	if len(k) != want {
		return nil, fmt.Errorf("密钥 %s 长度是 %d,期望 %d", path, len(k), want)
	}
	return k, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}
