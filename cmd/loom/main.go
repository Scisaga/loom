// Command loom 是 L0 的命令行入口:校验、渲染、diff。
//
// 这一层不含任何自动部署(§20.1)—— 生成完文件,人工 scp 过去。
// apply / rollback / probe 属于 L4 与 L2,尚未实现。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/snapshot"
	"loom/internal/validate"
)

const usage = `loom —— 链路与服务调度基础设施的配置渲染器(L0)

用法:
  loom validate <ssot.yaml>              校验 SSOT,列出全部问题
  loom render   <ssot.yaml> -o <目录>     校验并渲染每节点配置包
  loom diff     <ssot.yaml> -o <目录>     渲染并与目录中已有内容比较,不写盘
  loom snapshot <ssot.yaml> -o <目录>     渲染并冻成带签名的不可变版本
  loom verify   <目录>                    校验快照签名,并比对目录内容是否漂移
  loom keygen   -o <目录>                 生成平台签名密钥对
  loom firewall <ssot.yaml>              列出每台机器需要放行的端口
  loom hydrate  -in <目录> -o <目录> -secrets <文件>
                                         把 ${secret:...} 占位符替换成真实值

尚未实现:apply / rollback / probe(分别属于 L4 与 L2)
`

// 快照产物的文件名。
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
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "validate":
		err = cmdValidate(args)
	case "render":
		err = cmdRender(args, true)
	case "diff":
		err = cmdRender(args, false)
	case "snapshot":
		err = cmdSnapshot(args)
	case "verify":
		err = cmdVerify(args)
	case "keygen":
		err = cmdKeygen(args)
	case "firewall":
		err = cmdFirewall(args)
	case "hydrate":
		err = cmdHydrate(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "错误:%v\n", err)
		os.Exit(1)
	}
}

// loadAndValidate 是 §15.1 流程的前两步。渲染永远不跳过校验 —— 校验器
// 拦住的正是那些"不报错、只是连不上"的配置。
func loadAndValidate(path string) (*model.SSOT, error) {
	s, err := model.LoadFile(path)
	if err != nil {
		return nil, err
	}
	if fs := validate.Validate(s); len(fs) > 0 {
		return nil, fmt.Errorf("校验未通过,%d 处问题:\n%s", len(fs), validate.Format(fs))
	}
	return s, nil
}

// parseInterspersed 允许标志出现在位置参数之后 —— `loom render ssot.yaml -o out`
// 是人会自然写出的形式,而 flag 包默认在第一个位置参数处就停止解析。
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

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个 SSOT 文件路径")
	}
	s, err := model.LoadFile(rest[0])
	if err != nil {
		return err
	}
	found := validate.Validate(s)
	if len(found) == 0 {
		fmt.Printf("✓ 校验通过\n")
		fmt.Printf("  拓扑    %d 个节点,%d 条隧道\n", len(s.Nodes), len(s.Tunnels))
		fmt.Printf("  服务    %d 个等价类,%d 条访问声明\n",
			len(s.EquivalenceClasses), len(s.Declarations))
		fmt.Printf("  接入    %d 张凭据,%d 个客户端档案\n",
			len(s.Credentials), len(s.Profiles))
		return nil
	}
	fmt.Print(validate.Format(found))
	return fmt.Errorf("%d 处问题", len(found))
}

func cmdRender(args []string, write bool) error {
	name := "diff"
	if write {
		name = "render"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	out := fs.String("o", "out", "配置包输出目录")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个 SSOT 文件路径")
	}

	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	res, err := render.Render(s)
	if err != nil {
		return err
	}

	// 跳过的隧道必须显式报出。静默少生成会被读成"全都覆盖到了"。
	for _, sk := range res.Skipped {
		fmt.Fprintf(os.Stderr, "! 跳过 %s:%s\n", sk.Where, sk.Reason)
	}

	existing, err := readDir(*out)
	if err != nil {
		return err
	}
	diff := render.Diff(existing, res)

	if !write {
		if diff == "" {
			fmt.Println("✓ 无变更")
		} else {
			fmt.Print(diff)
		}
		return nil
	}

	if diff == "" {
		fmt.Println("✓ 无变更,未写盘")
	} else {
		fmt.Print(diff)
	}
	if err := writeBundles(*out, res); err != nil {
		return err
	}

	fmt.Printf("\n已渲染 %d 个节点:\n", len(res.Bundles))
	for _, b := range res.Bundles {
		fmt.Printf("  %-12s %d 个文件  %s\n", b.Owner, len(b.Files), b.Hash()[:12])
	}
	return nil
}

// readDir 把已有的输出目录读回成 Result,用于 diff。目录不存在视为空。
func readDir(dir string) (*render.Result, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return &render.Result{}, nil
	}
	byNode := map[string][]render.File{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		node, sub, ok := strings.Cut(filepath.ToSlash(rel), "/")
		if !ok {
			return nil // 顶层散落文件不是配置包的一部分
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		byNode[node] = append(byNode[node], render.File{Path: sub, Content: string(data)})
		return nil
	})
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(byNode))
	for id := range byNode {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	res := &render.Result{}
	for _, id := range ids {
		files := byNode[id]
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		res.Bundles = append(res.Bundles, render.Bundle{Owner: id, Files: files})
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// 快照与签名
// ---------------------------------------------------------------------------

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

func cmdSnapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	out := fs.String("o", "out", "配置包输出目录")
	keyPath := fs.String("key", "", "平台签名私钥;不给则只打快照不签名")
	author := fs.String("author", "", "记入快照的作者")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个 SSOT 文件路径")
	}

	ssotBytes, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	res, err := render.Render(s)
	if err != nil {
		return err
	}
	for _, sk := range res.Skipped {
		fmt.Fprintf(os.Stderr, "! 跳过 %s:%s\n", sk.Where, sk.Reason)
	}

	// 时间与作者从这里注入。渲染和打包都不读时钟 —— 否则 §12 的纯函数
	// 性质就没了,dry-run diff 与漂移检测都会失真。
	m := snapshot.Build(s, res, ssotBytes, snapshot.Meta{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Author:    *author,
	})

	if err := writeBundles(*out, res); err != nil {
		return err
	}
	body, err := m.Bytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, manifestFile), body, 0o644); err != nil {
		return err
	}

	signed := "未签名"
	if *keyPath != "" {
		priv, err := readKey(*keyPath, ed25519.PrivateKeySize)
		if err != nil {
			return err
		}
		sig, err := snapshot.Sign(m, ed25519.PrivateKey(priv))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*out, sigFile), []byte(b64(sig)+"\n"), 0o644); err != nil {
			return err
		}
		signed = "已签名"
	} else {
		_ = os.Remove(filepath.Join(*out, sigFile))
		fmt.Fprintln(os.Stderr,
			"! 未提供 -key,快照没有签名 —— 节点无法验证它的真实性(§14.3)")
	}

	fmt.Printf("快照 %s(%s)\n", m.ID, signed)
	fmt.Printf("  源头    %s\n", m.SSOTHash)
	fmt.Printf("  配置包  %d 个\n", len(m.Bundles))
	fmt.Printf("  跳过    %d 条\n", len(m.Skipped))
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pubkey", "", "平台签名公钥;不给则跳过签名校验")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个快照目录")
	}
	dir := rest[0]

	body, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return fmt.Errorf("读取快照:%w", err)
	}
	var m snapshot.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("解析快照:%w", err)
	}

	var problems []string

	// 一 · 签名。传输通道可以不可信,内容必须可验证(§14.3)。
	switch sig, sigErr := os.ReadFile(filepath.Join(dir, sigFile)); {
	case *pubPath == "":
		fmt.Fprintln(os.Stderr, "! 未提供 -pubkey,跳过签名校验")
	case sigErr != nil:
		problems = append(problems, "缺少签名文件 "+sigFile)
	default:
		pub, err := readKey(*pubPath, ed25519.PublicKeySize)
		if err != nil {
			return err
		}
		raw, err := decodeB64(string(sig))
		if err != nil {
			return fmt.Errorf("解析签名:%w", err)
		}
		if err := snapshot.VerifySignature(body, raw, ed25519.PublicKey(pub)); err != nil {
			problems = append(problems, err.Error())
		}
	}

	// 二 · 内容。目录里的文件是否还是快照记录的样子 —— 这就是 §15.3 的
	// 漂移检测在做的比对。
	onDisk, err := readDir(dir)
	if err != nil {
		return err
	}
	problems = append(problems, snapshot.VerifyBundles(&m, onDisk)...)

	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "✗ %s\n", p)
		}
		return fmt.Errorf("%d 处问题", len(problems))
	}
	fmt.Printf("✓ 快照 %s 校验通过\n", m.ID)
	fmt.Printf("  创建于  %s\n", m.CreatedAt)
	fmt.Printf("  源头    %s\n", m.SSOTHash)
	fmt.Printf("  配置包  %d 个,内容与快照一致\n", len(m.Bundles))
	return nil
}

func writeBundles(dir string, res *render.Result) error {
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			p := filepath.Join(dir, b.Owner, f.Path)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(f.Content), 0o600); err != nil {
				return err
			}
		}
	}
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
