// Command loom 是 L0 的命令行入口:校验、渲染、diff。
//
// 这一层不含任何自动部署(§20.1)—— 生成完文件,人工 scp 过去。
// apply / rollback / probe 属于 L4 与 L2,尚未实现。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/validate"
)

const usage = `loom —— 链路与服务调度基础设施的配置渲染器(L0)

用法:
  loom validate <ssot.yaml>              校验 SSOT,列出全部问题
  loom render   <ssot.yaml> -o <目录>     校验并渲染每节点配置包
  loom diff     <ssot.yaml> -o <目录>     渲染并与目录中已有内容比较,不写盘

尚未实现:apply / rollback / probe(分别属于 L4 与 L2)
`

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
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			p := filepath.Join(*out, b.NodeID, f.Path)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(f.Content), 0o600); err != nil {
				return err
			}
		}
	}

	fmt.Printf("\n已渲染 %d 个节点:\n", len(res.Bundles))
	for _, b := range res.Bundles {
		fmt.Printf("  %-12s %d 个文件  %s\n", b.NodeID, len(b.Files), b.Hash()[:12])
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
		res.Bundles = append(res.Bundles, render.Bundle{NodeID: id, Files: files})
	}
	return res, nil
}
