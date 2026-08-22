package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/render"
	"loom/internal/secret"
)

// secrets split 把一份总表拆成每节点一份,**每台机器只拿它自己用得到的**。
//
// 现在总表在工作站上,hydrate 也在工作站做,于是推出去的配置里是明文凭据。
// 改成节点自己填之后,每台机器需要一份本地秘密层 —— 而它**不该**拿到全网的:
// cn-a 不需要知道 access-a 的控制端点口令。
//
// 哪些 ref 属于哪个节点不用人去分:扫一遍那个节点的渲染产物就知道了。
func cmdSecrets(args []string) error {
	if len(args) == 0 || args[0] != "split" {
		return fmt.Errorf("用法:loom secrets split <ssot.yaml> -secrets <总表> -o <目录>")
	}
	fs := flag.NewFlagSet("secrets split", flag.ExitOnError)
	master := fs.String("secrets", "", "总表(必需)")
	out := fs.String("o", "", "输出目录,每节点一个 <node>.env(必需)")

	rest, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	if len(rest) != 1 || *master == "" || *out == "" {
		return fmt.Errorf("用法:loom secrets split <ssot.yaml> -secrets <总表> -o <目录>")
	}

	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	res, err := render.Render(s)
	if err != nil {
		return err
	}
	all, err := secret.Load(*master)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}

	var missing []string
	unused := map[string]bool{}
	for k := range all {
		unused[k] = true
	}

	for _, b := range res.Bundles {
		refs := map[string]bool{}
		for _, f := range b.Files {
			for _, r := range secret.Refs(f.Content) {
				refs[r] = true
			}
		}
		mine := map[string]string{}
		var names []string
		for r := range refs {
			names = append(names, r)
			delete(unused, r)
			v, ok := all[r]
			if !ok {
				missing = append(missing, b.Owner+":"+r)
				continue
			}
			mine[r] = v
		}
		sort.Strings(names)
		dst := filepath.Join(*out, b.Owner+".env")
		hdr := fmt.Sprintf("# %s 的秘密层 —— 由 loom secrets split 生成\n"+
			"# 只含这台机器自己用得到的引用。装到 /etc/loom/secrets/node.env,0600。\n\n", b.Owner)
		if err := secret.Write(dst, mine, hdr); err != nil {
			return err
		}
		fmt.Printf("  %-8s %d 项:%s\n", b.Owner, len(mine), strings.Join(names, " "))
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("总表里缺这些引用:%s", strings.Join(missing, " "))
	}
	// 总表里有、却没有任何节点用到的项:要么是废弃的,要么是某处忘了引用。
	// 两种都值得看一眼,所以说出来而不是默默跳过。
	if len(unused) > 0 {
		var u []string
		for k := range unused {
			u = append(u, k)
		}
		sort.Strings(u)
		fmt.Fprintf(os.Stderr, "\n! 总表里这些引用没有任何节点用到:%s\n", strings.Join(u, " "))
	}
	fmt.Printf("\n→ %s\n每份只含该机器自己的凭据 —— 分发点和别的节点都看不到。\n", *out)
	return nil
}
