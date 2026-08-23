package main

import (
	"crypto/rand"
	"encoding/base64"
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
	if len(args) == 0 {
		return secretsUsage()
	}
	switch args[0] {
	case "split":
	case "rotate":
		return cmdSecretsRotate(args[1:])
	case "retire":
		return cmdSecretsRetire(args[1:])
	default:
		return secretsUsage()
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
		// 形如 `<什么>/<节点 id>` 的引用归这个节点,**即使没有任何渲染产物
		// 引用它**。中控界面的运维口令 `ui/access-a` 就是这种:它由本机 bootstrap
		// 配置读取,不出现在任何渲染文件里。不认这条规则的话,每次重新拆分
		// 都会把它丢掉,而症状是"界面突然登不进去了"。
		for r := range all {
			if _, node, ok := strings.Cut(r, "/"); ok && node == b.Owner {
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

func secretsUsage() error {
	return fmt.Errorf(`用法:
  loom secrets split  <ssot.yaml> -secrets <总表> -o <目录>   拆成每节点一份
  loom secrets rotate <ssot.yaml> -cred <id> -secrets <总表>  生成下一代凭据
  loom secrets retire <ssot.yaml> -cred <id> -secrets <总表>  删掉已经没人引用的旧代`)
}

// cmdSecretsRotate 生成一份凭据的下一代(§13.4 第一步)。
//
// 它只动秘密层,**不改 SSOT** —— 因为改 SSOT 会触发发布,而新值必须先在
// 总表里就位,否则 hydrate 会因为"缺引用"整体失败。顺序反了的话,全网会
// 卡在一个装不上的快照上。
func cmdSecretsRotate(args []string) error {
	fs := flag.NewFlagSet("secrets rotate", flag.ExitOnError)
	master := fs.String("secrets", "", "总表(必需)")
	credID := fs.String("cred", "", "要轮换的凭据 id(必需)")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *master == "" || *credID == "" {
		return secretsUsage()
	}
	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	c := s.CredentialByID()[*credID]
	if c == nil {
		return fmt.Errorf("SSOT 里没有叫 %q 的凭据", *credID)
	}
	all, err := secret.Load(*master)
	if err != nil {
		return err
	}

	next := c.Gen() + 1
	nextRef := c.SecretRef + fmt.Sprintf("@%d", next)
	if _, exists := all[nextRef]; exists {
		return fmt.Errorf("%s 已经在总表里了 —— 上一次轮换没做完?", nextRef)
	}
	if _, ok := all[c.Ref()]; !ok {
		return fmt.Errorf("总表里没有当前代 %s —— 先把它补上再轮换", c.Ref())
	}

	val, err := newSecretValue()
	if err != nil {
		return err
	}
	all[nextRef] = val
	if err := secret.Write(*master, all,
		"# Loom 秘密层。渲染产物里的 ${secret:REF} 由 loom hydrate 从这里取值。\n"+
			"# 绝不进版本库(.gitignore 已排除)。0600。\n\n"); err != nil {
		return err
	}

	fmt.Printf("✓ 已生成 %s\n\n", nextRef)
	fmt.Printf("接下来两步,**必须分开发布**(§13.4):\n\n")
	fmt.Printf("  第一步 —— 在 SSOT 里把这份凭据改成:\n")
	fmt.Printf("      generation: %d\n      accept_previous: true\n\n", next)
	fmt.Printf("    服务器两代都收,客户端换成新的。等全网都取到这一版\n")
	fmt.Printf("    (loom status 看快照一致),再做第二步。\n\n")
	fmt.Printf("  第二步 —— 把 accept_previous 改回 false,发布;然后:\n")
	fmt.Printf("      loom secrets retire %s -cred %s -secrets %s\n\n", rest[0], *credID, *master)
	fmt.Printf("**别跳过第一步。** 分发是最终一致的,客户端和服务器不可能在\n")
	fmt.Printf("同一刻切换 —— 没有过渡窗口,轮换的瞬间连接全断。\n")
	return nil
}

// cmdSecretsRetire 删掉已经没人引用的旧代(§13.4 第二步)。
func cmdSecretsRetire(args []string) error {
	fs := flag.NewFlagSet("secrets retire", flag.ExitOnError)
	master := fs.String("secrets", "", "总表(必需)")
	credID := fs.String("cred", "", "凭据 id(必需)")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *master == "" || *credID == "" {
		return secretsUsage()
	}
	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	c := s.CredentialByID()[*credID]
	if c == nil {
		return fmt.Errorf("SSOT 里没有叫 %q 的凭据", *credID)
	}
	prev := c.PrevRef()
	if prev == "" {
		return fmt.Errorf("%s 还是第一代,没有旧代可退役", *credID)
	}
	// **还在过渡窗口里就删,服务器会因为缺引用而装不上配置。**
	// 先改 SSOT 关掉窗口、等全网取到,再退役。
	if c.AcceptPrevious {
		return fmt.Errorf("%s 的 accept_previous 还是 true —— 服务器仍在引用 %s。"+
			"先把它改成 false、发布、等全网取到(loom status 看快照一致),再退役",
			*credID, prev)
	}
	all, err := secret.Load(*master)
	if err != nil {
		return err
	}
	if _, ok := all[prev]; !ok {
		fmt.Printf("总表里已经没有 %s,无事可做\n", prev)
		return nil
	}
	delete(all, prev)
	if err := secret.Write(*master, all,
		"# Loom 秘密层。渲染产物里的 ${secret:REF} 由 loom hydrate 从这里取值。\n"+
			"# 绝不进版本库(.gitignore 已排除)。0600。\n\n"); err != nil {
		return err
	}
	fmt.Printf("✓ 已删除 %s\n", prev)
	fmt.Printf("\n**各节点上的旧值要等它们下一次取配置才消失** —— hydrate 是在\n")
	fmt.Printf("节点上做的,而节点的 node.env 由 loom secrets split 重新分发。\n")
	return nil
}

// newSecretValue 生成一个新的凭据值。
func newSecretValue() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
