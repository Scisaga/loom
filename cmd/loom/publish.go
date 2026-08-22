package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/render"
	"loom/internal/secret"
	"loom/internal/snapshot"
)

// publish 产出一棵**可以放在任何地方**的分发树(§14.2)。
//
// 关键性质:树里全是 `${secret:REF}` 占位符,而且整份 manifest 有 Ed25519
// 签名。于是
//
//   - 分发点看不到任何凭据 —— 秘密层在各节点本地,合并发生在节点上(D9)
//   - 分发点**不需要被信任** —— 改一个字节,节点验签就过不了
//
// 签名私钥只在这一步用到,留在执行 publish 的机器上,不上任何服务器。
//
// 树的结构:
//
//	current.json              指向当前快照 id
//	<id>/snapshot.json        manifest(含每个配置包的哈希)
//	<id>/snapshot.sig         对 manifest 的签名
//	<id>/nodes/<node>.json    这个节点的全部文件,未 hydrate
type distBundle struct {
	Owner string            `json:"owner"`
	Files map[string]string `json:"files"`
}

type currentDoc struct {
	Snapshot string `json:"snapshot"`
	// PublishedAt 只是给人看的。节点不拿它做任何判断 —— 时间可以被分发点
	// 篡改,而它没有被签名覆盖。
	PublishedAt string `json:"published_at"`
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	out := fs.String("o", "", "分发树输出目录(必需)")
	keyPath := fs.String("key", "", "平台签名私钥(必需)")
	author := fs.String("author", "", "记进 manifest 的作者")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *out == "" || *keyPath == "" {
		return fmt.Errorf("用法:loom publish <ssot.yaml> -o <目录> -key <私钥>")
	}

	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	ssotBytes, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	res, err := render.Render(s)
	if err != nil {
		return err
	}
	privBytes, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	priv := ed25519.PrivateKey(privBytes)

	// 时间由调用方注入,包内不读时钟(§12、D14)。
	man := snapshot.Build(s, res, ssotBytes, snapshot.Meta{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Author:    *author,
	})
	manBytes, err := man.Bytes()
	if err != nil {
		return err
	}
	sig, err := snapshot.Sign(man, priv)
	if err != nil {
		return err
	}

	root := filepath.Join(*out, man.ID)
	if err := os.MkdirAll(filepath.Join(root, "nodes"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, manifestFile), manBytes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, sigFile), sig, 0o644); err != nil {
		return err
	}

	leaked := 0
	for _, b := range res.Bundles {
		d := distBundle{Owner: b.Owner, Files: map[string]string{}}
		for _, f := range b.Files {
			// 渲染层本来就只写占位符;真漏了明文,分发出去就收不回来了。
			// 这里再挡一道 —— 代价是一次遍历,收益是一个不可逆的错误。
			if len(secret.Refs(f.Content)) == 0 && looksLikeSecret(f.Content) {
				leaked++
			}
			d.Files[f.Path] = f.Content
		}
		body, err := json.MarshalIndent(&d, "", "  ")
		if err != nil {
			return err
		}
		dst := filepath.Join(root, "nodes", b.Owner+".json")
		if err := os.WriteFile(dst, append(body, '\n'), 0o644); err != nil {
			return err
		}
	}
	if leaked > 0 {
		_ = os.RemoveAll(root)
		return fmt.Errorf("有 %d 个文件疑似含明文秘密,已放弃发布", leaked)
	}

	cur, err := json.MarshalIndent(&currentDoc{
		Snapshot: man.ID, PublishedAt: man.CreatedAt}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "current.json"), append(cur, '\n'), 0o644); err != nil {
		return err
	}

	owners := make([]string, 0, len(res.Bundles))
	for _, b := range res.Bundles {
		owners = append(owners, b.Owner)
	}
	sort.Strings(owners)
	fmt.Printf("✓ 快照 %s\n", man.ID)
	fmt.Printf("  %d 个节点:%v\n", len(owners), owners)
	fmt.Printf("  → %s\n", *out)
	fmt.Printf("\n树里全是占位符,没有任何凭据;manifest 已签名。\n")
	fmt.Printf("分发点不需要被信任 —— 改一个字节,节点验签就过不了。\n")
	return nil
}

// looksLikeSecret 是最后一道粗筛:渲染层理应只写占位符。
//
// 只认已知的秘密字段名,不做启发式猜测 —— 猜测会产生假阳性,而一个会误报
// 的检查最终会被人绕过。
func looksLikeSecret(content string) bool {
	for _, k := range []string{`"password": "`, "PrivateKey = ", `"secret": "`} {
		if i := indexOf(content, k); i >= 0 {
			rest := content[i+len(k):]
			// 占位符已经被上面排除了,这里剩下的非空值就是明文。
			if len(rest) > 0 && rest[0] != '"' && rest[0] != '\n' {
				return true
			}
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
