// Package publish 把 SSOT 变成一棵可分发的、签了名的树,并送到分发点。
//
// 它跑在**中控**上(§14.2.2、D35)—— 签名私钥在哪,发布器就在哪,没得选。
// 但中控只在"改变系统"时需要:它挂了,节点照常按最后一个快照运行。
//
// **分发出去的树里没有任何凭据**:全是 `${secret:REF}` 占位符,合并发生在
// 各节点本地。所以分发点既看不到秘密,也改不了内容(改了验签过不去)。
package publish

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/secret"
	"loom/internal/snapshot"
	"loom/internal/validate"
)

// Tree 是一次发布的全部产物,按相对路径索引。
//
// 先在内存里凑齐再落盘/推送:发布到一半失败会留下一棵自相矛盾的树,
// 而节点可能正好在那一刻来取。
type Tree struct {
	Snapshot string
	Files    map[string][]byte

	// Blobs 是**内容寻址**的大文件(当前只有 Agent 二进制)。
	//
	// 和 Files 分开,是因为它们的推送语义不同:路径就是内容哈希,所以
	// 分发点上已经存在就不必再传 —— 12MB 的东西每次发布都重推是白费。
	// 回滚到旧快照时,旧二进制也还在,不用重新下载。
	Blobs map[string][]byte
}

// Bundle 是分发树里每个节点那一份的结构。
type Bundle struct {
	Owner string            `json:"owner"`
	Files map[string]string `json:"files"`
}

// Current 是 current.json 的结构。
type Current struct {
	Snapshot string `json:"snapshot"`
	// PublishedAt 只给人看。节点不拿它做任何判断 —— 它没有被签名覆盖。
	PublishedAt string `json:"published_at"`
}

// Meta 是发布的外部输入。时间由调用方注入,包内不读时钟(§12、D14)。
type Meta struct {
	CreatedAt string
	Author    string
	// Binaries 是要一起发的 Agent 二进制,键是 "<os>/<arch>"。
	Binaries map[string][]byte
}

// Build 校验 → 渲染 → 打快照 → 签名 → 组装成树。
//
// **校验不过就不发布。** 渲染一份自相矛盾的配置出去,比什么都不做糟得多:
// 节点会照单全收,而问题要等到流量打不通才暴露。
func Build(ssotBytes []byte, priv ed25519.PrivateKey, meta Meta) (*Tree, error) {
	s, err := model.Load(ssotBytes)
	if err != nil {
		return nil, fmt.Errorf("解析 SSOT:%w", err)
	}
	if fs := validate.Validate(s); len(fs) > 0 {
		return nil, fmt.Errorf("SSOT 校验不通过,不发布:\n%s", validate.Format(fs))
	}
	res, err := render.Render(s)
	if err != nil {
		return nil, fmt.Errorf("渲染:%w", err)
	}

	// 二进制进 manifest,于是它和配置在同一个签名之下、同一个快照 id 之内。
	blobs := map[string][]byte{}
	var refs []snapshot.BinaryRef
	for plat, body := range meta.Binaries {
		goos, goarch, ok := strings.Cut(plat, "/")
		if !ok {
			return nil, fmt.Errorf("二进制平台要写成 <os>/<arch>,收到 %q", plat)
		}
		sum := sha256.Sum256(body)
		ref := snapshot.BinaryRef{
			OS: goos, Arch: goarch,
			SHA256: hex.EncodeToString(sum[:]), Size: len(body),
		}
		refs = append(refs, ref)
		blobs[ref.Path()] = body
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].OS != refs[j].OS {
			return refs[i].OS < refs[j].OS
		}
		return refs[i].Arch < refs[j].Arch
	})

	man := snapshot.Build(s, res, ssotBytes, snapshot.Meta{
		CreatedAt: meta.CreatedAt, Author: meta.Author, Binaries: refs,
	})
	manBytes, err := man.Bytes()
	if err != nil {
		return nil, err
	}
	sig, err := snapshot.Sign(man, priv)
	if err != nil {
		return nil, err
	}

	t := &Tree{Snapshot: man.ID, Files: map[string][]byte{}, Blobs: blobs}
	t.Files[man.ID+"/snapshot.json"] = manBytes
	t.Files[man.ID+"/snapshot.sig"] = sig

	var leaked []string
	for _, b := range res.Bundles {
		d := Bundle{Owner: b.Owner, Files: map[string]string{}}
		for _, f := range b.Files {
			// 渲染层本来就只写占位符。真漏了明文,发出去就收不回来了 ——
			// 这道检查的代价是一次遍历,收益是一个不可逆错误。
			if len(secret.Refs(f.Content)) == 0 && looksLikeSecret(f.Content) {
				leaked = append(leaked, b.Owner+"/"+f.Path)
			}
			d.Files[f.Path] = f.Content
		}
		body, err := json.MarshalIndent(&d, "", "  ")
		if err != nil {
			return nil, err
		}
		t.Files[man.ID+"/nodes/"+b.Owner+".json"] = append(body, '\n')
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		return nil, fmt.Errorf("这些文件疑似含明文秘密,已放弃发布:%s", strings.Join(leaked, " "))
	}

	cur, err := json.MarshalIndent(&Current{Snapshot: man.ID, PublishedAt: man.CreatedAt}, "", "  ")
	if err != nil {
		return nil, err
	}
	t.Files["current.json"] = append(cur, '\n')
	return t, nil
}

// Owners 列出树里包含哪些节点的配置包。
func (t *Tree) Owners() []string {
	var out []string
	prefix := t.Snapshot + "/nodes/"
	for p := range t.Files {
		if strings.HasPrefix(p, prefix) {
			out = append(out, strings.TrimSuffix(strings.TrimPrefix(p, prefix), ".json"))
		}
	}
	sort.Strings(out)
	return out
}

// Paths 返回全部相对路径,排序后。
func (t *Tree) Paths() []string {
	out := make([]string, 0, len(t.Files))
	for p := range t.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// looksLikeSecret 是最后一道粗筛。
//
// 只认已知的秘密字段名,不做启发式猜测 —— 会误报的检查最终会被人绕过。
func looksLikeSecret(content string) bool {
	for _, k := range []string{`"password": "`, "PrivateKey = ", `"secret": "`} {
		i := strings.Index(content, k)
		if i < 0 {
			continue
		}
		rest := content[i+len(k):]
		if len(rest) > 0 && rest[0] != '"' && rest[0] != '\n' {
			return true
		}
	}
	return false
}
