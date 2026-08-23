// Package snapshot 把一次渲染冻成不可变版本,并对它签名。
//
// 快照不是 git 提交。git 里放的是 SSOT —— 源头;快照是从源头**生成出来的
// 成品**,打了版本号、签了名。三件事依赖它(§12.1、§15.2、§15.4):
//
//  1. 回滚需要一个"回到哪儿"的基准;
//  2. 漂移检测需要一个"应该是什么样"的期望值;
//  3. 配置经中继反代下发(§14.3),签名让**传输通道与内容真实性解耦** ——
//     即使中继被攻破也注入不了恶意配置。
package snapshot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"loom/internal/model"
	"loom/internal/render"
)

// BundleRef 是一个配置包的内容哈希。只覆盖渲染层 —— 秘密层不在其中(§12.1)。
type BundleRef struct {
	Owner string `json:"owner"` // 节点 id 或客户端档案 id
	Hash  string `json:"hash"`
}

// ComponentRef 钉住一台机器上各组件的版本(§15.4)。
//
// **配置与二进制必须绑定回滚。** 新版可能不认旧配置,旧版也可能不认新配置;
// 只回滚其一会得到起不来的节点。所以版本和配置冻在同一个快照里。
type ComponentRef struct {
	Node      string `json:"node"`
	SingBox   string `json:"sing_box,omitempty"`
	WireGuard string `json:"wireguard,omitempty"`
	Tailscale string `json:"tailscale,omitempty"`
	Agent     string `json:"agent,omitempty"`
}

// SecretRef 记录一台机器秘密层的代次。
//
// **只记代次,不记私钥。** 回滚也不回滚秘密层:节点保留当前代次的私钥,
// 代次对不上时应当告警,而不是悄悄换密钥(§12.1)。
type SecretRef struct {
	Node       string `json:"node"`
	Generation int    `json:"generation"`
	PublicKey  string `json:"public_key,omitempty"`
}

// Manifest 是快照的全部内容。字段顺序即序列化顺序,所有切片都排过序 ——
// 同样的输入必须产生同样的字节,否则签名和去重都无从谈起。
type Manifest struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Author    string `json:"author,omitempty"`

	// SSOTHash 是源头文件的哈希:这份成品是从哪一版源头生成的。
	SSOTHash string `json:"ssot_hash"`

	// Binaries 是这个快照配套的 Agent 二进制。
	//
	// **它必须和配置在同一个签名之下**(§15.4)。分开发的话,回滚配置会
	// 得到一个跑着不匹配二进制的节点 —— 新版可能不认旧配置,旧版也可能
	// 不认新配置,而"回滚"最不该产生的就是起不来的节点。
	Binaries []BinaryRef `json:"binaries,omitempty"`

	// Decommissioned 是被明确下线的节点。**签名覆盖它**,所以节点读到
	// 自己在这个名单里时,那是一条经过认证的停机指令,不是猜测。
	Decommissioned []string `json:"decommissioned,omitempty"`

	Bundles           []BundleRef    `json:"bundles"`
	Components        []ComponentRef `json:"components,omitempty"`
	SecretGenerations []SecretRef    `json:"secret_generations,omitempty"`

	// Skipped 把渲染期跳过的东西一并冻进来。没有它,一份"少生成了东西"
	// 的快照看起来和完整的一模一样。
	Skipped []render.Skip `json:"skipped,omitempty"`
}

// BinaryRef 是一个平台的 Agent 二进制。
//
// 内容寻址:分发树里的路径就是 `bin/<sha256>`,于是同一个二进制跨快照复用,
// 回滚时也不用重新下载。
type BinaryRef struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// Path 是这个二进制在分发树里的位置。
func (b *BinaryRef) Path() string { return "bin/" + b.SHA256 }

// Meta 是快照的外部输入。时间与作者由调用方给出,**不从包内读取** ——
// 渲染与打包都必须是纯函数,否则 §12.1 的三个产物全都靠不住。
type Meta struct {
	CreatedAt string
	Author    string
	// Binaries 由调用方给出 —— 和时间、作者一样是外部输入,包内不去
	// 文件系统上找二进制(§12 纯函数)。
	Binaries []BinaryRef
}

// Build 把一次渲染结果冻成 manifest。
//
// ID 是内容哈希(不含时间与作者):同样的 SSOT 渲染两次得到同一个 id,
// 于是"没改动"这件事可以被直接看出来,而不需要逐文件比对。
func Build(s *model.SSOT, res *render.Result, ssotBytes []byte, meta Meta) *Manifest {
	var decom []string
	for i := range s.Nodes {
		if s.Nodes[i].Decommission {
			decom = append(decom, s.Nodes[i].ID)
		}
	}
	sort.Strings(decom)

	m := &Manifest{
		Binaries:       append([]BinaryRef(nil), meta.Binaries...),
		Decommissioned: decom,
		CreatedAt:      meta.CreatedAt,
		Author:         meta.Author,
		SSOTHash:       "sha256:" + hexSum(ssotBytes),
		Skipped:        append([]render.Skip(nil), res.Skipped...),
	}

	for i := range res.Bundles {
		b := &res.Bundles[i]
		m.Bundles = append(m.Bundles, BundleRef{Owner: b.Owner, Hash: b.Hash()})
	}
	sort.Slice(m.Bundles, func(i, j int) bool { return m.Bundles[i].Owner < m.Bundles[j].Owner })

	for i := range s.Nodes {
		n := &s.Nodes[i]
		v := s.VersionsFor(n)
		m.Components = append(m.Components, ComponentRef{
			Node: n.ID, SingBox: v.SingBox, WireGuard: v.WireGuard,
			Tailscale: v.Tailscale, Agent: v.Agent,
		})
		if secretGen(n) > 0 || wgPub(n) != "" {
			m.SecretGenerations = append(m.SecretGenerations, SecretRef{
				Node: n.ID, Generation: secretGen(n), PublicKey: wgPub(n),
			})
		}
	}
	sort.Slice(m.Components, func(i, j int) bool { return m.Components[i].Node < m.Components[j].Node })
	sort.Slice(m.SecretGenerations, func(i, j int) bool {
		return m.SecretGenerations[i].Node < m.SecretGenerations[j].Node
	})
	sort.Slice(m.Skipped, func(i, j int) bool {
		if m.Skipped[i].Where != m.Skipped[j].Where {
			return m.Skipped[i].Where < m.Skipped[j].Where
		}
		return m.Skipped[i].Reason < m.Skipped[j].Reason
	})

	m.ID = m.contentID()
	return m
}

// contentID 是除时间与作者外全部内容的哈希前 12 位。
func (m *Manifest) contentID() string {
	c := *m
	c.ID, c.CreatedAt, c.Author = "", "", ""
	b, err := json.Marshal(&c)
	if err != nil {
		// 结构体里只有基本类型,序列化不会失败。
		panic("snapshot: marshal manifest: " + err.Error())
	}
	return hexSum(b)[:12]
}

// Bytes 是被签名的确切字节。签名针对它,校验也针对它 —— 中间不做任何
// 重新规范化,否则"签的"和"验的"可能不是同一串字节。
func (m *Manifest) Bytes() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Sign 用平台私钥对 manifest 签名。
func Sign(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("签名私钥长度不对:%d", len(priv))
	}
	b, err := m.Bytes()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, b), nil
}

// ErrNoSignature 表示这份快照没有签名可验。
var ErrNoSignature = errors.New("快照没有签名")

// VerifySignature 校验签名。
//
// 这是 §14.3 那条"传输通道与配置真实性解耦"的落点:配置经中继反代下发,
// 中继可以不可信,但内容必须可验证。
func VerifySignature(manifestBytes, sig []byte, pub ed25519.PublicKey) error {
	if len(sig) == 0 {
		return ErrNoSignature
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("公钥长度不对:%d", len(pub))
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return errors.New("签名校验失败 —— 这份快照不是用可信密钥签的,或已被篡改")
	}
	return nil
}

// VerifyBundles 比对 manifest 里记录的哈希与实际渲染出的内容。
//
// 这是 §15.3 漂移检测的核心比对逻辑:Agent 拿到快照后做的就是这件事。
func VerifyBundles(m *Manifest, res *render.Result) []string {
	want := map[string]string{}
	for _, b := range m.Bundles {
		want[b.Owner] = b.Hash
	}
	var problems []string
	seen := map[string]bool{}
	for i := range res.Bundles {
		b := &res.Bundles[i]
		seen[b.Owner] = true
		h, ok := want[b.Owner]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s:快照里没有这个配置包", b.Owner))
		case h != b.Hash():
			problems = append(problems, fmt.Sprintf("%s:内容与快照不符(快照 %s,实际 %s)",
				b.Owner, h[:12], b.Hash()[:12]))
		}
	}
	for _, b := range m.Bundles {
		if !seen[b.Owner] {
			problems = append(problems, fmt.Sprintf("%s:快照里有,但本次没渲染出来", b.Owner))
		}
	}
	sort.Strings(problems)
	return problems
}

// 秘密层信息只有服务器节点才有 —— 接入节点不参与隧道。
func secretGen(n *model.Node) int {
	if n.Server == nil {
		return 0
	}
	return n.Server.SecretGeneration
}

func wgPub(n *model.Node) string {
	if n.Server == nil {
		return ""
	}
	return n.Server.WGPublicKey
}

func hexSum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
