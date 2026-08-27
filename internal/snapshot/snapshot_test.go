package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/render"
)

const fixture = "../../testdata/matrix/ssot.yaml"

func build(t *testing.T, meta Meta) (*model.SSOT, *render.Result, *Manifest) {
	t.Helper()
	raw := mustRead(t, fixture)
	s, err := model.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := render.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	return s, res, Build(s, res, raw, meta)
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBuildIsDeterministic:同样的输入必须产生同样的字节。
// 签名针对这些字节,不确定就等于签名随机失效。
func TestBuildIsDeterministic(t *testing.T) {
	meta := Meta{CreatedAt: "2026-08-21T00:00:00Z", Author: "tester"}
	_, _, a := build(t, meta)
	_, _, b := build(t, meta)

	ab, err := a.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(bb) {
		t.Error("两次打包的字节不同 —— 打包过程不是确定的")
	}
	if a.ID != b.ID {
		t.Errorf("两次打包的 id 不同:%s vs %s", a.ID, b.ID)
	}
}

// TestIDIgnoresTimeAndAuthor:id 是内容哈希。
//
// 这让"这次改动有没有实际影响产物"变成一个可以直接看出来的问题 ——
// 同一份 SSOT 隔天再打一次,id 应当一样。
func TestIDIgnoresTimeAndAuthor(t *testing.T) {
	_, _, a := build(t, Meta{CreatedAt: "2026-01-01T00:00:00Z", Author: "alice"})
	_, _, b := build(t, Meta{CreatedAt: "2026-12-31T23:59:59Z", Author: "bob"})
	if a.ID != b.ID {
		t.Errorf("时间与作者不同导致 id 变了:%s vs %s", a.ID, b.ID)
	}
	if a.CreatedAt == b.CreatedAt {
		t.Error("created_at 应当如实记录,不该被抹掉")
	}
}

// TestSignVerifyRoundTrip:签名能被对应公钥验过。
func TestSignVerifyRoundTrip(t *testing.T) {
	_, _, m := build(t, Meta{CreatedAt: "2026-08-21T00:00:00Z"})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(body, sig, pub); err != nil {
		t.Errorf("自己签的自己验不过:%v", err)
	}
}

// TestTamperedManifestFailsVerification 是 §14.3 那条不变量的落点:
// 配置经中继反代下发,中继可以不可信,但内容必须可验证。
func TestTamperedManifestFailsVerification(t *testing.T) {
	_, _, m := build(t, Meta{CreatedAt: "2026-08-21T00:00:00Z"})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	for name, tampered := range map[string][]byte{
		"改了一个配置包哈希": []byte(strings.Replace(string(body), m.Bundles[0].Hash,
			strings.Repeat("0", len(m.Bundles[0].Hash)), 1)),
		"改了源头哈希": []byte(strings.Replace(string(body), m.SSOTHash, "sha256:deadbeef", 1)),
		"多加一个字节": append(append([]byte{}, body...), ' '),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifySignature(tampered, sig, pub); err == nil {
				t.Error("篡改后的 manifest 竟然验过了")
			}
		})
	}
}

// TestWrongKeyFailsVerification:换一把密钥签的快照必须验不过。
func TestWrongKeyFailsVerification(t *testing.T) {
	_, _, m := build(t, Meta{CreatedAt: "2026-08-21T00:00:00Z"})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := m.Bytes()
	if err := VerifySignature(body, sig, otherPub); err == nil {
		t.Error("用另一把公钥竟然验过了 —— 这等于谁都能签配置")
	}
	if err := VerifySignature(body, nil, otherPub); err != ErrNoSignature {
		t.Errorf("空签名应报 ErrNoSignature,得到 %v", err)
	}
}

// TestVerifyBundlesDetectsDrift 是 §15.3 漂移检测的核心比对。
func TestVerifyBundlesDetectsDrift(t *testing.T) {
	_, res, m := build(t, Meta{CreatedAt: "2026-08-21T00:00:00Z"})

	if p := VerifyBundles(m, res); len(p) > 0 {
		t.Fatalf("刚打的快照就对不上:%v", p)
	}

	t.Run("内容被改", func(t *testing.T) {
		drifted := *res
		drifted.Bundles = append([]render.Bundle(nil), res.Bundles...)
		b := drifted.Bundles[0]
		b.Files = append([]render.File(nil), b.Files...)
		b.Files[0].Content += "# 有人手工改了这里\n"
		drifted.Bundles[0] = b

		p := VerifyBundles(m, &drifted)
		if len(p) != 1 || !strings.Contains(p[0], "内容与快照不符") {
			t.Errorf("没检出内容漂移:%v", p)
		}
	})

	t.Run("少了一个配置包", func(t *testing.T) {
		short := *res
		short.Bundles = res.Bundles[1:]
		p := VerifyBundles(m, &short)
		if len(p) != 1 || !strings.Contains(p[0], "本次没渲染出来") {
			t.Errorf("没检出缺失:%v", p)
		}
	})

	t.Run("多了一个配置包", func(t *testing.T) {
		extra := *res
		extra.Bundles = append(append([]render.Bundle(nil), res.Bundles...),
			render.Bundle{Owner: "zz-new"})
		p := VerifyBundles(m, &extra)
		if len(p) != 1 || !strings.Contains(p[0], "快照里没有这个配置包") {
			t.Errorf("没检出多余:%v", p)
		}
	})
}

// TestFreezesVersionsAndSecrets:§15.4 要求配置与二进制绑定回滚,
// 所以版本必须和配置冻在同一个快照里;秘密层只冻代次(§12.1)。
func TestFreezesVersionsAndSecrets(t *testing.T) {
	s, _, m := build(t, Meta{CreatedAt: "2026-08-21T00:00:00Z"})

	if len(m.Components) != len(s.Nodes) {
		t.Errorf("冻了 %d 台机器的版本,期望 %d 台", len(m.Components), len(s.Nodes))
	}
	for _, c := range m.Components {
		if c.SingBox == "" || c.Agent == "" {
			t.Errorf("%s 的版本没冻全:%+v", c.Node, c)
		}
	}
	// fixture 里 cn-bj 有节点级覆盖,应当压过全局默认。
	var bj *ComponentRef
	for i := range m.Components {
		if m.Components[i].Node == "cn-bj" {
			bj = &m.Components[i]
		}
	}
	if bj == nil {
		t.Fatal("找不到 cn-bj")
	}
	if bj.SingBox != "1.11.5" {
		t.Errorf("cn-bj 的 sing_box 是 %q,期望节点级覆盖 1.11.5", bj.SingBox)
	}

	body, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// 秘密层只记代次和公钥,私钥永不出现(§12.1、§13.1)。
	for _, forbidden := range []string{"PrivateKey", "private_key", "secret_ref"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("快照里出现了 %q —— 秘密层不该进快照", forbidden)
		}
	}
	found := false
	for _, sr := range m.SecretGenerations {
		if sr.Node == "cn-bj" && sr.Generation == 1 {
			found = true
		}
	}
	if !found {
		t.Error("cn-bj 的秘密层代次没冻进快照")
	}
}

// TestFreezesSkips:跳过项必须一并冻进去。
// 没有它,一份"少生成了东西"的快照看起来和完整的一模一样。
func TestFreezesSkips(t *testing.T) {
	_, res, m := build(t, Meta{CreatedAt: "2026-08-21T00:00:00Z"})
	if len(m.Skipped) != len(res.Skipped) {
		t.Errorf("冻了 %d 条跳过,渲染时有 %d 条", len(m.Skipped), len(res.Skipped))
	}
	if len(m.Skipped) == 0 {
		t.Error("fixture 本应有跳过项,快照里却是空的")
	}
}
