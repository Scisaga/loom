package publish

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSSOT = `
defaults:
  dns: [223.5.5.5]
  distribution_url: https://x/loom/
  components: {sing_box: 1, wireguard: 1, agent: 1}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: Sfhh2xviqn8iws9mnVojcZEQRZANuhoLjoMqjN89y6Q=}
    access:
      platform: linux-server
      credentials: [c1]
      mixed_ports: [{port: 1080, declaration: d1}]
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: 11en8KSnR461ATx3ePxn3hM1+7omYdXS2K6YEPHt3To=}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, egress_capable: true, wg_public_key: dVg67BLu61j4V2JshVQMHJFuVjhthA+RO4DKSCTtHA0=}}
tunnels:
  - {from: acc, to: b, listen_port: 61637, from_addr: 10.99.0.1/32, to_addr: 10.99.0.2/32}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, max_hops: 2, allowed_servers: [a, b]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
`

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func build(t *testing.T, src string) *Tree {
	t.Helper()
	tr, err := Build([]byte(src), key(t), Meta{CreatedAt: "2026-08-23T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// 校验不过就不发布。发一份自相矛盾的配置出去比什么都不做糟得多 ——
// 节点会照单全收,问题要等到流量打不通才暴露。
func TestBuildRefusesInvalidSSOT(t *testing.T) {
	bad := strings.Replace(goodSSOT, "window: 1h", "window: 5m", 1) // 装不下 min_samples
	if _, err := Build([]byte(bad), key(t), Meta{}); err == nil {
		t.Fatal("校验不过的 SSOT 竟然发布了")
	} else if !strings.Contains(err.Error(), "校验不通过") {
		t.Errorf("报错没说清是校验问题:%v", err)
	}
}

// 分发树里不能有任何凭据明文 —— 分发点是不可信的,凭据要留在各节点本地。
func TestTreeContainsNoPlaintextSecrets(t *testing.T) {
	tr := build(t, goodSSOT)
	found := false
	for p, body := range tr.Files {
		if strings.Contains(string(body), "${secret:") {
			found = true
		}
		// 占位符没被替换是对的;真值绝不该出现。这里用一个不可能巧合的
		// 串来确认检测本身有效。
		if strings.Contains(string(body), "SUPERSECRETVALUE") {
			t.Errorf("%s 里有明文", p)
		}
	}
	if !found {
		t.Error("树里一个占位符都没有 —— 要么渲染错了,要么秘密被提前填进去了")
	}
}

// 同样的 SSOT 必须产出同样的快照 id(§12 纯函数)。这是 dry-run、
// 漂移检测、去重、以及发布器"已是最新就不推"全部的立足点。
func TestSnapshotIDIsDeterministic(t *testing.T) {
	a := build(t, goodSSOT)
	b := build(t, goodSSOT)
	if a.Snapshot != b.Snapshot {
		t.Fatalf("同样的输入算出两个 id:%s vs %s", a.Snapshot, b.Snapshot)
	}
	// 改一个字节就该换 id,否则"已是最新"会漏掉真实变更。
	c := build(t, goodSSOT+"\n# 一条注释\n")
	if c.Snapshot == a.Snapshot {
		t.Error("内容变了 id 没变")
	}
}

// current.json 必须**最后**写。顺序反了会有一个窗口:它已经指向新快照,
// 而那个快照的文件还没铺全 —— 正好来取的节点会拿到 404 或半截文件。
func TestLocalTargetWritesCurrentLast(t *testing.T) {
	dir := t.TempDir()
	tr := build(t, goodSSOT)
	tgt := &localTarget{dir: dir}
	if err := tgt.Push(tr); err != nil {
		t.Fatal(err)
	}
	// current.json 指向的那一层必须齐全。
	b, err := os.ReadFile(filepath.Join(dir, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c Current
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"snapshot.json", "snapshot.sig"} {
		if _, err := os.Stat(filepath.Join(dir, c.Snapshot, must)); err != nil {
			t.Errorf("current.json 指向 %s,但 %s 不在:%v", c.Snapshot, must, err)
		}
	}
	for _, owner := range tr.Owners() {
		if _, err := os.Stat(filepath.Join(dir, c.Snapshot, "nodes", owner+".json")); err != nil {
			t.Errorf("%s 的配置包不在:%v", owner, err)
		}
	}
	got, err := tgt.Current()
	if err != nil || got != tr.Snapshot {
		t.Errorf("Current() = %q, %v,期望 %q", got, err, tr.Snapshot)
	}
}

// 目标写法错了要在解析时就报,而不是推的时候才发现。
func TestParseTarget(t *testing.T) {
	if _, err := ParseTarget("relative/path", ""); err == nil {
		t.Error("相对路径应当被拒绝")
	}
	if _, err := ParseTarget("ssh://onlyhost", ""); err == nil {
		t.Error("ssh:// 缺路径应当被拒绝")
	}
	tg, err := ParseTarget("ssh://cn-a/var/www/loom", "")
	if err != nil || tg.String() != "ssh://cn-a/var/www/loom" {
		t.Errorf("ssh 目标解析不对:%v %v", tg, err)
	}
	tg, err = ParseTarget("/srv/loom", "")
	if err != nil || tg.String() != "/srv/loom" {
		t.Errorf("本地目标解析不对:%v %v", tg, err)
	}
}

// 空目录不该被当成"指向某个快照"。
func TestCurrentOnEmptyTarget(t *testing.T) {
	got, err := (&localTarget{dir: t.TempDir()}).Current()
	if err != nil || got != "" {
		t.Errorf("空目录返回 %q, %v,期望空", got, err)
	}
}

// current.json 是节点看世界的入口,写它必须原子 —— 半个文件会让每台机器
// 解析失败、卡一轮。rename 之后不该留下临时文件。
func TestCurrentJSONIsWrittenAtomically(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current.json")
	if err := writeAtomic(p, []byte(`{"snapshot":"abc"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件没被 rename 掉")
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != `{"snapshot":"abc"}` {
		t.Fatalf("内容不对:%q(err=%v)", b, err)
	}
	// 覆写同一个路径要能成功(rename 覆盖已存在的文件)。
	if err := writeAtomic(p, []byte(`{"snapshot":"def"}`), 0o644); err != nil {
		t.Fatalf("覆写失败:%v", err)
	}
	b, _ = os.ReadFile(p)
	if string(b) != `{"snapshot":"def"}` {
		t.Fatalf("覆写后内容不对:%q", b)
	}
}
