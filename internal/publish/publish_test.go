package publish

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	for _, bad := range []string{
		"relative/path", "/", "//", "/tmp/..", "/tmp/loom/",
		"ssh://onlyhost", "ssh://h//", "ssh://h/a/../..", "ssh://h/srv/loom/",
		"ssh://-oProxyCommand=touch-pwned/srv/loom", "ssh://bad host/srv/loom", "ssh://bad\\host/srv/loom",
	} {
		t.Run("reject-"+strings.ReplaceAll(bad, "/", "_"), func(t *testing.T) {
			if _, err := ParseTarget(bad, ""); err == nil {
				t.Fatalf("危险/非规范分发根目录 %q 应被拒绝", bad)
			}
		})
	}
	tg, err := ParseTarget("ssh://cn-a/var/www/loom", "")
	if err != nil || tg.String() != "ssh://cn-a/var/www/loom" {
		t.Errorf("ssh 目标解析不对:%v %v", tg, err)
	}
	for _, good := range []string{"ssh://user@host/srv/loom", "ssh://alias_name/srv/loom", "ssh://[2001:db8::1]/srv/loom"} {
		if _, err := ParseTarget(good, ""); err != nil {
			t.Errorf("正常 ssh 目标 %q 被拒绝:%v", good, err)
		}
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

func TestTargetsRejectUnsafeTreePathBeforeWriting(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "dist")
	tr := &Tree{Files: map[string][]byte{
		"current.json": []byte(`{"snapshot":"bad"}`),
		"../escaped":   []byte("must not escape"),
	}}
	if err := (&localTarget{dir: dist}).Push(tr); err == nil {
		t.Fatal("本地分发点应拒绝路径穿越")
	}
	if _, err := os.Stat(filepath.Join(root, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("非法 Tree 写出分发根目录:%v", err)
	}
	if _, err := os.Stat(filepath.Join(dist, "current.json")); !os.IsNotExist(err) {
		t.Fatalf("路径预检必须在任何写入之前失败:%v", err)
	}

	// SSH 也走同一道预检：错误必须是路径错误，而不是
	// 真的尝试连接这个不存在的主机。
	if err := (&sshTarget{host: "must-not-connect.invalid", dir: "/srv/loom"}).Push(tr); err == nil ||
		!strings.Contains(err.Error(), "规范的相对路径") {
		t.Fatalf("SSH 分发点没有在连接前拒绝路径:%v", err)
	}
}

func TestLocalTargetRejectsSymlinkEscapeWithoutWritingOutside(t *testing.T) {
	for _, tc := range []struct {
		name     string
		linkPath func(root string) string
		filePath string
	}{
		{"snapshot-ancestor", func(root string) string { return filepath.Join(root, "snap") }, "snap/nodes/a.json"},
		{"blob-ancestor", func(root string) string { return filepath.Join(root, "bin") }, "bin/" + strings.Repeat("0", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if err := os.Symlink(outside, tc.linkPath(root)); err != nil {
				t.Fatal(err)
			}
			tr := &Tree{Snapshot: "snap", Files: map[string][]byte{
				"current.json":      []byte(`{"snapshot":"snap"}`),
				"snap/nodes/a.json": []byte("node"),
			}}
			if tc.name == "blob-ancestor" {
				body := []byte("blob")
				sum := sha256.Sum256(body)
				tr.Blobs = map[string][]byte{"bin/" + hex.EncodeToString(sum[:]): body}
			}
			if err := (&localTarget{dir: root}).Push(tr); err == nil {
				t.Fatal("本地分发点必须拒绝符号链接 ancestor")
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("通过 symlink 写出了分发根:%v", entries)
			}
			if _, _, err := (&localTarget{dir: root}).ReadFile(tc.filePath); err == nil {
				t.Fatal("ReadFile 也必须拒绝 symlink ancestor")
			}
		})
	}

	t.Run("target-root", func(t *testing.T) {
		outside := t.TempDir()
		link := filepath.Join(t.TempDir(), "dist-link")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		tr := &Tree{Files: map[string][]byte{"current.json": []byte(`{"snapshot":"snap"}`)}}
		if err := (&localTarget{dir: link}).Push(tr); err == nil {
			t.Fatal("本地分发根本身是 symlink 时必须拒绝")
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("symlink 根外部被写入:%v err=%v", entries, err)
		}
	})
}

func TestLocalTargetReadFileRejectsOversizedUntrustedBody(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oversized.json")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxTargetReadFileBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&localTarget{dir: dir}).ReadFile("oversized.json"); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("不可信本地分发点的大文件必须有硬上限:%v", err)
	}
}

func TestBuildRefusesOwnerPathTraversal(t *testing.T) {
	bad := strings.Replace(goodSSOT, "id: acc", "id: ../../escaped", 1)
	bad = strings.Replace(bad, "from: acc", "from: ../../escaped", 1)
	if _, err := Build([]byte(bad), key(t), Meta{}); err == nil {
		t.Fatal("Build 不应允许 node owner 生成越界路径")
	}
}

func TestLocalTargetValidatesAndRepairsExistingBlob(t *testing.T) {
	dir := t.TempDir()
	body := []byte("approved binary bytes")
	s := sha256.Sum256(body)
	sha := hex.EncodeToString(s[:])
	p := "bin/" + sha
	dst := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	// 同名、同尺寸、错误内容:只 test -s 或只看大小都会误判为缓存命中。
	if err := os.WriteFile(dst, []byte(strings.Repeat("x", len(body))), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &Tree{
		Snapshot: "snap",
		Blobs:    map[string][]byte{p: body},
		Files: map[string][]byte{
			"snap/nodes/a.json": []byte("complete node body\n"),
			"current.json":      []byte(`{"snapshot":"snap"}`),
		},
	}
	if err := (&localTarget{dir: dir}).Push(tr); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != string(body) {
		t.Fatalf("错误 blob 没被原子修复:%q", got)
	}
	if ok, err := (&localTarget{dir: dir}).HasBlob(p); err != nil || !ok {
		t.Fatalf("修复后完整性检查失败(ok=%v,err=%v)", ok, err)
	}
}

func TestTargetRejectsBlobStoredUnderWrongHash(t *testing.T) {
	tr := &Tree{
		Snapshot: "snap",
		Blobs:    map[string][]byte{"bin/" + strings.Repeat("0", 64): []byte("not zeros")},
		Files:    map[string][]byte{"current.json": []byte(`{"snapshot":"snap"}`)},
	}
	if err := (&localTarget{dir: t.TempDir()}).Push(tr); err == nil {
		t.Fatal("内容与内容寻址路径不一致时必须拒绝")
	}
}

func TestTargetRejectsWrongBodyEvenWhenCorrectBlobAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	approved := []byte("approved")
	s := sha256.Sum256(approved)
	sha := hex.EncodeToString(s[:])
	p := "bin/" + sha
	dst := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, approved, 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &Tree{
		Snapshot: "snap",
		Blobs:    map[string][]byte{p: []byte("different")},
		Files:    map[string][]byte{"current.json": []byte(`{"snapshot":"snap"}`)},
	}
	if err := (&localTarget{dir: dir}).Push(tr); err == nil {
		t.Fatal("缓存命中也不能吞掉 Tree 内部 body/path 不一致")
	}
}

func TestTargetRejectsBlobPathTraversalEvenWithValidHash(t *testing.T) {
	body := []byte("valid body")
	s := sha256.Sum256(body)
	sha := hex.EncodeToString(s[:])
	tr := &Tree{
		Snapshot: "snap",
		Blobs:    map[string][]byte{"../escape/" + sha: body},
		Files:    map[string][]byte{"current.json": []byte(`{"snapshot":"snap"}`)},
	}
	if err := (&localTarget{dir: t.TempDir()}).Push(tr); err == nil {
		t.Fatal("blob 路径即使带合法哈希也不能逃出 bin/")
	}
}

func TestSSHTargetRepairsBlobThroughTempThenRename(t *testing.T) {
	tools := t.TempDir()
	ssh := filepath.Join(tools, "ssh")
	// 测试替身执行 ssh 收到的最后一个参数(远端命令),stdin 保持原样。
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nfor arg do remote=$arg; done\nexec sh -c \"$remote\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	body := []byte("ssh approved binary")
	s := sha256.Sum256(body)
	sha := hex.EncodeToString(s[:])
	p := "bin/" + sha
	dst := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte(strings.Repeat("x", len(body))), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &Tree{
		Snapshot: "snap",
		Blobs:    map[string][]byte{p: body},
		Files: map[string][]byte{
			"snap/nodes/a.json": []byte("complete node body\n"),
			"current.json":      []byte(`{"snapshot":"snap"}`),
		},
	}
	tgt := &sshTarget{host: "fake", dir: dir}
	if err := tgt.Push(tr); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != string(body) {
		t.Fatalf("SSH 目标没有修复错误 blob:%q", got)
	}
	nodeBody, err := os.ReadFile(filepath.Join(dir, "snap/nodes/a.json"))
	if err != nil || string(nodeBody) != "complete node body\n" {
		t.Fatalf("SSH 快照正文没有从目标内临时树 rename 到位:%q(err=%v)", nodeBody, err)
	}
	matches, err := filepath.Glob(dst + ".tmp.*")
	if err != nil || len(matches) != 0 {
		t.Fatalf("原子 rename 后不应残留 blob 临时文件:%v(err=%v)", matches, err)
	}
	stages, err := filepath.Glob(filepath.Join(dir, ".loom-push.*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("快照正文 rename 后不应残留 staging 树:%v(err=%v)", stages, err)
	}
}

func TestSSHTargetRejectsOversizedUntrustedBody(t *testing.T) {
	installFakeSSH(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "oversized.json")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxTargetReadFileBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&sshTarget{host: "fake", dir: dir}).ReadFile("oversized.json"); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("不可信 SSH 分发点的大文件必须在客户端硬停止:%v", err)
	}
}

func TestSSHTargetSmallCommandsHaveTotalDeadline(t *testing.T) {
	tools := t.TempDir()
	ssh := filepath.Join(tools, "ssh")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+":"+os.Getenv("PATH"))
	tgt := &sshTarget{host: "fake", dir: t.TempDir(), commandTimeout: 30 * time.Millisecond}
	body := []byte("blob")
	sum := sha256.Sum256(body)
	blobPath := "bin/" + hex.EncodeToString(sum[:])
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"read", func() error { _, _, err := tgt.ReadFile("current.json"); return err }},
		{"hash", func() error { _, err := tgt.HasBlob(blobPath); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			err := tc.run()
			if err == nil || !strings.Contains(err.Error(), "总期限") {
				t.Fatalf("卡死 SSH %s 必须以总期限失败:%v", tc.name, err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("30ms 测试期限却耗时 %s", elapsed)
			}
		})
	}
}

func TestSSHTargetRejectsSymlinkAncestorsWithoutTouchingSentinel(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(root, outside string) (*Tree, string)
	}{
		{
			name: "root-ancestor",
			set: func(root, outside string) (*Tree, string) {
				link := filepath.Join(root, "remote-link")
				if err := os.Symlink(outside, link); err != nil {
					t.Fatal(err)
				}
				return &Tree{Files: map[string][]byte{"current.json": []byte(`{"snapshot":"snap"}`)}}, filepath.Join(link, "dist")
			},
		},
		{
			name: "snapshot-ancestor",
			set: func(root, outside string) (*Tree, string) {
				dist := filepath.Join(root, "dist")
				if err := os.MkdirAll(dist, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(dist, "snap")); err != nil {
					t.Fatal(err)
				}
				return &Tree{Snapshot: "snap", Files: map[string][]byte{
					"snap/nodes/a.json": []byte("node"),
					"current.json":      []byte(`{"snapshot":"snap"}`),
				}}, dist
			},
		},
		{
			name: "blob-ancestor",
			set: func(root, outside string) (*Tree, string) {
				dist := filepath.Join(root, "dist")
				if err := os.MkdirAll(dist, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(dist, "bin")); err != nil {
					t.Fatal(err)
				}
				body := []byte("blob")
				sum := sha256.Sum256(body)
				return &Tree{Snapshot: "snap", Blobs: map[string][]byte{
					"bin/" + hex.EncodeToString(sum[:]): body,
				}, Files: map[string][]byte{"current.json": []byte(`{"snapshot":"snap"}`)}}, dist
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installFakeSSH(t)
			root := t.TempDir()
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "sentinel")
			if err := os.WriteFile(sentinel, []byte("untouched"), 0o644); err != nil {
				t.Fatal(err)
			}
			tr, remoteRoot := tc.set(root, outside)
			if err := (&sshTarget{host: "fake", dir: remoteRoot}).Push(tr); err == nil || !strings.Contains(err.Error(), "符号链接") {
				t.Fatalf("SSH 分发点必须拒绝 symlink ancestor:%v", err)
			}
			got, err := os.ReadFile(sentinel)
			if err != nil || string(got) != "untouched" {
				t.Fatalf("symlink 诱导触碰了根外 sentinel:%q err=%v", got, err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 1 {
				t.Fatalf("symlink 诱导在分发根外创建了文件:%v err=%v", entries, err)
			}
		})
	}
}

func TestSSHTargetRejectsNonRegularMktempResultBeforeWriting(t *testing.T) {
	tools := installFakeSSH(t)
	realMktemp, err := exec.LookPath("mktemp")
	if err != nil {
		t.Fatal(err)
	}
	// exec.LookPath 此刻会看到即将创建 wrapper 的目录；先解析真实路径。
	if filepath.Dir(realMktemp) == tools {
		t.Fatal("测试 mktemp wrapper 已意外存在")
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "malicious-mktemp-link")
	if err := os.Symlink(sentinel, link); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(tools, "mktemp")
	body := "#!/bin/sh\nif [ \"$1\" = \"-d\" ]; then exec " + shellQuote(realMktemp) + " \"$@\"; fi\nprintf '%s\\n' \"$LOOM_TEST_MKTEMP\"\n"
	if err := os.WriteFile(wrapper, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOOM_TEST_MKTEMP", link)

	blob := []byte("approved")
	sum := sha256.Sum256(blob)
	p := "bin/" + hex.EncodeToString(sum[:])
	tr := &Tree{Snapshot: "snap", Blobs: map[string][]byte{p: blob}, Files: map[string][]byte{
		"current.json": []byte(`{"snapshot":"snap"}`),
	}}
	if err := (&sshTarget{host: "fake", dir: t.TempDir()}).Push(tr); err == nil || !strings.Contains(err.Error(), "mktemp") {
		t.Fatalf("mktemp 返回 symlink 时必须在 cat 前拒绝:%v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("恶意 mktemp symlink 覆写了 sentinel:%q err=%v", got, err)
	}
}

func installFakeSSH(t *testing.T) string {
	t.Helper()
	tools := t.TempDir()
	ssh := filepath.Join(tools, "ssh")
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nfor arg do remote=$arg; done\nexec sh -c \"$remote\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+":"+os.Getenv("PATH"))
	return tools
}

func TestShellQuoteDoesNotExecuteTargetPath(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	input := "dist$(touch " + marker + ")'literal"
	cmd := exec.Command("sh", "-c", "set -- "+shellQuote(input)+"; printf '%s' \"$1\"")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != input {
		t.Fatalf("shell quote round-trip=%q,期望 %q", out, input)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("目标路径里的命令替换被执行了:%v", err)
	}
}
