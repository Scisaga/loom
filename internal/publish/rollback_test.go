package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/snapshot"
)

// **源头绝不能出现在分发树里。**
//
// 这是本文件里最重要的一条,因为它挡的是一次已经发生过的错误:回滚一开始
// 就是把 SSOT 当成一个 blob 塞进分发树做的,理由是"分发点早就有全部渲染
// 产物,不增加泄露面"。那个论证漏了一类东西 —— 源头里的 `ssh_port` 之类
// 字段**不出现在任何渲染产物里**,SSOT 自己的注释还写着它们"记在这里是
// 为了 bootstrap 与排障,不是为了被连"。
//
// 分发点在设计上是当作已被攻陷来对待的(D32),而签名拦不住这一类风险。
func TestSSOTStaysOutOfDistributionTree(t *testing.T) {
	tr := build(t, goodSSOT)

	for p, body := range tr.Blobs {
		if strings.Contains(string(body), "declarations:") {
			t.Errorf("分发树的 blob %s 里出现了源头内容", p)
		}
	}
	for p, body := range tr.Files {
		if strings.Contains(string(body), "address_axis: from_request") {
			t.Errorf("分发树的文件 %s 里出现了源头内容", p)
		}
	}

	// manifest 仍然记着源头的哈希 —— 权威在签名里,只是字节不出去。
	var man snapshot.Manifest
	unmarshalManifest(t, tr, &man)
	sum := sha256.Sum256([]byte(goodSSOT))
	if man.SSOTSum() != hex.EncodeToString(sum[:]) {
		t.Errorf("manifest 里的源头哈希不对:%s", man.SSOTSum())
	}
}

// 存档往返:存进去,按 manifest 给的哈希取回来,必须逐字节一致。
// 回滚整条链就架在这上面。
func TestArchiveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tr := build(t, goodSSOT)
	var man snapshot.Manifest
	unmarshalManifest(t, tr, &man)

	sum, err := ArchiveSSOT(dir, []byte(goodSSOT))
	if err != nil {
		t.Fatal(err)
	}
	if sum != man.SSOTSum() {
		t.Fatalf("存档哈希 %s 与 manifest 说的 %s 对不上", sum, man.SSOTSum())
	}
	got, err := ReadArchivedSSOT(dir, man.SSOTSum())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goodSSOT {
		t.Error("取回来的源头与存进去的不同")
	}
}

// 存档在本机,但"本机文件没被动过"不是一个能假设的前提 —— 漂移检测
// 这一整套东西存在的理由就是它。改过的存档必须被认出来,而不是拿去
// 覆盖事实来源。
func TestArchiveDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	sum, err := ArchiveSSOT(dir, []byte(goodSSOT))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ArchivePath(dir, sum), []byte("# 被人改过\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArchivedSSOT(dir, sum); err == nil {
		t.Fatal("存档被改过,却读出来了")
	} else if !strings.Contains(err.Error(), "被改过") {
		t.Errorf("报错没说清是存档被改过:%v", err)
	}
}

// 内容寻址:同一版存两次只有一份,改了才多一份。
// 这决定了存档的代价 —— SSOT 不常变。
func TestArchiveIsContentAddressed(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := ArchiveSSOT(dir, []byte(goodSSOT)); err != nil {
			t.Fatal(err)
		}
	}
	if n := countFiles(t, dir); n != 1 {
		t.Errorf("同一版存了 3 次,存档里有 %d 份", n)
	}
	if _, err := ArchiveSSOT(dir, []byte(goodSSOT+"\n# 改了一行\n")); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, dir); n != 2 {
		t.Errorf("改了之后应该有 2 份,实际 %d 份", n)
	}
}

// 回滚的地基:源头与二进制取回来重算一遍,必须还是同一个快照 id。
//
// 渲染是纯函数(§12),所以这条等式该成立。它一旦不成立,回滚就会留下一个
// **看起来成功、实际没回去**的系统 —— 所以 rollback 每次都会当场重算自证,
// 而这个测试钉的是自证所依赖的那条等式本身。
func TestSnapshotIDMatchesBuild(t *testing.T) {
	bins := map[string][]byte{"linux/amd64": []byte("假装这是个二进制")}

	tr, err := Build([]byte(goodSSOT), key(t), Meta{
		CreatedAt: "2026-08-23T00:00:00Z", Author: "甲", Binaries: bins,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := SnapshotID([]byte(goodSSOT), bins)
	if err != nil {
		t.Fatal(err)
	}
	if id != tr.Snapshot {
		t.Fatalf("自证算出 %s,发布得到 %s —— 回滚会发出与目标不同的配置", id, tr.Snapshot)
	}

	// 时间与作者不进内容哈希(D14),所以自证路径不给它们也必须一致。
	tr2, err := Build([]byte(goodSSOT), key(t), Meta{
		CreatedAt: "2030-01-01T00:00:00Z", Author: "乙", Binaries: bins,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr2.Snapshot != id {
		t.Errorf("换了时间与作者,快照 id 就变了:%s ≠ %s", tr2.Snapshot, id)
	}
}

// 二进制变了,快照 id 必须变(§15.4 的绑定回滚)。
// 自证同时覆盖源头与二进制,靠的就是这条。
func TestSnapshotIDTracksBinary(t *testing.T) {
	a, err := SnapshotID([]byte(goodSSOT), map[string][]byte{"linux/amd64": []byte("甲")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := SnapshotID([]byte(goodSSOT), map[string][]byte{"linux/amd64": []byte("乙")})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("换了二进制,快照 id 却没变 —— 回滚二进制这一半就无从验证")
	}
}

// 明文秘密在 SSOT 里无处可放:模型只有 secret_ref(引用名)与
// wg_public_key(公钥),严格解码(KnownFields)拒绝任何别的键。
//
// 源头现在只存在中控本地,但这条仍然值得钉住 —— 存档会被 `loom backup`
// 打包带走,而备份的目的地由人决定。
func TestSSOTCannotCarryPlaintextSecret(t *testing.T) {
	for _, field := range []string{"password: hunter2", "private_key: AAAA", "secret: hunter2"} {
		bad := strings.Replace(goodSSOT,
			`  - {id: c1, declaration: d1, secret_ref: "cred/c1"}`,
			`  - {id: c1, declaration: d1, secret_ref: "cred/c1", `+field+`}`, 1)
		if _, err := model.Load([]byte(bad)); err == nil {
			t.Errorf("SSOT 竟然接受了 %q —— 它会被存档并随备份带走", field)
		}
	}
}

func unmarshalManifest(t *testing.T, tr *Tree, man *snapshot.Manifest) {
	t.Helper()
	b, ok := tr.Files[tr.Snapshot+"/snapshot.json"]
	if !ok {
		t.Fatal("树里没有 manifest")
	}
	if err := json.Unmarshal(b, man); err != nil {
		t.Fatal(err)
	}
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*"+archiveExt))
	if err != nil {
		t.Fatal(err)
	}
	return len(m)
}
