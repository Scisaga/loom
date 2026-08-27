package publish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/snapshot"
)

type safetyTarget struct {
	mu         sync.Mutex
	current    string
	currentErr error
	files      map[string][]byte
	blobs      map[string][]byte
	pushes     int
	failPushes int
	onPush     func()
}

func (t *safetyTarget) Push(tree *Tree) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pushes++
	if t.pushes <= t.failPushes {
		return errors.New("injected push failure")
	}
	var current Current
	if err := json.Unmarshal(tree.Files["current.json"], &current); err != nil {
		return err
	}
	t.current = current.Snapshot
	t.currentErr = nil
	if t.files == nil {
		t.files = make(map[string][]byte)
	}
	for path, body := range tree.Files {
		t.files[path] = append([]byte(nil), body...)
	}
	if t.blobs == nil {
		t.blobs = make(map[string][]byte)
	}
	for path, body := range tree.Blobs {
		t.blobs[path] = append([]byte(nil), body...)
	}
	if t.onPush != nil {
		t.onPush()
	}
	return nil
}
func (t *safetyTarget) ReadFile(path string) ([]byte, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.files[path]
	return append([]byte(nil), b...), ok, nil
}
func (t *safetyTarget) HasBlob(path string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.blobs[path]
	return ok, nil
}
func (t *safetyTarget) Current() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.current, t.currentErr
}
func (t *safetyTarget) String() string { return "safety-target" }

func cloneBytesMap(src map[string][]byte) map[string][]byte {
	dst := make(map[string][]byte, len(src))
	for p, b := range src {
		dst[p] = append([]byte(nil), b...)
	}
	return dst
}

func attachSignedDeploymentCurrent(t *testing.T, tree *Tree, priv ed25519.PrivateKey,
	generation uint64, publishedAt string) *DeploymentCurrent {
	t.Helper()
	current := &DeploymentCurrent{
		Schema: DeploymentCurrentSchema, Generation: generation,
		Snapshot: tree.Snapshot, PublishedAt: publishedAt,
	}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	tree.Files["current.json"] = body
	return current
}

func writeSafetySSOT(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(p, []byte(goodSSOT), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Most Run tests exercise behavior after the signed-current transition.  Seed
// that durable era explicitly so the separate generation-1 capability gate
// cannot mask the failure path each test is meant to pin down.
func seedSignedEraForSSOT(t *testing.T, dir string, priv ed25519.PrivateKey,
	body []byte, bins map[string][]byte) *DeploymentCurrent {
	t.Helper()
	id, err := SnapshotID(body, bins)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := ensureReleaseAuthority(dir, id, nil,
		"2026-08-25T00:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func TestPublisherSafetyGatesFailClosedAndWriteHealth(t *testing.T) {
	ssot := writeSafetySSOT(t)
	for _, tc := range []struct {
		name string
		prep func(t *testing.T, o *Options)
		want string
	}{
		{"pin", func(t *testing.T, o *Options) {
			o.PinDir = t.TempDir()
			if err := os.WriteFile(filepath.Join(o.PinDir, pinFile), []byte("{"), 0o644); err != nil {
				t.Fatal(err)
			}
			o.ReleaseDir = t.TempDir()
		}, "读钉住状态失败"},
		{"release", func(t *testing.T, o *Options) {
			o.ReleaseDir = t.TempDir()
			if err := os.WriteFile(filepath.Join(o.ReleaseDir, releaseFile), []byte("{"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "读放行状态失败"},
		{"binary", func(t *testing.T, o *Options) {
			o.BinaryPath = filepath.Join(t.TempDir(), "missing")
		}, "读二进制失败"},
		{"version", func(t *testing.T, o *Options) {
			o.BinaryPath = filepath.Join(t.TempDir(), "not-a-go-binary")
			if err := os.WriteFile(o.BinaryPath, []byte("not a Go executable"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "构建信息"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt := &safetyTarget{}
			healthPath := filepath.Join(t.TempDir(), "publisher.json")
			o := Options{
				SSOTPath: ssot, Key: key(t), Target: tgt, Once: true,
				HealthPath: healthPath,
				Now:        func() time.Time { return at("2026-08-26T20:00:00Z") },
			}
			tc.prep(t, &o)
			err := Run(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("安全门应 fail-closed 且返回 %q,得到:%v", tc.want, err)
			}
			if tgt.pushes != 0 {
				t.Fatalf("安全门失败时不应 Push,却推了 %d 次", tgt.pushes)
			}
			h, rerr := ReadHealth(healthPath)
			if rerr != nil || h == nil || !strings.Contains(h.LastError, tc.want) {
				t.Fatalf("Health 必须保存失败原因,得到:%+v(err=%v)", h, rerr)
			}
		})
	}
}

func TestPublisherRetriesUnchangedInputAfterFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tgt := &safetyTarget{failPushes: 1}
	tgt.onPush = cancel
	err := Run(ctx, Options{
		SSOTPath: writeSafetySSOT(t), Key: key(t), Target: tgt,
		ReleaseDir: t.TempDir(), Interval: time.Millisecond,
		HealthPath: filepath.Join(t.TempDir(), "publisher.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 2 {
		t.Fatalf("同一输入第一次失败后必须重试,Push 次数=%d,期望 2", tgt.pushes)
	}
}

func TestPublisherUsesNonBlockingLockPerPublishTransaction(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "publisher.lock")
	unlock, err := AcquireLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	tgt := &safetyTarget{}
	healthPath := filepath.Join(t.TempDir(), "publisher.json")
	opts := Options{
		SSOTPath: writeSafetySSOT(t), Key: key(t), Target: tgt, Once: true,
		ReleaseDir: t.TempDir(), HealthPath: healthPath, LockPath: lockPath,
		Now: func() time.Time { return at("2026-08-26T20:00:00Z") },
	}
	err = Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "另一笔发布事务") {
		t.Fatalf("撞上正在发布的一轮应非阻塞失败并留待重试:%v", err)
	}
	if tgt.pushes != 0 {
		t.Fatalf("未取得锁不得 Push:%d", tgt.pushes)
	}
	h, readErr := ReadHealth(healthPath)
	if readErr != nil || h == nil || !strings.Contains(h.LastError, "另一笔发布事务") {
		t.Fatalf("锁竞争必须进入 Health:%+v(err=%v)", h, readErr)
	}

	unlock()
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("上一笔事务结束后下一轮应能发布:%v", err)
	}
	if tgt.pushes != 1 {
		t.Fatalf("锁只覆盖事务，释放后应正常 Push:%d", tgt.pushes)
	}
}

func TestPublisherSSHCommandDeadlineReleasesPublishLock(t *testing.T) {
	tools := t.TempDir()
	ssh := filepath.Join(tools, "ssh")
	// Current/ReadFile 真执行远端命令并快速返回；进入锁内 Push 后故意睡眠。
	// sleep 会继承 stderr pipe，也顺便验证 CommandContext + WaitDelay 不会
	// 在杀掉外层 shell 后继续等子进程五秒。
	script := "#!/bin/sh\nfor arg do remote=$arg; done\ncase \"$remote\" in\n  *printf*) exec sh -c \"$remote\" ;;\n  *) sleep 5 ;;\nesac\n"
	if err := os.WriteFile(ssh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+":"+os.Getenv("PATH"))

	lockPath := filepath.Join(t.TempDir(), "publisher.lock")
	priv := key(t)
	archiveDir := t.TempDir()
	seedSignedEraForSSOT(t, archiveDir, priv, []byte(goodSSOT), nil)
	tgt := &sshTarget{
		host: "fake", dir: t.TempDir(),
		commandTimeout: 40 * time.Millisecond,
	}
	started := time.Now()
	err := Run(context.Background(), Options{
		SSOTPath: writeSafetySSOT(t), Key: priv, Target: tgt, Once: true,
		ReleaseDir: t.TempDir(), ArchiveDir: archiveDir,
		HealthPath: filepath.Join(t.TempDir(), "publisher.json"), LockPath: lockPath,
	})
	if err == nil || !strings.Contains(err.Error(), "总期限") {
		t.Fatalf("卡死 SSH Push 必须以总期限失败:%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("40ms 测试期限却耗时 %s，SSH 子进程/pipe 仍卡住", elapsed)
	}

	// Run 内部持锁的 publishOnce 超时返回后，defer 必须立即释放锁；否则
	// 一次坏分发点就会让后续所有自动/手工发布永久失败。
	unlock, lockErr := AcquireLock(lockPath)
	if lockErr != nil {
		t.Fatalf("SSH 超时后 publisher.lock 没释放:%v", lockErr)
	}
	unlock()
}

func TestSSHPushTimeoutScalesAndCaps(t *testing.T) {
	if got := sshPushTimeout(0); got != sshPushMinTimeout {
		t.Fatalf("空/小推送期限=%s,期望 %s", got, sshPushMinTimeout)
	}
	if small, larger := sshPushTimeout(1), sshPushTimeout(64<<20); larger <= small {
		t.Fatalf("Push deadline 没有随 body size 增长:small=%s larger=%s", small, larger)
	}
	if got := sshPushTimeout(1 << 40); got != sshPushMaxTimeout {
		t.Fatalf("超大输入期限=%s,应封顶 %s", got, sshPushMaxTimeout)
	}
}

func TestPublisherRejectsStaleInputsAfterAcquiringPublishLock(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := []byte(strings.Replace(goodSSOT, "https://x/loom/", "https://fresh.example/loom/", 1))
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, oldBody, 0o644); err != nil {
		t.Fatal(err)
	}
	priv := key(t)
	newTree, err := Build(newBody, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	tgt := &safetyTarget{current: "older-current"}
	healthPath := filepath.Join(t.TempDir(), "publisher.json")
	opts := Options{
		SSOTPath: ssotPath, Key: priv, Target: tgt, Once: true,
		ReleaseDir: t.TempDir(), ArchiveDir: t.TempDir(),
		HealthPath: healthPath, LockPath: filepath.Join(t.TempDir(), "publisher.lock"),
		Now: func() time.Time { return at("2026-08-26T20:00:00Z") },
	}
	opts.beforeLock = func() {
		// 精确模拟 B 在 A 读完旧输入后先发布了新版。
		if err := os.WriteFile(ssotPath, newBody, 0o644); err != nil {
			t.Fatal(err)
		}
		tgt.mu.Lock()
		tgt.current = newTree.Snapshot
		tgt.files = cloneBytesMap(newTree.Files)
		tgt.blobs = cloneBytesMap(newTree.Blobs)
		tgt.mu.Unlock()
	}
	err = Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "发布输入在读取后、取锁前发生变化") {
		t.Fatalf("旧输入等锁后不得覆盖已发布的新版:%v", err)
	}
	if tgt.pushes != 0 || tgt.current != newTree.Snapshot {
		t.Fatalf("A 必须放弃旧输入，不能回退 B 的 current:pushes=%d current=%s", tgt.pushes, tgt.current)
	}
	h, readErr := ReadHealth(healthPath)
	if readErr != nil || h == nil || !strings.Contains(h.LastError, "发布输入") {
		t.Fatalf("新鲜度失败必须进 Health:%+v(err=%v)", h, readErr)
	}
}

func TestPublisherRetriesWithFreshInputsAfterFreshnessAbort(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := []byte(strings.Replace(goodSSOT, "https://x/loom/", "https://retry.example/loom/", 1))
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, oldBody, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tgt := &safetyTarget{onPush: cancel}
	priv := key(t)
	archiveDir := t.TempDir()
	seedSignedEraForSSOT(t, archiveDir, priv, oldBody, nil)
	var once sync.Once
	opts := Options{
		SSOTPath: ssotPath, Key: priv, Target: tgt,
		ReleaseDir: t.TempDir(), ArchiveDir: archiveDir,
		LockPath: filepath.Join(t.TempDir(), "publisher.lock"), Interval: time.Millisecond,
	}
	opts.beforeLock = func() {
		once.Do(func() {
			if err := os.WriteFile(ssotPath, newBody, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := Run(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 1 {
		t.Fatalf("新鲜度中止后 daemon 应用新输入重试:pushes=%d", tgt.pushes)
	}
	want, err := SnapshotID(newBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.current != want {
		t.Fatalf("重试发布的不是新输入:got=%s want=%s", tgt.current, want)
	}
}

func TestPinSnapshotMismatchFailsClosedBeforePush(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := []byte(strings.Replace(goodSSOT, "https://x/loom/", "https://new-config.example/loom/", 1))
	bin := releaseTestBinary(t)
	bins := map[string][]byte{runtime.GOOS + "/" + runtime.GOARCH: bin}
	pinnedID, err := SnapshotID(oldBody, bins)
	if err != nil {
		t.Fatal(err)
	}
	pinDir := t.TempDir()
	if err := WritePin(pinDir, &Pin{Snapshot: pinnedID, Reason: "rollback safety"}, bin); err != nil {
		t.Fatal(err)
	}
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, newBody, 0o644); err != nil {
		t.Fatal(err)
	}
	tgt := &safetyTarget{current: pinnedID}
	healthPath := filepath.Join(t.TempDir(), "publisher.json")
	err = Run(context.Background(), Options{
		SSOTPath: ssotPath, Key: key(t), Target: tgt, Once: true,
		PinDir: pinDir, ReleaseDir: t.TempDir(), ArchiveDir: t.TempDir(),
		HealthPath: healthPath, LockPath: filepath.Join(t.TempDir(), "publisher.lock"),
		AllowUntraceable: true,
	})
	if err == nil || !strings.Contains(err.Error(), "钉住安全门") {
		t.Fatalf("钉住二进制+不同 SSOT 必须 fail-closed:%v", err)
	}
	if tgt.pushes != 0 || tgt.current != pinnedID {
		t.Fatalf("危险组合不得改 current:pushes=%d current=%s", tgt.pushes, tgt.current)
	}
	h, readErr := ReadHealth(healthPath)
	if readErr != nil || h == nil || !strings.Contains(h.LastError, "钉住安全门") {
		t.Fatalf("钉住安全门失败必须进 Health:%+v(err=%v)", h, readErr)
	}
}

func TestArchiveAndHistoryFailuresCannotProduceGreenPublish(t *testing.T) {
	for _, tc := range []struct {
		name       string
		breakState func(t *testing.T, dir string)
		wantPushes int
		want       string
	}{
		{
			name: "archive-before-push",
			breakState: func(t *testing.T, dir string) {
				if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantPushes: 0, want: "源头存档失败",
		},
		{
			name: "history-after-push",
			breakState: func(t *testing.T, dir string) {
				if err := os.MkdirAll(filepath.Join(dir, historyFile), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantPushes: 1, want: "发布历史持久化失败",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			archiveDir := filepath.Join(base, "history")
			priv := key(t)
			if tc.name == "history-after-push" {
				seedSignedEraForSSOT(t, archiveDir, priv, []byte(goodSSOT), nil)
			}
			tc.breakState(t, archiveDir)
			tgt := &safetyTarget{}
			healthPath := filepath.Join(t.TempDir(), "publisher.json")
			err := Run(context.Background(), Options{
				SSOTPath: writeSafetySSOT(t), Key: priv, Target: tgt, Once: true,
				ReleaseDir: t.TempDir(), ArchiveDir: archiveDir,
				HealthPath: healthPath, LockPath: filepath.Join(t.TempDir(), "publisher.lock"),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("应以 %q 失败:%v", tc.want, err)
			}
			if tgt.pushes != tc.wantPushes {
				t.Fatalf("pushes=%d want=%d", tgt.pushes, tc.wantPushes)
			}
			h, readErr := ReadHealth(healthPath)
			if readErr != nil || h == nil || h.LastSuccess != "" || !strings.Contains(h.LastError, tc.want) {
				t.Fatalf("持久化失败不得写绿色 Health:%+v(err=%v)", h, readErr)
			}
		})
	}
}

func TestBrokenCurrentIsRepushedInsteadOfBlockingSelfRepair(t *testing.T) {
	tgt := &safetyTarget{currentErr: errors.New("truncated current.json")}
	err := Run(context.Background(), Options{
		SSOTPath: writeSafetySSOT(t), Key: key(t), Target: tgt,
		ReleaseDir: t.TempDir(), Once: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 1 {
		t.Fatalf("current.json 损坏应重铺自修复,Push 次数=%d", tgt.pushes)
	}
}

func TestPublishOnceVerifiesEvenWhenTargetAlreadyCurrent(t *testing.T) {
	body := []byte(goodSSOT)
	now := func() time.Time { return at("2026-08-26T20:00:00Z") }
	for _, code := range []int{http.StatusOK, http.StatusBadGateway} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			priv := key(t)
			tree, err := Build(body, priv, Meta{CreatedAt: now().Format(time.RFC3339)})
			if err != nil {
				t.Fatal(err)
			}
			id := tree.Snapshot
			tgt := &safetyTarget{current: id, files: cloneBytesMap(tree.Files), blobs: cloneBytesMap(tree.Blobs)}
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if code != http.StatusOK {
					w.WriteHeader(code)
					return
				}
				if body, ok, _ := tgt.ReadFile(strings.TrimPrefix(r.URL.Path, "/")); ok {
					_, _ = w.Write(body)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			_, err = publishOnce(&Options{
				Key: priv, Target: tgt, VerifyURL: srv.URL, Now: now,
			}, body, nil, func(string, ...any) {})
			if requests == 0 {
				t.Fatal("目标已指向快照也必须执行节点视角 VerifyServed")
			}
			if code == http.StatusOK && err != nil {
				t.Fatal(err)
			}
			if code != http.StatusOK && err == nil {
				t.Fatal("节点视角取不到时不能因为 current 相同而假成功")
			}
			if tgt.pushes != 1 {
				t.Fatalf("legacy current 首次迁移应只 Push 一次,实际 %d 次", tgt.pushes)
			}
		})
	}
}

func TestPublishOnceRepairsBlobEvenWhenCurrentAlreadyMatches(t *testing.T) {
	body := []byte(goodSSOT)
	bins := map[string][]byte{"linux/amd64": []byte("binary blob")}
	priv := key(t)
	now := func() time.Time { return at("2026-08-26T20:00:00Z") }
	tree, err := Build(body, priv, Meta{CreatedAt: now().Format(time.RFC3339), Binaries: bins})
	if err != nil {
		t.Fatal(err)
	}
	// blobs 故意不填,模拟 current.json 正确但内容寻址二进制
	// 被删掉或篡改。不能被“快照已最新”的早退吞掉。
	tgt := &safetyTarget{current: tree.Snapshot, files: cloneBytesMap(tree.Files)}
	if _, err := publishOnce(&Options{
		Key: priv, Target: tgt, Now: now,
	}, body, bins, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 1 {
		t.Fatalf("current 相同但 blob 损坏时必须重铺,Push 次数=%d", tgt.pushes)
	}
}

func TestPublishOnceRepairsEveryMissingOrCorruptSnapshotFile(t *testing.T) {
	body := []byte(goodSSOT)
	priv := key(t)
	now := func() time.Time { return at("2026-08-26T20:00:00Z") }
	tree, err := Build(body, priv, Meta{CreatedAt: now().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	var nodePath string
	for _, p := range tree.Paths() {
		if strings.Contains(p, "/nodes/") {
			nodePath = p
			break
		}
	}
	if nodePath == "" {
		t.Fatal("测试快照没有节点正文")
	}

	for _, tc := range []struct {
		name    string
		path    string
		corrupt bool
	}{
		{"missing-manifest", tree.Snapshot + "/snapshot.json", false},
		{"corrupt-manifest", tree.Snapshot + "/snapshot.json", true},
		{"missing-signature", tree.Snapshot + "/snapshot.sig", false},
		{"corrupt-signature", tree.Snapshot + "/snapshot.sig", true},
		{"missing-node-body", nodePath, false},
		{"corrupt-node-body", nodePath, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt := &safetyTarget{
				current: tree.Snapshot,
				files:   cloneBytesMap(tree.Files),
				blobs:   cloneBytesMap(tree.Blobs),
			}
			if tc.corrupt {
				tgt.files[tc.path] = []byte("corrupt")
			} else {
				delete(tgt.files, tc.path)
			}
			if _, err := publishOnce(&Options{Key: priv, Target: tgt, Now: now}, body, nil, func(string, ...any) {}); err != nil {
				t.Fatal(err)
			}
			if tgt.pushes != 1 {
				t.Fatalf("current 相同但 %s 时必须重铺,Push 次数=%d", tc.name, tgt.pushes)
			}
			got, found, err := tgt.ReadFile(tc.path)
			if err != nil || !found || !bytes.Equal(got, tree.Files[tc.path]) {
				t.Fatalf("重铺后 %s 未恢复(found=%v,err=%v)", tc.path, found, err)
			}
		})
	}
}

func TestPublishOnceAcceptsOlderValidMetadataForSameSnapshot(t *testing.T) {
	body := []byte(goodSSOT)
	priv := key(t)
	oldTree, err := Build(body, priv, Meta{
		CreatedAt: "2026-08-25T20:00:00Z", Author: "old-publisher",
	})
	if err != nil {
		t.Fatal(err)
	}
	attachSignedDeploymentCurrent(t, oldTree, priv, 1, "2026-08-26T20:00:00Z")
	tgt := &safetyTarget{
		current: oldTree.Snapshot,
		files:   cloneBytesMap(oldTree.Files),
		blobs:   cloneBytesMap(oldTree.Blobs),
	}
	_, err = publishOnce(&Options{
		Key: priv, Target: tgt, Author: "new-publisher",
		Now: func() time.Time { return at("2026-08-26T20:00:00Z") },
	}, body, nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 0 {
		t.Fatalf("同一内容快照的合法旧 metadata 不应触发机械重铺,Push 次数=%d", tgt.pushes)
	}
}

func TestPublishOnceKeepsCurrentSnapshotForCommentOnlySSOTChange(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := append(append([]byte(nil), oldBody...), []byte("\n# operator note only\n")...)
	priv := key(t)
	oldTree, err := Build(oldBody, priv, Meta{CreatedAt: "2026-08-25T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	newTree, err := Build(newBody, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if oldTree.Snapshot == newTree.Snapshot {
		t.Fatal("测试前提不成立:raw SSOT 注释目前应改变 snapshot id")
	}
	tgt := &safetyTarget{
		current: oldTree.Snapshot,
		files:   cloneBytesMap(oldTree.Files),
		blobs:   cloneBytesMap(oldTree.Blobs),
	}
	var log bytes.Buffer
	got, err := publishOnce(&Options{
		Key: priv, Target: tgt,
		Now: func() time.Time { return at("2026-08-26T20:00:00Z") },
	}, newBody, nil, func(f string, a ...any) { fmt.Fprintf(&log, f, a...) })
	if err != nil {
		t.Fatal(err)
	}
	if got != oldTree.Snapshot || tgt.pushes != 1 {
		t.Fatalf("注释变化应保留旧 current 并完成 signed 迁移:got=%s pushes=%d", got, tgt.pushes)
	}
	if !strings.Contains(log.String(), "运行产物未变") {
		t.Fatalf("日志必须明确解释为何不发布:%q", log.String())
	}
}

func TestEquivalentOldSnapshotWithoutItsSSOTArchivePublishesNewSnapshot(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := append(append([]byte(nil), oldBody...), []byte("\n# equivalent but old archive is gone\n")...)
	priv := key(t)
	oldTree, err := Build(oldBody, priv, Meta{CreatedAt: "2026-08-25T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	newTree, err := Build(newBody, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	archiveDir := t.TempDir() // 故意没有 oldTree 的 SSOTHash 存档。
	seedSignedEraForSSOT(t, archiveDir, priv, oldBody, nil)
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, newBody, 0o644); err != nil {
		t.Fatal(err)
	}
	tgt := &safetyTarget{
		current: oldTree.Snapshot,
		files:   cloneBytesMap(oldTree.Files),
		blobs:   cloneBytesMap(oldTree.Blobs),
	}
	if err := Run(context.Background(), Options{
		SSOTPath: ssotPath, Key: priv, Target: tgt, Once: true,
		ReleaseDir: t.TempDir(), ArchiveDir: archiveDir,
		LockPath: filepath.Join(t.TempDir(), "publisher.lock"),
		Now:      func() time.Time { return at("2026-08-26T20:00:00Z") },
	}); err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 1 || tgt.current != newTree.Snapshot {
		t.Fatalf("旧等价快照没有源头存档时必须发新 id:pushes=%d current=%s want=%s",
			tgt.pushes, tgt.current, newTree.Snapshot)
	}
	var man snapshot.Manifest
	if err := json.Unmarshal(newTree.Files[newTree.Snapshot+"/snapshot.json"], &man); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArchivedSSOT(archiveDir, man.SSOTSum()); err != nil {
		t.Fatalf("新快照发布前应已存好可回滚源头:%v", err)
	}
}

func TestPublisherRestartFirstLoopKeepsEquivalentCurrentAndUpdatesHealth(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := append(append([]byte(nil), oldBody...), []byte("\n# formatting-only restart case\n")...)
	priv := key(t)
	oldTree, err := Build(oldBody, priv, Meta{CreatedAt: "2026-08-25T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	tgt := &safetyTarget{
		current: oldTree.Snapshot,
		files:   cloneBytesMap(oldTree.Files),
		blobs:   cloneBytesMap(oldTree.Blobs),
	}
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, newBody, 0o644); err != nil {
		t.Fatal(err)
	}
	healthPath := filepath.Join(t.TempDir(), "publisher.json")
	if err := Run(context.Background(), Options{
		SSOTPath: ssotPath, Key: priv, Target: tgt, Once: true,
		ReleaseDir: t.TempDir(), HealthPath: healthPath,
		Now: func() time.Time { return at("2026-08-26T20:00:00Z") },
	}); err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 1 || tgt.current != oldTree.Snapshot {
		t.Fatalf("发布器重启首轮应只迁移 signed current，不把注释变更扩散成 rollout:pushes=%d current=%s", tgt.pushes, tgt.current)
	}
	h, err := ReadHealth(healthPath)
	if err != nil || h == nil {
		t.Fatalf("读 Health:%v (%+v)", err, h)
	}
	if h.LastSnapshot != oldTree.Snapshot || len(h.LastSSOT) != sha256.Size*2 || h.LastSuccess == "" {
		t.Fatalf("保留 current 后也应更新输入缓存对应的健康坐标:%+v", h)
	}
}

func TestPublishOnceDoesNotKeepCurrentWhenRuntimeContentChanges(t *testing.T) {
	oldBody := []byte(goodSSOT)
	newBody := []byte(strings.Replace(goodSSOT, "https://x/loom/", "https://new.example/loom/", 1))
	priv := key(t)
	oldTree, err := Build(oldBody, priv, Meta{CreatedAt: "2026-08-25T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	tgt := &safetyTarget{
		current: oldTree.Snapshot,
		files:   cloneBytesMap(oldTree.Files),
		blobs:   cloneBytesMap(oldTree.Blobs),
	}
	got, err := publishOnce(&Options{
		Key: priv, Target: tgt,
		Now: func() time.Time { return at("2026-08-26T20:00:00Z") },
	}, newBody, nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.pushes != 1 || got == oldTree.Snapshot {
		t.Fatalf("运行配置变化必须发布新快照:got=%s pushes=%d", got, tgt.pushes)
	}
}

func TestVerifyServedChecksManifestSignatureAndEveryNodeBody(t *testing.T) {
	priv := key(t)
	tree, err := Build([]byte(goodSSOT), priv, Meta{
		CreatedAt: "2026-08-26T20:00:00Z",
		Binaries:  map[string][]byte{"linux/amd64": []byte("served-agent-binary")},
	})
	if err != nil {
		t.Fatal(err)
	}
	attachSignedDeploymentCurrent(t, tree, priv, 1, "2026-08-26T20:00:00Z")
	manifestPath := tree.Snapshot + "/snapshot.json"
	signaturePath := tree.Snapshot + "/snapshot.sig"
	var nodePath string
	for _, p := range tree.Paths() {
		if strings.Contains(p, "/nodes/") {
			nodePath = p
			break
		}
	}
	if nodePath == "" {
		t.Fatal("测试快照没有节点正文")
	}

	for _, tc := range []struct {
		name string
		edit func(map[string][]byte)
		bad  bool
	}{
		{"complete", func(map[string][]byte) {}, false},
		{"missing-manifest", func(f map[string][]byte) { delete(f, manifestPath) }, true},
		{"corrupt-manifest", func(f map[string][]byte) { f[manifestPath] = []byte("{}") }, true},
		{"corrupt-signature", func(f map[string][]byte) { f[signaturePath] = []byte("bad") }, true},
		{"missing-node-body", func(f map[string][]byte) { delete(f, nodePath) }, true},
		{"corrupt-node-body", func(f map[string][]byte) { f[nodePath] = []byte("bad") }, true},
		{"missing-served-blob", func(f map[string][]byte) {
			for p := range tree.Blobs {
				delete(f, p)
			}
		}, true},
		{"corrupt-served-blob", func(f map[string][]byte) {
			for p, b := range tree.Blobs {
				bad := append([]byte(nil), b...)
				bad[0] ^= 0xff
				f[p] = bad
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served := cloneBytesMap(tree.Files)
			for p, b := range tree.Blobs {
				served[p] = append([]byte(nil), b...)
			}
			tc.edit(served)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if b, ok := served[strings.TrimPrefix(r.URL.Path, "/")]; ok {
					_, _ = w.Write(b)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()
			err := VerifyServed(srv.URL, tree.Snapshot, "", time.Second, tree,
				priv.Public().(ed25519.PublicKey))
			if tc.bad && err == nil {
				t.Fatal("节点视角缺失/损坏不能通过")
			}
			if !tc.bad && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyServedChecksEveryAssignedSnapshotSurface(t *testing.T) {
	priv := key(t)
	oldBody := []byte(goodSSOT)
	newBody := []byte(strings.Replace(goodSSOT, "https://x/loom/", "https://assignment.example/loom/", 1))
	oldTree, err := Build(oldBody, priv, Meta{CreatedAt: "2026-08-25T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	newTree, err := Build(newBody, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	current := &DeploymentCurrent{
		Schema: DeploymentCurrentSchema, Generation: 9, Snapshot: newTree.Snapshot,
		Assignments: []DeploymentAssignment{{Node: "a", Snapshot: oldTree.Snapshot}},
		PublishedAt: "2026-08-26T20:00:00Z",
	}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	currentBody, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	newTree.Files["current.json"] = currentBody

	var oldNodePath string
	for _, p := range oldTree.Paths() {
		if strings.Contains(p, "/nodes/") {
			oldNodePath = p
			break
		}
	}
	if oldNodePath == "" {
		t.Fatal("assignment 测试快照没有节点正文")
	}
	for _, tc := range []struct {
		name string
		edit func(map[string][]byte)
		bad  bool
	}{
		{name: "complete", edit: func(map[string][]byte) {}},
		{name: "missing-assigned-manifest", bad: true, edit: func(f map[string][]byte) {
			delete(f, oldTree.Snapshot+"/snapshot.json")
		}},
		{name: "missing-assigned-node-body", bad: true, edit: func(f map[string][]byte) {
			delete(f, oldNodePath)
		}},
		{name: "corrupt-assigned-node-body", bad: true, edit: func(f map[string][]byte) {
			f[oldNodePath] = []byte(`{"owner":"a","files":{}}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served := cloneBytesMap(oldTree.Files)
			for p, b := range newTree.Files {
				served[p] = append([]byte(nil), b...)
			}
			for p, b := range oldTree.Blobs {
				served[p] = append([]byte(nil), b...)
			}
			for p, b := range newTree.Blobs {
				served[p] = append([]byte(nil), b...)
			}
			tc.edit(served)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if b, ok := served[strings.TrimPrefix(r.URL.Path, "/")]; ok {
					_, _ = w.Write(b)
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			err := VerifyServed(srv.URL, newTree.Snapshot, "", time.Second, newTree,
				priv.Public().(ed25519.PublicKey))
			if tc.bad && err == nil {
				t.Fatal("assignment 指向的不可变表面缺失/损坏仍显示绿色")
			}
			if !tc.bad && err != nil {
				t.Fatal(err)
			}
		})
	}
}
