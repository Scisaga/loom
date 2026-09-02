package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"loom/internal/publish"
	"loom/internal/releasefloor"
)

func signedPullCurrent(t *testing.T, generation uint64) ([]byte, ed25519.PublicKey, *publish.DeploymentCurrent) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := &publish.DeploymentCurrent{
		Schema: publish.DeploymentCurrentSchema, Generation: generation,
		Snapshot: "aaaaaaaaaaaa", PublishedAt: "2026-08-27T12:00:00Z",
		Assignments: []publish.DeploymentAssignment{
			{Node: "demo-b", Snapshot: "bbbbbbbbbbbb"},
			{Node: "demo-c", Snapshot: "cccccccccccc"},
		},
	}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return body, pub, current
}

func TestDecodePullCurrentVerifiesSelectsAndChecksFloor(t *testing.T) {
	body, pub, envelope := signedPullCurrent(t, 8)
	digest, err := envelope.PayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	floor := &releasefloor.Record{
		Schema: releasefloor.CurrentSchema, Generation: 8,
		PayloadSHA256: digest, SelectedSnapshot: "cccccccccccc",
	}
	got, err := decodePullCurrent(body, "demo-c", pub, floor, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.snapshot != "cccccccccccc" || got.signed == nil || got.digest != digest {
		t.Fatalf("signed current 选择/坐标不对:%+v", got)
	}
	wrongSelection := *floor
	wrongSelection.SelectedSnapshot = "bbbbbbbbbbbb"
	if _, err := decodePullCurrent(body, "demo-c", pub, &wrongSelection, false); err == nil {
		t.Fatal("同 generation/payload 的 floor 选择坐标不一致仍被接受")
	}

	staleFloor := *floor
	staleFloor.Generation++
	if _, err := decodePullCurrent(body, "demo-c", pub, &staleFloor, false); err == nil || !strings.Contains(err.Error(), "防重放") {
		t.Fatalf("低于 floor 的 generation 未拒绝:%v", err)
	}
}

func TestDecodePullCurrentNeverDowngradesBadSignedEnvelope(t *testing.T) {
	body, pub, _ := signedPullCurrent(t, 3)
	body = []byte(strings.Replace(string(body), `"generation": 3`, `"generation": 4`, 1))
	if _, err := decodePullCurrent(body, "demo-b", pub, nil, false); err == nil || !strings.Contains(err.Error(), "验签失败") {
		t.Fatalf("signed payload 被改后不应降级成 legacy:%v", err)
	}
}

func TestDecodePullCurrentLegacyMigrationIsStrictAndOneWay(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"snapshot":"0123456789ab","published_at":"2026-08-27T12:00:00Z"}`)
	got, err := decodePullCurrent(legacy, "demo-d", pub, nil, true)
	if err != nil || got.snapshot != "0123456789ab" || got.signed != nil {
		t.Fatalf("迁移期 strict legacy 未被接受:got=%+v err=%v", got, err)
	}
	floor := &releasefloor.Record{
		Schema: releasefloor.CurrentSchema, Generation: 1,
		PayloadSHA256: strings.Repeat("a", 64), SelectedSnapshot: "0123456789ab",
	}
	if _, err := decodePullCurrent(legacy, "demo-d", pub, floor, true); err == nil || !strings.Contains(err.Error(), "拒绝 unsigned") {
		t.Fatalf("floor 激活后仍接受 legacy:%v", err)
	}
	if _, err := decodePullCurrent(legacy, "demo-d", pub, nil, false); err == nil ||
		!strings.Contains(err.Error(), "standalone") {
		t.Fatalf("新版 standalone pull 不应因 floor 缺失重开 legacy 迁移口:%v", err)
	}

	for _, bad := range [][]byte{
		[]byte(`{"snapshot":"0123456789ab","published_at":"x","unknown":true}`),
		[]byte(`{"snapshot":"0123456789ab","snapshot":"aaaaaaaaaaaa","published_at":"x"}`),
		[]byte(`{"snapshot":"NOT-A-SNAPSHOT","published_at":"x"}`),
		[]byte(`{"snapshot":"0123456789ab","published_at":"x"} {}`),
	} {
		if _, err := decodePullCurrent(bad, "demo-d", pub, nil, true); err == nil {
			t.Fatalf("非严格 legacy 被接受:%s", bad)
		}
	}
}

func TestContinuationRecordsHigherSignedFloorBeforeSnapshotMismatch(t *testing.T) {
	body, pub, envelope := signedPullCurrent(t, 19)
	dir := t.TempDir()
	floorPath := filepath.Join(dir, "release-floor.json")
	lockPath := filepath.Join(dir, "deploy.lock")
	pubPath := filepath.Join(dir, "platform.pub")
	statusPath := filepath.Join(dir, "continuation.json")
	binPath := filepath.Join(dir, "loom")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	capable := []byte("#!/bin/sh\n[ \"$*\" = 'selfcheck -q -require signed-current-v1' ]\n")
	if err := os.WriteFile(binPath, capable, 0o755); err != nil {
		t.Fatal(err)
	}

	lock, busy, err := acquireNodeDeployLock(lockPath)
	if err != nil || busy {
		t.Fatalf("取得测试部署锁:busy=%v err=%v", busy, err)
	}
	// inheritNodeDeployLock 会为本次 cmdPull 包装并关闭同一个 fd；测试不再
	// 另外 Close lock，避免关闭已被续跑端消费的描述符。
	t.Setenv(deployLockFDEnv, strconv.Itoa(int(lock.file.Fd())))
	t.Setenv(contEnv, "1")
	t.Setenv(contStatusEnv, statusPath)
	t.Setenv(contSnapshotEnv, "aaaaaaaaaaaa")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/current.json" {
			_, _ = w.Write(body)
			return
		}
		http.Error(w, "must stop before payload", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err = cmdPull([]string{
		"-url", srv.URL, "-node", "demo-c", "-pubkey", pubPath,
		"-release-floor", floorPath, "-deploy-lock", lockPath,
		"-bin", binPath,
	})
	if err == nil || !strings.Contains(err.Error(), "续跑期间分发点") {
		t.Fatalf("续跑看到不同目标必须停止:%v", err)
	}
	floor, err := releasefloor.Read(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	if floor == nil || floor.Generation != envelope.Generation || floor.SelectedSnapshot != "cccccccccccc" {
		t.Fatalf("续跑在快照不匹配前没有记住已验签的高代决策:%+v", floor)
	}
	status, err := readContinuationStatus(statusPath, "aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != continuationConfiguring {
		t.Fatalf("floor 落盘前没有越过禁止恢复旧 reader 的屏障:%+v", status)
	}
}

func TestFirstSeenHigherGenerationRequiresOutOfBandCurrent(t *testing.T) {
	body, pub, _ := signedPullCurrent(t, 7)
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "platform.pub")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var payloadRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/current.json" {
			_, _ = w.Write(body)
			return
		}
		payloadRequests.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv(contEnv, "")
	t.Setenv(contStatusEnv, "")
	t.Setenv(contSnapshotEnv, "")

	err := cmdPull([]string{
		"-url", srv.URL, "-node", "demo-c", "-pubkey", pubPath,
		"-release-floor", filepath.Join(dir, "floor.json"),
		"-deploy-lock", filepath.Join(dir, "deploy.lock"),
	})
	if err == nil || !strings.Contains(err.Error(), "-expected-current") {
		t.Fatalf("无 floor 首见高代不应从公开分发点直接 latch:%v", err)
	}
	if payloadRequests.Load() != 0 {
		t.Fatal("带外权威未钉住前不应请求 payload")
	}
}

func TestPullAdvancesSignedFloorBeforeManifestDownloadFails(t *testing.T) {
	body, pub, envelope := signedPullCurrent(t, 11)
	dir := t.TempDir()
	floorPath := filepath.Join(dir, "release-floor.json")
	lockPath := filepath.Join(dir, "deploy.lock")
	pubPath := filepath.Join(dir, "platform.pub")
	expectedPath := filepath.Join(dir, "expected-current.json")
	binPath := filepath.Join(dir, "loom")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	capable := []byte("#!/bin/sh\n[ \"$*\" = 'selfcheck -q -require signed-current-v1' ]\n")
	if err := os.WriteFile(binPath, capable, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(expectedPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var manifestSawFloor atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/current.json" {
			_, _ = w.Write(body)
			return
		}
		floor, err := releasefloor.Read(floorPath)
		if err == nil && floor != nil && floor.Generation == envelope.Generation {
			manifestSawFloor.Store(true)
		}
		http.Error(w, "payload withheld", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv(contEnv, "")
	t.Setenv(contStatusEnv, "")
	t.Setenv(contSnapshotEnv, "")

	err := cmdPull([]string{
		"-url", server.URL, "-node", "demo-c", "-pubkey", pubPath,
		"-release-floor", floorPath, "-deploy-lock", lockPath, "-bin", binPath,
		"-expected-current", expectedPath,
	})
	if err == nil {
		t.Fatal("manifest 下载被扣住时 pull 应失败")
	}
	if !manifestSawFloor.Load() {
		t.Fatal("请求 manifest 时高 generation floor 尚未持久化")
	}
	floor, err := releasefloor.Read(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	if floor == nil || floor.Generation != 11 || floor.SelectedSnapshot != "cccccccccccc" {
		t.Fatalf("payload 后续失败没有保留已验签 release decision:%+v", floor)
	}
}

func TestPullNeverPersistsFloorBesideIncapableInstalledReader(t *testing.T) {
	body, pub, _ := signedPullCurrent(t, 13)
	dir := t.TempDir()
	floorPath := filepath.Join(dir, "release-floor.json")
	pubPath := filepath.Join(dir, "platform.pub")
	expectedPath := filepath.Join(dir, "expected-current.json")
	binPath := filepath.Join(dir, "loom")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(expectedPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyReader := []byte("#!/bin/sh\n[ \"$*\" = selfcheck ]\n")
	if err := os.WriteFile(binPath, legacyReader, 0o755); err != nil {
		t.Fatal(err)
	}
	var payloadRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/current.json" {
			_, _ = w.Write(body)
			return
		}
		payloadRequests.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv(contEnv, "")
	t.Setenv(contStatusEnv, "")
	t.Setenv(contSnapshotEnv, "")

	err := cmdPull([]string{
		"-url", srv.URL, "-node", "demo-c", "-pubkey", pubPath,
		"-expected-current", expectedPath, "-release-floor", floorPath,
		"-deploy-lock", filepath.Join(dir, "deploy.lock"), "-bin", binPath,
	})
	if err == nil || !strings.Contains(err.Error(), signedCurrentCapability) {
		t.Fatalf("旧 reader 不应与新 floor 共存:%v", err)
	}
	if floor, err := releasefloor.Read(floorPath); err != nil || floor != nil {
		t.Fatalf("capability 失败后写出了无人能执行的 floor:%+v err=%v", floor, err)
	}
	if payloadRequests.Load() != 0 {
		t.Fatal("当前 reader 能力未确认前不应请求 payload")
	}
}
