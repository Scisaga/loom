package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"loom/internal/publish"
)

func mirrorCurrent(t *testing.T, priv ed25519.PrivateKey, generation uint64, snapshotID string) []byte {
	t.Helper()
	current := &publish.DeploymentCurrent{
		Schema: publish.DeploymentCurrentSchema, Generation: generation,
		Snapshot: snapshotID, PublishedAt: "2026-08-29T00:00:00Z",
	}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func currentServer(body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/current.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
}

func TestPullMirrorsChooseHighestValidGenerationNotFirstURL(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stale := currentServer(mirrorCurrent(t, priv, 4, "aaaaaaaaaaaa"))
	defer stale.Close()
	fresh := currentServer(mirrorCurrent(t, priv, 7, "bbbbbbbbbbbb"))
	defer fresh.Close()

	selection, err := selectPullCurrentFromMirrors(stale.Client(), []string{stale.URL, fresh.URL},
		"demo-f", pub, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if selection.current.signed.Generation != 7 || selection.current.snapshot != "bbbbbbbbbbbb" ||
		selection.currentBase != fresh.URL || selection.contentBases[0] != fresh.URL {
		t.Fatalf("没有选择最高代并优先其镜像:%+v", selection)
	}
}

func TestPullMirrorsIgnoreBrokenMirrorWhenAnotherIsValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	broken := currentServer([]byte(`{"schema":1,"broken":true}`))
	defer broken.Close()
	good := currentServer(mirrorCurrent(t, priv, 3, "aaaaaaaaaaaa"))
	defer good.Close()

	selection, err := selectPullCurrentFromMirrors(good.Client(), []string{broken.URL, good.URL},
		"demo-f", pub, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if selection.currentBase != good.URL || len(selection.warnings) != 1 {
		t.Fatalf("坏镜像没有降级成可见告警:%+v", selection)
	}
}

func TestPullMirrorsFailClosedOnSameGenerationFork(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := currentServer(mirrorCurrent(t, priv, 8, "aaaaaaaaaaaa"))
	defer a.Close()
	b := currentServer(mirrorCurrent(t, priv, 8, "bbbbbbbbbbbb"))
	defer b.Close()

	_, err = selectPullCurrentFromMirrors(a.Client(), []string{a.URL, b.URL},
		"demo-f", pub, nil, false, nil)
	if err == nil || !strings.Contains(err.Error(), "同一 signed generation") {
		t.Fatalf("同代分叉应失败关闭:%v", err)
	}
}

func TestPullMirrorCurrentReadsRunConcurrently(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := mirrorCurrent(t, priv, 2, "aaaaaaaaaaaa")
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(180 * time.Millisecond)
		_, _ = w.Write(body)
	}))
	defer slow.Close()
	slowTwo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(180 * time.Millisecond)
		_, _ = w.Write(body)
	}))
	defer slowTwo.Close()

	start := time.Now()
	_, err = selectPullCurrentFromMirrors(slow.Client(), []string{slow.URL, slowTwo.URL},
		"demo-f", pub, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The function waits for diagnostics from every mirror, but requests must
	// overlap rather than paying slow+fast sequential latency.
	if elapsed := time.Since(start); elapsed > 320*time.Millisecond {
		t.Fatalf("current 镜像没有并行读取:%s", elapsed)
	}
}
