package publish

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func deploymentCurrentBody(t *testing.T, current *DeploymentCurrent) []byte {
	t.Helper()
	body, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func makeSignedDeploymentCurrent(t *testing.T, priv ed25519.PrivateKey, generation uint64,
	snapshot, publishedAt string) *DeploymentCurrent {
	t.Helper()
	current := &DeploymentCurrent{
		Schema: DeploymentCurrentSchema, Generation: generation,
		Snapshot: snapshot, PublishedAt: publishedAt,
	}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return current
}

func TestPublishOncePushFailureRetryReusesExactDurableCurrent(t *testing.T) {
	body := []byte(goodSSOT)
	priv := key(t)
	archiveDir := t.TempDir()
	now := at("2026-08-26T20:00:00Z")
	target := &safetyTarget{failPushes: 1}
	opts := Options{
		Key: priv, Target: target, ArchiveDir: archiveDir,
		Now: func() time.Time { return now },
	}

	if _, err := publishOnce(&opts, body, nil, func(string, ...any) {}); err == nil ||
		!strings.Contains(err.Error(), "injected push failure") {
		t.Fatalf("首次 Push 应失败:%v", err)
	}
	first, err := ReadReleaseAuthority(archiveDir, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first.Generation != 1 || first.PublishedAt != "2026-08-26T20:00:00Z" {
		t.Fatalf("Push 前没有耐久化 generation 1:%+v", first)
	}
	firstBody := deploymentCurrentBody(t, first)
	if _, found, err := target.ReadFile("current.json"); err != nil || found {
		t.Fatalf("Push 失败后分发点不应已更新:found=%v err=%v", found, err)
	}

	// A retry is a continuation of the same release decision.  Wall-clock time
	// may have advanced, but generation, PublishedAt and signature must not.
	now = at("2026-08-26T21:00:00Z")
	if _, err := publishOnce(&opts, body, nil, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	second, err := ReadReleaseAuthority(archiveDir, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	secondBody := deploymentCurrentBody(t, second)
	servedBody, found, err := target.ReadFile("current.json")
	if err != nil || !found {
		t.Fatalf("重试后读 current.json:found=%v err=%v", found, err)
	}
	if target.pushes != 2 || !bytes.Equal(firstBody, secondBody) || !bytes.Equal(firstBody, servedBody) {
		t.Fatalf("重试改变了已分配 envelope:pushes=%d first=%s second=%s served=%s",
			target.pushes, firstBody, secondBody, servedBody)
	}
}

func TestInitialSignedCurrentRequiresCapableAgentBeforeAuthorityAllocation(t *testing.T) {
	priv := key(t)
	dir := t.TempDir()
	opts := &Options{Key: priv, ArchiveDir: dir}
	platform := runtime.GOOS + "/" + runtime.GOARCH

	for _, tc := range []struct {
		name string
		bins map[string][]byte
	}{
		{name: "missing-agent"},
		{name: "legacy-agent", bins: map[string][]byte{
			platform: []byte("#!/bin/sh\n[ \"$*\" = selfcheck ]\n"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := requireInitialSignedCurrentAgent(opts, tc.bins); err == nil ||
				!strings.Contains(err.Error(), SignedCurrentCapability) {
				t.Fatalf("generation 1 的旧/空 Agent 未被能力门禁挡住:%v", err)
			}
			authority, err := ReadReleaseAuthority(dir, priv.Public().(ed25519.PublicKey))
			if err != nil || authority != nil {
				t.Fatalf("能力门禁失败前不得分配 authority:authority=%+v err=%v", authority, err)
			}
		})
	}

	capable := map[string][]byte{
		platform: []byte("#!/bin/sh\n[ \"$*\" = 'selfcheck -q -require signed-current-v1' ]\n"),
	}
	if err := requireInitialSignedCurrentAgent(opts, capable); err != nil {
		t.Fatalf("明确声明 signed-current capability 的 Agent 被拒绝:%v", err)
	}
	target := &safetyTarget{}
	opts.Target = target
	opts.Now = func() time.Time { return at("2026-08-26T20:00:00Z") }
	if _, err := publishOnce(opts, []byte(goodSSOT), capable, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	authority, err := ReadReleaseAuthority(dir, priv.Public().(ed25519.PublicKey))
	if err != nil || authority == nil || authority.Generation != 1 {
		t.Fatalf("能力门禁通过后没有正常分配 generation 1:authority=%+v err=%v", authority, err)
	}
}

func TestPublishOnceFailsClosedOnSignedGenerationFork(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, priv ed25519.PrivateKey, authority *DeploymentCurrent) *DeploymentCurrent
		want string
	}{
		{
			name: "served-higher-generation",
			make: func(t *testing.T, priv ed25519.PrivateKey, authority *DeploymentCurrent) *DeploymentCurrent {
				return makeSignedDeploymentCurrent(t, priv, authority.Generation+1,
					authority.Snapshot, "2026-08-26T21:00:00Z")
			},
			want: "高于本地 authority",
		},
		{
			name: "same-generation-different-payload",
			make: func(t *testing.T, priv ed25519.PrivateKey, authority *DeploymentCurrent) *DeploymentCurrent {
				return makeSignedDeploymentCurrent(t, priv, authority.Generation,
					authority.Snapshot, "2026-08-26T21:00:00Z")
			},
			want: "同一 generation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(goodSSOT)
			priv := key(t)
			tree, err := Build(body, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
			if err != nil {
				t.Fatal(err)
			}
			archiveDir := t.TempDir()
			authority, _, err := ensureReleaseAuthority(archiveDir, tree.Snapshot, nil,
				"2026-08-26T20:00:00Z", priv)
			if err != nil {
				t.Fatal(err)
			}
			served := tc.make(t, priv, authority)
			tree.Files["current.json"] = deploymentCurrentBody(t, served)
			target := &safetyTarget{
				current: tree.Snapshot, files: cloneBytesMap(tree.Files), blobs: cloneBytesMap(tree.Blobs),
			}
			_, err = publishOnce(&Options{
				Key: priv, Target: target, ArchiveDir: archiveDir,
				Now: func() time.Time { return at("2026-08-26T22:00:00Z") },
			}, body, nil, func(string, ...any) {})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("应 fail closed 且包含 %q:%v", tc.want, err)
			}
			if target.pushes != 0 {
				t.Fatalf("分叉 current 被覆盖:pushes=%d", target.pushes)
			}
			got, _, readErr := target.ReadFile("current.json")
			if readErr != nil || !bytes.Equal(got, deploymentCurrentBody(t, served)) {
				t.Fatalf("分发点 current 在 fail closed 时被改动:err=%v", readErr)
			}
		})
	}
}

func TestPublishOnceRepairsValidLowerGeneration(t *testing.T) {
	body := []byte(goodSSOT)
	priv := key(t)
	tree, err := Build(body, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	archiveDir := t.TempDir()
	if _, _, err := ensureReleaseAuthority(archiveDir, "aaaaaaaaaaaa", nil,
		"2026-08-26T18:00:00Z", priv); err != nil {
		t.Fatal(err)
	}
	authority, _, err := ensureReleaseAuthority(archiveDir, tree.Snapshot, nil,
		"2026-08-26T20:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Generation != 2 {
		t.Fatalf("测试前提失败:authority=%+v", authority)
	}
	lower := makeSignedDeploymentCurrent(t, priv, 1, tree.Snapshot, "2026-08-26T19:00:00Z")
	tree.Files["current.json"] = deploymentCurrentBody(t, lower)
	target := &safetyTarget{
		current: tree.Snapshot, files: cloneBytesMap(tree.Files), blobs: cloneBytesMap(tree.Blobs),
	}
	if _, err := publishOnce(&Options{
		Key: priv, Target: target, ArchiveDir: archiveDir,
		Now: func() time.Time { return at("2026-08-26T21:00:00Z") },
	}, body, nil, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	got, found, err := target.ReadFile("current.json")
	if err != nil || !found || target.pushes != 1 ||
		!bytes.Equal(got, deploymentCurrentBody(t, authority)) {
		t.Fatalf("低 generation 没有修复到本地 authority:pushes=%d found=%v err=%v",
			target.pushes, found, err)
	}
}

func TestReleasePointerDetectsAndRepairsSameSnapshotTamper(t *testing.T) {
	body := []byte(goodSSOT)
	priv := key(t)
	tree, err := Build(body, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	archiveDir := t.TempDir()
	authority, _, err := ensureReleaseAuthority(archiveDir, tree.Snapshot, nil,
		"2026-08-26T20:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	authorityBody := deploymentCurrentBody(t, authority)

	for _, tc := range []struct {
		name   string
		mutate func(*DeploymentCurrent)
	}{
		{"generation", func(current *DeploymentCurrent) { current.Generation++ }},
		{"signature", func(current *DeploymentCurrent) {
			current.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *authority
			tc.mutate(&tampered)
			treeFiles := cloneBytesMap(tree.Files)
			treeFiles["current.json"] = deploymentCurrentBody(t, &tampered)
			target := &safetyTarget{
				current: tree.Snapshot, files: treeFiles, blobs: cloneBytesMap(tree.Blobs),
			}
			opts := Options{
				Key: priv, Target: target, ArchiveDir: archiveDir,
				Now: func() time.Time { return at("2026-08-26T21:00:00Z") },
			}
			known, converged, err := releasePointerConverged(&opts)
			if err != nil || !known || converged {
				t.Fatalf("同 snapshot %s 篡改未被 daemon 对账发现:known=%v converged=%v err=%v",
					tc.name, known, converged, err)
			}
			if _, err := publishOnce(&opts, body, nil, func(string, ...any) {}); err != nil {
				t.Fatal(err)
			}
			got, found, err := target.ReadFile("current.json")
			if err != nil || !found || target.pushes != 1 || !bytes.Equal(got, authorityBody) {
				t.Fatalf("同 snapshot %s 篡改未自愈:pushes=%d found=%v err=%v",
					tc.name, target.pushes, found, err)
			}
		})
	}
}

func TestPublishOnceRefusesFutureCurrentSchema(t *testing.T) {
	body := []byte(goodSSOT)
	priv := key(t)
	tree, err := Build(body, priv, Meta{CreatedAt: "2026-08-26T20:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	future := []byte(`{"schema":2,"generation":9,"snapshot":"` + tree.Snapshot +
		`","published_at":"2026-08-26T20:00:00Z","rollout":{"protocol":"future"},"signature":"future"}`)
	tree.Files["current.json"] = future
	target := &safetyTarget{
		current: tree.Snapshot, files: cloneBytesMap(tree.Files), blobs: cloneBytesMap(tree.Blobs),
	}
	archiveDir := t.TempDir()
	_, err = publishOnce(&Options{
		Key: priv, Target: target, ArchiveDir: archiveDir,
		Now: func() time.Time { return at("2026-08-26T21:00:00Z") },
	}, body, nil, func(string, ...any) {})
	if err == nil || !errors.Is(err, errFutureDeploymentCurrentSchema) {
		t.Fatalf("未知未来 schema 应 fail closed:%v", err)
	}
	if target.pushes != 0 {
		t.Fatalf("未来 schema 被旧 publisher 覆盖:pushes=%d", target.pushes)
	}
	got, _, readErr := target.ReadFile("current.json")
	if readErr != nil || !bytes.Equal(got, future) {
		t.Fatalf("未来 schema 在 fail closed 时被改动:err=%v", readErr)
	}
	if _, statErr := os.Stat(ReleaseAuthorityPath(archiveDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("未来 schema 失败前不应初始化 authority:%v", statErr)
	}
}
