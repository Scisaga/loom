package publish

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseAuthorityGenerationIsDurableAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	priv := key(t)
	first, allocated, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
		"2026-08-27T12:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	if !allocated || first.Generation != 1 {
		t.Fatalf("首次 authority=%+v allocated=%v", first, allocated)
	}
	firstBytes, err := first.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	// A later build timestamp is not a release decision.  Reusing the same
	// logical target must retain the exact envelope, not re-sign generation 1.
	again, allocated, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
		"2026-08-27T13:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	againBytes, _ := again.Bytes()
	if allocated || again.Generation != 1 || string(againBytes) != string(firstBytes) {
		t.Fatalf("同一 target 没有精确复用:allocated=%v current=%+v", allocated, again)
	}

	changed, allocated, err := ensureReleaseAuthority(dir, "bbbbbbbbbbbb", nil,
		"2026-08-27T14:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	if !allocated || changed.Generation != 2 || changed.Snapshot != "bbbbbbbbbbbb" {
		t.Fatalf("目标变化没有推进一代:%+v allocated=%v", changed, allocated)
	}

	onDisk, err := ReadReleaseAuthority(dir, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !deploymentCurrentBytesEqual(onDisk, changed) {
		t.Fatalf("磁盘 authority 与返回值不同:onDisk=%+v want=%+v", onDisk, changed)
	}
	for _, name := range []string{releaseAuthorityFile, releaseAuthorityMarkerFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
}

func TestReleaseAuthorityAssignmentsAreLogicalTarget(t *testing.T) {
	dir := t.TempDir()
	priv := key(t)
	a := []DeploymentAssignment{
		{Node: "hz01", Snapshot: "cccccccccccc"},
		{Node: "gz02", Snapshot: "bbbbbbbbbbbb"},
	}
	first, _, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", a,
		"2026-08-27T12:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	a[0], a[1] = a[1], a[0]
	again, allocated, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", a,
		"2026-08-27T13:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	if allocated || again.Generation != first.Generation {
		t.Fatalf("assignment 换序不应生成新代:first=%d again=%d allocated=%v",
			first.Generation, again.Generation, allocated)
	}
	a[0].Snapshot = "dddddddddddd"
	third, allocated, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", a,
		"2026-08-27T14:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	if !allocated || third.Generation != first.Generation+1 {
		t.Fatalf("assignment 变化没有推进 generation:%+v", third)
	}
}

func TestReleaseAuthorityMissingAfterMarkerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	priv := key(t)
	if _, _, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
		"2026-08-27T12:00:00Z", priv); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ReleaseAuthorityPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReleaseAuthority(dir, priv.Public().(ed25519.PublicKey)); err == nil ||
		!strings.Contains(err.Error(), "拒绝从 generation 1") {
		t.Fatalf("authority 丢失后应 fail closed:%v", err)
	}
	if _, _, err := ensureReleaseAuthority(dir, "bbbbbbbbbbbb", nil,
		"2026-08-27T13:00:00Z", priv); err == nil {
		t.Fatal("marker 存在时仍重新初始化 authority")
	}
}

func TestReleaseAuthorityCleanLegacyAndTamper(t *testing.T) {
	dir := t.TempDir()
	priv := key(t)
	pub := priv.Public().(ed25519.PublicKey)
	current, err := ReadReleaseAuthority(dir, pub)
	if err != nil || current != nil {
		t.Fatalf("干净 legacy 目录应可迁移:current=%+v err=%v", current, err)
	}
	if _, _, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
		"2026-08-27T12:00:00Z", priv); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(ReleaseAuthorityPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 1
	if err := os.WriteFile(ReleaseAuthorityPath(dir), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReleaseAuthority(dir, pub); err == nil {
		t.Fatal("损坏的 authority 被接受")
	}
}

func TestReleaseAuthorityBackupStateRequiresCompleteDurablePair(t *testing.T) {
	priv := key(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  bool
		bad   bool
	}{
		{name: "clean-legacy"},
		{name: "complete-signed-era", want: true, setup: func(t *testing.T, dir string) {
			if _, _, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
				"2026-08-27T12:00:00Z", priv); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "authority-only", bad: true, setup: func(t *testing.T, dir string) {
			if _, _, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
				"2026-08-27T12:00:00Z", priv); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(releaseAuthorityMarkerPath(dir)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "marker-only", bad: true, setup: func(t *testing.T, dir string) {
			if err := os.WriteFile(releaseAuthorityMarkerPath(dir), []byte(releaseAuthorityMarkerBody), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt-authority", bad: true, setup: func(t *testing.T, dir string) {
			if _, _, err := ensureReleaseAuthority(dir, "aaaaaaaaaaaa", nil,
				"2026-08-27T12:00:00Z", priv); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ReleaseAuthorityPath(dir), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			got, err := ReleaseAuthorityBackupState(dir)
			if tc.bad && err == nil {
				t.Fatalf("不完整 authority 状态被当成可恢复备份:enabled=%v", got)
			}
			if !tc.bad && (err != nil || got != tc.want) {
				t.Fatalf("enabled=%v want=%v err=%v", got, tc.want, err)
			}
		})
	}
}
