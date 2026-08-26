package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/deploy"
	"loom/internal/rollout"
)

func TestParseApplyInventorySortsInstalledFilesAndBindsHash(t *testing.T) {
	body := []byte(`{"node":"n1","files":{"/etc/wireguard/wg-b.conf":"b","/etc/loom/report/config.json":"a"}}`)
	got, err := parseApplyInventory("n1", "manifest.json", body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/loom/report/config.json", "/etc/wireguard/wg-b.conf"}
	if !reflect.DeepEqual(got.files, want) {
		t.Fatalf("installed 列表未稳定排序：%v，期望 %v", got.files, want)
	}
	sum := sha256.Sum256(body)
	if got.sha256 != hex.EncodeToString(sum[:]) || got.absent {
		t.Fatalf("inventory guard 不对：%+v", got)
	}
}

func TestParseApplyInventoryRejectsWrongNodeAndRelativePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "wrong-node", body: `{"node":"n2","files":{}}`},
		{name: "relative-path", body: `{"node":"n1","files":{"etc/loom/config":"x"}}`},
		{name: "outside-managed-roots", body: `{"node":"n1","files":{"/etc/passwd":"x"}}`},
		{name: "path-traversal", body: `{"node":"n1","files":{"/etc/loom/../passwd":"x"}}`},
		{name: "transaction-delimiter", body: `{"node":"n1","files":{"/etc/loom/report/a|b":"x"}}`},
		{name: "shell-quote", body: `{"node":"n1","files":{"/etc/loom/report/a'b":"x"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseApplyInventory("n1", "manifest.json", []byte(tc.body)); err == nil {
				t.Fatalf("危险 inventory 应被拒绝：%s", tc.body)
			}
		})
	}
}

func TestReadApplyInventoryLocalMissingMeansFirstInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	got, err := readApplyInventory("n1", "", true, time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.absent || len(got.files) != 0 || got.sha256 != "" {
		t.Fatalf("缺清单应是首次安装的空 inventory：%+v", got)
	}
}

func TestReadApplyInventoryLocalCorruptionFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readApplyInventory("n1", "", true, time.Second, path); err == nil {
		t.Fatal("存在但损坏的清单不能按空 inventory 继续")
	}
}

func TestBindInstalledInventoryUsesDifferenceAndAddsGuard(t *testing.T) {
	plan := &deploy.Plan{Files: map[string]string{"/etc/loom/report/config.json": "new"}}
	inv := applyInventory{
		files: []string{
			"/etc/loom/report/config.json",
			"/etc/wireguard/wg-stale.conf",
		},
		sha256: "abc123",
	}
	bindInstalledInventory(plan, inv, "/etc/loom/report/manifest.json")
	if want := []string{"/etc/wireguard/wg-stale.conf"}; !reflect.DeepEqual(plan.Remove, want) {
		t.Fatalf("没有按 installed−desired 计算删除集合：%v", plan.Remove)
	}
	if plan.InventoryGuard == nil || plan.InventoryGuard.Path != "/etc/loom/report/manifest.json" ||
		plan.InventoryGuard.SHA256 != "abc123" || plan.InventoryGuard.Absent {
		t.Fatalf("没有把同一份 inventory 绑定到持锁脚本：%+v", plan.InventoryGuard)
	}
}

func TestManualApplyInvalidatesOldSnapshotCoordinatesInsideDeployTransaction(t *testing.T) {
	plan := &deploy.Plan{}
	bindManualApplyCoordinates(plan)
	want := []string{appliedSnapshotPath, rollout.Path}
	if !reflect.DeepEqual(plan.InvalidateOnChange, want) {
		t.Fatalf("manual apply 必须作废旧 applied/rollout 坐标:got=%v want=%v",
			plan.InvalidateOnChange, want)
	}
}

func TestQuoteRemotePath(t *testing.T) {
	if got, want := quoteRemotePath("/tmp/a'b"), `'/tmp/a'"'"'b'`; got != want {
		t.Fatalf("远端路径引用错误：%s，期望 %s", got, want)
	}
}

func TestRunScriptTimeoutAllowsExitTrapForLocalAndSSH(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "ssh"}[remote], func(t *testing.T) {
			dir := t.TempDir()
			if remote {
				ssh := filepath.Join(dir, "ssh")
				// 参数只是在模拟 ssh 前端；stdin 原样交给远端 sh。
				if err := os.WriteFile(ssh, []byte("#!/bin/sh\nexec /bin/sh -s\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			}
			marker := filepath.Join(dir, "rolled-back")
			script := fmt.Sprintf("trap 'printf done > %s; exit 143' TERM\nwhile :; do sleep 1; done\n", quoteRemotePath(marker))
			err := runScriptWithGrace("node", script, "unused", !remote, 30*time.Millisecond, time.Second)
			if err == nil || !strings.Contains(err.Error(), "已请求终止") {
				t.Fatalf("超时应 TERM 后等待 trap，得到:%v", err)
			}
			if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "done" {
				t.Fatalf("%s EXIT/TERM trap 没有完成:%q err=%v", map[bool]string{false: "本地", true: "SSH"}[remote], got, readErr)
			}
		})
	}
}

func TestRunScriptHardTimeoutDoesNotClaimRollback(t *testing.T) {
	err := runScriptWithGrace("node", "trap '' TERM\nwhile :; do :; done\n", "", true,
		20*time.Millisecond, 20*time.Millisecond)
	if err == nil {
		t.Fatal("忽略 TERM 的脚本必须被 KILL")
	}
	if !strings.Contains(err.Error(), "不能确认已回滚") {
		t.Fatalf("强制终止不能宣称已经回滚:%v", err)
	}
}

func TestValidateHydratedBundleRequiresExactManifestSetAndHashes(t *testing.T) {
	valid := map[string]string{
		"agent/config.json":          `{ "node": "n1" }`,
		"systemd/loom-agent.service": "[Service]\nExecStart=/usr/bin/loom agent\n",
	}
	valid[manifestBundlePath] = buildManifest("n1", valid)
	if err := validateHydratedBundle("n1", valid); err != nil {
		t.Fatalf("合法 hydrate bundle 被拒绝:%v", err)
	}

	for _, tc := range []struct {
		name string
		edit func(map[string]string)
		want string
	}{
		{"missing-manifest", func(f map[string]string) { delete(f, manifestBundlePath) }, "缺少"},
		{"bad-manifest", func(f map[string]string) { f[manifestBundlePath] = "{" }, "解析"},
		{"wrong-node", func(f map[string]string) {
			f[manifestBundlePath] = strings.Replace(f[manifestBundlePath], `"node": "n1"`, `"node": "n2"`, 1)
		}, "不是目录节点"},
		{"modified-body", func(f map[string]string) { f["agent/config.json"] += "tampered" }, "内容哈希不符"},
		{"extra-body", func(f map[string]string) { f["report/extra.json"] = "extra" }, "多出"},
		{"missing-body", func(f map[string]string) { delete(f, "agent/config.json") }, "缺少 manifest 声明"},
		{"unmapped-body", func(f map[string]string) { f["unknown/file"] = "extra" }, "没有安全的安装位置"},
		{"traversal-body", func(f map[string]string) { f["agent/../escape"] = "extra" }, "越界或非规范"},
		{"shell-meta-body", func(f map[string]string) { f["report/a'b.json"] = "extra" }, "越界或非规范"},
		{"outside-manifest-path", func(f map[string]string) {
			f[manifestBundlePath] = `{"node":"n1","files":{"/etc/passwd":"` + strings.Repeat("0", 64) + `"}}`
		}, "越界或非规范安装路径"},
		{"unknown-manifest-field", func(f map[string]string) {
			f[manifestBundlePath] = strings.Replace(f[manifestBundlePath], `"files":`, `"unexpected":true,"files":`, 1)
		}, "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := cloneStringMap(valid)
			tc.edit(files)
			if err := validateHydratedBundle("n1", files); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("应以 %q 拒绝，得到:%v", tc.want, err)
			}
		})
	}
}

func TestReadBundlesRejectsSymlinkAndRootExtras(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		node := filepath.Join(root, "n1")
		if err := os.MkdirAll(node, 0o755); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(node, "escape")); err != nil {
			t.Fatal(err)
		}
		if _, err := readBundles(root); err == nil || !strings.Contains(err.Error(), "符号链接") {
			t.Fatalf("不能跟随 bundle 内符号链接:%v", err)
		}
	})

	t.Run("root-extra", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readBundles(root); err == nil || !strings.Contains(err.Error(), "非节点目录") {
			t.Fatalf("hydrate 根目录额外文件不能静默忽略:%v", err)
		}
	})

	t.Run("invalid-node-directory", func(t *testing.T) {
		root := t.TempDir()
		bad := filepath.Join(root, "Bad'Node")
		if err := os.Mkdir(bad, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := readBundles(root); err == nil || !strings.Contains(err.Error(), "非法节点目录") {
			t.Fatalf("非法 node 目录不能进入脚本/SSH 边界:%v", err)
		}
	})
}

func cloneStringMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
