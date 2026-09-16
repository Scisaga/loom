//go:build linux

package clientv2

import (
	"os"
	"slices"
	"testing"

	"loom/internal/deploy"
	"loom/internal/render"
)

func TestMigrationRetiresOldEntrypointsAndPreservesNetworkIdentity(t *testing.T) {
	files := map[string]string{
		render.ManifestPath:                          `{"node":"demo-node","files":{"/etc/loom/tls/node.key":"original","/etc/wireguard/wg-demo-peer.conf":"original"}}`,
		"/etc/systemd/system/loom-pull.timer":        "[Timer]\nOnUnitActiveSec=60\n",
		"/etc/systemd/system/loom-publisher.service": "[Service]\nExecStart=/usr/local/bin/loom publisher\n",
		"/etc/loom/report/config.json":               `{"node":"demo-node"}`,
	}
	plan := &deploy.Plan{Node: "demo-node", Files: map[string]string{"/etc/wireguard/wg-demo-peer.conf": "new"}}
	read := func(path string) ([]byte, error) {
		body, found := files[path]
		if !found {
			return nil, os.ErrNotExist
		}
		return []byte(body), nil
	}
	if err := bindLinuxMigrationRetirement(plan, read); err != nil {
		t.Fatal(err)
	}
	for path := range files {
		if !slices.Contains(plan.Remove, path) {
			t.Fatal("旧业务文件未进入事务删除", path)
		}
	}
	for _, path := range []string{"/etc/loom/tls/node.key", "/etc/wireguard/wg-demo-peer.conf", "/etc/systemd/system/loom-control.service"} {
		if slices.Contains(plan.Remove, path) {
			t.Fatal("原身份、网络或当前 control 被删除", path)
		}
	}
	if !slices.Contains(plan.RetireServices(), "loom-pull.timer") || !slices.Contains(plan.RetireServices(), "loom-publisher") {
		t.Fatal("旧后台写入者没有停用")
	}
	files[render.ManifestPath] = `{"node":"demo-other","files":{}}`
	if err := bindLinuxMigrationRetirement(&deploy.Plan{Node: "demo-node"}, read); err == nil {
		t.Fatal("接受了别人的安装清单")
	}
}
