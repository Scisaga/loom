//go:build linux

package clientv2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"

	"loom/internal/deploy"
	"loom/internal/render"
	"loom/internal/report"
)

// 只在原身份迁移验证后接管已知旧运行入口。原 WireGuard 文件由 v2 计划
// 原位管理，身份、CA、秘密与 floors 不在删除集合。失败由同一部署事务恢复。
func bindLinuxMigrationRetirement(plan *deploy.Plan, read func(string) ([]byte, error)) error {
	retired := map[string]bool{
		"/etc/loom/sing-box/config.json":             true,
		"/etc/loom/agent/config.json":                true,
		"/etc/loom/report/config.json":               true,
		"/etc/systemd/system/sing-box.service":       true,
		"/etc/systemd/system/loom-agent.service":     true,
		"/etc/systemd/system/loom-report.service":    true,
		"/etc/systemd/system/loom-pull.service":      true,
		"/etc/systemd/system/loom-pull.timer":        true,
		"/etc/systemd/system/loom-publisher.service": true,
		"/etc/systemd/system/loom-publisher.timer":   true,
	}
	paths := make([]string, 0, len(retired)+1)
	for path := range retired {
		paths = append(paths, path)
	}
	paths = append(paths, render.ManifestPath)
	sort.Strings(paths)
	for _, path := range paths {
		body, err := read(path)
		if errors.Is(err, os.ErrNotExist) {
			plan.AdditionalInventoryGuards = append(plan.AdditionalInventoryGuards, deploy.InventoryGuard{Path: path, Absent: true})
			continue
		}
		if err != nil {
			return err
		}
		if path == render.ManifestPath {
			var previous report.Manifest
			if json.Unmarshal(body, &previous) != nil || previous.Node != plan.Node || previous.Files == nil {
				return errors.New("[Linux 迁移] 原安装清单损坏或属于其他设备")
			}
		}
		sum := sha256.Sum256(body)
		plan.AdditionalInventoryGuards = append(plan.AdditionalInventoryGuards, deploy.InventoryGuard{Path: path, SHA256: hex.EncodeToString(sum[:])})
		plan.Remove = append(plan.Remove, path)
	}
	sort.Strings(plan.Remove)
	return nil
}
