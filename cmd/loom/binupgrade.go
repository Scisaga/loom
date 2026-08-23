package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"loom/internal/snapshot"
)

// upgradeBinary 按签名过的 manifest 把本机的 Agent 二进制换成配套的那个(§15.4)。
//
// **顺序是先二进制、后配置。** 配对失败的方向不对称:新版通常读得懂旧配置,
// 旧版读不懂新配置 —— 发布器就是这么崩过一次的(旧二进制遇到新增字段,
// 直接拒绝发布)。先换二进制,这一步之后无论配置新旧都能读。
//
// 返回 true 表示换过了。
func upgradeBinary(c *http.Client, base string, man *snapshot.Manifest, binPath string, dry bool) (bool, error) {
	var want *snapshot.BinaryRef
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			want = &man.Binaries[i]
		}
	}
	if want == nil {
		// 快照没带这个平台的二进制。不是错误 —— 只是这次不管二进制。
		return false, nil
	}

	have, err := fileSum(binPath)
	if err != nil {
		return false, fmt.Errorf("算不出本机二进制的哈希:%w", err)
	}
	if have == want.SHA256 {
		return false, nil
	}
	fmt.Printf("  二进制要换:%s → %s(%.1f MB)\n", short(have), short(want.SHA256), float64(want.Size)/(1<<20))
	if dry {
		return true, nil
	}

	body, err := getBytes(c, base+"/"+want.Path())
	if err != nil {
		return false, fmt.Errorf("下载二进制:%w", err)
	}
	// 内容寻址,但仍然自己算一遍 —— 路径由 manifest 给出,而 manifest 已经
	// 验过签;这一步确认下下来的字节确实是那个哈希,而不是被截断的。
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
		return false, fmt.Errorf("下载的二进制哈希对不上(签名说 %s,实际 %s)", short(want.SHA256), short(got))
	}
	if len(body) != want.Size {
		return false, fmt.Errorf("下载的二进制大小对不上(%d vs %d)", len(body), want.Size)
	}

	// 冒烟测试:先落到临时位置跑一遍。**一个跑不起来的二进制装上去,
	// 这台机器就再也拉不到修复了** —— 那是最糟的失败模式。
	stage := binPath + ".new"
	if err := os.WriteFile(stage, body, 0o755); err != nil {
		return false, err
	}
	defer os.Remove(stage)
	out, err := exec.Command(stage, "selfcheck").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("新二进制没通过自检,不安装:%w\n%s", err, strings.TrimSpace(string(out)))
	}

	// 留一份旧的。后面任何一个服务起不来就换回去。
	prev := binPath + ".prev"
	_ = os.Remove(prev)
	if old, err := os.ReadFile(binPath); err == nil {
		if err := os.WriteFile(prev, old, 0o755); err != nil {
			return false, err
		}
	}
	// install 会 unlink 再建,所以正在跑的进程不受影响 —— 它们继续用旧的
	// inode,直到各自重启。
	if err := os.Rename(stage, binPath); err != nil {
		return false, err
	}

	// 常驻服务要重启才会用上新二进制。**不重启 loom-pull** —— 那是正在
	// 跑的这个,重启它等于在一次升级里再套一次升级。
	units := []string{"loom-report", "loom-agent", "loom-publisher"}
	var failed []string
	for _, u := range units {
		if !unitExists(u) {
			continue
		}
		_ = exec.Command("systemctl", "restart", u).Run()
	}
	time.Sleep(5 * time.Second)
	for _, u := range units {
		if !unitExists(u) {
			continue
		}
		if activeState(u) != "active" {
			failed = append(failed, u)
		}
	}
	if len(failed) > 0 {
		fmt.Printf("  !! 换二进制之后 %s 起不来,换回旧版\n", strings.Join(failed, " "))
		if _, err := os.Stat(prev); err == nil {
			_ = os.Rename(prev, binPath)
			for _, u := range units {
				if unitExists(u) {
					_ = exec.Command("systemctl", "restart", u).Run()
				}
			}
		}
		return false, fmt.Errorf("新二进制装上后 %s 起不来,已换回旧版", strings.Join(failed, " "))
	}
	fmt.Printf("  ✅ 二进制已换,%d 个服务重启正常\n", len(units))
	return true, nil
}

func fileSum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func unitExists(u string) bool {
	out, _ := exec.Command("systemctl", "list-unit-files", u+".service", "--no-legend").Output()
	return strings.TrimSpace(string(out)) != ""
}

func activeState(u string) string {
	out, _ := exec.Command("systemctl", "is-active", u).Output()
	return strings.TrimSpace(string(out))
}
