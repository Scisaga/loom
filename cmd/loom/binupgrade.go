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
		// 文件对了,但**跑着的进程可能还是旧的**。
		//
		// 实测踩到:中控上二进制是 `go build` 直接换的,升级流程看哈希
		// "没变化"就什么都不做,而 loom-report 用旧 inode 跑了几个小时 ——
		// 它上报的数据结构比别人少字段,而这在任何检查里都看不出来。
		if stale := staleUnits(); len(stale) > 0 {
			fmt.Printf("  %s 还跑着被替换掉的旧二进制,重启\n", strings.Join(stale, " "))
			if dry {
				return false, nil
			}
			for _, u := range stale {
				_ = exec.Command("systemctl", "restart", u).Run()
			}
		}
		return false, nil
	}
	fmt.Printf("  二进制要换:%s → %s(%.1f MB)\n", short(have), short(want.SHA256), float64(want.Size)/(1<<20))
	if dry {
		return true, nil
	}

	// 二进制走 getBlob,不走 getBytes —— 后者那个 60 秒总超时装不下 12 MB。
	body, err := getBlob(c, base+"/"+want.Path(), int64(want.Size)+1<<20, blobStall)
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

// staleUnits 找出"跑着的二进制已经不是磁盘上那个"的服务。
//
// 判据是 /proc/<pid>/exe:替换文件时旧 inode 还被进程持有,内核在这个
// 符号链接后面加 " (deleted)"。这比比对哈希可靠 —— 进程内存里的代码
// 无从哈希。
func staleUnits() []string {
	var out []string
	for _, u := range []string{"loom-report", "loom-agent", "loom-publisher"} {
		if !unitExists(u) || activeState(u) != "active" {
			continue
		}
		pid, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", u).Output()
		if err != nil {
			continue
		}
		p := strings.TrimSpace(string(pid))
		if p == "" || p == "0" {
			continue
		}
		link, err := os.Readlink("/proc/" + p + "/exe")
		if err != nil {
			continue
		}
		if strings.HasSuffix(link, " (deleted)") {
			out = append(out, u)
		}
	}
	return out
}

// binarySHA 取快照里本平台那个二进制的 sha。没有就返回空串。
func binarySHA(man *snapshot.Manifest) string {
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			return man.Binaries[i].SHA256
		}
	}
	return ""
}

// contEnv 标记"我是被续跑起来的子进程"。
//
// 防的是无限套娃:正常情况下子进程看到二进制哈希已经对上,不会再换,
// 于是深度天然是 1。但**"正常情况"是个假设**,而这个假设错了的话
// 代价是 fork 炸弹。所以显式挡一道。
const contEnv = "LOOM_PULL_CONTINUATION"

// continuePull 用**刚装好的那个二进制**跑完这一轮剩下的活。
//
// # 为什么是子进程,不是 exec
//
// exec 把当前进程替换掉,而当前进程是唯一还知道"旧二进制在 .prev、
// 出事了怎么退回去"的东西。子进程留住了这个能力,代价只是一个进程。
//
// 父进程在这里等着,不做别的 —— 它存在的意义就是看着子进程的结果。
func continuePull(binPath string, args []string) error {
	if os.Getenv(contEnv) != "" {
		return fmt.Errorf("续跑的子进程又要换二进制 —— 这不该发生,停下来免得套娃")
	}
	fmt.Printf("  用新二进制续跑同一个快照(不等下一轮)\n")

	cmd := exec.Command(binPath, append([]string{"pull"}, args...)...)
	cmd.Env = append(os.Environ(), contEnv+"=1")
	cmd.Stdout, cmd.Stderr = prefixWriter{"  "}, prefixWriter{"  "}
	return cmd.Run()
}

// needsLock 说这一次 pull 要不要抢互斥锁。
//
// 续跑的子进程不抢:它不是"另一次 pull",而是同一次的后半段,父进程
// 正拿着锁在 wait。**抢的话会被自己的父进程挡在门外** —— D80 第一次
// 上真机就是这样,续跑变成一句空话:提示印了,活没干。
func needsLock() bool { return os.Getenv(contEnv) == "" }
