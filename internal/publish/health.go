//go:build !windows

package publish

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	"loom/internal/version"
)

// HealthPath 是发布器写自己状态的地方。
//
// 放在中控本地,不进分发树 —— 它是关于**这个进程**的事实,不是配置。
const HealthPath = "/var/lib/loom/publisher.json"

// Health 是发布器**对外可见的自己**。
//
// # 为什么需要它
//
// 2026-08-24 发布器连续 2 小时 17 分发不出任何东西,而 `systemctl status`
// 全程是 `active (running)`。**进程活着不等于功能活着**,而当时没有任何
// 地方能区分这两件事 —— 要发现它得去翻 journal,而没人会去翻一个显示
// 正常的服务的日志。
//
// 版本坐标(D69)也没覆盖到它:`loom report` 报的是**跑 report 那个二进制**
// 的 commit,而发布器是另一个进程,可能还持着被换掉的旧 inode。
//
// # 两条设计约束
//
//  1. **LastError 不随成功清空。** 清了的话,一次成功就把"刚才卡了两小时"
//     抹掉了。要看的是"上次成功是什么时候",而不是"此刻这一轮有没有报错"。
//  2. **LastSuccess 是绝对时间,不是"多久以前"。** 后者要读的人心算,
//     而且跨重启就不准了。
type Health struct {
	Version version.Coordinate `json:"version"`
	PID     int                `json:"pid"`

	StartedAt string `json:"started_at"`
	UpdatedAt string `json:"updated_at"`
	// IntervalSeconds 让读者按发布器自己的循环周期判断心跳是否过期。
	// 老状态没有这个字段时使用保守的两分钟阈值。
	IntervalSeconds int64 `json:"interval_seconds,omitempty"`

	// LastSuccess 是最近一次**真的发出去**的时刻。
	LastSuccess  string `json:"last_success,omitempty"`
	LastSnapshot string `json:"last_snapshot,omitempty"`
	LastSSOT     string `json:"last_ssot,omitempty"`

	// LastError 是最近一次失败,**成功不清空**(见类型注释)。
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt string `json:"last_error_at,omitempty"`

	// DistributionChecks are exact, per-URL VerifyServed results for the most
	// recent publish attempt. Enrollment consumes only successful checks bound
	// to the same snapshot and SSOT; aggregate publisher health is insufficient.
	DistributionChecks []DistributionCheck `json:"distribution_checks,omitempty"`
}

type DistributionCheck struct {
	URL       string `json:"url"`
	Snapshot  string `json:"snapshot"`
	SSOT      string `json:"ssot"`
	CheckedAt string `json:"checked_at"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// Write 原子写:先写临时文件再 rename。读的人要么看到旧的完整版本,
// 要么看到新的完整版本,不会读到写了一半的。
func (h *Health) Write(path string) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o644)
}

// ReadHealth 读回发布器状态。文件不存在返回 (nil, nil) —— 那是"发布器
// 没在这台机器上跑",不是错误。
func ReadHealth(path string) (*Health, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h Health
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("解析 %s:%w", path, err)
	}
	return &h, nil
}

// Findings 是这份状态里**要让人看见**的东西,返回给调用方去印。
//
// # 判据是"上次成功之后又失败了",不是"很久没成功"
//
// 发布器只在 SSOT 变了(或分发点分叉)时才发布。一周不改 SSOT 就一周不发,
// 那是完全正常的 —— 拿"距上次成功多久"当告警会天天误报,而误报的面板
// 等于没有面板(D64–D67)。
//
// 昨天那次故障的真正形状是:**19:43 成功过一次,之后每一次都失败,
// 而进程一直 active**。所以判据是 LastErrorAt 比 LastSuccess 新 ——
// 它同时覆盖了"发不出去"和"没人注意到",而且 SSOT 不变时不会响。
func (h *Health) Findings(now time.Time) (lines []string, bad bool) {
	add := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }

	add("  发布器 %s · pid %d", h.Version.Line(), h.PID)

	// UpdatedAt 是活性信号,LastSuccess 是功能结果。只看后者会把“一周没改
	// 配置”误报；只看前者则会让进程死亡后遗留的 JSON 永久假绿。阈值取
	// max(2 分钟,3 个循环),既容得下调度抖动,又能及时发现默认 30 秒发布器。
	staleAfter := 2 * time.Minute
	if h.IntervalSeconds > 0 {
		if d := 3 * time.Duration(h.IntervalSeconds) * time.Second; d > staleAfter {
			staleAfter = d
		}
	}
	if h.UpdatedAt == "" {
		add("  ⚠️ 发布器没有心跳时间(UpdatedAt),无法证明进程仍在工作")
		bad = true
	} else if t, err := time.Parse(time.RFC3339, h.UpdatedAt); err != nil {
		add("  ⚠️ 发布器心跳时间无效:%q", h.UpdatedAt)
		bad = true
	} else if age := now.Sub(t); age > staleAfter {
		add("  ⚠️ 发布器心跳已过期:%s(%s 前;阈值 %s)", h.UpdatedAt, roughAge(age), staleAfter)
		bad = true
	} else if age < -time.Minute {
		add("  ⚠️ 发布器心跳来自未来:%s(本机时钟可能漂移)", h.UpdatedAt)
		bad = true
	}

	// 心跳最长要等阈值才暴露；PID 已经消失时可以立即报。kill(pid, 0) 不
	// 发送信号,EPERM 也表示进程存在。PID 复用无法单靠数字解决,所以它只是
	// 心跳的补充,不是替代。
	switch {
	case h.PID <= 0:
		add("  ⚠️ 发布器 PID 无效:%d", h.PID)
		bad = true
	case syscall.Kill(h.PID, 0) == syscall.ESRCH:
		add("  ⚠️ 发布器进程 pid %d 已不存在(状态文件是遗留物)", h.PID)
		bad = true
	}

	if h.LastSuccess == "" {
		add("  ⚠️ 启动以来**一次都没发布成功过**")
		if h.LastError != "" {
			add("     最近一次失败(%s):%s", h.LastErrorAt, h.LastError)
		}
		return lines, true
	}

	if t, err := time.Parse(time.RFC3339, h.LastSuccess); err == nil {
		add("  上次成功 %s(%s 前),快照 %s",
			h.LastSuccess, roughAge(now.Sub(t)), version.Short(h.LastSnapshot))
	} else {
		add("  上次成功 %s,快照 %s", h.LastSuccess, version.Short(h.LastSnapshot))
	}

	// 不做字符串比较:RFC3339Nano 的小数秒是变长的,"...00.1Z" 与
	// "...00Z" 的字典序不等于时间序。解析后比较也避免“同一秒先成功后
	// 失败”被秒级时间戳吞掉而假绿。
	failureIsCurrent := false
	if h.LastError != "" {
		failedAt, ferr := time.Parse(time.RFC3339, h.LastErrorAt)
		succeededAt, serr := time.Parse(time.RFC3339, h.LastSuccess)
		if ferr != nil || serr != nil {
			add("  ⚠️ 发布器成功/失败时间无效(last_success=%q,last_error_at=%q)",
				h.LastSuccess, h.LastErrorAt)
			bad = true
		} else {
			failureIsCurrent = failedAt.After(succeededAt)
		}
	}
	if h.LastError != "" && failureIsCurrent {
		add("  ⚠️ 自那之后一直发不出去(最近 %s):%s", h.LastErrorAt, h.LastError)
		add("     **进程 active 不代表功能活着** —— 后续每一次 SSOT 改动都不会生效")
		return lines, true
	}
	if h.LastError != "" {
		// 已经恢复了,但历史留着:知道它出过什么事有价值,只是别报成告警。
		add("  (曾经失败过 %s:%s —— 之后已恢复)", h.LastErrorAt, h.LastError)
	}
	return lines, bad
}

func roughAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d 小时 %d 分", int(d.Hours()), int(d.Minutes())%60)
	}
}
