package publish

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	// LastSuccess 是最近一次**真的发出去**的时刻。
	LastSuccess  string `json:"last_success,omitempty"`
	LastSnapshot string `json:"last_snapshot,omitempty"`
	LastSSOT     string `json:"last_ssot,omitempty"`

	// LastError 是最近一次失败,**成功不清空**(见类型注释)。
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt string `json:"last_error_at,omitempty"`
}

// Write 原子写:先写临时文件再 rename。读的人要么看到旧的完整版本,
// 要么看到新的完整版本,不会读到写了一半的。
func (h *Health) Write(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

	// 字符串比较对 RFC3339 是可行的:同一时区、定长、字典序即时间序。
	// 发布器写这两个字段时都用 UTC。
	if h.LastError != "" && h.LastErrorAt > h.LastSuccess {
		add("  ⚠️ 自那之后一直发不出去(最近 %s):%s", h.LastErrorAt, h.LastError)
		add("     **进程 active 不代表功能活着** —— 后续每一次 SSOT 改动都不会生效")
		return lines, true
	}
	if h.LastError != "" {
		// 已经恢复了,但历史留着:知道它出过什么事有价值,只是别报成告警。
		add("  (曾经失败过 %s:%s —— 之后已恢复)", h.LastErrorAt, h.LastError)
	}
	return lines, false
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
