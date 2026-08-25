// Package rollout 把"节点装一份新快照"这件事从**隐式状态机**变成显式的。
//
// # 现在的样子
//
// 阶段本来就存在:验签 → 换二进制 → 装配置 → 验证。但它们只是 pull 里的
// 一串注释,没有名字、不落盘、崩了就丢。两个后果:
//
//  1. **崩在半路等于失忆。** 装到一半断电,下一轮从头开始,而"上一次死在
//     哪一步"没人知道 —— 排障只能翻日志猜。
//  2. **"等下一个定时器"被当成了续跑机制。** 换完二进制主动 return,靠
//     10 分钟后的下一次 pull 接着装配置。安全原则("旧程序绝不处理新
//     schema")是对的,但拿定时器当 continuation,代价是二进制+配置一起
//     变时要 20 分钟才收敛。
//
// # 这个包做什么
//
// 只做一件事:**把阶段写下来**。它现在是观察者,不接管任何决策 ——
// 先跑几轮真实发布,确认记录的阶段和现实吻合,再让它接管控制流。
//
// 这样切换那一刻不是"新代码第一次上真机"。
package rollout

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Path 是节点上记录 rollout 状态的地方。
//
// 和 /var/lib/loom/applied 分开:applied 是**结果**(现在装着哪个),
// 这里是**过程**(正在往哪个走、走到哪一步了)。一台卡在 activating 的
// 机器,applied 仍是旧值 —— 两个都要有才说得清它的处境。
const Path = "/var/lib/loom/rollout.json"

// Stage 是一次 rollout 走到了哪一步。
type Stage string

const (
	// Staging:取产物、验签、比对哈希。**还没动这台机器上的任何东西。**
	// 死在这一步是安全的 —— 什么都没改。
	Staging Stage = "staging"

	// Activating:换二进制、装配置、重启服务。**这一步不是原子的**,
	// 死在这里的机器处于半装状态,正是最需要被看见的那种。
	Activating Stage = "activating"

	// Verifying:装完了,在确认隧道和服务真的起来了。
	Verifying Stage = "verifying"

	// Verified:这一份确实在跑。LastGood 会被推进到它。
	Verified Stage = "verified"

	// Failed:失败,Error 说为什么。LastGood 保持不动 —— 它是回退目标。
	Failed Stage = "failed"
)

// Record 是当前(或最近一次)rollout 的全部状态。
type Record struct {
	// Snapshot 是这次要装的那一份。
	Snapshot string `json:"snapshot"`
	// Binary 是这次要换成的二进制 sha。空表示这次不换二进制。
	Binary string `json:"binary,omitempty"`

	Stage     Stage  `json:"stage"`
	StartedAt string `json:"started_at"`
	// EnteredAt 是**进入当前阶段**的时刻。卡住多久要靠它算 ——
	// StartedAt 算的是整次 rollout,分不出卡在哪一步。
	EnteredAt string `json:"entered_at"`

	// LastGood 是最近一次 Verified 的快照,也就是**回退目标**。
	// 失败时它保持不动,这是它存在的全部意义。
	LastGood string `json:"last_good,omitempty"`

	Error string `json:"error,omitempty"`

	// Steps 记走过的每一步和耗时。排障时"哪一步慢"比"总共多久"有用。
	Steps []Step `json:"steps,omitempty"`
}

// Step 是一个已经走完的阶段。
type Step struct {
	Stage Stage  `json:"stage"`
	At    string `json:"at"`
	MS    int64  `json:"ms"`
}

// Read 读当前状态。文件不存在返回 (nil, nil) —— 那是"这台机器还没做过
// 任何 rollout",不是错误。
func Read(path string) (*Record, error) {
	// 空路径 = 明确关掉记录(dry-run 就是这么用的)。与 Write 对称,
	// **不要靠 os.ReadFile("") 恰好返回 ENOENT** —— 那是巧合不是契约。
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("解析 %s:%w", path, err)
	}
	return &r, nil
}

// Write 原子落盘。读的人要么看到完整的旧状态,要么看到完整的新状态。
func (r *Record) Write(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Begin 开一次新的 rollout。**LastGood 从上一条记录继承** ——
// 它是跨越多次 rollout 的东西,不能因为开了新的一轮就丢掉回退目标。
func Begin(prev *Record, snapshot, binary string, now time.Time) *Record {
	ts := now.UTC().Format(time.RFC3339)
	r := &Record{
		Snapshot: snapshot, Binary: binary,
		Stage: Staging, StartedAt: ts, EnteredAt: ts,
	}
	if prev != nil {
		r.LastGood = prev.LastGood
	}
	return r
}

// Enter 迁移到下一个阶段,并把上一个阶段的耗时记进 Steps。
func (r *Record) Enter(s Stage, now time.Time) {
	t := now.UTC()
	if prev, err := time.Parse(time.RFC3339, r.EnteredAt); err == nil {
		r.Steps = append(r.Steps, Step{Stage: r.Stage, At: r.EnteredAt, MS: t.Sub(prev).Milliseconds()})
	}
	r.Stage = s
	r.EnteredAt = t.Format(time.RFC3339)
	if s == Verified {
		// **只有 Verified 推进 LastGood。** 装上了不算,跑起来了才算 ——
		// 否则回退目标会指向一份装得上但跑不了的快照。
		r.LastGood = r.Snapshot
		r.Error = ""
	}
}

// Fail 记一次失败。**LastGood 不动** —— 它是回退目标。
func (r *Record) Fail(err error, now time.Time) {
	r.Enter(Failed, now)
	if err != nil {
		r.Error = err.Error()
	}
}

// InFlight 说这条记录是不是"还没走完"。
//
// Verified 和 Failed 都是终态;其余三个都意味着**有一次 rollout 停在半路**,
// 而 Activating 那种停法会留下半装的机器。
func (r *Record) InFlight() bool {
	switch r.Stage {
	case Verified, Failed:
		return false
	}
	return true
}

// Stuck 说这条记录是不是卡住了 —— 在同一个非终态阶段待得太久。
//
// 判据是**进入当前阶段有多久**,不是整次 rollout 多久:一次正常的
// 二进制升级本来就要走好几步,总时长长不说明问题,某一步长才说明。
func (r *Record) Stuck(now time.Time, limit time.Duration) bool {
	if !r.InFlight() {
		return false
	}
	t, err := time.Parse(time.RFC3339, r.EnteredAt)
	if err != nil {
		return false
	}
	return now.UTC().Sub(t) > limit
}
