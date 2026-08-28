// Package report 是节点上的**上报者**。
//
// 它和 Agent 是两个角色,别混:
//
//	决策者(internal/agent)  排序、切 selector。每个接入节点恰好一个 ——
//	                         多一个就是两个互不知情的决策者(D11)。
//	上报者(本包)            观测、自检、如实说。每个节点都该有,服务器也是。
//
// 上报者**不做任何决定**,也不碰 selector。它只回答两个问题:隧道还活着吗、
// 机器上的配置还是渲染出来的那份吗。
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/rollout"
	"loom/internal/version"
)

// Status 是一次自检的全部结果。字段顺序即 JSON 顺序 —— 人要直接读它。
type Status struct {
	Node string `json:"node"`
	TS   string `json:"ts"`

	// Applied 是本机当前装着的快照 id(§14.2)。
	//
	// 有它才能一眼看出全网是不是同一版。没有的话,"某台机器落后了一个版本"
	// 这件事只能靠逐台 ssh 去查 —— 而落后的那台往往正是出问题的那台。
	Applied string `json:"applied,omitempty"`

	// Version 是这台机器上二进制的坐标(commit + 二进制哈希)。
	//
	// 有它,"远端跑的是哪一版源码"才答得上来 —— 以前只能报一串二进制
	// 哈希,而哈希对不回 git。它和 Applied 是一对:Applied 说配置是哪
	// 一版,Version 说读这份配置的程序是哪一版。**两者错配正是发布器
	// 崩掉的那类故障**(旧二进制读不懂新字段,§15.4)。
	Version *version.Coordinate `json:"version,omitempty"`

	// Rollout 是这台机器**正在往哪个快照走、走到哪一步了**(D78)。
	//
	// 和 Applied 是一对:Applied 说现在装着哪个(结果),Rollout 说过程。
	// 一台卡在 activating 的机器 Applied 仍是旧值 —— 只看 Applied 会
	// 以为它一切正常,只是"还没轮到它"。
	Rollout *RolloutState `json:"rollout,omitempty"`

	// Agent 是本机 Agent 从 sing-box selector 读到的实际选择。服务器节点
	// 没有 Agent，字段为空是正常形态。
	Agent *AgentState `json:"agent,omitempty"`

	// Components 是节点实际执行版本命令得到的结果，并与渲染配置中的期望
	// 并排保存。manifest 里的期望值本身不能证明机器已经安装了该版本。
	Components []ComponentStatus `json:"components,omitempty"`

	// Publisher 只在中控节点出现，与 /status 和 HTML 同源。
	Publisher *PublisherState `json:"publisher,omitempty"`

	Tunnels []Tunnel `json:"tunnels"`
	Drift   *Drift   `json:"drift,omitempty"`

	// Observation 是本节点自己量到的东西(到邻居的 RTT、到各目标的可达性)。
	Observation *Observation `json:"observation,omitempty"`
	// Learned 是从邻居那里听来的别人的观测,原样转述。
	Learned []Observation `json:"learned,omitempty"`

	// Rotating 是本机正在同时接受两代的凭据(§13.4)。
	//
	// **过渡窗口是过渡态,不是稳态。** 忘了做第二步的话旧凭据永远有效,
	// 而轮换的全部意义就是让旧的失效。这个状态会进事件历史,于是"开了
	// 三天还没关"变成一条持续中的记录,而不是没人知道的事。
	Rotating []string `json:"rotating,omitempty"`

	// Errors 是采集过程本身的失败。**采集不到与"一切正常"必须分得开** ——
	// 空的 Tunnels 既可能是没有隧道,也可能是 wg 命令跑不起来。
	Errors []string `json:"errors,omitempty"`
}

// Tunnel 是一条隧道在本节点看到的样子。
type Tunnel struct {
	Interface string `json:"interface"`
	// InterfacePresent / PeerPresent record what the single `wg dump` snapshot
	// actually contained. In particular, a peer whose latest-handshake field is
	// zero still exists; zero means "never handshook", not "interface down".
	InterfacePresent bool `json:"interface_present,omitempty"`
	PeerPresent      bool `json:"peer_present,omitempty"`
	// Down 表示这个接口在 `wg show` 里根本不存在 —— 隧道没起来。
	// 它和"握手很旧"是两种故障,排障动作也不同,不能合并成一个字段。
	Down bool `json:"down,omitempty"`
	// UnitState 是 wg-quick@<iface> 的状态。
	//
	// **只看接口在不在会漏掉一整类故障。** wg-quick 的 restart 有 down/up
	// 竞态,失败后 unit 停在 failed 而接口还在 —— 隧道照常工作,直到下次
	// 重启机器它不会自己起来。cn-a 和 cn-b 都被这样留过。
	UnitState string `json:"unit_state,omitempty"`
	// HandshakeAgeSec 是距上次握手的秒数。-1 表示接口在但从未握手过。
	HandshakeAgeSec int64 `json:"handshake_age_sec"`
	// Stale 表示握手年龄超过阈值。发起方设了 PersistentKeepalive=25,
	// 健康的隧道握手年龄不会超过约 180 秒。
	Stale bool  `json:"stale"`
	RxByt int64 `json:"rx_bytes"`
	TxByt int64 `json:"tx_bytes"`
}

// Drift 是配置自检的结果。
type Drift struct {
	Checked  int      `json:"checked"`
	Modified []string `json:"modified,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	// Unreadable 与 Modified 分开:读不到不等于被改了,但同样不能当作没事。
	Unreadable []string `json:"unreadable,omitempty"`
}

// OK 报告这次自检有没有发现问题。
func (s *Status) OK() bool {
	return s.OKAt(time.Now().UTC())
}

// RolloutStuckAfter 是 rollout 在同一阶段停留多久后影响健康状态。
// 它与 status 汇总、事件和 HTML 共用，避免三个入口各自发明阈值。
const RolloutStuckAfter = 10 * time.Minute

// OKAt 是可测试的健康判定。Failed、时间戳损坏和阶段超时都必须失败；
// 否则 /status 会在 rollout 已经躺住时仍返回 200。
func (s *Status) OKAt(now time.Time) bool {
	if len(s.Errors) > 0 {
		return false
	}
	if s.Rollout != nil {
		if s.Rollout.Stage == string(rollout.Failed) {
			return false
		}
		if s.Rollout.InFlight() {
			d, ok := s.Rollout.StuckFor(now)
			if !ok || d > RolloutStuckAfter {
				return false
			}
		}
	}
	if s.Publisher != nil {
		if s.Publisher.Unhealthy(now) {
			return false
		}
	}
	for i := range s.Components {
		if !s.Components[i].OK() {
			return false
		}
	}
	if s.Agent != nil {
		for i := range s.Agent.Selections {
			h := s.Agent.Selections[i].Health
			// 只有“所有候选近期都明确失败”才把节点判红。全 unknown/stale
			// 表示证据不足，由界面显示未知，不能冒充已确认故障。
			if h != nil && h.Candidates > 0 && h.RecentFailed == h.Candidates {
				return false
			}
		}
	}
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		if t.Down || t.Stale || t.HandshakeAgeSec < 0 {
			return false
		}
		// 接口在、握手也新,但 unit 不是 active —— 重启机器它就不回来了。
		if t.UnitState != "" && t.UnitState != "active" {
			return false
		}
	}
	if d := s.Drift; d != nil && (len(d.Modified) > 0 || len(d.Missing) > 0 || len(d.Unreadable) > 0) {
		return false
	}
	if s.Observation != nil {
		for i := range s.Observation.Targets {
			r := &s.Observation.Targets[i]
			// 普通 Target 是给 Agent 剪枝的测量数据：某个出口按设计可能
			// 到不了它。只有 Uplink 才表达“本机本该够得到”，其失败必须
			// 影响 /status 与界面的节点健康，不能只躺在明细里。
			if r.Uplink && !r.OK() {
				return false
			}
		}
	}
	return true
}

// Collect 采集一次状态。now 由调用方注入,便于测试。
// RolloutState 是 rollout 记录的**转述用形式**:够回答"它卡住了吗、
// 卡在哪一步",但不带 Steps —— 那是本机排障用的,转述出去只是噪音。
type RolloutState struct {
	Snapshot  string `json:"snapshot"`
	Stage     string `json:"stage"`
	EnteredAt string `json:"entered_at"`
	LastGood  string `json:"last_good,omitempty"`
	Error     string `json:"error,omitempty"`
}

// AgentState / AgentSelection 是转述用的实际选路状态。TS 是 Agent 最后一次
// 成功读取 selector 的时间，不是 report 转述它的时间。
type AgentState struct {
	Node string `json:"node"`
	TS   string `json:"ts"`
	// ComponentVersion 保留既有 JSON 名称，承载的是 Agent 线协议版本；
	// 它不能替代运行中 Agent 进程的 commit/binary 构建坐标。
	ComponentVersion string           `json:"component_version,omitempty"`
	Selections       []AgentSelection `json:"selections"`
}

type AgentSelection struct {
	Declaration string                `json:"declaration"`
	Selector    string                `json:"selector"`
	Candidate   string                `json:"candidate"`
	Chain       []string              `json:"chain,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	UpdatedAt   string                `json:"updated_at"`
	Health      *AgentCandidateHealth `json:"health,omitempty"`
}

// AgentCandidateHealth 与 internal/agent.CandidateHealth 共用线格式。
// report 不能 import agent（agent 已经依赖 report），因此在边界处显式镜像。
// 字段可选以兼容尚未完成滚动升级的旧 Agent。
type AgentCandidateHealth struct {
	Candidates       int    `json:"candidates"`
	RecentSuccess    int    `json:"recent_success"`
	RecentDegraded   int    `json:"recent_degraded,omitempty"`
	RecentFailed     int    `json:"recent_failed"`
	Stale            int    `json:"stale"`
	Unknown          int    `json:"unknown"`
	SelectedState    string `json:"selected_state"`
	SelectedSamples  int    `json:"selected_samples,omitempty"`
	SelectedFailures int    `json:"selected_failures,omitempty"`
	SelectedP50MS    *int   `json:"selected_p50_ms,omitempty"`
	SelectedP95MS    *int   `json:"selected_p95_ms,omitempty"`
	BestP50MS        *int   `json:"best_p50_ms,omitempty"`
	SelectedKBps     *int   `json:"selected_kbps,omitempty"`
	BestKBps         *int   `json:"best_kbps,omitempty"`
}

// InFlight 说这次 rollout 还没走完。Verified / Decommissioned / Failed
// 都是终态；下线成功不能被报成永远卡在 staging。
func (r *RolloutState) InFlight() bool {
	return r != nil && r.Stage != string(rollout.Verified) &&
		r.Stage != string(rollout.Decommissioned) && r.Stage != string(rollout.Failed)
}

// StuckFor 返回它在当前阶段待了多久。解析不出时间返回 0 ——
// **不要猜**,算不出来就说算不出来,别拿 0 冒充"刚进来"。
func (r *RolloutState) StuckFor(now time.Time) (time.Duration, bool) {
	if r == nil {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, r.EnteredAt)
	if err != nil {
		return 0, false
	}
	return now.UTC().Sub(t), true
}

func Collect(cfg *Config, now time.Time) *Status {
	_, stats, errs := readWGSnapshot()
	return collectWithWGStats(cfg, now, stats, errs)
}

// collectWithWGStats lets one observation round reuse a single WireGuard dump
// for both carrier health and the separately signed traffic attachment. Two
// back-to-back commands can otherwise describe different interface lifetimes
// and double the most frequent privileged subprocess work.
func collectWithWGStats(cfg *Config, now time.Time, stats map[string]wgInterfaceStats, wgErrors []string) *Status {
	st := &Status{Node: cfg.Node, TS: now.UTC().Format(time.RFC3339)}
	vc := version.Self()
	st.Version = &vc
	if b, err := os.ReadFile(appliedPath); err == nil {
		st.Applied = strings.TrimSpace(string(b))
	}
	if r, err := rollout.Read(rollout.Path); err != nil {
		st.Errors = append(st.Errors, "读 rollout 状态:"+err.Error())
	} else if r != nil {
		st.Rollout = &RolloutState{
			Snapshot: r.Snapshot, Stage: string(r.Stage),
			EnteredAt: r.EnteredAt, LastGood: r.LastGood, Error: r.Error,
		}
	}
	if a, err := readAgentState(cfg.AgentState); err != nil {
		st.Errors = append(st.Errors, "读 Agent 当前选择:"+err.Error())
	} else if cfg.AgentState != "" && a == nil {
		st.Errors = append(st.Errors, "Agent 当前选择状态不存在")
	} else {
		st.Agent = a
		st.Errors = append(st.Errors, validateAgentStateForConfig(a, cfg, now)...)
	}
	st.Components = componentStatuses(cfg, st.Agent, now)
	if cfg.PublisherHealth != "" {
		if h, err := readPublisherState(cfg.PublisherHealth); err != nil {
			st.Errors = append(st.Errors, "读发布器状态:"+err.Error())
		} else if h == nil {
			st.Errors = append(st.Errors, "发布器状态不存在")
		} else {
			st.Publisher = h
		}
	}
	stale, err := cfg.Stale()
	if err != nil {
		st.Errors = append(st.Errors, err.Error())
		stale = 5 * time.Minute
	}

	st.Errors = append(st.Errors, wgErrors...)
	// 只看配置里列出的接口 —— 机器上别的 WireGuard 接口不归 Loom 管。
	ifaces := append([]string(nil), cfg.Interfaces...)
	sort.Strings(ifaces)
	for _, i := range ifaces {
		t := Tunnel{Interface: i, HandshakeAgeSec: -1}
		t.UnitState = unitState("wg-quick@" + i)
		stat := stats[i]
		t.InterfacePresent = stat.InterfacePresent
		t.PeerPresent = stat.PeerPresent
		if !stat.InterfacePresent {
			t.Down = true
			st.Tunnels = append(st.Tunnels, t)
			continue
		}
		if stat.LatestHandshake > 0 {
			t.HandshakeAgeSec = now.Unix() - stat.LatestHandshake
			t.Stale = time.Duration(t.HandshakeAgeSec)*time.Second > stale
		}
		t.RxByt, t.TxByt = stat.RXBytes, stat.TXBytes
		st.Tunnels = append(st.Tunnels, t)
	}

	st.Rotating = rotatingCreds(singBoxConfigPath)

	if cfg.Manifest != "" {
		d, err := checkDrift(cfg.Manifest)
		if err != nil {
			st.Errors = append(st.Errors, "配置自检:"+err.Error())
		} else {
			st.Drift = d
		}
	}
	return st
}

// wgStats 读 wg 的握手时间与收发字节。
//
// 用 `wg show all dump` 而不是逐个 interface 查:一次调用拿全,不会在两次
// 调用之间因为接口起落而拿到自相矛盾的快照。
type wgInterfaceStats struct {
	InterfacePresent bool
	PeerPresent      bool
	LatestHandshake  int64
	RXBytes          int64
	TXBytes          int64
}

func readWGSnapshot() ([]byte, map[string]wgInterfaceStats, []string) {
	out, err := exec.Command("wg", "show", "all", "dump").Output()
	if err != nil {
		return nil, map[string]wgInterfaceStats{}, []string{"wg show all dump 失败:" + errText(err)}
	}
	stats, errs := parseWGStats(out)
	return out, stats, errs
}

func parseWGStats(out []byte) (map[string]wgInterfaceStats, []string) {
	stats := map[string]wgInterfaceStats{}
	var errs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		// dump 格式:接口自身一行 5 列,之后每个 peer 一行 9 列。
		// peer 行:iface pubkey psk endpoint allowed-ips handshake rx tx keepalive
		if len(f) == 5 && f[0] != "" {
			stat := stats[f[0]]
			stat.InterfacePresent = true
			stats[f[0]] = stat
			continue
		}
		if len(f) < 9 {
			continue
		}
		iface := f[0]
		stat := stats[iface]
		// A peer row is also positive interface evidence. Keeping these booleans
		// independent from LatestHandshake is what preserves handshake=0.
		stat.InterfacePresent = true
		stat.PeerPresent = true
		h, err1 := strconv.ParseInt(f[5], 10, 64)
		rx, err2 := strconv.ParseInt(f[6], 10, 64)
		tx, err3 := strconv.ParseInt(f[7], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || h < 0 || rx < 0 || tx < 0 {
			errs = append(errs, "无法解析 wg dump 的一行:"+iface)
			stats[iface] = stat
			continue
		}
		// 一条隧道一个接口(D1),但接口理论上可以有多个 peer:取最近的握手,
		// 收发字节相加。
		if h > stat.LatestHandshake {
			stat.LatestHandshake = h
		}
		stat.RXBytes = saturatingCounterAdd(stat.RXBytes, rx)
		stat.TXBytes = saturatingCounterAdd(stat.TXBytes, tx)
		stats[iface] = stat
	}
	return stats, errs
}

const maxCounterValue int64 = 1<<63 - 1

func saturatingCounterAdd(total, value int64) int64 {
	if total < 0 {
		total = 0
	}
	if value < 0 {
		value = 0
	}
	if value > maxCounterValue-total {
		return maxCounterValue
	}
	return total + value
}

func errText(err error) string {
	if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
		return strings.TrimSpace(string(ee.Stderr))
	}
	return err.Error()
}

// checkDrift 按清单逐个文件比对哈希。
//
// 清单由 loom hydrate 产出 —— 它是最后一个知道文件最终字节的环节(渲染层
// 只有占位符)。清单里只有哈希,不含秘密。
func checkDrift(manifestPath string) (*Drift, error) {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	d := &Drift{}
	paths := make([]string, 0, len(m.Files))
	for p := range m.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		d.Checked++
		body, err := os.ReadFile(p)
		switch {
		case os.IsNotExist(err):
			d.Missing = append(d.Missing, p)
		case err != nil:
			d.Unreadable = append(d.Unreadable, fmt.Sprintf("%s(%v)", p, err))
		default:
			h := sha256.Sum256(body)
			if hex.EncodeToString(h[:]) != m.Files[p] {
				d.Modified = append(d.Modified, p)
			}
		}
	}
	return d, nil
}

// appliedPath 是 loom pull 记录当前快照 id 的地方。
const appliedPath = "/var/lib/loom/applied"

// Manifest 是 loom hydrate 产出的清单:机器上的绝对路径 → 内容哈希。
type Manifest struct {
	Node  string            `json:"node"`
	Files map[string]string `json:"files"`
}

// unitState 读一个 systemd 单元的状态。读不到时返回空字符串,由调用方当作
// "不知道"处理 —— 把未知当成故障会在没有 systemd 的环境里全线报警。
func unitState(name string) string {
	out, err := exec.Command("systemctl", "is-active", name).Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// singBoxConfigPath 是本机 sing-box 配置的位置(与 render.InstallPath 一致)。
const singBoxConfigPath = "/etc/loom/sing-box/config.json"

// rotatingCreds 从本机 sing-box 配置里找出正在过渡窗口里的凭据。
//
// 判据是 inbound 里出现了 `<id>@<代次>` 形式的 user —— 那是上一代,只有
// 开着过渡窗口才会渲染出来。读本机配置而不是 SSOT:节点上没有 SSOT,
// 也不该有。
func rotatingCreds(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil // 不是每台机器都有 inbound
	}
	var cfg struct {
		Inbounds []struct {
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, in := range cfg.Inbounds {
		for _, u := range in.Users {
			id, _, ok := strings.Cut(u.Name, "@")
			if !ok || id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
