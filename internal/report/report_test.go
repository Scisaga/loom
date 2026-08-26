package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"loom/internal/rollout"
)

// 上报接口没有自己的认证 —— 它靠 WireGuard 兜住。绑到公网地址上就等于
// 把拓扑和隧道健康白送,而且这种错误一旦发生不会有任何症状。
func TestRefusesPublicListenAddress(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:61802", "1.2.3.4:61802", "[::]:61802"} {
		b, _ := json.Marshal(Config{Node: "n", Listen: []string{addr}})
		if _, err := Load(b); err == nil {
			t.Errorf("监听 %s 竟然通过了校验", addr)
		}
	}
	for _, addr := range []string{"10.99.0.1:61802", "127.0.0.1:61802", "192.168.1.5:61802"} {
		b, _ := json.Marshal(Config{Node: "n", Listen: []string{addr}})
		if _, err := Load(b); err != nil {
			t.Errorf("监听 %s 被误拒:%v", addr, err)
		}
	}
	// 主机部分不是 IP 就无法判断它指向哪 —— 宁可拒绝。
	b, _ := json.Marshal(Config{Node: "n", Listen: []string{"example.com:61802"}})
	if _, err := Load(b); err == nil {
		t.Error("域名形式的监听地址竟然通过了校验")
	}
}

// down / 陈旧 / 漂移都必须让自检不通过。漏掉任何一个,退出码就会说"没事"。
func TestOKCoversEveryFailureKind(t *testing.T) {
	cases := map[string]Status{
		"隧道没起来":        {Tunnels: []Tunnel{{Interface: "a", Down: true}}},
		"从未握手":         {Tunnels: []Tunnel{{Interface: "a", HandshakeAgeSec: -1}}},
		"握手陈旧":         {Tunnels: []Tunnel{{Interface: "a", HandshakeAgeSec: 900, Stale: true}}},
		"配置被改":         {Drift: &Drift{Checked: 1, Modified: []string{"/x"}}},
		"配置缺失":         {Drift: &Drift{Checked: 1, Missing: []string{"/x"}}},
		"配置读不到":        {Drift: &Drift{Checked: 1, Unreadable: []string{"/x"}}},
		"采集本身失败":       {Errors: []string{"wg 跑不起来"}},
		"rollout 失败":   {Rollout: &RolloutState{Stage: string(rollout.Failed)}},
		"rollout 卡住":   {Rollout: &RolloutState{Stage: string(rollout.Activating), EnteredAt: "2026-08-26T10:00:00Z"}},
		"rollout 时间损坏": {Rollout: &RolloutState{Stage: string(rollout.Activating), EnteredAt: "坏时间"}},
	}
	for name, st := range cases {
		if st.OKAt(time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("%s 竟然算通过", name)
		}
	}
	good := Status{
		Tunnels: []Tunnel{{Interface: "a", HandshakeAgeSec: 30, UnitState: "active"}},
		Drift:   &Drift{Checked: 5},
	}
	if !good.OK() {
		t.Error("一切正常却算不通过")
	}
}

func TestRecentInFlightRolloutIsHealthy(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	st := Status{Rollout: &RolloutState{
		Stage: string(rollout.Activating), EnteredAt: now.Add(-time.Minute).Format(time.RFC3339),
	}}
	if !st.OKAt(now) {
		t.Error("刚进入 activating 是正常过渡态，不应误报")
	}
}

func TestOnlyFailedUplinkTargetAffectsHealth(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	normalFailure := Status{Observation: &Observation{Targets: []Reach{{
		Target: "https://blocked.example/", Error: "timeout", Samples: 5, Failures: 5,
	}}}}
	if !normalFailure.OKAt(now) {
		t.Fatal("普通 Target 失败是给 Agent 的路径数据，不应把节点判成不健康")
	}
	uplinkFailure := normalFailure
	uplinkFailure.Observation = &Observation{Targets: []Reach{{
		Target: "https://uplink.example/", Error: "timeout", Samples: 5, Failures: 5, Uplink: true,
	}}}
	if uplinkFailure.OKAt(now) {
		t.Fatal("本机 Uplink 全部失败却仍被判成健康")
	}
	uplinkOK := Status{Observation: &Observation{Targets: []Reach{{
		Target: "https://uplink.example/", FirstByteMs: 12, Samples: 5, Uplink: true,
	}}}}
	if !uplinkOK.OKAt(now) {
		t.Fatal("可达的 Uplink 被误判成不健康")
	}
}

func TestDecommissionedRolloutIsTerminalAndNotAHealthFailure(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	r := &RolloutState{Stage: string(rollout.Decommissioned), EnteredAt: now.Add(-24 * time.Hour).Format(time.RFC3339)}
	if r.InFlight() {
		t.Fatal("decommissioned 不应按卡住处理")
	}
	if !(&Status{Rollout: r}).OKAt(now) {
		t.Fatal("有意下线终态本身不是 rollout 故障")
	}
}

// 机器上可能有与 Loom 无关的 WireGuard 接口(access-a 上就有一个 wg5)。
// 把它们算进来,别人的接口一断这台机器就整体报不健康。
func TestOnlyReportsConfiguredInterfaces(t *testing.T) {
	cfg := &Config{Node: "n", Interfaces: []string{"wg-a", "wg-b"}}
	st := Collect(cfg, time.Now())
	if len(st.Tunnels) != 2 {
		t.Fatalf("报了 %d 个接口,配置里只有 2 个:%+v", len(st.Tunnels), st.Tunnels)
	}
	// 这台机器上没有 wg-a / wg-b,必须报 down 而不是从表里消失 ——
	// 隧道没起来正是最该被看见的状态。
	for i := range st.Tunnels {
		if !st.Tunnels[i].Down {
			t.Errorf("%s 不存在却没报 down", st.Tunnels[i].Interface)
		}
	}
	if st.OK() {
		t.Error("两条隧道都没起来,自检却算通过")
	}
}

func TestStaleThresholdParsing(t *testing.T) {
	if _, err := Load([]byte(`{"node":"n","handshake_stale":"1z"}`)); err == nil {
		t.Error("非法的 handshake_stale 通过了")
	}
	if _, err := Load([]byte(`{"node":"n","handshake_stale":"-5m"}`)); err == nil {
		t.Error("负的 handshake_stale 通过了")
	}
	c, err := Load([]byte(`{"node":"n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := c.Stale(); d != 5*time.Minute {
		t.Errorf("默认阈值是 %v,期望 5m", d)
	}
}

func TestLoadRequiresNode(t *testing.T) {
	if _, err := Load([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "node") {
		t.Errorf("缺 node 时的报错不对:%v", err)
	}
}

// **可达性检查必须走自带 DNS,不能用系统解析器。**
//
// 这是上线之后当场踩到的:jm24 的 systemd-resolved 上游是 8.8.8.8(大陆
// 被污染),于是上报者报"够不到 baidu",而同一台机器换 223.5.5.5 解析后
// 直连是 200/59ms。
//
// 症状特别误导 —— 它长得像"这台机器出网坏了",而真实流量一直好着
// (sing-box 自己配了 DNS)。`internal/netx` 存在的全部理由就是不依赖
// 机器全局设置,而量可达性的这个函数偏偏没用它。
func TestReachTargetUsesConfiguredDNS(t *testing.T) {
	// 给一个只有本机才解析得出的名字,配一个不存在的解析器:
	// 走系统解析器可能歪打正着,走配置的解析器必然失败。
	_, err := reachTarget("https://nx.invalid.example/", "203.0.113.253:53", 2*time.Second)
	if err == nil {
		t.Fatal("配了一个不可用的解析器,却仍然解析成功了 —— 说明没走配置的 DNS")
	}
}

// 没配解析器时退回系统的 —— 不是每个节点都必须配,而空字符串不该让
// netx 崩掉。
func TestReachTargetToleratesEmptyDNS(t *testing.T) {
	if _, err := reachTarget("https://nx.invalid.example/", "", 2*time.Second); err == nil {
		t.Error("不存在的名字竟然解析成功了")
	}
}

// 只取第一个解析器:netx 只收一个,而"用哪个解析器测的"含糊掉之后,
// 一个不一致的结果就无从解释。
func TestFirstDNS(t *testing.T) {
	if got := firstDNS([]string{"223.5.5.5", "119.29.29.29"}); got != "223.5.5.5" {
		t.Errorf("取了 %q", got)
	}
	if got := firstDNS(nil); got != "" {
		t.Errorf("空列表该返回空,得到 %q", got)
	}
}
