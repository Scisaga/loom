package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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
		"隧道没起来":  {Tunnels: []Tunnel{{Interface: "a", Down: true}}},
		"从未握手":   {Tunnels: []Tunnel{{Interface: "a", HandshakeAgeSec: -1}}},
		"握手陈旧":   {Tunnels: []Tunnel{{Interface: "a", HandshakeAgeSec: 900, Stale: true}}},
		"配置被改":   {Drift: &Drift{Checked: 1, Modified: []string{"/x"}}},
		"配置缺失":   {Drift: &Drift{Checked: 1, Missing: []string{"/x"}}},
		"配置读不到":  {Drift: &Drift{Checked: 1, Unreadable: []string{"/x"}}},
		"采集本身失败": {Errors: []string{"wg 跑不起来"}},
	}
	for name, st := range cases {
		if st.OK() {
			t.Errorf("%s 竟然算通过", name)
		}
	}
	good := Status{
		Tunnels: []Tunnel{{Interface: "a", HandshakeAgeSec: 30}},
		Drift:   &Drift{Checked: 5},
	}
	if !good.OK() {
		t.Error("一切正常却算不通过")
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
