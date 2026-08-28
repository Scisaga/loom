package webui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)

func deps(op string, acts map[string]func() (string, error)) Deps {
	return Deps{
		Node: "n1", Operator: op, Actions: acts,
		Now: func() time.Time { return at },
		Snapshot: func() View {
			return View{Self: "n1", IntentSource: "serving node applied inventory", Nodes: []NodeView{
				{ID: "n1", Declared: true, Self: true, Reached: true, Applied: "abc123",
					Tunnels: []TunnelView{{Interface: "wg-a", CarrierPresent: true, State: "active", AgeSec: 30, CounterPresent: true, OK: true}},
					Targets: []TargetView{{Target: "https://t/", MS: 100}}},
				{ID: "n2", Declared: true, Applied: "abc123",
					Targets: []TargetView{{Target: "https://t/", Err: `Get "https://t/": dial tcp 1.2.3.4:443: connect: connection refused`}}},
			}}
		},
	}
}

func get(t *testing.T, h http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// 页面里不能有任何外部资源。这些机器不一定能出网,通过 ssh 端口转发进来时
// 更不能 —— 一个依赖 CDN 的界面在最需要它的时候恰好打不开。
func TestPageIsSelfContained(t *testing.T) {
	body := get(t, Handler(deps("", nil)), "/", nil).Body.String()
	for _, bad := range []string{"http://", "https://cdn", "<script", "src="} {
		// 目标地址本身会以 https:// 出现在表格里,那是内容不是资源引用。
		if bad == "http://" {
			continue
		}
		if strings.Contains(body, bad) {
			t.Errorf("页面里有外部资源或脚本:%s", bad)
		}
	}
	csp := get(t, Handler(deps("", nil)), "/", nil).Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "img-src data:") {
		t.Errorf("没有为内嵌导航图标设置自包含 CSP:%q", csp)
	}
}

// 没登录不许写。任何节点都能到任何节点的隧道地址,一台被拿下就能去动别人。
func TestWriteRequiresAuth(t *testing.T) {
	ran := false
	h := Handler(deps("pw", map[string]func() (string, error){
		"重启": func() (string, error) { ran = true; return "", nil },
	}))
	r := httptest.NewRequest("POST", "/act/重启", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if ran {
		t.Fatal("没登录就执行了动作")
	}
	if w.Code != http.StatusSeeOther {
		t.Errorf("期望跳转到登录,得到 %d", w.Code)
	}
}

// GET 不该能触发动作 —— 否则一个链接就能让浏览器替人执行。
func TestActionsRejectGET(t *testing.T) {
	h := Handler(deps("pw", map[string]func() (string, error){"x": func() (string, error) { return "", nil }}))
	if w := get(t, h, "/act/x", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET 触发动作返回 %d,应当拒绝", w.Code)
	}
}

// 没配口令时,写操作一律拒绝 —— 不是"不需要认证"。
func TestNoOperatorMeansNoWrites(t *testing.T) {
	d := deps("", map[string]func() (string, error){"x": func() (string, error) { return "", nil }})
	if authed(d, httptest.NewRequest("GET", "/", nil)) {
		t.Error("没配口令却算已认证")
	}
	// 伪造一个用空口令签的票也不行。
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: mintToken(d)})
	if authed(d, r) {
		t.Error("空口令签出来的票被接受了")
	}
}

// 票过期就失效,而且改一个字节就验不过。
func TestTokenExpiryAndTamper(t *testing.T) {
	d := deps("pw", nil)
	tok := mintToken(d)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	if !authed(d, r) {
		t.Fatal("刚签出来的票就验不过")
	}
	// 过期
	later := d
	later.Now = func() time.Time { return at.Add(sessionTTL + time.Minute) }
	if authed(later, r) {
		t.Error("过期的票还能用")
	}
	// 改签名
	bad := httptest.NewRequest("GET", "/", nil)
	bad.AddCookie(&http.Cookie{Name: cookieName, Value: tok[:len(tok)-1] + "x"})
	if authed(d, bad) {
		t.Error("改过的票还能用")
	}
	// 换口令 —— 已发出去的票必须立刻全失效
	other := deps("newpw", nil)
	other.Now = d.Now
	if authed(other, r) {
		t.Error("换了口令,旧票还能用")
	}
}

// 只读机器上不该出现登录入口:一个点进去只会说"没配口令"的链接,
// 只会让人以为自己配错了。
func TestNoLoginLinkWhenNothingToAuthorize(t *testing.T) {
	body := get(t, Handler(deps("", nil)), "/", nil).Body.String()
	if strings.Contains(body, `href="/login"`) {
		t.Error("只读机器上出现了登录入口")
	}
	if !strings.Contains(body, "只读") {
		t.Error("没有标明这是只读的")
	}
}

// 全网视图必须真的显示出来 —— 包括转述来的节点。
func TestOverviewShowsWholeNetwork(t *testing.T) {
	body := get(t, Handler(deps("", nil)), "/", nil).Body.String()
	for _, must := range []string{"n1", "n2", "abc123", "全网一致", "100ms", "connection refused"} {
		if !strings.Contains(body, must) {
			t.Errorf("页面里没有 %q", must)
		}
	}
	// 长错误要压短,否则表格被撑爆。
	if strings.Contains(body, `Get &#34;https://t/&#34;: dial tcp`) {
		t.Error("错误信息没有压短")
	}
}

func TestTargetShowsMeasurementAgeNotNodeStatusAge(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{{
			ID: "n1", ObservedAt: at.Format(time.RFC3339),
			Targets: []TargetView{{
				Target: "https://old-measurement.test/", MS: 12,
				ObservedAt: at.Add(-5 * time.Minute).Format(time.RFC3339),
			}},
		}}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	if !strings.Contains(body, "old-measurement.test") || !strings.Contains(body, "5 分钟前") {
		t.Fatalf("目标测量没有显示自己的旧时间:%s", body)
	}
}

func TestTargetFailureIsDataButUplinkFailureIsProblem(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{{ID: "n1", Targets: []TargetView{
			{Target: "https://ordinary.test/", Err: "blocked"},
			{Target: "https://uplink.test/", Err: "timeout", Uplink: true},
		}}}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	if !strings.Contains(body, `class="tiny info clip">target · https://ordinary.test/ · 不可达（剪枝数据）`) {
		t.Fatalf("ordinary Target failure was not rendered as pruning data: %s", body)
	}
	if !strings.Contains(body, `class="tiny bad clip">uplink · https://uplink.test/`) {
		t.Fatalf("uplink failure was not rendered as a problem: %s", body)
	}
}

// 节点 id 和错误信息都来自别的机器,必须转义 —— 一台被拿下的机器不该能
// 往别人的界面里注入脚本。
func TestUntrustedStringsAreEscaped(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{{ID: `<script>alert(1)</script>`,
			Targets: []TargetView{{Target: "t", Err: `<img onerror=x>`}}}}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img onerror") {
		t.Error("来自别的节点的字符串没有转义")
	}
}

// 版本不一致必须显眼 —— 落后的那台往往正是出问题的那台。
func TestVersionSkewIsSurfaced(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{{ID: "a", Declared: true, Applied: "v1"}, {ID: "b", Declared: true, Applied: "v2"}}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	if !strings.Contains(body, "全网不是同一个快照") {
		t.Error("版本不一致没有报出来")
	}
}

func TestNoInlineScriptSlipsIn(t *testing.T) {
	body := get(t, Handler(deps("", nil)), "/", nil).Body.String()
	// 前面要求空白,否则 content= 里的 "ontent=" 会被当成事件处理器。
	if regexp.MustCompile(`(?i)<script|\son[a-z]+\s*=`).MatchString(body) {
		t.Error("页面里有脚本或内联事件处理器")
	}
}

func TestOnlyOverviewAutoRefreshes(t *testing.T) {
	h := Handler(deps("pw", nil))
	body := get(t, h, "/", nil).Body.String()
	if !strings.Contains(body, `http-equiv=refresh content=30`) {
		t.Fatal("总览没有 30 秒 SSR 刷新")
	}
	for _, want := range []string{"近实时拓扑", "采样约 1 分钟", "页面每 30 秒刷新"} {
		if !strings.Contains(body, want) {
			t.Fatalf("总览没有诚实说明近实时节奏:%q", want)
		}
	}
	if body := get(t, h, "/login", nil).Body.String(); strings.Contains(body, `http-equiv=refresh`) {
		t.Fatal("登录页不应自动刷新")
	}
}

func TestUnknownNodesAreNotCountedHealthy(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{
			{ID: "silent", Declared: true, Health: "unknown"},
			{ID: "relay", Declared: true, Health: "unknown", Source: "未签名转述"},
		}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	for _, want := range []string{"0 <small>/ 2", "0 故障 · 2 未知", "unknown 不等于 healthy", "状态未知"} {
		if !strings.Contains(body, want) {
			t.Errorf("三态健康摘要缺少 %q", want)
		}
	}
	if strings.Contains(body, "全网无已知故障") {
		t.Fatal("unknown 被写成全网健康")
	}
}

func TestTopologyShowsKindsSourceAndObservationAge(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{ObservedAt: at.Format(time.RFC3339), Nodes: []NodeView{
			{ID: "a", Health: "healthy"}, {ID: "b", Health: "unknown"}, {ID: "c", Health: "unknown"},
		}, Links: []LinkView{
			{From: "a", To: "b", Kind: "tunnel", State: "unknown", Source: "SSOT 常驻 WG"},
			{From: "b", To: "c", Kind: "tunnel", State: "degraded", Source: "5 样本/4 失败"},
			{From: "a", To: "c", Kind: "candidate", State: "unverified", Source: "SSOT RouteCandidate.ServerChain · 候选跳，未核验"},
		}, Candidates: []CandidatePathView{
			{Node: "a", Declaration: "svc", Chain: []string{"a", "b", "c"}, State: "unverified", Source: "SSOT RouteCandidate.ServerChain"},
			{Node: "a", Declaration: "svc", Chain: []string{"a", "c"}, State: "selected", ObservedAt: at.Format(time.RFC3339), Source: "selector 实读"},
		}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	for _, want := range []string{"候选跳（未核验）", "tunnel / unknown", "tunnel / degraded", "部分失败", "承载可达性观测", "candidate / unverified", "SSOT 常驻 WG", "selector 实读", "无直边 ≠ 无路径", "a → b → c", "候选（未核验）", "当前选中"} {
		if !strings.Contains(body, want) {
			t.Errorf("拓扑来源表缺少 %q", want)
		}
	}
	if strings.Contains(body, `M16 2c4`) {
		t.Fatal("未批准的临时花形 logo 仍在页面")
	}
	if !strings.Contains(body, `fill="#239b68"`) || strings.Contains(body, `fill="#ffd166"`) {
		t.Fatal("当前路径箭头没有与绿色路径线保持一致")
	}
}

func TestOverviewShowsComponentDriftAndAgentCandidateHealth(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{
			Nodes: []NodeView{{
				ID: "gz02", Health: "problem",
				Components: []ComponentView{{
					Name: "wireguard", Expected: "1.0.20250521", Actual: "1.0.20210914", OK: false,
				}},
			}},
			Routes: []RouteView{{
				Node: "jm24", Declaration: "best-egress", Chain: []string{"jm24", "gz02"},
				ObservedAt: at.Format(time.RFC3339), Source: "签名转述",
				Health: &CandidateHealthView{
					Candidates: 4, RecentSuccess: 1, RecentDegraded: 1, RecentFailed: 1, Unknown: 1,
					SelectedState: "degraded", SelectedMetrics: "p50 80ms · p95 190ms · 300 KB/s",
					BestMetrics: "p50 60ms · 500 KB/s",
				},
			}},
		}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	for _, want := range []string{
		"wireguard 1.0.20210914 / 期望 1.0.20250521",
		"1 正常 · 1 波动 · 1 失败 · 0 过期 · 1 未知",
		"当前候选 波动 · p50 80ms · p95 190ms · 300 KB/s",
		"窗口最佳 p50 60ms · 500 KB/s",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview missing %q", want)
		}
	}
}

func TestOverviewShowsSelectedFailureWithoutMetrics(t *testing.T) {
	d := deps("", nil)
	d.Snapshot = func() View {
		return View{Routes: []RouteView{{
			Node: "jm24", Declaration: "d", Chain: []string{"jm24", "gz02"},
			Health: &CandidateHealthView{
				Candidates: 2, RecentFailed: 2, SelectedState: "failed",
			},
		}}}
	}
	body := get(t, Handler(d), "/", nil).Body.String()
	if !strings.Contains(body, "当前候选 失败") {
		t.Fatalf("没有指标的失败候选状态被隐藏:\n%s", body)
	}
}

func TestDecommissionedRolloutIsSuccessfulTerminalState(t *testing.T) {
	if got := rolloutCSS(&RolloutView{Stage: "decommissioned"}); got != "ok" {
		t.Fatalf("decommissioned rollout rendered as %q, want ok", got)
	}
}
