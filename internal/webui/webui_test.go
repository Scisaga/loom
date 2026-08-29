package webui

import (
	"crypto/sha256"
	"encoding/base64"
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
	w := get(t, Handler(deps("", nil)), "/", nil)
	body := w.Body.String()
	if strings.Count(body, "<script>") != 1 || !strings.Contains(body, `<script>`+topologyInteractionScript+`</script>`) {
		t.Fatal("overview must contain exactly the approved self-contained topology interaction script")
	}
	for _, bad := range []string{"http://", "https://cdn", "<script src=", "src="} {
		// 目标地址本身会以 https:// 出现在表格里,那是内容不是资源引用。
		if bad == "http://" {
			continue
		}
		if strings.Contains(body, bad) {
			t.Errorf("页面里有外部资源或脚本:%s", bad)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "img-src 'self' data:") {
		t.Errorf("没有为内嵌导航图标设置自包含 CSP:%q", csp)
	}
	digest := sha256.Sum256([]byte(topologyInteractionScript))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	if !strings.Contains(csp, want) || strings.Contains(strings.Split(csp, "style-src")[0], "'unsafe-inline'") {
		t.Fatalf("topology script CSP = %q, want exact hash %q and no script unsafe-inline", csp, want)
	}
}

func TestEnrollmentProgressScriptIsInlineAndCSPHashLocked(t *testing.T) {
	d := misakaDeps()
	d.Control.Enrollment = &NodeEnrollmentDeps{}
	body := pageNodeAdd(d, nodeAddPageState{
		Phase:      "confirm",
		Connection: EnrollmentConnection{Host: "203.0.113.42", User: "root", Port: 22},
		HostKey: EnrollmentHostKey{
			Algorithm: "ssh-ed25519", PublicKey: "AAAAC3Nza", Fingerprint: "SHA256:test",
		},
	}, true)
	if strings.Count(body, "<script>") != 1 || !strings.Contains(body, progressSubmitScript) || strings.Contains(body, "<script src=") {
		t.Fatalf("enrollment progress script is not the single approved inline script")
	}
	w := httptest.NewRecorder()
	writeHTML(w, body)
	digest := sha256.Sum256([]byte(progressSubmitScript))
	want := "script-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) || strings.Contains(csp, "'unsafe-inline'") && strings.Contains(strings.Split(csp, "style-src")[0], "'unsafe-inline'") {
		t.Fatalf("progress script CSP = %q, want exact hash %q", csp, want)
	}
}

func TestFaviconUsesSimplifiedLoomMark(t *testing.T) {
	w := get(t, Handler(deps("", nil)), "/favicon.svg", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("favicon status=%d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Fatalf("favicon content type=%q", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<svg xmlns="http://www.w3.org/2000/svg"`) ||
		!strings.Contains(body, `<path id="loom-outline"`) ||
		!strings.Contains(body, `<path id="petal-opening" d="M628 1040C520 945 535 790 628 660C721 790 736 945 628 1040Z"/>`) {
		t.Fatal("favicon does not contain the simplified Loom silhouette")
	}
	if strings.Contains(body, approvedLogoPath) || strings.Count(body, `<use href="#petal-opening"`) != 6 {
		t.Fatal("favicon must use one simple opening for each of its six petals")
	}
	if !strings.Contains(body, `<path id="weave-detail"`) ||
		strings.Count(body, `<use href="#weave-detail"`) != 6 ||
		!strings.Contains(body, `stroke-width="18" stroke-linecap="round" opacity=".72"`) {
		t.Fatal("favicon must use one subtle nested thread in each petal")
	}
	if !strings.Contains(body, `<rect x="127" y="112" width="1000" height="1000" fill="#fff"/>`) ||
		!strings.Contains(body, `<use href="#loom-outline" fill="#111"/>`) ||
		!strings.Contains(body, `<g fill="#fff">`) {
		t.Fatal("favicon must use a white background and a black single-band mark")
	}
}

func TestTopologyUsesConcentricRingsAndObservedLinkMetrics(t *testing.T) {
	view := View{Nodes: []NodeView{
		{ID: "jm24", Self: true, Declared: true, Health: "healthy", Direction: "bidirectional", Roles: []string{"control", "access", "server", "egress"}, City: "北京"},
		{ID: "gz02", Declared: true, Health: "healthy", Direction: "bidirectional", Roles: []string{"server", "egress"}, City: "广州"},
		{ID: "hz01", Declared: true, Health: "healthy", Direction: "bidirectional", Roles: []string{"server", "egress"}, City: "杭州"},
		{ID: "ber01", Declared: true, Health: "healthy", Direction: "reverse_only", Roles: []string{"server", "egress"}, City: "柏林"},
		{ID: "sg02", Declared: true, Health: "healthy", Direction: "reverse_only", Roles: []string{"server", "egress"}, City: "新加坡"},
		{ID: "sv01", Declared: true, Health: "healthy", Direction: "reverse_only", Roles: []string{"server", "egress"}, City: "硅谷"},
	}, Links: []LinkView{
		{From: "jm24", To: "sv01", Kind: "tunnel", State: "active", MS: 18, Samples: 5, ObservedAt: "2026-08-29T12:00:00Z", RecentTXBytes: 75_000, RateWindowSeconds: 300, RateSamples: 4, RateReportingEndpoints: 2, QualityP50MS: 40, QualityP95MS: 75, QualityObservations: 8, MetricsSource: "trusted test evidence"},
		{From: "gz02", To: "jm24", Kind: "candidate", State: "unverified", Source: "test intent"},
	}}

	topology := topologySVG(view)
	if strings.Contains(topology, `ry=130/>`) || strings.Contains(topology, `r=3/>`) || strings.Contains(topology, `rx=5/>`) {
		t.Fatal("self-closing SVG element left its final attribute unquoted; HTML would absorb the slash into the value")
	}
	if strings.Count(topology, `data-ring="inner"`) != 3 || strings.Count(topology, `data-ring="outer"`) != 3 {
		t.Fatalf("topology did not divide the six nodes into two equal rings: %s", topology)
	}
	for _, want := range []string{
		`class="topology-ring outer"`, `class="topology-ring inner"`,
		`data-node="jm24" data-ring="inner" data-angle="-90.0"`,
		`data-node="ber01" data-ring="outer" data-angle="-30.0"`,
		`role=button tabindex="0" aria-pressed="false"`,
		`A 170.0 75.0`, `18ms · Δ35ms · 2.0kb/s`, `硅谷 · server + egress`,
		`class=edge-metric data-from="jm24" data-to="sv01"`,
		`近 5 分钟实际传输速率 2.0kb/s`,
	} {
		if !strings.Contains(topology, want) {
			t.Errorf("concentric topology missing %q", want)
		}
	}
	if strings.Contains(topology, `test intent</text>`) {
		t.Fatal("candidate intent incorrectly received an observed metric label")
	}
	carrier := regexp.MustCompile(`<path class="tunnel" d="([^"]+)"/><path class=edge-hit d="([^"]+)"/>`).FindStringSubmatch(topology)
	if len(carrier) != 3 || carrier[1] != carrier[2] || !strings.Contains(carrier[1], " Q ") || strings.Contains(carrier[1], " L ") {
		t.Fatalf("visible and hit carrier paths must share one continuous curve, got %q", carrier)
	}
	if strings.Contains(topology, "±") {
		t.Fatal("topology variation must use Δ rather than imply a symmetric ± error")
	}
}

func TestTopologyLinkMetricUsesCompactDeltaOrder(t *testing.T) {
	compact, detail := topologyLinkMetric(LinkView{
		From: "jm24", To: "sv01", MS: 207, Samples: 5, ObservedAt: "2026-08-29T12:00:00Z",
		RecentTXBytes: 671_250, RateWindowSeconds: 300, RateSamples: 4, RateReportingEndpoints: 2,
		QualityP50MS: 203, QualityP95MS: 207, QualityObservations: 8,
	})
	if compact != "207ms · Δ4ms · 17.9kb/s" {
		t.Fatalf("compact topology metric = %q", compact)
	}
	for _, want := range []string{"P95−P50", "P50 203ms / P95 207ms", "近 5 分钟实际传输速率 17.9kb/s"} {
		if !strings.Contains(detail, want) {
			t.Errorf("topology metric detail missing %q: %s", want, detail)
		}
	}
}

func TestTopologyInteractionContract(t *testing.T) {
	for _, want := range []string{
		`pointerenter`, `addEventListener("click"`, `event.key==="Enter"`,
		`event.key===" "`, `event.key==="Escape"`, `aria-pressed`,
		`is-related`, `is-muted`, `edge-metric`,
	} {
		if !strings.Contains(topologyInteractionScript, want) {
			t.Errorf("topology interaction script missing %q", want)
		}
	}
	if strings.Contains(topologyInteractionScript, `innerHTML`) || strings.Contains(topologyInteractionScript, `eval(`) {
		t.Fatal("topology interaction must not parse node data as HTML or code")
	}
}

func TestFocusedTopologyMetricsDoNotOverlapForSixNodeMesh(t *testing.T) {
	positions := map[string]topologyPoint{}
	topologyRingPositions(positions, []string{"jm24", "gz02", "hz01"}, "inner", -90, 170, 75)
	topologyRingPositions(positions, []string{"ber01", "sg02", "sv01"}, "outer", -30, 310, 130)
	nodes := map[string]NodeView{
		"jm24":  {ID: "jm24", City: "北京", Roles: []string{"control", "access", "server", "egress"}},
		"gz02":  {ID: "gz02", City: "广州", Roles: []string{"server", "egress"}},
		"hz01":  {ID: "hz01", City: "杭州", Roles: []string{"server", "egress"}},
		"ber01": {ID: "ber01", City: "柏林", Roles: []string{"server", "egress"}},
		"sg02":  {ID: "sg02", City: "新加坡", Roles: []string{"server", "egress"}},
		"sv01":  {ID: "sv01", City: "硅谷", Roles: []string{"server", "egress"}},
	}
	measuredLink := func(from, to string) LinkView {
		return LinkView{
			From: from, To: to, Kind: "tunnel", MS: 207, Samples: 5, ObservedAt: "2026-08-29T12:00:00Z",
			RecentTXBytes: 671_250, RateWindowSeconds: 300, RateSamples: 4,
			QualityP50MS: 203, QualityP95MS: 207, QualityObservations: 8,
		}
	}
	var links []LinkView
	for _, inner := range []string{"jm24", "gz02", "hz01"} {
		for _, outer := range []string{"ber01", "sg02", "sv01"} {
			links = append(links, measuredLink(inner, outer))
		}
	}
	// Same-ring persistent tunnels must use the same measured-label placement
	// path. (Candidate arcs deliberately remain unmeasured.)
	links = append(links,
		measuredLink("jm24", "gz02"),
		measuredLink("gz02", "hz01"),
		measuredLink("hz01", "jm24"),
	)
	labels := topologyMetricPositions(links, positions, nodes)
	if len(labels) != len(links) {
		t.Fatalf("metric positions = %d, want all %d persistent tunnels including inner-ring links", len(labels), len(links))
	}
	obstacles := topologyNodeObstacles(positions, nodes)
	metricBounds := map[string]svgRect{}
	for _, link := range links {
		key := topologyLinkKey(link.From, link.To)
		metric, _ := topologyLinkMetric(link)
		bounds := topologyMetricBounds(labels[key], topologyMetricHalfWidth(metric))
		metricBounds[key] = bounds
		for _, obstacle := range obstacles {
			if topologyRectsOverlap(bounds, obstacle.bounds) {
				t.Fatalf("metric %s overlaps marker or label for %s: metric=%+v obstacle=%+v", key, obstacle.node, bounds, obstacle.bounds)
			}
		}
	}
	// Regression: this was the top-left label hidden behind sv01 and its
	// subtitle when its outer-ring fan used a position only 14%% from the node.
	svKey := topologyLinkKey("sv01", "jm24")
	for _, obstacle := range obstacles {
		if obstacle.node == "sv01" && topologyRectsOverlap(metricBounds[svKey], obstacle.bounds) {
			t.Fatalf("sv01↔jm24 metric still overlaps sv01: metric=%+v obstacle=%+v", metricBounds[svKey], obstacle.bounds)
		}
	}
	for _, node := range []string{"jm24", "gz02", "hz01", "ber01", "sg02", "sv01"} {
		var incident []svgRect
		for _, link := range links {
			if link.From == node || link.To == node {
				incident = append(incident, metricBounds[topologyLinkKey(link.From, link.To)])
			}
		}
		for i := range incident {
			for j := i + 1; j < len(incident); j++ {
				if topologyRectsOverlap(incident[i], incident[j]) {
					t.Fatalf("focused metrics overlap for %s at %+v and %+v", node, incident[i], incident[j])
				}
			}
		}
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
	if !strings.Contains(body, "配置仍在同步") || !strings.Contains(body, "snapshot-group") {
		t.Error("版本不一致没有报出来")
	}
}

func TestNoInlineScriptSlipsIn(t *testing.T) {
	body := get(t, Handler(deps("", nil)), "/", nil).Body.String()
	approved := `<script>` + topologyInteractionScript + `</script>`
	if strings.Count(body, approved) != 1 {
		t.Fatal("overview topology script is missing or duplicated")
	}
	body = strings.Replace(body, approved, "", 1)
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
	for _, want := range []string{"0 <small>/ 2 正常", "0 个节点正常 · 2 个等待可信状态上报", "2 个节点尚无可信状态上报", "等待上报：", "silent", "relay", "没有故障证据不等于健康"} {
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
