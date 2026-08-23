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
			return View{Self: "n1", Nodes: []NodeView{
				{ID: "n1", Self: true, Reached: true, Applied: "abc123",
					Tunnels: []TunnelView{{Interface: "wg-a", State: "active", AgeSec: 30, OK: true}},
					Targets: []TargetView{{Target: "https://t/", MS: 100}}},
				{ID: "n2", Applied: "abc123",
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
	if !strings.Contains(get(t, Handler(deps("", nil)), "/", nil).Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("没有设 CSP")
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
		return View{Nodes: []NodeView{{ID: "a", Applied: "v1"}, {ID: "b", Applied: "v2"}}}
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
