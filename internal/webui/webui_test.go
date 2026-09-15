package webui

import (
	"net/http"
	"net/http/httptest"

	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)

func deps(op string, acts map[string]func() (string, error)) Deps {
	return Deps{
		Node: "n1", Admin: op != "", Actions: acts,
		Now: func() time.Time { return at },
		Snapshot: func() View {
			return View{Self: "n1", IntentSource: "serving node applied inventory", Nodes: []NodeView{
				{ID: "n1", Declared: true, Self: true, Reached: true, Applied: "abc123",
					Tunnels: []TunnelView{{Interface: "wg-a", CarrierPresent: true, State: "active", AgeSec: 30, CounterPresent: true, OK: true}},
					Targets: []TargetView{{Target: "https://t/", MS: 100}}},
				{ID: "n2", Declared: true, Applied: "abc123",
					Targets: []TargetView{{Target: "https://t/", Err: `Get "https://t/": dial tcp 192.0.2.44:443: connect: connection refused`}}},
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

// 目标地址本身会以 https:// 出现在表格里,那是内容不是资源引用。

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
		!strings.Contains(body, `<linearGradient id="background-gradient"`) ||
		!strings.Contains(body, `<path id="loom-outline"`) ||
		!strings.Contains(body, `<path id="petal-opening" d="M628 1040C520 945 535 790 628 660C721 790 736 945 628 1040Z"/>`) {
		t.Fatal("favicon does not contain the v4 gradient and simplified Loom silhouette")
	}
	if strings.Count(body, `<use href="#petal-opening"`) != 6 {
		t.Fatal("favicon must use one simple opening for each of its six petals")
	}
	if !strings.Contains(body, `stop-color="#667eea"`) ||
		!strings.Contains(body, `stop-color="#764ba2"`) ||
		!strings.Contains(body, `<mask id="loom-mark"`) ||
		!strings.Contains(body, `fill="url(#background-gradient)" mask="url(#loom-mark)"`) ||
		!strings.Contains(body, `scale(1 -1)" fill="#fafaf7">`) {
		t.Fatal("favicon must use a transparent canvas with a v4-gradient mark and ivory petals")
	}
}
