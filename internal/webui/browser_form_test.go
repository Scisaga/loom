package webui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBrowserPageOmitsReferrerToOtherOrigins(t *testing.T) {
	browser := os.Getenv("LOOM_BROWSER_TEST_BINARY")
	if browser == "" {
		t.Skip("设置 LOOM_BROWSER_TEST_BINARY 运行真实 Chromium 隐私回归")
	}
	referred := make(chan string, 1)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/demo-destination" {
			referred <- r.Header.Get("Referer")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	destination, _ := json.Marshal(other.URL + "/demo-destination")
	script := "location.href=" + string(destination) + ";"
	digest := sha256.Sum256([]byte(script))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		writeHTML(recorder, "<!doctype html><title>Demo private page</title>")
		for name, values := range recorder.Header() {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Security-Policy", strings.Replace(w.Header().Get("Content-Security-Policy"),
			"script-src ", "script-src 'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"' ", 1))
		_, _ = w.Write(append(recorder.Body.Bytes(), []byte("<script>"+script+"</script>")...))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, browser, "--headless", "--no-sandbox", "--disable-gpu",
		"--no-proxy-server", "--no-first-run", "--disable-background-networking", "--ignore-certificate-errors",
		"--user-data-dir="+t.TempDir(), "--dump-dom", "--virtual-time-budget=2000", server.URL+"/devices/demo-private-id")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("启动浏览器失败: %v\n%s", err, output)
	}
	select {
	case referer := <-referred:
		if referer != "" {
			t.Fatal("浏览器向其他 origin 泄露了 private UI URL")
		}
	case <-time.After(time.Second):
		t.Fatal("浏览器没有完成跨 origin 导航")
	}
}

// 用真实浏览器从实际设备表单发出 POST，不能手工注入一个“正确”的 Origin
// 掩盖 no-referrer 对普通 HTML form navigation 的影响。
func TestDeviceCreateBrowserFormPreservesOrigin(t *testing.T) {
	browser := os.Getenv("LOOM_BROWSER_TEST_BINARY")
	if browser == "" {
		t.Skip("设置 LOOM_BROWSER_TEST_BINARY 运行真实 Chromium 表单回归")
	}
	deps := clientUIDeps()
	deps.Admin = true
	created := make(chan ClientInviteInput, 1)
	deps.Control.Clients.CreateInvite = func(input ClientInviteInput) (ClientInviteView, error) {
		created <- input
		return ClientInviteView{InviteID: "demo-browser-invite"}, nil
	}
	handler := Handler(deps)
	type submission struct {
		origin, site string
		status       int
	}
	submitted := make(chan submission, 1)
	const submitScript = `document.querySelector('#client-name').value='demo-browser';document.querySelector('form[data-device-enrollment-form]').requestSubmit();`
	digest := sha256.Sum256([]byte(submitScript))
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/devices/create" {
			// 与 private control UI 的 exact-origin 门禁相同；浏览器自己产生请求头。
			if r.Header.Get("Origin") != server.URL || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
				submitted <- submission{r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"), http.StatusForbidden}
				http.Error(w, "demo-origin-rejected", http.StatusForbidden)
				return
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			submitted <- submission{r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"), recorder.Code}
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		if r.URL.Path == "/devices" && r.URL.Query().Get("new") == "1" {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			// 仅测试页面增加自动点击脚本的 CSP hash；表单与 Referrer-Policy
			// 仍来自生产 renderer。无需外部浏览器驱动或下载依赖。
			csp := strings.Replace(w.Header().Get("Content-Security-Policy"), "script-src ",
				"script-src 'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"' ", 1)
			w.Header().Set("Content-Security-Policy", csp)
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(append(recorder.Body.Bytes(), []byte("<script>"+submitScript+"</script>")...))
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, browser, "--headless", "--no-sandbox", "--disable-gpu",
		"--no-proxy-server", "--no-first-run", "--disable-background-networking", "--ignore-certificate-errors",
		"--user-data-dir="+t.TempDir(), "--dump-dom", "--virtual-time-budget=2000", server.URL+"/devices?new=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("启动浏览器失败: %v\n%s", err, output)
	}
	select {
	case result := <-submitted:
		if result.origin != server.URL || result.site != "same-origin" || result.status != http.StatusSeeOther {
			t.Fatalf("浏览器提交被误拒绝: origin=%q site=%q status=%d", result.origin, result.site, result.status)
		}
	case <-time.After(time.Second):
		t.Fatal("真实页面没有发出设备创建 POST")
	}
	select {
	case input := <-created:
		if input.Name != "demo-browser" {
			t.Fatal("表单字段未到达 CreateInvite")
		}
	default:
		t.Fatal("浏览器表单未进入 Device 创建处理器")
	}
}
