package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type chromeDebugTarget struct {
	Type                 string `json:"type"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type chromeDevTools struct {
	connection *websocket.Conn
	nextID     int
}

func (client *chromeDevTools) call(ctx context.Context, method string, params any, result any) error {
	client.nextID++
	id := client.nextID
	if err := wsjson.Write(ctx, client.connection, map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return err
	}
	for {
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := wsjson.Read(ctx, client.connection, &response); err != nil {
			return err
		}
		if response.ID != id {
			continue
		}
		if response.Error != nil {
			return errors.New(response.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(response.Result, result)
	}
}

func (client *chromeDevTools) evaluate(ctx context.Context, expression string) (any, error) {
	var response struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	err := client.call(ctx, "Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "awaitPromise": true}, &response)
	if err != nil {
		return nil, err
	}
	if len(response.Exception) != 0 {
		return nil, fmt.Errorf("Chrome evaluation failed: %s", response.Exception)
	}
	return response.Result.Value, nil
}

func waitChromeEvaluation(t *testing.T, client *chromeDevTools, expression string) any {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		value, err := client.evaluate(ctx, expression)
		cancel()
		if err == nil && value != nil && value != false && value != "" {
			return value
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Chrome condition did not become true: %s", expression)
	return nil
}

func openChromeDevTools(t *testing.T, chrome string, rootPEM []byte, identity chromeClientIdentity, target string) *chromeDevTools {
	t.Helper()
	home, profile, autoSelect := chromeIdentityProfile(t, rootPEM, identity)
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
		"--remote-debugging-port=0", "--remote-allow-origins=*", "--user-data-dir="+profile,
		"--auto-select-certificate-for-urls="+autoSelect, target)
	command.Env = append(os.Environ(), "HOME="+home)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = command.Wait()
	})
	active := filepath.Join(profile, "DevToolsActivePort")
	var port int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(active)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(body)), "\n")
			if len(lines) >= 1 {
				port, _ = strconv.Atoi(lines[0])
				if port > 0 {
					break
				}
			}
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			t.Fatalf("Chrome exited before DevTools became ready: %s", boundedText(output.String()))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if port == 0 {
		t.Fatalf("Chrome DevTools port was not published: %s", boundedText(output.String()))
	}
	var socketURL string
	client := &http.Client{Timeout: 2 * time.Second}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
		if err == nil {
			var targets []chromeDebugTarget
			decodeErr := json.NewDecoder(response.Body).Decode(&targets)
			response.Body.Close()
			if decodeErr == nil {
				for _, current := range targets {
					if current.Type == "page" && strings.HasPrefix(current.URL, target) {
						socketURL = current.WebSocketDebuggerURL
					}
				}
			}
		}
		if socketURL != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if socketURL == "" {
		t.Fatalf("Chrome page target was not found: %s", boundedText(output.String()))
	}
	dialContext, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	connection, _, err := websocket.Dial(dialContext, socketURL, nil)
	dialCancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.CloseNow() })
	return &chromeDevTools{connection: connection}
}

// TestWebTLSChromePreservesDraftAcrossLiveConflict exercises the real SPA,
// TLS 1.3, an exact admin client certificate, WebSocket snapshot updates and
// the normal typed operation endpoint. A live head change must not replace the
// focused form node, and the subsequent stale submission must keep the draft.
func TestWebTLSChromePreservesDraftAcrossLiveConflict(t *testing.T) {
	if os.Getenv("LOOM_WEB_TLS_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_TLS_CHROME_TEST=1 to run the Chrome mTLS interaction acceptance")
	}
	chrome := requireExecutable(t, "google-chrome")
	requireExecutable(t, "certutil")
	requireExecutable(t, "pk12util")
	requireExecutable(t, "openssl")
	installChromeClientCertificatePolicy(t)
	fixture := newChromeTLSFixture(t)
	state := testState()
	state.Projection = visualWebProjection()
	state.BrowserTLS = fixture.browser
	state.ReadCertDER = []string{base64.RawURLEncoding.EncodeToString(fixture.admin.certDER)}
	state.AdminCertDER = append([]string(nil), state.ReadCertDER...)
	server := testWritableRuntimeServer(t, state)
	server.Config.BrowserTLS = fixture.browser
	server.Config.ReadCertDER = append([]string(nil), state.ReadCertDER...)
	server.Config.AdminCertDER = append([]string(nil), state.AdminCertDER...)
	intent := testNetworkIntent(t)
	server.Runtime.Authority.mu.Lock()
	server.Runtime.Authority.projection.NetworkIntent = &intent
	server.Runtime.Authority.certified.Projection.NetworkIntent = &intent
	server.Runtime.Authority.mu.Unlock()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	server.Channel.config.Listen = []string{address}
	tlsConfig, err := browserTLSConfig(server.Config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(tls.NewListener(listener, tlsConfig)) }()
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
		<-served
	})
	target := "https://" + address + "/services?new=1"
	debug := openChromeDevTools(t, chrome, fixture.rootPEM, fixture.admin, target)
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form input[name=name]') !== null`)
	value, err := debug.evaluate(context.Background(), `(()=>{window.__loomErrors=[];addEventListener('error',event=>window.__loomErrors.push(String(event.error||event.message)));addEventListener('unhandledrejection',event=>window.__loomErrors.push(String(event.reason)));const form=document.querySelector('#service-form'),input=form.querySelector('input[name=name]');form.querySelector('input[name=id]').value='demo-draft';form.querySelector('input[name=matchers]').value='draft.example';input.value='Preserved draft';input.dispatchEvent(new Event('input',{bubbles:true}));input.focus();window.__loomHeldInput=input;return input.value})()`)
	if err != nil || value != "Preserved draft" {
		t.Fatalf("failed to create browser draft: value=%v err=%v", value, err)
	}
	baseHead := currentHead(server.Runtime)
	status, body := postAdminOperation(t, server, "service.put", "live-conflict", baseHead,
		Service{ID: "demo-live", Name: "Live update", Matchers: []string{"live.example"}, Policy: "demo-policy"}, nil)
	if status != http.StatusOK {
		t.Fatalf("live operation status=%d body=%s", status, body)
	}
	waitChromeEvaluation(t, debug, `window.__loomHeldInput===document.activeElement&&window.__loomHeldInput.isConnected&&window.__loomHeldInput.value==='Preserved draft'`)
	submission, err := debug.evaluate(context.Background(), `(()=>{const form=document.querySelector('#service-form'),button=form.querySelector('button[type=submit]');button.scrollIntoView({block:'center'});const rect=button.getBoundingClientRect(),hit=document.elementFromPoint(rect.left+rect.width/2,rect.top+rect.height/2);return JSON.stringify({valid:form.checkValidity(),disabled:button.disabled,x:rect.left+rect.width/2,y:rect.top+rect.height/2,hit:hit?.outerHTML?.slice(0,160)||'',associated:button.form===form})})()`)
	if err != nil {
		t.Fatal(err)
	}
	var point struct {
		Valid      bool    `json:"valid"`
		Disabled   bool    `json:"disabled"`
		X          float64 `json:"x"`
		Y          float64 `json:"y"`
		Hit        string  `json:"hit"`
		Associated bool    `json:"associated"`
	}
	if err := json.Unmarshal([]byte(fmt.Sprint(submission)), &point); err != nil || !point.Valid || point.Disabled {
		t.Fatalf("browser draft has no clickable valid submit control: value=%v err=%v", submission, err)
	}
	clickContext, clickCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer clickCancel()
	if !strings.Contains(point.Hit, "type=\"submit\"") {
		t.Fatalf("submit button is not the pointer hit target: %+v", point)
	}
	if err := debug.call(clickContext, "Page.bringToFront", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"mousePressed", "mouseReleased"} {
		if err := debug.call(clickContext, "Input.dispatchMouseEvent", map[string]any{
			"type": kind, "x": point.X, "y": point.Y, "button": "left", "clickCount": 1,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	statusValue, statusErr := debug.evaluate(context.Background(), `document.querySelector('#operation-status')?.textContent||''`)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if !strings.Contains(strings.ToLower(fmt.Sprint(statusValue)), "stale") {
		t.Fatalf("stale browser operation did not expose a conflict: form=%v status=%v", submission, statusValue)
	}
	waitChromeEvaluation(t, debug, `window.__loomHeldInput.isConnected&&window.__loomHeldInput.value==='Preserved draft'`)
}
