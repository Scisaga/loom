package clientreport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"loom/internal/nodepresence"
)

func testPresenceHeartbeat(t *testing.T) nodepresence.Heartbeat {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat, err := nodepresence.Sign("demo-windows", time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return heartbeat
}

func TestSendPresenceUsesOnlyExactThreeFieldProtocol(t *testing.T) {
	heartbeat := testPresenceHeartbeat(t)
	requests := 0
	client := &http.Client{Transport: responseTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodPost || request.URL.Scheme != "https" ||
			request.URL.Host != "control.example" || request.URL.Path != "/loom-client/report" ||
			request.URL.RawQuery != "presence=1" || request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("Authorization") != "" {
			t.Fatalf("Windows 心跳请求边界无效:%s %s headers=%v", request.Method, request.URL, request.Header)
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, nodepresence.MaxEnvelopeBytes+1))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 3 {
			t.Fatalf("心跳不是三字段 JSON:%s err=%v", body, err)
		}
		for _, name := range []string{"node", "ts", "signature"} {
			if _, ok := fields[name]; !ok {
				t.Fatalf("心跳缺少字段 %s:%s", name, body)
			}
		}
		var decoded nodepresence.Heartbeat
		if err := json.Unmarshal(body, &decoded); err != nil || decoded != heartbeat {
			t.Fatalf("心跳正文被传输层改写:%+v err=%v", decoded, err)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
	})}
	result := SendPresence(context.Background(), client,
		"https://control.example/loom-client/report", &heartbeat)
	if result.Err != nil || result.Status != http.StatusNoContent || requests != 1 {
		t.Fatalf("Windows 心跳结果=%+v requests=%d", result, requests)
	}
}

func TestSendPresenceHasNoLegacySuccessOrRedirectFallback(t *testing.T) {
	heartbeat := testPresenceHeartbeat(t)
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: http.Header{},
					Body: io.NopCloser(strings.NewReader("legacy")), ContentLength: 6}, nil
			})}
			if got := SendPresence(context.Background(), client,
				"https://control.example/loom-client/report", &heartbeat); got.Err == nil {
				t.Fatalf("旧心跳成功语义被接受:%+v", got)
			}
		})
	}
	redirectRequests := 0
	client := &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
		redirectRequests++
		if redirectRequests > 1 {
			return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
		}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{
			"Location": []string{"https://redirect.example/loom-client/report?presence=1"},
		}, Body: io.NopCloser(strings.NewReader("redirect")), ContentLength: 8}, nil
	})}
	if got := SendPresence(context.Background(), client,
		"https://control.example/loom-client/report", &heartbeat); got.Err == nil || redirectRequests != 1 {
		t.Fatalf("Windows 心跳跟随或接受了重定向:result=%+v requests=%d", got, redirectRequests)
	}
	for _, endpoint := range []string{
		"https://control.example/loom-client/report?presence=1",
		"https://control.example/loom-client/report?observations=1",
		"https://control.example/loom-client/report#presence",
	} {
		if got := SendPresence(context.Background(), http.DefaultClient, endpoint, &heartbeat); got.Err == nil {
			t.Fatalf("调用方附加查询或 fragment 绕过固定端点:%s", endpoint)
		}
	}
}
