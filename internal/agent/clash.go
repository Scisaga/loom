package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// clash 是 sing-box 控制端点(§7.3.1)的最小客户端:读 selector 的当前
// 选择、把它设成别的候选。只用这两个动作 —— 选路的决策者只有一个(D11),
// 别的接口不碰。
type clash struct {
	base   string
	secret string
	c      *http.Client
}

func newClash(addr, secret string) *clash {
	return &clash{
		base:   "http://" + addr,
		secret: secret,
		// Proxy 显式置空:节点上设了 HTTP_PROXY 的话,默认 Transport 会把
		// 发往 127.0.0.1 的控制请求也交给那个代理。
		c: &http.Client{
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
			Timeout:   5 * time.Second,
		},
	}
}

func (k *clash) do(method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, k.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s → HTTP %d:%s", method, path, resp.StatusCode, bytes.TrimSpace(b))
	}
	return b, nil
}

// Now 返回 selector 当前选中的出站。
func (k *clash) Now(selector string) (string, error) {
	b, err := k.do("GET", "/proxies/"+url.PathEscape(selector), nil)
	if err != nil {
		return "", err
	}
	var r struct {
		Now  string `json:"now"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", err
	}
	if r.Type != "Selector" {
		return "", fmt.Errorf("%s 不是 selector 而是 %s —— 选路的决策者只能有一个(D11)", selector, r.Type)
	}
	return r.Now, nil
}

// Select 把 selector 切到指定候选。
func (k *clash) Select(selector, candidate string) error {
	body, _ := json.Marshal(map[string]string{"name": candidate})
	_, err := k.do("PUT", "/proxies/"+url.PathEscape(selector), body)
	return err
}
