package agent

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ProbeOnce 经探测入口打一条候选,返回首字节时间(毫秒)。
//
// 用 HTTP 代理而不是 SOCKS5:mixed 入站两种都说,而 HTTP 代理的凭据由
// Go 标准库处理,不必引第三方依赖。域名在代理端解析,所以测到的是**这条
// 候选到目标的真实可达性**,不是本机的。
//
// Proxy 一律显式指定,**不读环境变量**:节点上可能设了 HTTP_PROXY,那会让
// 探测悄悄绕开被测的候选,测出来的是那个代理的延迟。
func ProbeOnce(probeAddr, secret, probeUser, target string, timeout time.Duration) (int, error) {
	pu := &url.URL{Scheme: "http", User: url.UserPassword(probeUser, secret), Host: probeAddr}
	c := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(pu),
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
		},
		Timeout: timeout,
		// 只测到首字节,不跟随跳转 —— 跳转会把别的目标的延迟算进来。
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := c.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	elapsed := int(time.Since(start).Milliseconds())

	// 代理拒绝时也会返回一个 HTTP 响应,别把它当成功。
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return elapsed, nil
}
