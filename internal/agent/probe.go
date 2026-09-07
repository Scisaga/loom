package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Result 是一次探测的结果。
//
// **首字节和吞吐是两件事,而且会给出相反的排序。** 实测同一批候选:
// edge-a 首字节排第 4(956ms),按拉完 2MB 的真实耗时排第 2 —— 比排在它
// 前面那条快 3.4 倍,因为它的吞吐是那条的 3 倍。
type Result struct {
	// FirstByteMs 是到首字节的时间。API 类的小请求由它主导。
	FirstByteMs int
	// Bytes / TotalMs 是实际读下来的字节数与总耗时。
	Bytes   int
	TotalMs int
}

// KBps 返回下载速度。样本太小时返回 0 —— **几百字节算出来的"速度"
// 只是首字节时间的倒数,不是吞吐**,当成吞吐用会误导排序。
func (r *Result) KBps() int {
	if r.Bytes < minThroughputBytes || r.TotalMs <= 0 {
		return 0
	}
	return r.Bytes * 1000 / r.TotalMs / 1024
}

// minThroughputBytes 是"算得出吞吐"的下限。
const minThroughputBytes = 32 << 10

// maxProbeBytes 是一次探测最多读多少。
//
// 读正文才有吞吐数据,而读正文要花带宽。32KB 起算、256KB 封顶:够把
// 一跳(860–2018 KB/s)和两跳(244–273 KB/s)分开,而每轮的量又可控 ——
// 前提是探测的候选数是**有界**的(§16.2 的探测预算)。
const maxProbeBytes = 256 << 10

// ProbeOnce 经探测入口打一条候选。
//
// 用 HTTP 代理而不是 SOCKS5:mixed 入站两种都说,而 HTTP 代理的凭据由
// Go 标准库处理,不必引第三方依赖。域名在代理端解析,所以测到的是**这条
// 候选到目标的真实可达性**,不是本机的。
//
// Proxy 一律显式指定,**不读环境变量**:节点上可能设了 HTTP_PROXY,那会让
// 探测悄悄绕开被测的候选,测出来的是那个代理的延迟。
func ProbeOnce(ctx context.Context, probeAddr, secret, probeUser, target string, timeout time.Duration) (Result, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result{}, err
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	r := Result{FirstByteMs: int(time.Since(start).Milliseconds())}

	// 代理拒绝时也会返回一个 HTTP 响应,别把它当成功。
	if resp.StatusCode >= 500 {
		return Result{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 读正文才有吞吐数据。读到上限就停 —— 目标可能很大,而我们只需要
	// 足够算出速度的那一段。
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBytes))
	if err != nil {
		// 首字节已经拿到了,正文读一半断掉只影响吞吐,不影响可达性判定。
		r.TotalMs = int(time.Since(start).Milliseconds())
		return r, nil
	}
	r.Bytes = int(n)
	r.TotalMs = int(time.Since(start).Milliseconds())
	return r, nil
}
