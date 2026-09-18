package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	linkMetricReflectorAddr = "127.0.0.1:61804"
	linkMetricProbePath     = "/loom-link-probe"
	linkMetricProbeBytes    = 64 << 10
)

var linkMetricReflectorBody = make([]byte, linkMetricProbeBytes)

// Serve 在每个配置的地址上提供 GET /status。
//
// 一个地址一个 listener:节点在每条隧道里有各自的地址,而绑 0.0.0.0 会把
// 接口暴露到公网。宁可多开几个 listener。
//
// 没有认证:能连上隧道内地址,就已经持有 WireGuard 密钥了。再加一层口令
// 只是多一个要分发和轮换的秘密,换不到实际的隔离。
func Serve(ctx context.Context, cfg *Config, now func() time.Time, logw io.Writer) error {
	if len(cfg.Listen) == 0 {
		return fmt.Errorf("没有监听地址 —— 该节点没有任何隧道内地址,上报接口无处可绑")
	}
	runtime, err := Start(ctx, cfg, now, logw)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           runtime.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	started := 0

	for _, addr := range cfg.Listen {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// 一个地址绑不上不该让整个上报者退出:隧道接口可能还没起来,
			// 而别的地址上的自检仍然有价值。
			fmt.Fprintf(logw, "! 无法监听 %s:%v\n", addr, err)
			continue
		}
		started++
		fmt.Fprintf(logw, "监听 %s\n", addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	if started == 0 {
		return fmt.Errorf("%d 个地址一个都没绑上 —— 隧道接口起来了吗", len(cfg.Listen))
	}

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	wg.Wait()
	if err := runtime.Wait(); firstErr == nil {
		firstErr = err
	}
	mu.Lock()
	defer mu.Unlock()
	return firstErr
}

const phaseBAttestationNotReady = "phase-B 尚未产生有效 canonical_version=5 本机观测"

// attachObservationState 是 HTML、/status 与事件检测共用的观测边界。phase B
// 中 table.put 已经保证入表前验过 v5；因此本机观测为空表示启动首轮尚未完成、
// 签名材料缺失或签名失败。三种情况都不能对外返回健康/ready。
func attachObservationState(cfg *Config, tbl *table, st *Status, at time.Time, maxAge time.Duration) {
	st.Observation, st.Learned = tbl.view(cfg.Node, at, maxAge)
	st.Errors = append(st.Errors, tbl.roundErrors()...)
	if cfg.AttestationMinVersion >= 5 && st.Observation == nil {
		st.Errors = append(st.Errors, phaseBAttestationNotReady)
	}
	st.Errors = append(st.Errors,
		AttestationErrors(st, at, maxAge, cfg.AttestationMinVersion)...)
}

func writeStatus(w http.ResponseWriter, st *Status, at time.Time) {
	w.Header().Set("Content-Type", "application/json")
	// 自检有发现时用 503:拉取方不必解析 JSON 就知道这台机器有问题,
	// 而 JSON 里仍有全部细节。
	if !st.OKAt(at) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(st)
}

// Fetch 从一个节点的上报接口拉一次状态。
//
// 503 是"自检有发现",不是传输失败 —— 照常解析,由调用方判断。
func Fetch(addr string, timeout time.Duration) (*Status, error) {
	return FetchContext(context.Background(), addr, timeout)
}

// FetchContext is Fetch with caller-controlled cancellation. Long-lived
// control loops must use it so a stopped generation cannot remain blocked on a
// peer and later continue into a selector decision.
func FetchContext(ctx context.Context, addr string, timeout time.Duration) (*Status, error) {
	c := &http.Client{
		// Proxy 显式置空:节点上设了 HTTP_PROXY 时,发往隧道地址的请求
		// 会被交给那个代理,拿回来的东西和这台机器毫无关系。
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Timeout:   timeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("HTTP %d,响应不是状态 JSON:%s", resp.StatusCode, truncate(string(b), 200))
	}
	return &st, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
