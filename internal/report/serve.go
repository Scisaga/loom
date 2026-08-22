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

	gp, err := cfg.Gossip()
	if err != nil {
		return err
	}
	maxAge, err := cfg.ObsStale()
	if err != nil {
		return err
	}
	tbl := newTable()

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		// 隧道健康和配置自检是**当场**算的,便宜。观测不是 —— 量一遍目标
		// 要好几秒,每次被拉都重量会让拉取方超时,也会把探测流量放大成
		// 拉取次数的倍数。所以观测走后台节奏,这里只交出最近一份。
		st := Collect(cfg, now())
		st.Observation, st.Learned = tbl.view(cfg.Node, now(), maxAge)
		w.Header().Set("Content-Type", "application/json")
		// 自检有发现时用 503:拉取方不必解析 JSON 就知道这台机器有问题,
		// 而 JSON 里仍有全部细节。
		if !st.OK() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	// 后台观测与转述。先跑一轮再进循环,免得刚起来那一分钟交出空表。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			gossip(cfg, tbl, now, maxAge)
			select {
			case <-ctx.Done():
				return
			case <-time.After(gp):
			}
		}
	}()

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
	mu.Lock()
	defer mu.Unlock()
	return firstErr
}

// Fetch 从一个节点的上报接口拉一次状态。
//
// 503 是"自检有发现",不是传输失败 —— 照常解析,由调用方判断。
func Fetch(addr string, timeout time.Duration) (*Status, error) {
	c := &http.Client{
		// Proxy 显式置空:节点上设了 HTTP_PROXY 时,发往隧道地址的请求
		// 会被交给那个代理,拿回来的东西和这台机器毫无关系。
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Timeout:   timeout,
	}
	resp, err := c.Get("http://" + addr + "/status")
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
