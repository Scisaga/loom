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

	trafficstore "loom/internal/traffic"
	"loom/internal/webui"
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

	gp, err := cfg.Gossip()
	if err != nil {
		return err
	}
	maxAge, err := cfg.ObsStale()
	if err != nil {
		return err
	}
	tbl := newTable(cfg.AttestationMinVersion)
	var trafficStore *trafficstore.Store
	trafficHistoryStatus := "not_supported"
	trafficHistoryError := ""

	mux := http.NewServeMux()

	// 界面挂在根路径,/status 仍然是同一份数据的 JSON 形式。
	//
	// **它们必须同源** —— 界面自己去采一遍的话,"页面上说的"和"接口返回的"
	// 会在某个时刻不一致,而那种不一致极难查。
	deps := webui.Deps{Node: cfg.Node, Now: now}
	decorateView := func(v *webui.View, at time.Time) {
		if v == nil {
			return
		}
		if deps.Control != nil && deps.Control.Enrich != nil {
			if err := deps.Control.Enrich(v); err != nil {
				v.Warnings = append(v.Warnings, "中控 SSOT 元数据不可用:"+err.Error())
			}
		}
		v.TrafficHistoryStatus = trafficHistoryStatus
		v.TrafficHistoryError = trafficHistoryError
		if trafficStore != nil {
			history, err := trafficHistoryFromStore(trafficStore, at)
			if err != nil {
				v.TrafficHistoryStatus = "unavailable"
				v.TrafficHistoryError = err.Error()
				v.Warnings = append(v.Warnings, "中控流量历史不可用:"+err.Error())
			} else {
				v.TrafficHistoryStatus = "available"
				v.TrafficHistory = history
			}
			if err := enrichTopologyLinkMetrics(trafficStore, at, v.Links); err != nil {
				v.Warnings = append(v.Warnings, "中控拓扑链路指标不可用:"+err.Error())
			}
		}
	}
	buildSnapshot := func() webui.View {
		at := now()
		st := Collect(cfg, at)
		// 和 /status 走完全同一条路 —— 界面自己再采一遍的话,
		// "页面上说的"和"接口返回的"会在某个时刻不一致。
		attachObservationState(cfg, tbl, st, at, maxAge)
		v := buildView(cfg, st, at)
		decorateView(&v, at)
		return v
	}
	deps.Snapshot = buildSnapshot
	var trafficCacheMu sync.RWMutex
	var trafficCache webui.View
	trafficCacheReady := false
	deps.TrafficSnapshot = func() webui.View {
		trafficCacheMu.RLock()
		ready, cached := trafficCacheReady, trafficCache
		trafficCacheMu.RUnlock()
		if ready {
			return cached
		}
		// Only startup can reach this path. The first gossip round immediately
		// installs the immutable cache used by subsequent scraper requests.
		return buildSnapshot()
	}
	var det *detector

	// 中控角色是本机 bootstrap 配置,不是渲染产物 —— 绝大多数节点没有它。
	ctl, pw, controlErr := LoadControl(ControlPath)
	if ctl != nil {
		trafficHistoryStatus = "unavailable"
		cfg.PublisherHealth = PublisherHealthPath
		if controlErr != nil {
			// 声明了中控角色却配不全,必须看得见。悄悄退化成只读的话,
			// 人会以为是自己没登录。
			fmt.Fprintf(logw, "! 中控配置有问题,写操作关闭:%v\n", controlErr)
		}
		deps.Operator = pw
		deps.Control = controlDeps(ctl)
		// 事件只在中控记。每个节点都有同样的视图(靠转述),记 N 份只会
		// 让人不知道该看哪份 —— 但代价是**中控停了就不记事件**。
		det = newDetector(EventsPath, 30*24*time.Hour)
		det.statePath = StatePath
		// 把上一次的"已知起点"接回来 —— 否则每次重启,面板上所有问题的
		// 时长都归零,而那正是它最该说话的时候。读不到就从头开始,不报错。
		if prev, err := LoadTrackedState(StatePath); err == nil {
			det.restore(prev)
		}
		deps.Events = func(limit int) []webui.EventView { return recentEvents(EventsPath, now(), limit, det.current) }
		deps.Unresolved = func() []webui.UnresolvedView {
			return unresolvedNow(EventsPath, now(), det.trackedState(now()))
		}
		trafficStore, err = trafficstore.NewStore(TrafficPath, trafficRetention, trafficMaximumGap)
		if err != nil {
			trafficHistoryError = err.Error()
			fmt.Fprintf(logw, "! 初始化中控流量历史失败:%v\n", err)
		} else if err := trafficStore.Compact(now()); err != nil {
			// A corrupt or unsafe existing history must not be appended to. Current
			// status remains available while the operator repairs the local file.
			fmt.Fprintf(logw, "! 读取中控流量历史失败，历史记录关闭:%v\n", err)
			trafficHistoryError = err.Error()
			_ = trafficStore.Close()
			trafficStore = nil
		} else {
			trafficHistoryStatus = "available"
			trafficHistoryError = ""
		}
		fmt.Fprintf(logw, "中控角色:%s(事件 %s,现状 %s,流量历史 %s)\n", ctl.SSOTPath, EventsPath, StatePath, TrafficPath)
	} else if controlErr != nil {
		fmt.Fprintf(logw, "! 读 %s 失败:%v\n", ControlPath, controlErr)
	}
	if trafficStore != nil {
		defer trafficStore.Close()
	}
	if ctl != nil {
		mux.Handle("/api/client/report", newClientReportReceiver(tbl, ctl, now, maxAge, logw))
	}
	mux.Handle("/", webui.Handler(deps))

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		// 隧道健康和配置自检是**当场**算的,便宜。观测不是 —— 量一遍目标
		// 要好几秒,每次被拉都重量会让拉取方超时,也会把探测流量放大成
		// 拉取次数的倍数。所以观测走后台节奏,这里只交出最近一份。
		at := now()
		st := Collect(cfg, at)
		attachObservationState(cfg, tbl, st, at, maxAge)
		writeStatus(w, st, at)
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
		ticker := time.NewTicker(gp)
		defer ticker.Stop()
		lastTrafficCompact := now().UTC()
		for {
			st := gossip(cfg, tbl, now, maxAge)
			// 每轮转述之后比一次:这一轮和上一轮有什么不同。
			// **只有变化才写下来** —— 状态本身已经在 /status 里了。
			{
				at := now()
				attachObservationState(cfg, tbl, st, at, maxAge)
				view := buildView(cfg, st, at)
				if trafficStore != nil {
					frame := trafficFrameFromView(view, at)
					if len(frame.Counters) > 0 || len(frame.Edges) > 0 {
						if err := trafficStore.Append(frame); err != nil {
							fmt.Fprintf(logw, "! 记流量历史失败:%v\n", err)
						}
					}
					if at.UTC().Sub(lastTrafficCompact) >= 6*time.Hour {
						if err := trafficStore.Compact(at); err != nil {
							fmt.Fprintf(logw, "! 压缩流量历史失败:%v\n", err)
						} else {
							lastTrafficCompact = at.UTC()
						}
					}
				}
				decorateView(&view, at)
				trafficCacheMu.Lock()
				trafficCache = view
				trafficCacheReady = true
				trafficCacheMu.Unlock()
				if det != nil {
					evs, err := det.observe(view, at)
					if err != nil {
						fmt.Fprintf(logw, "! 记事件失败:%v\n", err)
					}
					for i := range evs {
						fmt.Fprintf(logw, "· %s %s %s:%s → %s\n",
							evs[i].Node, evs[i].Kind, evs[i].Subject, evs[i].From, evs[i].To)
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
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

	var reflectorSrv *http.Server
	if cfg.LinkReflector {
		reflectorMux := http.NewServeMux()
		reflectorMux.HandleFunc(linkMetricProbePath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Loom-Node", cfg.Node)
			w.Header().Set("X-Loom-Probe-Bytes", fmt.Sprint(len(linkMetricReflectorBody)))
			_, _ = w.Write(linkMetricReflectorBody)
		})
		ln, err := net.Listen("tcp", linkMetricReflectorAddr)
		if err != nil {
			fmt.Fprintf(logw, "! 无法监听 Hy2 链路探测反射器 %s:%v\n", linkMetricReflectorAddr, err)
		} else {
			reflectorSrv = &http.Server{
				Handler: reflectorMux, ReadHeaderTimeout: 5 * time.Second,
			}
			fmt.Fprintf(logw, "监听 Hy2 链路探测反射器 %s\n", linkMetricReflectorAddr)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := reflectorSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}()
		}
	}

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	if reflectorSrv != nil {
		_ = reflectorSrv.Shutdown(shutCtx)
	}
	wg.Wait()
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
