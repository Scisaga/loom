package report

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Runtime owns the report handler and its observation workers. A caller may
// serve Handler on an existing private listener instead of opening another
// port.
type Runtime struct {
	handler http.Handler
	wait    sync.WaitGroup
	mu      sync.Mutex
	err     error
}

func Start(ctx context.Context, cfg *Config, now func() time.Time, logw io.Writer) (*Runtime, error) {
	gp, err := cfg.Gossip()
	if err != nil {
		return nil, err
	}
	maxAge, err := cfg.ObsStale()
	if err != nil {
		return nil, err
	}
	tbl := newTable(cfg.AttestationMinVersion)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		at := now()
		st := Collect(cfg, at)
		attachObservationState(cfg, tbl, st, at, maxAge)
		writeStatus(w, st, at)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	runtime := &Runtime{handler: mux}
	runtime.wait.Add(1)
	go func() {
		defer runtime.wait.Done()
		ticker := time.NewTicker(gp)
		defer ticker.Stop()
		for {
			_ = gossip(cfg, tbl, now, maxAge)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
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
		listener, listenErr := net.Listen("tcp", linkMetricReflectorAddr)
		if listenErr != nil {
			fmt.Fprintf(logw, "! 无法监听 Hy2 链路探测反射器 %s:%v\n", linkMetricReflectorAddr, listenErr)
		} else {
			server := &http.Server{Handler: reflectorMux, ReadHeaderTimeout: 5 * time.Second}
			fmt.Fprintf(logw, "监听 Hy2 链路探测反射器 %s\n", linkMetricReflectorAddr)
			runtime.wait.Add(2)
			go func() {
				defer runtime.wait.Done()
				if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
					runtime.record(serveErr)
				}
			}()
			go func() {
				defer runtime.wait.Done()
				<-ctx.Done()
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdown)
			}()
		}
	}
	return runtime, nil
}

func (runtime *Runtime) Handler() http.Handler { return runtime.handler }
func (runtime *Runtime) Wait() error {
	runtime.wait.Wait()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.err
}
func (runtime *Runtime) record(err error) {
	runtime.mu.Lock()
	if runtime.err == nil {
		runtime.err = err
	}
	runtime.mu.Unlock()
}
