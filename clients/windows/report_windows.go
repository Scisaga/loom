//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"loom/internal/clientcore"
	"loom/internal/clientreport"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/netx"
)

type windowsReporter struct {
	mu              sync.Mutex
	state           clientRuntimeState
	worker          *clientreport.Worker
	stop            func()
	revision        uint64
	sampledRevision uint64
	interrupt       context.CancelFunc
	check           func(context.Context, *clientruntime.WindowsHealthPlan) []string
	readPaths       func(context.Context, *clientruntime.WindowsAgent, time.Time) (*clientreport.AgentState, error)
}

func (reporter *windowsReporter) update(state clientRuntimeState) {
	reporter.mu.Lock()
	changed := reporter.state.Applied != state.Applied || reporter.state.Ready != state.Ready || reporter.state.Exited != state.Exited || reporter.state.Health != state.Health || reporter.state.Agent != state.Agent || reporter.state.Generation != state.Generation
	if changed {
		reporter.revision++
		if reporter.interrupt != nil {
			reporter.interrupt()
		}
	}
	reporter.state = state
	reporter.mu.Unlock()
	if changed && state.active() {
		reporter.worker.Trigger()
	}
}

func startWindowsReporter(root string, protector clientsecret.Protector, config clientupdate.Config,
	client *http.Client) (*windowsReporter, error) {
	identity, err := readWindowsJoinIdentity(root, protector)
	if err != nil {
		return nil, errors.New("无法读取 DPAPI 上报身份")
	}
	retained := false
	defer func() {
		if !retained {
			clearPreparedIdentity(&identity)
		}
	}()
	endpoint, err := clientreport.Endpoint(identity.Endpoint)
	if err != nil {
		return nil, err
	}
	cert, err := os.ReadFile(filepath.Join(root, "tls", "node.crt"))
	if err != nil {
		return nil, errors.New("无法读取上报节点证书")
	}
	ca, err := os.ReadFile(filepath.Join(root, "tls", "ca.crt"))
	if err != nil {
		return nil, errors.New("无法读取上报 CA")
	}
	if client == nil {
		dns := ""
		if len(config.DNS) > 0 {
			dns = config.DNS[0]
		}
		client = netx.Client(dns, 5*time.Second)
	}
	reporter := &windowsReporter{check: clientruntime.CheckWindowsHealth}
	reporter.worker = clientreport.NewWorker(func(ctx context.Context, at time.Time) (*clientreport.Observation, error) {
		state, problems, agentState, ok := reporter.sampleReport(ctx, filepath.Join(root, "state", "preference.json"), at)
		if !ok {
			return nil, nil
		}
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		if !reporter.state.active() || reporter.sampledRevision != reporter.revision {
			return nil, nil
		}
		return clientreport.BuildWithAgent(config.NodeID, state.Applied, problems, agentState, at, identity.PrivateKeyPEM, cert, ca)
	}, func(ctx context.Context, o *clientreport.Observation) clientreport.Result {
		reporter.mu.Lock()
		if !reporter.state.active() || reporter.sampledRevision != reporter.revision {
			reporter.mu.Unlock()
			return clientreport.Result{Err: errors.New("本轮数据面已变化，丢弃旧健康结果")}
		}
		sendCtx, cancel := context.WithCancel(ctx)
		generation := reporter.state.Generation
		activeAgent, revision := reporter.state.Agent, reporter.revision
		reporter.interrupt = cancel
		reporter.mu.Unlock()
		defer cancel()
		if generation != nil {
			stop := context.AfterFunc(generation, cancel)
			defer stop()
			if generation.Err() != nil {
				cancel()
			}
		}
		result, observations := clientreport.SendWithObservations(sendCtx, client, endpoint, o)
		if result.Err == nil && result.ObservationsErr == nil && len(observations) > 0 {
			reporter.mu.Lock()
			current := reporter.state.active() && reporter.revision == revision && reporter.state.Agent == activeAgent
			reporter.mu.Unlock()
			if current && sendCtx.Err() == nil {
				result.ObservationsErr = activeAgent.IngestObservations(observations, ca, time.Now())
				if activeAgent != nil && result.ObservationsErr == nil {
					log.Printf("Windows server observations: verified %d source snapshots", len(observations))
				}
			}
		}
		return result
	}, func(result clientreport.Result) {
		if result.Err == nil {
			log.Printf("Windows signed report: HTTP %d", result.Status)
		} else {
			log.Printf("Windows signed report: %v", result.Err)
		}
		if result.ObservationsErr != nil {
			log.Printf("Windows server observations: %v", result.ObservationsErr)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); reporter.worker.Run(ctx) }()
	reporter.stop = func() { cancel(); <-done; clearPreparedIdentity(&identity); client.CloseIdleConnections() }
	retained = true
	return reporter, nil
}

// §16.1：先读本机路径，再做网络健康探测；健康超时不能抹掉已经取得的路径证据。
func (reporter *windowsReporter) sampleReport(ctx context.Context, preferencePath string, at time.Time) (clientRuntimeState, []string, *clientreport.AgentState, bool) {
	reporter.mu.Lock()
	state, revision, read := reporter.state, reporter.revision, reporter.readPaths
	reporter.mu.Unlock()
	if !state.active() {
		return state, nil, nil, false
	}
	if read == nil {
		read = func(ctx context.Context, a *clientruntime.WindowsAgent, at time.Time) (*clientreport.AgentState, error) {
			return a.Report(ctx, at)
		}
	}
	agentState, pathErr := read(ctx, state.Agent, at)
	current, problems, ok := reporter.sampleHealth(ctx, preferencePath)
	reporter.mu.Lock()
	unchanged := revision == reporter.revision && reporter.sampledRevision == revision
	reporter.mu.Unlock()
	if !ok || !unchanged {
		return current, nil, nil, false
	}
	if pathErr != nil {
		problems = append(problems, "Agent 实际路径读取失败")
	}
	if agentState != nil {
		for _, s := range agentState.Selections {
			// §5.8：样本不足属于选优证据不足，不能冒充路径已经失败。
			if s.Health != nil && (s.Health.SelectedState == "failed" || s.Health.SelectedState == "degraded") {
				problems = append(problems, fmt.Sprintf("路由 %s 探测失败 %d/%d 次", s.Declaration, s.Health.SelectedFailures, s.Health.SelectedSamples))
			}
		}
	}
	return current, problems, agentState, true
}

// §16.1：网络探测不持有激活锁，切换/停止可取消；每轮结果只属于同一次 active。
func (reporter *windowsReporter) sampleHealth(ctx context.Context, preferencePath string) (clientRuntimeState, []string, bool) {
	reporter.mu.Lock()
	state, revision, check := reporter.state, reporter.revision, reporter.check
	if !state.active() {
		reporter.mu.Unlock()
		return state, nil, false
	}
	probeCtx, cancel := context.WithCancel(ctx)
	reporter.interrupt = cancel
	reporter.mu.Unlock()
	defer cancel()
	if state.Generation != nil {
		stop := context.AfterFunc(state.Generation, cancel)
		defer stop()
		if state.Generation.Err() != nil {
			cancel()
		}
	}
	preference, preferenceErr := clientcore.ReadPreference(preferencePath)
	problems := check(probeCtx, state.Health)
	if state.Health != nil {
		current, err := clientcore.ReadPreference(preferencePath)
		if preferenceErr != nil || err != nil {
			problems = []string{"无法核对当前路由偏好"}
		} else if current != preference {
			return state, nil, false
		}
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.revision != revision || !reporter.state.active() {
		return state, nil, false
	}
	reporter.sampledRevision = revision
	return state, problems, true
}
