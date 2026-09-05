//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"loom/internal/clientreport"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/netx"
)

type windowsReporter struct {
	mu     sync.Mutex
	state  clientRuntimeState
	worker *clientreport.Worker
	stop   func()
}

func (reporter *windowsReporter) update(state clientRuntimeState) {
	reporter.mu.Lock()
	changed := reporter.state.Applied != state.Applied || reporter.state.Ready != state.Ready || reporter.state.Exited != state.Exited
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
	reporter := &windowsReporter{}
	reporter.worker = clientreport.NewWorker(func(ctx context.Context, at time.Time) (*clientreport.Observation, error) {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		if !reporter.state.active() {
			return nil, nil
		}
		// 当前 Windows 宿主没有与 active 配置绑定的代表性端到端探测结果。
		// 进程存活和启动宽限期不能替代健康证据；先如实提供已激活快照，禁止虚报绿灯。
		problems := []string{"Windows 数据面缺少可信的端到端健康证据"}
		return clientreport.Build(config.NodeID, reporter.state.Applied, problems, at, identity.PrivateKeyPEM, cert, ca)
	}, func(ctx context.Context, o *clientreport.Observation) clientreport.Result {
		return clientreport.Send(ctx, client, endpoint, o)
	}, func(result clientreport.Result) {
		if result.Err == nil {
			log.Printf("Windows signed report: HTTP 204")
		} else {
			log.Printf("Windows signed report: %v", result.Err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); reporter.worker.Run(ctx) }()
	reporter.stop = func() { cancel(); <-done; clearPreparedIdentity(&identity); client.CloseIdleConnections() }
	retained = true
	return reporter, nil
}
