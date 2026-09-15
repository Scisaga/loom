package clientruntime

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"loom/internal/agent"
)

// WindowsUnderlayMonitor 和 probe registry 一样由进程持有；切换配置、Direct
// 或重启数据面都不能销毁它。只有 OS 事件后的有效网络快照变化才推进预算代次。
type WindowsUnderlayMonitor struct {
	mu         sync.Mutex
	read       func() (windowsUnderlaySnapshot, error)
	snapshot   windowsUnderlaySnapshot
	generation uint64
	available  bool
	problem    string
	changed    chan struct{}
	closed     bool
	stop       func()
	stopOnce   sync.Once
}

type windowsUnderlayRoute struct {
	prefix netip.Prefix
	source string
	metric uint64
	index  uint32
}

type windowsUnderlaySnapshot struct {
	key    string
	routes []windowsUnderlayRoute
}

// 不使用捕获流量后的全局最佳路由；它可能指向 Loom 自己的 TUN。只在
// gateway underlay 的路由中按最长前缀、有效 metric 和稳定接口序选源地址。
func (snapshot windowsUnderlaySnapshot) source(address string) string {
	destination, err := netip.ParseAddr(address)
	var best *windowsUnderlayRoute
	for i := range snapshot.routes {
		route := &snapshot.routes[i]
		if err != nil && route.prefix.Bits() != 0 || err == nil && !route.prefix.Contains(destination.Unmap()) {
			continue
		}
		if best == nil || route.prefix.Bits() > best.prefix.Bits() ||
			route.prefix.Bits() == best.prefix.Bits() && (route.metric < best.metric || route.metric == best.metric && route.index < best.index) {
			best = route
		}
	}
	if best == nil {
		return ""
	}
	return best.source
}

func newWindowsUnderlayMonitor(ctx context.Context, read func() (windowsUnderlaySnapshot, error),
	register func(func()) (func(), error),
) *WindowsUnderlayMonitor {
	monitor := &WindowsUnderlayMonitor{read: read, changed: make(chan struct{})}
	// 先注册再读取，关闭启动快照与订阅之间的事件丢失窗口。回调只读本机
	// 网络信息；不发送包，不等待 Agent，也不在回调线程内取消订阅。
	stop, err := register(monitor.refresh)
	if err != nil {
		monitor.mu.Lock()
		monitor.available = false
		monitor.problem = err.Error()
		monitor.closed = true
		monitor.mu.Unlock()
		return monitor // 不可靠的事件源不能授权主动探测，数据面仍可启动。
	}
	monitor.stop = stop
	monitor.refresh()
	context.AfterFunc(ctx, monitor.Close)
	return monitor
}

// Close 只在进程退出时调用，不属于 Agent/profile 生命周期。取消必须在
// 不持有回调需要的锁时执行；返回时所有已经进入的 OS 回调均已退出。
func (monitor *WindowsUnderlayMonitor) Close() {
	if monitor == nil {
		return
	}
	monitor.stopOnce.Do(func() {
		if monitor.stop != nil {
			monitor.stop()
		}
		monitor.mu.Lock()
		defer monitor.mu.Unlock()
		if monitor.closed {
			return
		}
		monitor.closed = true
		monitor.available = false
		monitor.problem = "Windows 底层网络事件监听已停止"
		close(monitor.changed)
		monitor.changed = nil
	})
}

func (monitor *WindowsUnderlayMonitor) refresh() {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.closed {
		return
	}
	snapshot, err := monitor.read()
	available := err == nil && len(snapshot.routes) > 0
	changed := monitor.available != available
	if err == nil {
		if monitor.snapshot.key != snapshot.key {
			monitor.generation++
			changed = true
		}
		monitor.snapshot = snapshot
	}
	// 读取失败使证据失效，但不伪造新网络代；恢复相同快照只能复用旧预算。
	monitor.available = available
	monitor.problem = ""
	if err != nil {
		monitor.problem = err.Error()
	} else if !available {
		monitor.problem = "Windows 没有可用于入口测量的 gateway underlay"
	}
	if changed {
		close(monitor.changed)
		monitor.changed = make(chan struct{})
	}
}

func (monitor *WindowsUnderlayMonitor) inputs(base agent.ClientOptions) (agent.ClientOptions, <-chan struct{}) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	out := base
	out.UnderlayGeneration = fmt.Sprintf("windows-underlay-%d", monitor.generation)
	out.EntryProbesUnavailable = !monitor.available
	out.EntryProbesError = monitor.problem
	out.Entries = append([]agent.ClientEntry(nil), base.Entries...)
	for i := range out.Entries {
		out.Entries[i].Source = monitor.snapshot.source(out.Entries[i].Address)
	}
	return out, monitor.changed
}

var processUnderlayMu sync.Mutex
var processUnderlay *WindowsUnderlayMonitor

// ProcessWindowsUnderlay 在第一次数据面激活前开始监听，Direct 同样只订阅
// OS 事件，不冻结入口、不启动 Agent，也不消耗任何探测预算。
func ProcessWindowsUnderlay() *WindowsUnderlayMonitor {
	processUnderlayMu.Lock()
	defer processUnderlayMu.Unlock()
	if processUnderlay == nil {
		processUnderlay = newWindowsUnderlayMonitor(context.Background(), readWindowsUnderlay, registerWindowsUnderlayChanges)
	}
	return processUnderlay
}

func CloseProcessWindowsUnderlay() {
	processUnderlayMu.Lock()
	monitor := processUnderlay
	processUnderlayMu.Unlock()
	monitor.Close()
}
