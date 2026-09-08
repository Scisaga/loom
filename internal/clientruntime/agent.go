package clientruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"loom/internal/agent"
	"loom/internal/clientreport"
	"loom/internal/version"
)

// §5.5、§16.1：每次激活拥有自己的 Agent 生命周期和证据目录，退出后不再提供报告。
type WindowsAgent struct {
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	config       *agent.Config
	statePath    string
	err          error
	once         sync.Once
	observations *agent.ObservationCache
}

func StartWindowsAgent(ctx context.Context, cfg *agent.Config, runtimeDir string, inputs ...agent.ClientOptions) (*WindowsAgent, error) {
	if ctx == nil || cfg == nil {
		return nil, errors.New("[§5.5] Agent 生命周期参数不完整")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// §12：宿主重配不能原地修改正在运行的 generation。
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var immutable agent.Config
	err = json.Unmarshal(encoded, &immutable)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	cfg = &immutable
	dir, err := newProtectedAgentDir(runtimeDir)
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	a := &WindowsAgent{ctx: child, cancel: cancel, done: make(chan struct{}), config: cfg, statePath: filepath.Join(dir, "state.json")}
	a.observations, err = agent.NewObservationCache(cfg)
	if err != nil {
		cancel()
		return nil, err
	}
	options := agent.ClientOptions{StatePath: a.statePath, Probe: pingWindowsEntry, Observations: a.observations}
	if len(inputs) > 0 {
		options.Entries = append([]agent.ClientEntry(nil), inputs[0].Entries...)
		options.HopCarriers = map[string][]string{}
		for tag, values := range inputs[0].HopCarriers {
			options.HopCarriers[tag] = append([]string(nil), values...)
		}
	}
	go func() {
		defer close(a.done)
		a.err = agent.RunClient(child, cfg, options)
	}()
	return a, nil
}

// IngestObservations 只接入当前激活代次；Direct 没有 Agent，不消费服务器证据。
// §16.1.2：拒收原因与设备健康分开，旧代次取消后不得向新回路输送事实。
func (a *WindowsAgent) IngestObservations(raw []json.RawMessage, ca []byte, now time.Time) error {
	if a == nil {
		return nil
	}
	select {
	case <-a.done:
		return errors.New("[§16.1.2] Agent 已退出，不能接收服务器观测")
	default:
	}
	return a.observations.Ingest(a.ctx, raw, ca, now)
}

// §5.5：调用者必须在停止数据面或下一次激活之前等待这个屏障。
func (a *WindowsAgent) Stop() error {
	if a == nil {
		return nil
	}
	a.once.Do(a.cancel)
	<-a.done
	return a.err
}
func (a *WindowsAgent) Done() <-chan struct{} {
	if a == nil {
		return nil
	}
	return a.done
}

func selectorReadback(ctx context.Context, cfg *agent.Config, selector string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.API+"/proxies/"+url.PathEscape(selector), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APISecret)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("[§7.3.1] Clash API 尚未就绪")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("[§7.3.1] Clash API 返回 HTTP %d", resp.StatusCode)
	}
	var state struct {
		Now  string `json:"now"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&state); err != nil {
		return "", err
	}
	if state.Type != "Selector" {
		return "", errors.New("[§5.5] 运行时端点不是 selector")
	}
	return state.Now, nil
}

// §7.3.1：进程存在不代表控制面已就绪；readback 必须属于本次授权集合。
func WaitWindowsAgentAPI(ctx context.Context, cfg *agent.Config) error {
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		ready := true
		for _, d := range cfg.Declarations {
			actual, err := selectorReadback(wait, cfg, d.Selector)
			if err != nil {
				ready = false
				break
			}
			found := false
			for _, c := range d.Candidates {
				found = found || c.Tag == actual
			}
			if !found {
				return errors.New("[§5.1] selector 实际值不在当前授权集合")
			}
		}
		if ready {
			return wait.Err()
		}
		select {
		case <-wait.Done():
			return wait.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// §16.1：链由当轮 GET 与当前签名 plan 映射；旧状态只在同一实例、同一实际候选且新鲜时补质量。
func (a *WindowsAgent) Report(ctx context.Context, now time.Time) (*clientreport.AgentState, error) {
	if a == nil {
		return nil, nil
	}
	if err := a.ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-a.done:
		return nil, errors.New("[§16.1] Agent 已退出")
	default:
	}
	read, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	st, err := agent.ReadState(a.statePath)
	if err != nil {
		return nil, err
	}
	out := &clientreport.AgentState{Node: a.config.Node, TS: now.UTC().Format(time.RFC3339), ComponentVersion: version.AgentProtocolVersion}
	for _, d := range a.config.Declarations {
		actual, err := selectorReadback(read, a.config, d.Selector)
		if err != nil {
			return nil, err
		}
		var chain []string
		found := false
		for _, c := range d.Candidates {
			if c.Tag == actual {
				chain = append([]string(nil), c.Chain...)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("[§16.1] selector 读回值无法映射当前签名 plan")
		}
		s := clientreport.AgentSelection{Declaration: d.ID, Selector: d.Selector, Candidate: actual, Chain: chain, UpdatedAt: out.TS, Reason: "unknown：本次 Agent 尚无当前候选的有效测量"}
		if st != nil && st.Node == a.config.Node {
			for _, old := range st.Selections {
				stale, _ := d.Stale()
				at, e := time.Parse(time.RFC3339, old.UpdatedAt)
				if old.Declaration != d.ID || old.Selector != d.Selector || old.Candidate != actual || len(old.DecisionScope) != 64 || e != nil || now.Sub(at) > stale || at.After(now.Add(2*time.Minute)) {
					continue
				}
				encoded, _ := json.Marshal(old.Health)
				if err := json.Unmarshal(encoded, &s.Health); err != nil {
					return nil, err
				}
				// §16.1：canonical v5 没有独立 scope 字段；使用已有、受签名保护的 reason，不扩展协议。
				s.Reason = old.Reason + " [decision_scope=" + old.DecisionScope + "]"
			}
		}
		out.Selections = append(out.Selections, s)
	}
	if err := read.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// §7.3.3：Direct 的界面观测同样来自实际 selector；偏好本身不能证明数据面已直连。
func (p *WindowsSelectorPlan) ReadDirectPaths(ctx context.Context, now time.Time) (*clientreport.AgentState, error) {
	if p == nil || !p.DirectAvailable() {
		return nil, errors.New("[§7.3.3] 当前签名计划没有完整直连授权")
	}
	cfg := p.DirectReadinessConfig()
	out := &clientreport.AgentState{Node: cfg.Node, TS: now.UTC().Format(time.RFC3339)}
	for _, d := range cfg.Declarations {
		actual, err := selectorReadback(ctx, cfg, d.Selector)
		if err != nil {
			return nil, err
		}
		found := false
		for _, candidate := range d.Candidates {
			found = found || candidate.Tag == actual && len(candidate.Chain) == 0
		}
		if !found {
			return nil, errors.New("[§7.3.3] 实际 selector 不属于当前签名直连候选")
		}
		out.Selections = append(out.Selections, clientreport.AgentSelection{
			Declaration: d.ID, Selector: d.Selector, Candidate: actual, UpdatedAt: out.TS,
			Reason: "直连模式；不进行 Agent 路径测量",
		})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// §13.5：随机代次目录继承受保护父目录；重启不把上代证据当成本代状态。
func newProtectedAgentDir(runtimeDir string) (string, error) {
	if err := validateRoot(runtimeDir); err != nil {
		return "", err
	}
	root := filepath.Join(runtimeDir, "agent")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	if err := protectAgentDirectory(root); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, "generation-")
}
