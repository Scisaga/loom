package report

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"time"

	"loom/internal/nodepresence"
	"loom/internal/webui"
)

const serverPresenceMaxBody = 64 << 10

type presenceBatch struct {
	Heartbeats []nodepresence.Heartbeat `json:"heartbeats"`
}

type serverPresenceReceiver struct {
	table    *table
	self     string
	expected map[string]bool
	now      func() time.Time
}

func newServerPresenceReceiver(tbl *table, cfg *Config, now func() time.Time) *serverPresenceReceiver {
	expected := make(map[string]bool, len(cfg.ExpectedNodes)+1)
	expected[cfg.Node] = true
	for _, node := range cfg.ExpectedNodes {
		expected[node] = true
	}
	return &serverPresenceReceiver{table: tbl, self: cfg.Node, expected: expected, now: now}
}

// ServeHTTP 是 overlay 内的心跳转发边界。它只接收最小签名心跳数组，绝不
// 接收 Status、Observation 或可由转发方改写的在线布尔值。
func (h *serverPresenceReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "[在线心跳] 只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "[在线心跳] 不接受查询参数", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "[在线心跳] 必须使用 application/json", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > serverPresenceMaxBody {
		http.Error(w, "[在线心跳] 转发批次超过大小限制", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, serverPresenceMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var batch presenceBatch
	if err := decoder.Decode(&batch); err != nil {
		writePresenceDecodeError(w, err)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writePresenceDecodeError(w, errors.New("JSON 后还有额外值"))
		return
	}
	if len(batch.Heartbeats) == 0 || len(batch.Heartbeats) > nodepresence.MaxBatchEntries {
		http.Error(w, "[在线心跳] 转发条目数量无效", http.StatusBadRequest)
		return
	}

	at := h.now().UTC()
	validated := make([]nodepresence.Heartbeat, 0, len(batch.Heartbeats))
	seen := make(map[string]bool, len(batch.Heartbeats))
	for _, heartbeat := range batch.Heartbeats {
		if heartbeat.Node == h.self {
			continue
		}
		if seen[heartbeat.Node] || !h.expected[heartbeat.Node] {
			http.Error(w, "[在线心跳] 转发身份未获授权", http.StatusForbidden)
			return
		}
		seen[heartbeat.Node] = true
		publicKey, err := h.table.presencePublicKey(heartbeat.Node)
		if err != nil {
			http.Error(w, "[在线心跳] 转发身份未获授权", http.StatusForbidden)
			return
		}
		if _, err := nodepresence.Verify(heartbeat, publicKey, at, nodepresence.MaximumTransit); err != nil {
			http.Error(w, "[在线心跳] 转发身份未获授权", http.StatusForbidden)
			return
		}
		validated = append(validated, heartbeat)
	}
	for _, heartbeat := range validated {
		h.table.putPresenceVerified(heartbeat, at)
	}
	w.WriteHeader(http.StatusNoContent)
}

func writePresenceDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "[在线心跳] 转发批次超过大小限制", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "[在线心跳] 转发格式错误", http.StatusBadRequest)
}

func (t *table) presencePublicKey(node string) (*ecdsa.PublicKey, error) {
	t.mu.Lock()
	observation := t.by[node]
	if observation != nil {
		copy := *observation
		observation = &copy
	}
	t.mu.Unlock()
	if observation == nil || !observationNeedsVerification(observation, 0) {
		return nil, errors.New("[在线心跳] 尚无已验签节点身份")
	}
	encoded, err := observationPublicKey(observation)
	if err != nil {
		return nil, err
	}
	return nodepresence.ParsePublicKey(encoded)
}

func attachPresenceView(tbl *table, view *webui.View) {
	if tbl == nil || view == nil {
		return
	}
	byNode := tbl.presenceView()
	for i := range view.Nodes {
		view.Nodes[i].PresenceAt = byNode[view.Nodes[i].ID]
	}
}

// runServerPresence 每五秒只签一次三字段心跳，并把当前仍可转发的签名包沿
// 既有邻居图传播。完整 gossip/Observation 仍由 GossipPeriod 独立运行。
func runServerPresence(ctx context.Context, cfg *Config, tbl *table, now func() time.Time, logw io.Writer) {
	ticker := time.NewTicker(nodepresence.Period)
	defer ticker.Stop()
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, MaxIdleConns: max(2, len(cfg.Neighbors)*2),
			MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute},
		Timeout: 3 * time.Second,
	}
	defer client.CloseIdleConnections()
	lastSignError := ""

	pulse := func() {
		pulseAt := now().UTC()
		key, err := os.ReadFile(nodeKeyPath)
		if err == nil {
			var heartbeat nodepresence.Heartbeat
			heartbeat, err = nodepresence.Sign(cfg.Node, pulseAt, key)
			if err == nil {
				tbl.putPresenceVerified(heartbeat, pulseAt)
			}
		}
		if err != nil {
			message := err.Error()
			if message != lastSignError {
				fmt.Fprintf(logw, "! 在线心跳签名不可用:%v\n", err)
			}
			lastSignError = message
		} else {
			lastSignError = ""
		}
	}

	send := func(heartbeats []nodepresence.Heartbeat) {
		if len(heartbeats) == 0 || len(cfg.Neighbors) == 0 {
			return
		}
		body, err := json.Marshal(presenceBatch{Heartbeats: heartbeats})
		if err != nil || len(body) > serverPresenceMaxBody {
			return
		}
		parallelProbe(len(cfg.Neighbors), func(i int) {
			request, err := http.NewRequestWithContext(ctx, http.MethodPost,
				"http://"+cfg.Neighbors[i].Addr+"/presence", bytes.NewReader(body))
			if err != nil {
				return
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
		})
	}
	flush := func() {
		for {
			heartbeats := tbl.takePendingPresences(nodepresence.MaxBatchEntries)
			if len(heartbeats) == 0 {
				return
			}
			send(heartbeats)
		}
	}

	pulse()
	changes := tbl.presenceChanges()
	flush()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pulse()
		case <-changes:
		}
		changes = tbl.presenceChanges()
		flush()
	}
}
