package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

const (
	deviceInventoryHeartbeat = 20 * time.Second
	deviceInventoryResync    = time.Minute
	deviceInventoryWriteWait = 5 * time.Second
)

type deviceInventoryLiveMessage struct {
	Type     string           `json:"type"`
	Snapshot *browserSnapshot `json:"snapshot,omitempty"`
}

// deviceInventoryLiveHandler 让浏览器投影与 JSON API 共用同一可信读取边界。
// WebSocket 只负责交付，不能把 registry 字样或未签名观测提升为 Online。
func deviceInventoryLiveHandler(d Deps) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "[实时设备列表] 只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" && r.URL.RawQuery != "archived=1" {
			http.Error(w, "[实时设备列表] 查询参数无效", http.StatusBadRequest)
			return
		}
		if !headerContainsToken(r.Header.Get("Connection"), "upgrade") ||
			!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
			w.Header().Set("Upgrade", "websocket")
			http.Error(w, "[实时设备列表] 需要 WebSocket upgrade", http.StatusUpgradeRequired)
			return
		}

		server := websocket.Server{
			Config: websocket.Config{Header: http.Header{
				"Cache-Control":          []string{"no-store"},
				"X-Content-Type-Options": []string{"nosniff"},
			}},
			Handshake: deviceInventoryWebSocketHandshake,
			Handler: func(ws *websocket.Conn) {
				streamDeviceInventory(ws, d, r.URL.Query().Get("archived") == "1")
			},
		}
		server.ServeHTTP(w, r)
	})
}

func deviceInventoryWebSocketHandshake(config *websocket.Config, r *http.Request) error {
	origin, err := websocket.Origin(config, r)
	if err != nil || origin == nil || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("[实时设备列表] WebSocket Origin 无效")
	}
	config.Origin = origin
	// 生产请求已经由 private HTTPS listener 精确核对 Origin，再经 root-only
	// Unix socket 转发并改写为这个内部 Host。直接嵌入 Handler 的调用方仍须
	// 使用与请求完全同源的 Origin。
	if r.Host == "loom-control-ui.local" {
		if origin.Scheme != "https" || origin.Host == "" {
			return errors.New("[实时设备列表] WebSocket 必须来自 private HTTPS 页面")
		}
		return nil
	}
	wantScheme := "http"
	if r.TLS != nil {
		wantScheme = "https"
	}
	if origin.Scheme != wantScheme || origin.Host != r.Host || (origin.Path != "" && origin.Path != "/") {
		return errors.New("[实时设备列表] WebSocket 必须同源")
	}
	return nil
}

func streamDeviceInventory(ws *websocket.Conn, d Deps, showArchived bool) {
	ws.MaxPayloadBytes = 1024
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var ignored []byte
			if err := websocket.Message.Receive(ws, &ignored); err != nil {
				return
			}
		}
	}()

	changes := deviceInventoryChanges(d)
	heartbeat := time.NewTicker(deviceInventoryHeartbeat)
	defer heartbeat.Stop()
	refresh := time.NewTimer(time.Hour)
	defer refresh.Stop()
	lastJSON := ""

	sendInventory := func(force bool) bool {
		snapshot := loadBrowserSnapshot(d)
		inventory := ClientInventory{Clients: snapshot.Inventory.Devices}
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return false
		}
		if !force && string(encoded) == lastJSON {
			resetDeviceInventoryTimer(refresh, nextDeviceInventoryRefresh(inventory, deviceNow(d)))
			return true
		}
		_ = ws.SetWriteDeadline(time.Now().Add(deviceInventoryWriteWait))
		if err := websocket.JSON.Send(ws, deviceInventoryLiveMessage{Type: "snapshot", Snapshot: &snapshot}); err != nil {
			return false
		}
		lastJSON = string(encoded)
		resetDeviceInventoryTimer(refresh, nextDeviceInventoryRefresh(inventory, deviceNow(d)))
		return true
	}

	if !sendInventory(true) {
		return
	}
	for {
		select {
		case <-done:
			return
		case <-changes:
			changes = deviceInventoryChanges(d)
			if !sendInventory(false) {
				return
			}
		case <-refresh.C:
			if !sendInventory(false) {
				return
			}
		case <-heartbeat.C:
			_ = ws.SetWriteDeadline(time.Now().Add(deviceInventoryWriteWait))
			if err := websocket.JSON.Send(ws, deviceInventoryLiveMessage{Type: "heartbeat"}); err != nil {
				return
			}
		}
	}
}

func deviceInventoryChanges(d Deps) <-chan struct{} {
	if d.DeviceChanges == nil {
		return nil
	}
	return d.DeviceChanges()
}

func deviceNow(d Deps) time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func nextDeviceInventoryRefresh(inventory ClientInventory, now time.Time) time.Duration {
	next := deviceInventoryResync
	for _, device := range inventory.Clients {
		deadlines := []struct {
			value string
			lease time.Duration
		}{
			{device.HeartbeatAt, clientPresenceStaleAfter},
			{device.LastSeenAt, clientRuntimeStaleAfter},
		}
		for _, deadline := range deadlines {
			observed, ok := parseClientObservedAt(deadline.value)
			if !ok {
				continue
			}
			remaining := observed.Add(deadline.lease).Sub(now)
			if remaining <= 0 {
				// 已经过期的嵌入快照不能形成热循环。
				continue
			}
			remaining += time.Millisecond
			if remaining < next {
				next = remaining
			}
		}
	}
	return next
}

func resetDeviceInventoryTimer(timer *time.Timer, after time.Duration) {
	if after <= 0 {
		after = time.Millisecond
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(after)
}

func headerContainsToken(value, want string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}
