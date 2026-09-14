package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestDeviceInventoryWebSocketPushesTrustedStateChanges(t *testing.T) {
	observed := time.Date(2026, 9, 13, 22, 48, 35, 0, time.UTC)
	var stateMu sync.Mutex
	now := observed.Add(3 * time.Second)
	changes := make(chan struct{})
	d := clientUIDeps()
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{{
			ID: "demo-phone", Name: "Phone", Platform: "android", Status: "ready", Membership: "active",
		}}}, nil
	}
	d.Now = func() time.Time {
		stateMu.Lock()
		defer stateMu.Unlock()
		return now
	}
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{{
			ID: "demo-phone", Declared: true, Health: "healthy", Source: "签名健康转述",
			ObservedAt: observed.Format(time.RFC3339), PresenceAt: observed.Format(time.RFC3339),
			AgeSec:  int(deviceNow(d).Sub(observed).Seconds()),
			Applied: "snapshot-live-0123456789",
		}}}
	}
	d.DeviceChanges = func() <-chan struct{} {
		stateMu.Lock()
		defer stateMu.Unlock()
		return changes
	}

	server := httptest.NewServer(Handler(d))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/control/device-inventory/live"
	connection, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))

	var initial deviceInventoryLiveMessage
	if err := websocket.JSON.Receive(connection, &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Type != "inventory" || !strings.Contains(initial.HTML, "Online") ||
		!strings.Contains(initial.HTML, `data-device-id="demo-phone"`) ||
		!strings.Contains(initial.HTML, "data-device-live-summary") {
		t.Fatalf("initial Device inventory update = %+v", initial)
	}

	stateMu.Lock()
	now = observed.Add(clientPresenceStaleAfter + time.Second)
	close(changes)
	changes = make(chan struct{})
	stateMu.Unlock()

	var stale deviceInventoryLiveMessage
	if err := websocket.JSON.Receive(connection, &stale); err != nil {
		t.Fatal(err)
	}
	if stale.Type != "inventory" || !strings.Contains(stale.HTML, "Stale") ||
		strings.Contains(stale.HTML, ">Online<") {
		t.Fatalf("stale Device inventory update = %+v", stale)
	}
}

func TestDeviceInventoryWebSocketRejectsCrossOriginAndPlainHTTP(t *testing.T) {
	d := clientUIDeps()
	server := httptest.NewServer(Handler(d))
	defer server.Close()
	path := "/api/control/device-inventory/live"
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + path
	config, err := websocket.NewConfig(wsURL, "https://cross-site.example")
	if err != nil {
		t.Fatal(err)
	}
	if connection, err := websocket.DialConfig(config); err == nil {
		_ = connection.Close()
		t.Fatal("cross-origin Device inventory WebSocket was accepted")
	}

	request := httptest.NewRequest(http.MethodGet, server.URL+path, nil)
	response := httptest.NewRecorder()
	Handler(d).ServeHTTP(response, request)
	if response.Code != http.StatusUpgradeRequired || response.Header().Get("Upgrade") != "websocket" {
		t.Fatalf("plain Device inventory request = %d headers=%v", response.Code, response.Header())
	}
}

func TestDeviceInventoryPageBootstrapsOnlyApprovedLiveScript(t *testing.T) {
	body := pageDevices(clientUIDeps(), clientPageState{}, false)
	if strings.Count(body, `<script>`+deviceInventoryLiveScript+`</script>`) != 1 ||
		!strings.Contains(body, "data-device-live-list") ||
		!strings.Contains(body, "data-device-live-state") {
		t.Fatal("Device inventory did not bootstrap its same-origin WebSocket updater")
	}
	if strings.Contains(deviceInventoryLiveScript, "innerHTML") || strings.Contains(deviceInventoryLiveScript, "eval(") {
		t.Fatal("Device inventory updater uses an unsafe HTML execution primitive")
	}
}

func TestDeviceInventorySchedulesOnlineLeaseExpiryWithoutAnotherReport(t *testing.T) {
	now := time.Date(2026, 9, 13, 22, 50, 0, 0, time.UTC)
	inventory := ClientInventory{Clients: []ClientView{{
		ID: "demo-phone", Platform: "android", DataPlaneStatus: "online",
		HeartbeatAt: now.Add(-10 * time.Second).Format(time.RFC3339),
		LastSeenAt:  now.Add(-10 * time.Second).Format(time.RFC3339),
	}}}
	want := 5*time.Second + time.Millisecond
	if got := nextDeviceInventoryRefresh(inventory, now); got != want {
		t.Fatalf("next live Device expiry refresh = %s, want %s", got, want)
	}
}
