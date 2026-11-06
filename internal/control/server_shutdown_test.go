package control

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestServerCancelClosesLiveSession(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(root, "admin.sock")
	server := &Server{Runtime: runtime, Config: config, AdminSocket: socket}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("control did not stop normally", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("control shutdown did not finish")
		}
	}()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	ready, stopReady := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopReady()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var connection *websocket.Conn
	for connection == nil {
		connection, _, err = websocket.Dial(ready, "ws://loom.local/api/control/ui/live", &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{"loom.control.ui"}})
		if err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatal("control exited before its live session", err)
		case <-ready.Done():
			t.Fatal("control live session was unavailable", err)
		case <-ticker.C:
		}
	}
	defer connection.CloseNow()
	_, body, err := connection.Read(ready)
	var first webLiveMessage
	if err != nil || json.Unmarshal(body, &first) != nil || first.Schema != 3 || len(first.Snapshot) == 0 {
		t.Fatal("live handler did not deliver its initial real snapshot", err)
	}
	// The first frame proves this handler is active. No client disconnect,
	// authority mutation or runtime.Close can release it before this assertion.
	cancel()
	closed, stopClosed := context.WithTimeout(context.Background(), time.Second)
	defer stopClosed()
	if _, _, err := connection.Read(closed); err == nil || closed.Err() != nil {
		t.Fatal("server cancellation left its authenticated live session open", err)
	}
}
