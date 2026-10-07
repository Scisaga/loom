package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestQuietWebSocketStopsReadingAfterBrowserDisconnect(t *testing.T) {
	for _, abrupt := range []bool{false, true} {
		name := "close-frame"
		if abrupt {
			name = "connection-loss"
		}
		t.Run(name, func(t *testing.T) {
			server, root, ca := adminServerFixture(t)
			admin, pair := adminTestLeaf(t, filepath.Dir(root), ca, "demo-live-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			if _, _, err := server.HandleOperation(context.Background(), adminPut(admin, "demo-live-admin-grant")); err != nil {
				t.Fatal(err)
			}
			tlsConfig, err := browserTLSConfig(server.Config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exited := make(chan struct{})
			handler := server.Handler()
			h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(exited)
				handler.ServeHTTP(w, r.WithContext(ctx))
			}))
			server.Channel = &PrivateChannel{config: PrivateChannelConfig{Listen: []string{h.Listener.Addr().String()}}}
			h.TLS = tlsConfig
			h.StartTLS()
			defer h.Close()
			pool := x509.NewCertPool()
			pool.AddCert(ca.certificate)
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}}}
			defer client.CloseIdleConnections()
			request, stop := context.WithTimeout(ctx, 8*time.Second)
			defer stop()
			ws, _, err := websocket.Dial(request, "wss"+strings.TrimPrefix(h.URL, "https")+"/api/control/ui/live", &websocket.DialOptions{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
			if _, _, err := ws.Read(request); err != nil {
				t.Fatal(err)
			}
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				if abrupt {
					_ = ws.CloseNow()
				} else {
					_ = ws.Close(websocket.StatusNormalClosure, "browser left")
				}
			}()
			// No authority, report or clock change can trigger another data write.
			// Disconnect itself must release the handler and its repeated reads.
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				cancel()
				_ = ws.CloseNow()
				<-closed
				t.Fatal("quiet disconnected browser kept its snapshot reader alive")
			}
			<-closed
		})
	}
}
