package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestWebChromeHistoryProgressDuringReportUpdates(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser scheduling acceptance")
	}
	p := relayProjectionFixture(t)
	reverse := p.NetworkIntent.Links[0]
	reverse.ID = "demo-link-reverse"
	reverse.FromNodeID, reverse.ToNodeID = reverse.ToNodeID, reverse.FromNodeID
	reverse.FromResourceID, reverse.ResourceID = reverse.ResourceID, reverse.FromResourceID
	for _, resource := range p.NetworkIntent.Resources {
		if resource.ID == reverse.ResourceID {
			address, err := WireGuardAccessAddress(resource, "")
			if err != nil {
				t.Fatal(err)
			}
			reverse.ProbeTarget.ResourceID, reverse.ProbeTarget.Host = resource.ID, address.String()
		}
	}
	p.NetworkIntent.Links = append(p.NetworkIntent.Links, reverse)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, []DeviceReport{})
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: &Runtime{Authority: &Authority{root: root, projection: p}, Reports: store}}
	normal := server.AdminHandler()
	var revoked atomic.Bool
	// Stable authorization with a changing last-report marker is a UI input.
	// History still comes from the real empty original-report collection.
	projection := func() WebSnapshot {
		value := buildWebSnapshot(p, true, true, true)
		for i := range value.Devices {
			value.Devices[i].LastReportAt = time.Now().UTC().Format(time.RFC3339Nano)
			if revoked.Load() {
				value.Devices[i].Authorized = false
			}
		}
		if revoked.Load() {
			for i := range value.Links {
				value.Links[i].Authorized = false
			}
		}
		return value
	}
	var trafficReads, completedLinkReads atomic.Int64
	var queryMu sync.Mutex
	var linkQueries []string
	stop := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/control/ui/snapshot":
			_ = json.NewEncoder(w).Encode(projection())
			return
		case "/api/control/ui/live":
			connection, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer connection.CloseNow()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				if wsjson.Write(r.Context(), connection, projection()) != nil {
					return
				}
				select {
				case <-stop:
					return
				case <-r.Context().Done():
					return
				case <-ticker.C:
				}
			}
		case "/api/control/ui/link-history":
			queryMu.Lock()
			linkQueries = append(linkQueries, r.URL.Query().Get("link"))
			queryMu.Unlock()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(350 * time.Millisecond):
				completedLinkReads.Add(1)
			}
		case "/api/control/ui/traffic-history":
			trafficReads.Add(1)
		}
		normal.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	defer close(stop)
	debug := openCommandChrome(t, httpServer.URL+"/topology?link=demo-link-reverse")
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.topology-traffic-card [data-traffic-endpoint]').length===48&&document.querySelectorAll('[data-link-history] .link-hour').length===48`)
	if trafficReads.Load() == 0 || completedLinkReads.Load() < 2 {
		t.Fatal("new reports starved other history scopes or repeatedly cancelled in-flight reads")
	}
	queryMu.Lock()
	first := linkQueries[0]
	queryMu.Unlock()
	if first != "demo-link-reverse" {
		t.Fatal("selected link RTT queued behind an unrelated link", first)
	}
	revoked.Store(true)
	waitChromeEvaluation(t, debug, `document.querySelector('.topology-traffic-card').textContent.includes('WG traffic unavailable for this authorization')&&document.querySelectorAll('[data-traffic-endpoint]').length===0&&document.querySelectorAll('[data-link-history] .link-hour').length===0`)
	// Allow the deliberately slower, previously authorized response to finish.
	time.Sleep(400 * time.Millisecond)
	if chromeDo(t, debug, `document.querySelectorAll('[data-traffic-endpoint], [data-link-history] .link-hour').length`) != float64(0) {
		t.Fatal("a late history response restored withdrawn authorization")
	}
}
