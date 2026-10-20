package control

import (
	"context"
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

func TestWebChromeOverviewNavigationStartup(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for navigation startup acceptance")
	}
	for _, scenario := range []string{"snapshot", "snapshot error", "pending first read", "leave before budget"} {
		t.Run(scenario, func(t *testing.T) {
			projection := relayProjectionFixture(t)
			snapshot := buildWebSnapshot(projection, true, true, true)
			normal := (&Server{Runtime: &Runtime{Authority: &Authority{root: t.TempDir(), projection: projection}}}).AdminHandler()
			now := time.Date(2030, 1, 2, 12, 30, 0, 0, time.UTC)
			deviceCount := 0
			for _, device := range snapshot.Devices {
				if device.Authorized {
					deviceCount++
				}
			}
			if deviceCount < 2 {
				t.Fatal("fixture requires independent history scopes")
			}
			history := func(device string, amount U64) WebTrafficHistory {
				from := now.Truncate(time.Hour).Add(-23 * time.Hour).UnixMilli()
				buckets := make([]WebTrafficBucket, 24)
				for i := range buckets {
					buckets[i].Hour = from + int64(i)*time.Hour.Milliseconds()
				}
				buckets[23].Delta = &WebTrafficDelta{TXBytes: amount, CoveredMS: 1000, Intervals: 1, FirstAt: now.Add(-time.Second).UnixMilli(), LastAt: now.UnixMilli()}
				return WebTrafficHistory{Schema: 3, Scope: "device:" + device, From: from, Until: now.UnixMilli(), Devices: []WebDeviceTraffic{{DeviceID: device, Buckets: buckets}}}
			}
			var snapshots, requests, active, maximum, networkRequests atomic.Int64
			var mu sync.Mutex
			reads := map[string]int{}
			firstStarted := make(chan string, 1)
			firstReturned, releaseFirst := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
			held := scenario == "pending first read" || scenario == "leave before budget"
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/control/ui/snapshot":
					count := snapshots.Add(1)
					w.Header().Set("Cache-Control", "no-store")
					if scenario == "snapshot error" && count == 1 {
						http.Error(w, "demo initial snapshot failure", http.StatusServiceUnavailable)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(snapshot)
					return
				case "/api/control/ui/enrollment-options":
					_ = json.NewEncoder(w).Encode(map[string]any{"schema": 3})
					return
				case "/api/control/ui/events":
					_, _ = w.Write([]byte(`{"schema":3,"events":[],"query":{"until":"2030-01-02T00:00:00Z"}}`))
					return
				case "/api/control/ui/live":
					connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"loom.control.ui"}})
					if err != nil {
						return
					}
					defer connection.CloseNow()
					if wsjson.Write(r.Context(), connection, map[string]any{"schema": 3, "snapshot": snapshot}) == nil {
						_, _, _ = connection.Read(r.Context())
					}
					return
				case "/api/control/ui/traffic-history":
					device := r.URL.Query().Get("device")
					if device == "" {
						networkRequests.Add(1)
						http.Error(w, "unexpected non-device query", http.StatusBadRequest)
						return
					}
					mu.Lock()
					reads[device]++
					mu.Unlock()
					request := requests.Add(1)
					count := active.Add(1)
					defer active.Add(-1)
					for before := maximum.Load(); count > before && !maximum.CompareAndSwap(before, count); before = maximum.Load() {
					}
					amount := U64(1024)
					if request == 1 && held {
						firstStarted <- device
						// Deliberately ignore cancellation to exercise stale response rejection.
						<-releaseFirst
						defer close(firstReturned)
						if scenario == "leave before budget" {
							amount = 1000000
						}
					}
					_ = json.NewEncoder(w).Encode(history(device, amount))
					return
				}
				normal.ServeHTTP(w, r)
			}))
			defer host.Close()
			defer release()
			debug := openCommandChrome(t, "about:blank")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := debug.call(ctx, "Page.enable", map[string]any{}, nil); err != nil {
				t.Fatal(err)
			}
			instrument := `(()=>{window.demoNavigation={snapshots:[],histories:[],unhandled:[],budgetTimers:new Set};addEventListener('unhandledrejection',e=>demoNavigation.unhandled.push(String(e.reason)));const fetchOriginal=fetch;window.fetch=function(input,...args){const path=new URL(String(input),location.href).pathname;if(path==='/api/control/ui/snapshot')demoNavigation.snapshots.push(performance.now());if(path==='/api/control/ui/traffic-history')demoNavigation.histories.push(performance.now());return fetchOriginal.call(this,input,...args)};const start=setTimeout,clear=clearTimeout;window.setTimeout=(fn,delay,...args)=>{let id;const tracked=typeof fn==='function'&&Math.abs(performance.now()+Number(delay)-3000)<30;id=start(()=>{demoNavigation.budgetTimers.delete(id);fn(...args)},delay);if(tracked)demoNavigation.budgetTimers.add(id);return id};window.clearTimeout=id=>{demoNavigation.budgetTimers.delete(id);return clear(id)}})()`
			if err := debug.call(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": instrument}, nil); err != nil {
				t.Fatal(err)
			}
			if err := debug.call(ctx, "Page.navigate", map[string]any{"url": host.URL + "/"}, nil); err != nil {
				t.Fatal(err)
			}
			if scenario == "snapshot error" {
				waitChromeEvaluation(t, debug, `document.querySelector('#app .error')?.textContent.includes('demo initial snapshot failure')`)
			}
			if held {
				select {
				case <-firstStarted:
				case <-time.After(5 * time.Second):
					t.Fatal("first history request did not start")
				}
				waitChromeEvaluation(t, debug, `demoNavigation.budgetTimers.size===1`)
				if scenario == "pending first read" {
					if chromeDo(t, debug, `(async()=>{while(performance.now()<2800)await new Promise(r=>setTimeout(r,10));return demoNavigation.histories.length===1&&performance.now()<3000})()`) != true {
						t.Fatal("first history did not retain its initial navigation budget")
					}
					waitChromeEvaluation(t, debug, `Number(document.querySelector('.overview-compact-card [data-traffic-loaded]')?.dataset.trafficLoaded)===Number(document.querySelector('[data-traffic-total]')?.dataset.trafficTotal)-1`)
					if chromeDo(t, debug, `demoNavigation.histories[1]>=3000&&demoNavigation.budgetTimers.size===0`) != true {
						t.Fatal("navigation budget did not release the second slot")
					}
				} else {
					chromeDo(t, debug, `history.pushState({},'','/demo-not-found');dispatchEvent(new PopStateEvent('popstate'));true`)
					waitChromeEvaluation(t, debug, `document.querySelector('.page-not-found')&&demoNavigation.budgetTimers.size===0`)
				}
				release()
				select {
				case <-firstReturned:
				case <-time.After(3 * time.Second):
					t.Fatal("held history did not finish after release")
				}
				if scenario == "leave before budget" {
					if chromeDo(t, debug, `document.querySelector('.page-not-found')&&document.querySelectorAll('[data-node-row]').length===0`) != true {
						t.Fatal("late history completion stole navigation")
					}
					chromeDo(t, debug, `history.pushState({},'','/');dispatchEvent(new PopStateEvent('popstate'));true`)
				}
			}
			waitChromeEvaluation(t, debug, `(()=>{const value=document.querySelector('.overview-compact-card [data-traffic-loaded]');return value&&value.dataset.trafficLoaded===value.dataset.trafficTotal&&value.dataset.trafficFailed==='0'})()`)
			if chromeDo(t, debug, `demoNavigation.unhandled.length===0&&demoNavigation.budgetTimers.size===0`) != true || maximum.Load() > 2 || networkRequests.Load() != 0 {
				t.Fatal("navigation startup leaked a timer, error or duplicate network scope")
			}
			wantSnapshots := int64(1)
			if scenario == "snapshot error" {
				wantSnapshots++
				if chromeDo(t, debug, `demoNavigation.snapshots.length===2&&demoNavigation.snapshots[1]-demoNavigation.snapshots[0]>=1950`) != true {
					t.Fatal("initial snapshot failure did not use the existing fresh retry")
				}
			}
			if snapshots.Load() != wantSnapshots {
				t.Fatal("preload duplicated the original snapshot request", snapshots.Load())
			}
			if scenario == "snapshot" {
				for i := int64(1); i <= 2; i++ {
					if chromeDo(t, debug, `(async()=>{const r=await fetch('/api/control/ui/snapshot',{headers:{Accept:'application/json'}});return r.status===200&&(await r.json()).schema===3})()`) != true || snapshots.Load() != wantSnapshots+i {
						t.Fatal("later no-store reads reused the consumed preload")
					}
				}
			}
			if scenario != "leave before budget" {
				mu.Lock()
				for _, count := range reads {
					if count != 1 {
						t.Error("an unchanged device history was requested twice")
					}
				}
				if len(reads) != deviceCount {
					t.Error("an authorized history scope was omitted")
				}
				mu.Unlock()
			}
			if chromeDo(t, debug, `document.querySelector('.overview-compact-card .metric').textContent.trim()===document.querySelector('[data-traffic-total]').dataset.trafficTotal+'.0 KiB'`) != true {
				t.Fatal("cancelled history entered the current aggregate")
			}
		})
	}
}
