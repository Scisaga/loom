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

func TestWebChromeOverviewSharesProgressiveTrafficAndRecoversReads(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for Overview history browser acceptance")
	}
	p := relayProjectionFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: &Runtime{Authority: &Authority{root: root, projection: p}}}
	normal := server.AdminHandler()
	now := time.Date(2030, 1, 2, 12, 30, 0, 0, time.UTC)
	var revoked atomic.Bool
	var reportVersion atomic.Int64
	projection := func() WebSnapshot {
		value := testWebSnapshotWithIntent(p, true, true, true)
		for i := range value.Devices {
			value.Devices[i].LastReportAt = now.Add(time.Duration(reportVersion.Load()) * time.Second).Format(time.RFC3339Nano)
			if revoked.Load() && value.Devices[i].ID == "demo-entry" {
				value.Devices[i].Authorized = false
			}
		}
		return value
	}
	// These canonical wire fixtures isolate browser scheduling and projection.
	// Original-report verification remains covered by the traffic handler tests.
	history := func(device string) WebTrafficHistory {
		from := now.Truncate(time.Hour).Add(-23 * time.Hour).UnixMilli()
		buckets := make([]WebTrafficBucket, 24)
		for i := range buckets {
			buckets[i].Hour = from + int64(i)*time.Hour.Milliseconds()
		}
		buckets[23].Delta = &WebTrafficDelta{RXBytes: 0, TXBytes: 1024, CoveredMS: 1000, Intervals: 1, FirstAt: now.Add(-time.Second).UnixMilli(), LastAt: now.UnixMilli()}
		return WebTrafficHistory{Schema: 3, Scope: "device:" + device, From: from, Until: now.UnixMilli(), Devices: []WebDeviceTraffic{{DeviceID: device, Buckets: buckets}}}
	}
	var mu sync.Mutex
	reads := map[string]int{}
	var networkReads, active, maximum atomic.Int64
	var hold atomic.Bool
	hold.Store(true)
	waiting, release, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/control/ui/snapshot":
			_ = json.NewEncoder(w).Encode(projection())
			return
		case "/api/control/ui/live":
			connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"loom.control.ui"}})
			if err != nil {
				return
			}
			defer connection.CloseNow()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				if wsjson.Write(r.Context(), connection, map[string]any{"schema": 3, "snapshot": projection()}) != nil {
					return
				}
				select {
				case <-ticker.C:
				case <-stop:
					return
				case <-r.Context().Done():
					return
				}
			}
		case "/api/control/ui/traffic-history":
			device := r.URL.Query().Get("device")
			if device == "" {
				networkReads.Add(1)
				http.Error(w, "unexpected non-device traffic scope", http.StatusBadRequest)
				return
			}
			mu.Lock()
			reads[device]++
			mu.Unlock()
			count := active.Add(1)
			defer active.Add(-1)
			for previous := maximum.Load(); count > previous && !maximum.CompareAndSwap(previous, count); previous = maximum.Load() {
			}
			if device == "demo-exit" && hold.Swap(false) {
				close(waiting)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			_ = json.NewEncoder(w).Encode(history(device))
			return
		}
		normal.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	defer close(stop)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	debug := openCommandChrome(t, httpServer.URL+"/")
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("Overview did not request device history")
	}
	waitChromeEvaluation(t, debug, `(()=>{const card=document.querySelector('.overview-compact-card [data-traffic-loaded]');return card&&Number(card.dataset.trafficLoaded)===Number(card.dataset.trafficTotal)-1&&document.querySelector('[data-node-row="demo-entry"] [data-traffic-scope]').textContent.includes('1.0 KiB')&&document.querySelector('[data-node-row="demo-exit"] [data-traffic-scope]').textContent.includes('Unknown')})()`)
	if chromeDo(t, debug, `window.demoTrafficTotal=Number(document.querySelector('[data-traffic-total]').dataset.trafficTotal);document.querySelector('.overview-compact-card .metric').textContent===(demoTrafficTotal-1)+'.0 KiB'&&document.querySelectorAll('[data-traffic-scope^="network:"] .wg-traffic-hour').length===24`) != true {
		t.Fatal("one slow device blocked existing rows or the partial network projection")
	}
	close(release)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-loaded="'+demoTrafficTotal+'"][data-traffic-total="'+demoTrafficTotal+'"]')&&document.querySelector('.overview-compact-card .metric').textContent===demoTrafficTotal+'.0 KiB'`)
	for _, width := range []int{1600, 900, 390} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 1100, "deviceScaleFactor": 1, "mobile": width == 390}, nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if chromeDo(t, debug, `(()=>{const card=document.querySelector('.overview-compact-card'),history=card.querySelector('.wg-traffic');return card.scrollHeight<=card.clientHeight+1&&history.getBoundingClientRect().bottom<=card.getBoundingClientRect().bottom+1&&history.scrollWidth<=history.clientWidth+1})()`) != true {
			t.Fatalf("traffic source coverage or cutoffs overflowed the Overview card at %d px", width)
		}
	}
	mu.Lock()
	repeated := false
	for _, count := range reads {
		repeated = repeated || count != 1
	}
	if len(reads) != len(projection().Devices) || repeated || networkReads.Load() != 0 || maximum.Load() > 2 {
		t.Errorf("Overview repeated device work or exceeded its read bound: %v network=%d maximum=%d", reads, networkReads.Load(), maximum.Load())
	}
	mu.Unlock()

	// Cancellation below exercises the normal two-slot round after the initial
	// navigation budget. Report changes refresh without manual controls.
	waitChromeEvaluation(t, debug, `performance.now()>=3000`)
	if chromeDo(t, debug, `!document.querySelector('[data-traffic-retry]')`) != true {
		t.Fatal("successful Overview history retained manual refresh controls")
	}
	// A fetch that ignores cancellation makes late-response rejection observable.
	chromeDo(t, debug, `window.demoFetch=window.fetch;window.demoPending=[];window.fetch=(url,options)=>String(url).startsWith('/api/control/ui/traffic-history')?new Promise(resolve=>demoPending.push({url,options,resolve})):demoFetch(url,options);true`)
	reportVersion.Add(1)
	waitChromeEvaluation(t, debug, `demoPending.length===2`)
	chromeDo(t, debug, `history.pushState({},'','/ssot');dispatchEvent(new PopStateEvent('popstate'));true`)
	chromeDo(t, debug, `history.pushState({},'','/');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `demoPending.length===4`)
	if chromeDo(t, debug, `!document.querySelector('[data-traffic-retry]')`) != true {
		t.Fatal("loading history exposed manual reload controls")
	}
	chromeDo(t, debug, `(async()=>{for(const pending of demoPending.slice(0,2))pending.resolve(await demoFetch(pending.url));return true})()`)
	if chromeDo(t, debug, `document.querySelector('[data-traffic-loaded="0"]')!==null`) != true {
		t.Fatal("navigation accepted a cancelled predecessor's late response")
	}
	chromeDo(t, debug, `(async()=>{window.fetch=demoFetch;for(const pending of demoPending.slice(2))pending.resolve(await demoFetch(pending.url));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-loaded="'+demoTrafficTotal+'"]')!==null`)

	// Shorten only the history deadline, preserving all other application timers.
	chromeDo(t, debug, `window.demoSetTimeout=window.setTimeout;window.setTimeout=(callback,delay,...args)=>demoSetTimeout(callback,delay===30000?40:delay,...args);window.demoTimeoutReads=0;window.fetch=(url,options)=>{if(String(url).startsWith('/api/control/ui/traffic-history')){demoTimeoutReads++;return new Promise(()=>{})}return demoFetch(url,options)};true`)
	reportVersion.Add(1)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-loaded="0"][data-traffic-failed="'+demoTrafficTotal+'"]')!==null`)
	chromeDo(t, debug, `new Promise(resolve=>demoSetTimeout(()=>resolve(demoTimeoutReads===demoTrafficTotal),180))`)
	if chromeDo(t, debug, `demoTimeoutReads===demoTrafficTotal&&document.querySelector('[data-traffic-retry^="network:"]').textContent==='Retry'`) != true {
		t.Fatal("deadline failures held queue slots or retried without a changed input")
	}
	chromeDo(t, debug, `window.fetch=demoFetch;window.setTimeout=demoSetTimeout;document.querySelector('[data-traffic-retry^="network:"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-loaded="'+demoTrafficTotal+'"][data-traffic-failed="0"]')!==null`)

	// Withdrawal invalidates both the row and its contribution to the aggregate.
	chromeDo(t, debug, `window.demoPending=[];window.fetch=(url,options)=>String(url).startsWith('/api/control/ui/traffic-history')?new Promise(resolve=>demoPending.push({url,options,resolve})):demoFetch(url,options);true`)
	reportVersion.Add(1)
	waitChromeEvaluation(t, debug, `demoPending.length===2`)
	revoked.Store(true)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-total="'+(demoTrafficTotal-1)+'"]')!==null`)
	chromeDo(t, debug, `(async()=>{window.fetch=demoFetch;for(const pending of demoPending)pending.resolve(await demoFetch(pending.url));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-loaded="'+(demoTrafficTotal-1)+'"][data-traffic-total="'+(demoTrafficTotal-1)+'"]')&&document.querySelector('.overview-compact-card .metric').textContent===(demoTrafficTotal-1)+'.0 KiB'`)
	if chromeDo(t, debug, `document.querySelector('[data-node-row="demo-entry"] [data-traffic-scope]').textContent==='Unknown / Unknown'`) != true {
		t.Fatal("a withdrawn device's late response restored its traffic")
	}

	result := chromeDo(t, debug, `(async()=>{
 const {trafficHistoryRequest,trafficSummary,networkTrafficSummary,trafficHistoryHTML,validateTrafficHistory}=await import('/assets/traffic-history.js');
 const p=await(await demoFetch('/api/control/ui/snapshot')).json();for(const device of p.devices)device.authorized=true;
 const hour=3600000,from=Date.UTC(2030,0,1,13),until=from+23.5*hour;
 const make=(id,start,cutoff,slot,amount)=>({schema:3,scope:'device:'+id,from:start,until:cutoff,devices:[{device_id:id,buckets:Array.from({length:24},(_,i)=>({hour:start+i*hour,...(i===slot?{delta:{rx_bytes:'0',tx_bytes:String(amount),covered_ms:1000,intervals:1,first_at:start+i*hour+1000,last_at:start+i*hour+2000}}:{})}))}]});
 const a=make('demo-entry',from,until,23,11),b=make('demo-exit',from+hour,until+hour,22,7),histories=new Map;
 a.devices[0].buckets[0].delta={rx_bytes:'0',tx_bytes:'100',covered_ms:1000,intervals:1,first_at:from+1000,last_at:from+2000};
 const put=data=>{const request=trafficHistoryRequest(p,data.scope);histories.set('traffic:'+data.scope,{...request,data})};put(a);put(b);
 const summary=networkTrafficSummary(p,histories),html=trafficHistoryHTML(summary,false,true);
 if(summary.loaded!==2||summary.total!==p.devices.length||summary.tx!==18n||summary.covered!==1||summary.buckets[0].hour!==from+hour||summary.buckets[23].tx!==null||Object.hasOwn(summary.data,'until')||!html.includes(new Date(until).toISOString())||!html.includes(new Date(until+hour).toISOString()))return {error:'UTC boundary alignment or original cutoff range was lost'};
 for(const mutate of [v=>v.schema=4,v=>v.scope='device:demo-other',v=>v.from++,v=>v.devices.push(structuredClone(v.devices[0])),v=>v.devices[0].buckets[0].hour+=hour,v=>v.devices[0].buckets[23].delta.tx_bytes='18446744073709551616',v=>v.devices[0].buckets[23].delta.first_at-=hour]){
  const invalid=structuredClone(a);mutate(invalid);let rejected=false;try{validateTrafficHistory(invalid,a.scope)}catch{rejected=true}if(!rejected)return {error:'malformed source accepted'};
  const request=trafficHistoryRequest(p,a.scope),value=trafficSummary(p,a.scope,{...request,data:invalid});if(value.data||!value.error||value.tx!==null)return {error:'malformed source contributed traffic'};
 }
 histories.set('traffic:'+a.scope,{...trafficHistoryRequest(p,a.scope),error:'demo source unavailable'});
 const partial=networkTrafficSummary(p,histories),partialHTML=trafficHistoryHTML(partial,false,true);
 if(partial.loaded!==1||partial.failed!==1||partial.tx!==7n||!partialHTML.includes('data-traffic-retry')||!partialHTML.includes('Retry')||!partialHTML.includes(new Date(b.until).toISOString()))return {error:'partial failure lost successful data, its cutoff, or retry'};
 for(const device of p.devices)device.authorized=false;const empty=networkTrafficSummary(p,histories),emptyHTML=trafficHistoryHTML(empty,false,true);if(empty.data||empty.tx!==null||!emptyHTML.includes('No authorized devices')||emptyHTML.includes('Loading')||emptyHTML.includes('data-traffic-retry'))return {error:'empty authorization waited for a query or invented traffic'};
 return {passed:true};
})()`)
	if value, ok := result.(map[string]any); !ok || value["passed"] != true {
		t.Fatalf("network source validation or independent UTC windows failed: %#v", result)
	}
}
