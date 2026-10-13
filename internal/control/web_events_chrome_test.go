//go:build linux

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebChromeOverviewRecentEventsUsesExplicitShortWindow(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for summary query acceptance")
	}
	server, _ := eventTestServer(t)
	server.Now = nil
	queries := make(chan url.Values, 1)
	normal := server.AdminHandler()
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/ui/events" {
			select {
			case queries <- r.URL.Query():
			default:
			}
		}
		normal.ServeHTTP(w, r)
	}))
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-overview-event-window]')?.title.endsWith('Z')`)
	select {
	case query := <-queries:
		from, errFrom := time.Parse(time.RFC3339Nano, query.Get("from"))
		until, errUntil := time.Parse(time.RFC3339Nano, query.Get("until"))
		if errFrom != nil || errUntil != nil || until.Sub(from) != time.Hour || time.Since(until) > time.Minute || query.Has("cursor") {
			t.Fatal("summary requested the full default window or an ambiguous cutoff")
		}
	default:
		t.Fatal("summary did not use the formal authenticated Events query")
	}
	if chromeDo(t, debug, `document.querySelector('[data-overview-event-window]').textContent.includes('past hour')&&document.querySelector('.overview-events a[data-nav]').pathname==='/events'`) != true {
		t.Fatal("summary scope or full history entry was lost")
	}
}

func TestWebChromeEventsScrollRetryDraftAndFilteredExport(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for Events browser acceptance")
	}
	server, now := eventTestServer(t)
	server.Now = nil
	for i := 1; i <= 125; i++ {
		state := "running"
		if i%2 == 0 {
			state = "stopped"
		}
		eventTestReport(t, server, i, state, now.Add(-time.Hour+time.Duration(i)*time.Second))
	}
	var refuse atomic.Bool
	refuse.Store(true)
	handler := server.AdminHandler()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/ui/events" && r.URL.Query().Get("cursor") != "" && refuse.Swap(false) {
			http.Error(w, "demo continuation failure", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		handler.ServeHTTP(w, r)
	}))
	defer web.Close()
	debug := openCommandChrome(t, web.URL+"/events?kind=runtime")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1586, "height": 1040, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-event-id]').length===100&&document.querySelectorAll('[data-event-bucket]').length===432`)
	if chromeDo(t, debug, `(()=>{const form=document.querySelector('#events-filter'),r=form.getBoundingClientRect();return Math.abs(r.height-42)<1&&document.querySelectorAll('.event-table-head>span').length===3&&!document.querySelector('.event-history.card')&&document.querySelectorAll('.event-record [style]').length===0&&document.querySelectorAll('.event-legend [style]').length===0&&form.querySelector('[data-events-window]')?.value==='72'&&document.documentElement.scrollWidth<=innerWidth})()`) != true {
		t.Fatal("Events drifted from its compact toolbar, open chart, three columns or strict styles")
	}

	chromeDo(t, debug, `(()=>{const select=document.querySelector('[data-events-window]');select.value='custom';select.dispatchEvent(new Event('change'));const f=select.form;f.elements.from.value=new Date(Date.parse(f.elements.until.value)-30*60000).toISOString();f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-events-total]').textContent.includes('0 events')&&document.querySelector('.events-range[open]')`)
	if chromeDo(t, debug, `!new URLSearchParams(location.search).has('window')&&document.querySelector('[data-events-window]').value==='custom'`) != true {
		t.Fatal("time-window presentation became an unknown wire field or lost its exact UTC range")
	}
	chromeDo(t, debug, `history.back();true`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-event-id]').length===100&&document.querySelector('[data-events-window]').value==='72'`)

	if chromeDo(t, debug, `(()=>{const rows=[...document.querySelectorAll('[data-event-id]')];window.demoFirst=rows[0].dataset.eventId;rows[0].querySelector('details').open=true;const input=document.querySelector('#events-filter [name=q]');input.value='Unsubmitted draft';input.focus();return document.querySelector('[data-events-total]').textContent.includes('125 events')})()`) != true {
		t.Fatal("chart total only counted loaded page")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('[data-events-bottom]').scrollIntoView();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-events-retry]')&&document.querySelectorAll('[data-event-id]').length===100`)
	chromeDo(t, debug, `(()=>{document.querySelector('[data-events-retry]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-event-id]').length===125&&document.querySelector('[data-events-bottom]').textContent.includes('All events loaded')`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-event-id="'+demoFirst+'"]');return row.querySelector('details').open&&document.querySelector('#events-filter [name=q]').value==='Unsubmitted draft'&&new Set([...document.querySelectorAll('[data-event-id]')].map(v=>v.dataset.eventId)).size===125})()`) != true {
		t.Fatal("continuation lost draft, open details or event identity")
	}
	if chromeDo(t, debug, `(async()=>{const original=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){window.demoExportURL=this.href};document.querySelector('[data-export-events]').click();HTMLAnchorElement.prototype.click=original;const u=new URL(demoExportURL),r=await fetch(u),body=await r.text();return u.searchParams.get('kind')==='runtime'&&!u.searchParams.has('q')&&u.searchParams.has('from')&&u.searchParams.has('until')&&u.searchParams.has('result')&&body.trim().split(String.fromCharCode(10)).length===126})()`) != true {
		t.Fatal("export used draft or loaded rows instead of fixed full filter")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#events-filter');f.elements.q.value='stopped';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-events-total]').textContent.includes('124 events')&&document.querySelectorAll('[data-event-id]').length>=100`)
	// Both transitions to stopped and transitions from stopped match search.
	chromeDo(t, debug, `(()=>{document.querySelector('[data-events-clear]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#events-filter [name=q]').value===''&&document.querySelector('#events-filter [name=kind]').value===''&&document.querySelector('[data-events-total]')`)
	chromeDo(t, debug, `(()=>{history.pushState({},'','/services');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('h1')?.textContent==='Services'&&!document.querySelector('[data-events-bottom]')`)
}
