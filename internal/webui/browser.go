package webui

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

//go:embed static/*
var browserFiles embed.FS

type browserSnapshot struct {
	View        View                         `json:"view"`
	Inventory   DeviceInventory              `json:"inventory"`
	Traffic     TrafficExportView            `json:"traffic"`
	NodeTraffic map[string]TrafficExportView `json:"node_traffic"`
	Error       string                       `json:"error,omitempty"`
}

func browserView(d Deps) View {
	var v View
	if d.TrafficSnapshot != nil {
		v = d.TrafficSnapshot()
	} else if d.Snapshot != nil {
		v = d.Snapshot()
	}
	if !d.Admin {
		// 匿名私有页面只投影健康摘要，不交出连接资料、证书、完整报告或 SSOT。
		nodes := make([]NodeView, 0, len(v.Nodes))
		for _, n := range v.Nodes {
			nodes = append(nodes, NodeView{ID: n.ID, Name: n.Name, Declared: n.Declared, Roles: n.Roles, Health: n.Health, ObservedAt: n.ObservedAt, AgeSec: n.AgeSec})
		}
		return View{ObservedAt: v.ObservedAt, Nodes: nodes}
	}
	if d.Control != nil && d.Control.Enrich != nil {
		if err := d.Control.Enrich(&v); err != nil {
			v.Warnings = append(v.Warnings, "SSOT metadata unavailable")
		}
	}
	return v
}

func loadBrowserSnapshot(d Deps) browserSnapshot {
	v := browserView(d)
	result := browserSnapshot{View: v, Traffic: trafficExport(v), NodeTraffic: map[string]TrafficExportView{}}
	if d.Admin {
		for _, n := range v.Nodes {
			result.NodeTraffic[n.ID] = trafficExport(View{Self: n.ID, Nodes: []NodeView{n}})
		}
	}
	if d.Admin {
		control := deviceControl(d)
		if control != nil && control.List != nil {
			inventory, err := control.List()
			if err != nil {
				result.Error = err.Error()
			} else {
				inventory = mergeClientRuntime(inventory, v, deviceNow(d))
				result.Inventory = DeviceInventory{Devices: inventory.Clients, ActiveInvites: inventory.ActiveInvites}
			}
		}
	}
	return result
}

func browserJSON(w http.ResponseWriter, r *http.Request, d Deps, method string, admin bool) bool {
	clientJSONHeaders(w)
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSONError(w, 405, "请求方法无效")
		return false
	}
	if admin && !d.Admin {
		writeJSONError(w, 403, "需要有效管理员客户端证书")
		return false
	}
	return true
}

func registerBrowserUI(mux *http.ServeMux, d Deps) {
	registerClientReleases(mux, d)
	assets, _ := fs.Sub(browserFiles, "static")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
	})))
	mux.HandleFunc("/api/control/ui", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", false) {
			return
		}
		capabilities := map[string]bool{"admin": d.Admin, "services": false, "ssot": false}
		if d.Admin && d.Control != nil {
			capabilities["services"] = d.Control.Services != nil
			capabilities["ssot"] = d.Control.Read != nil
			if c := deviceControl(d); c != nil {
				capabilities["create"] = c.CreateInvite != nil
				capabilities["pause"] = c.SetDevicePaused != nil
				capabilities["renew"] = c.RenewInvite != nil
				capabilities["replace"] = c.ReplaceDevice != nil
				capabilities["delete"] = c.DeleteDevice != nil
				capabilities["purge"] = c.PurgeRevoked != nil
				capabilities["discard"] = c.DiscardPending != nil
			}
		}
		actions := []string{}
		if d.Admin {
			for name := range d.Actions {
				actions = append(actions, name)
			}
			sort.Strings(actions)
		}
		writeJSON(w, 200, map[string]any{"capabilities": capabilities, "actions": actions, "snapshot": loadBrowserSnapshot(d)})
	})
	mux.HandleFunc("/api/control/ui/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", false) {
			return
		}
		writeJSON(w, 200, loadBrowserSnapshot(d))
	})
	mux.HandleFunc("/api/control/ui/enrollment-options", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", true) {
			return
		}
		options, err := deviceEnrollmentOptions(d)
		if err != nil {
			writeJSONError(w, 503, err.Error())
			return
		}
		writeJSON(w, 200, options)
	})
	mux.HandleFunc("/api/control/ui/invites/", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", true) {
			return
		}
		c := deviceControl(d)
		if c == nil || c.InviteArtifact == nil {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/control/ui/invites/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		invite, err := c.InviteArtifact(id)
		if err != nil {
			writeJSONError(w, clientProtocolStatus(err), err.Error())
			return
		}
		writeJSON(w, 200, invite)
	})
	mux.HandleFunc("/api/control/ui/device-action", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "POST", true) {
			return
		}
		var input struct {
			ID      string `json:"id"`
			Action  string `json:"action"`
			Confirm bool   `json:"confirm"`
		}
		if err := decodeClientJSON(w, r, &input); err != nil {
			writeJSONError(w, clientDecodeStatus(err), err.Error())
			return
		}
		if input.ID == "" || strings.Contains(input.ID, "/") {
			writeJSONError(w, 400, "Device ID 无效")
			return
		}
		c := deviceControl(d)
		if c == nil {
			writeJSONError(w, 501, "Device 管理不可用")
			return
		}
		var err error
		var invite ClientInviteView
		switch {
		case input.Action == "pause" && c.SetDevicePaused != nil:
			err = c.SetDevicePaused(input.ID, true)
		case input.Action == "resume" && c.SetDevicePaused != nil:
			err = c.SetDevicePaused(input.ID, false)
		case input.Action == "renew" && c.RenewInvite != nil:
			invite, err = c.RenewInvite(input.ID)
		case input.Action == "replace" && c.ReplaceDevice != nil && input.Confirm:
			invite, err = c.ReplaceDevice(input.ID)
		case input.Action == "delete" && c.DeleteDevice != nil && input.Confirm:
			err = c.DeleteDevice(input.ID)
		case input.Action == "purge" && c.PurgeRevoked != nil && input.Confirm:
			err = c.PurgeRevoked(input.ID)
		case input.Action == "discard" && c.DiscardPending != nil && input.Confirm:
			err = c.DiscardPending(input.ID)
		default:
			writeJSONError(w, 400, "动作不可用或缺少确认")
			return
		}
		if err != nil {
			writeJSONError(w, clientProtocolStatus(err), err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"invite": invite})
	})
	mux.HandleFunc("/api/control/ui/services", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "POST", true) {
			return
		}
		if d.Control == nil || d.Control.Services == nil {
			writeJSONError(w, 501, "Service 管理不可用")
			return
		}
		var input struct {
			Service  ServiceInput `json:"service"`
			Revision string       `json:"revision"`
			Delete   bool         `json:"delete"`
		}
		if err := decodeClientJSON(w, r, &input); err != nil {
			writeJSONError(w, clientDecodeStatus(err), err.Error())
			return
		}
		var err error
		if input.Delete {
			if d.Control.Services.Delete == nil {
				writeJSONError(w, 501, "Service 删除不可用")
				return
			}
			err = d.Control.Services.Delete(input.Service.ID, input.Revision)
		} else {
			if d.Control.Services.Upsert == nil {
				writeJSONError(w, 501, "Service 编辑不可用")
				return
			}
			err = d.Control.Services.Upsert(input.Service, input.Revision)
		}
		if err != nil {
			writeJSONError(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"saved": true})
	})
	mux.HandleFunc("/api/control/ui/ssot", func(w http.ResponseWriter, r *http.Request) {
		clientJSONHeaders(w)
		if !d.Admin {
			writeJSONError(w, 403, "需要有效管理员客户端证书")
			return
		}
		if d.Control == nil || d.Control.Read == nil {
			writeJSONError(w, 501, "SSOT 不可用")
			return
		}
		c := d.Control
		revision := func() string {
			if c.Revision != nil {
				v, _ := c.Revision()
				return v
			}
			return ""
		}
		if r.Method == "GET" {
			body, err := c.Read()
			if err != nil {
				writeJSONError(w, 503, err.Error())
				return
			}
			writeJSON(w, 200, map[string]string{"content": body, "revision": revision()})
			return
		}
		if r.Method != "POST" {
			writeJSONError(w, 405, "只接受 GET 或 POST")
			return
		}
		var input struct {
			Content  string `json:"content"`
			Revision string `json:"revision"`
			Action   string `json:"action"`
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeJSONError(w, 415, "Content-Type 必须是 application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			writeJSONError(w, 400, "JSON 无法解析")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			writeJSONError(w, 400, "请求只能包含一个 JSON 对象")
			return
		}
		if input.Action != "validate" && input.Action != "save" {
			writeJSONError(w, 400, "SSOT 动作无效")
			return
		}
		if c.Validate == nil {
			writeJSONError(w, 501, "SSOT 校验不可用")
			return
		}
		findings, err := c.Validate(input.Content)
		if err != nil {
			writeJSONError(w, 400, err.Error())
			return
		}
		if input.Action == "save" && findings == "" {
			if c.SaveIfRevision == nil {
				writeJSONError(w, 501, "缺少带 revision 的保存能力")
				return
			}
			if err = c.SaveIfRevision(input.Content, input.Revision); err != nil {
				writeJSONError(w, 409, err.Error())
				return
			}
		}
		writeJSON(w, 200, map[string]any{"findings": findings, "saved": input.Action == "save" && findings == "", "revision": revision()})
	})
	mux.HandleFunc("/api/control/ui/events", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", true) {
			return
		}
		events := []EventView{}
		if d.Events != nil {
			events = filterEvents(d.Events(1000), eventFilterFromRequest(r))
		}
		unresolved := []UnresolvedView{}
		if d.Unresolved != nil {
			unresolved = d.Unresolved()
		}
		writeJSON(w, 200, map[string]any{"events": events, "unresolved": unresolved})
	})
	mux.HandleFunc("/api/control/ui/action/", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "POST", true) {
			return
		}
		fn, ok := d.Actions[strings.TrimPrefix(r.URL.Path, "/api/control/ui/action/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		out, err := fn()
		if err != nil {
			writeJSONError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"output": out})
	})
	mux.HandleFunc("/events.csv", func(w http.ResponseWriter, r *http.Request) {
		if !browserJSON(w, r, d, "GET", true) {
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="loom-events.csv"`)
		writer := csv.NewWriter(w)
		defer writer.Flush()
		_ = writer.Write([]string{"timestamp", "node", "kind", "subject", "from", "to", "level", "duration", "ongoing", "detail"})
		if d.Events != nil {
			for _, e := range filterEvents(d.Events(10000), eventFilterFromRequest(r)) {
				_ = writer.Write([]string{e.TS, e.Node, e.Kind, e.Subject, e.From, e.To, e.Level, e.Lasted, strconv.FormatBool(e.Ongoing), e.Detail})
			}
		}
	})
	mux.HandleFunc("/devices/download/linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Path = "/clients/download/linux-amd64"
		clone.URL = &u
		mux.ServeHTTP(w, clone)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		removed := map[string]bool{"/login": true, "/logout": true, "/nodes/add": true, "/nodes/add/": true, "/devices/create": true, "/devices/pause": true, "/devices/resume": true, "/devices/delete": true, "/devices/renew-invite": true, "/devices/replace": true, "/devices/purge-revoked": true, "/devices/discard-pending": true}
		if removed[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "只接受 GET", 405)
			return
		}
		path := r.URL.Path
		switch path {
		case "/", "/devices", "/clients", "/nodes", "/topology", "/services", "/routing", "/releases", "/deployments", "/events", "/settings", "/ssot":
		default:
			if !strings.HasPrefix(path, "/devices/") && !strings.HasPrefix(path, "/nodes/") {
				http.NotFound(w, r)
				return
			}
		}
		body, _ := browserFiles.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "same-origin")
		if r.Method == "GET" {
			_, _ = w.Write(body)
		}
	})
}
