package webui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultExitAPIRequiresOperatorSessionAndUsesRevisionedJSON(t *testing.T) {
	d := Deps{
		Operator: "operator-secret",
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Snapshot: func() View { return View{} },
		Control:  &ControlDeps{},
	}
	getCalls := 0
	var setNode, setDeclaration, setRevision string
	d.Control.DefaultExits = &DefaultExitControlDeps{
		Get: func(nodeID string) (DefaultExitState, error) {
			getCalls++
			return DefaultExitState{
				Node: nodeID, Revision: "revision-1", Current: "best-egress",
				Options: []DefaultExitOption{{Name: "No default", Mode: "none", Available: true}},
			}, nil
		},
		Set: func(nodeID, declaration, revision string) (DefaultExitState, error) {
			setNode, setDeclaration, setRevision = nodeID, declaration, revision
			return DefaultExitState{Node: nodeID, Revision: "revision-2", Current: declaration}, nil
		},
	}
	handler := Handler(d)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/control/default-exit?node=win01", nil))
	if unauthorized.Code != http.StatusUnauthorized || getCalls != 0 ||
		!strings.Contains(unauthorized.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unauthorized GET = %d calls=%d headers=%v", unauthorized.Code, getCalls, unauthorized.Header())
	}

	get := authenticatedJSONRequest(t, d, http.MethodGet, "/api/control/default-exit?node=win01", "")
	handler.ServeHTTP(get.recorder, get.request)
	if get.recorder.Code != http.StatusOK || getCalls != 1 ||
		!strings.Contains(get.recorder.Body.String(), `"revision":"revision-1"`) ||
		get.recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated GET = %d body=%s headers=%v", get.recorder.Code, get.recorder.Body.String(), get.recorder.Header())
	}

	wrongType := authenticatedJSONRequest(t, d, http.MethodPut, "/api/control/default-exit", `{}`)
	wrongType.request.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(wrongType.recorder, wrongType.request)
	if wrongType.recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content type = %d", wrongType.recorder.Code)
	}

	unknown := authenticatedJSONRequest(t, d, http.MethodPut, "/api/control/default-exit",
		`{"node":"win01","declaration":"de-fixed","revision":"revision-1","extra":true}`)
	handler.ServeHTTP(unknown.recorder, unknown.request)
	if unknown.recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON field = %d body=%s", unknown.recorder.Code, unknown.recorder.Body.String())
	}

	put := authenticatedJSONRequest(t, d, http.MethodPut, "/api/control/default-exit",
		`{"node":"win01","declaration":"de-fixed","revision":"revision-1"}`)
	handler.ServeHTTP(put.recorder, put.request)
	if put.recorder.Code != http.StatusOK || setNode != "win01" || setDeclaration != "de-fixed" ||
		setRevision != "revision-1" || !strings.Contains(put.recorder.Body.String(), `"revision":"revision-2"`) {
		t.Fatalf("PUT = %d call=%q/%q/%q body=%s", put.recorder.Code, setNode, setDeclaration, setRevision, put.recorder.Body.String())
	}
}

func TestDefaultExitAPIMapsRevisionConflictAndRejectsOtherMethods(t *testing.T) {
	d := Deps{
		Operator: "operator-secret",
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Snapshot: func() View { return View{} },
		Control: &ControlDeps{DefaultExits: &DefaultExitControlDeps{
			Get: func(string) (DefaultExitState, error) { return DefaultExitState{}, nil },
			Set: func(string, string, string) (DefaultExitState, error) {
				return DefaultExitState{}, errors.New("SSOT 已被其他操作修改，请重新加载")
			},
		}},
	}
	handler := Handler(d)

	conflict := authenticatedJSONRequest(t, d, http.MethodPut, "/api/control/default-exit",
		`{"node":"win01","declaration":"","revision":"old"}`)
	handler.ServeHTTP(conflict.recorder, conflict.request)
	if conflict.recorder.Code != http.StatusConflict || !strings.Contains(conflict.recorder.Body.String(), "SSOT") {
		t.Fatalf("conflict = %d body=%s", conflict.recorder.Code, conflict.recorder.Body.String())
	}

	post := authenticatedJSONRequest(t, d, http.MethodPost, "/api/control/default-exit", "")
	handler.ServeHTTP(post.recorder, post.request)
	if post.recorder.Code != http.StatusMethodNotAllowed || post.recorder.Header().Get("Allow") != "GET, PUT" {
		t.Fatalf("POST = %d Allow=%q", post.recorder.Code, post.recorder.Header().Get("Allow"))
	}
}

type jsonRequest struct {
	request  *http.Request
	recorder *httptest.ResponseRecorder
}

func authenticatedJSONRequest(t *testing.T, d Deps, method, target, body string) jsonRequest {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: cookieName, Value: mintToken(d)})
	return jsonRequest{request: request, recorder: httptest.NewRecorder()}
}
